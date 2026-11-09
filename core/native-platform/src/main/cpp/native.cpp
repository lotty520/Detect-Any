#include <dlfcn.h>
#include <fcntl.h>
#include <jni.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <string>
#include <vector>

// ---- 内部桥接声明（实现见 raw_syscalls.cpp / elf_inspect.cpp / props.cpp） ----
long da_svc_fstatat(int dirfd, const char *path, struct stat *st, int flags);
long da_libc_fstatat(int dirfd, const char *path, struct stat *st, int flags);
long da_svc_faccessat(int dirfd, const char *path, int mode);
long da_libc_faccessat(int dirfd, const char *path, int mode);
bool da_svc_nr_allowed(long nr);
unsigned long da_elf_export_value(const char *path, const char *symbol);
unsigned long da_maps_base(const char *path);
int da_prop_list(std::vector<std::string> *out);
int da_prop_get(const char *key, char *buf, size_t buf_size, int *truncated);

// raw_syscalls.cpp / probes.cpp / elf_inspect.cpp 新增探针
long da_svc_statfs(const char *path, unsigned long *f_type, unsigned long *bsize, unsigned long *blocks);
int da_supercall_timing(long *out_truncate_ns, long *out_ftruncate_ns, long *out_getpid_ns, int iterations);
int da_fd_names(std::vector<std::string> *out);
int da_ksu_probe(long magic1, long magic2, long magic3, long arg4,
                 long *ret, int *err, std::vector<std::string> *new_fds);
int da_apatch_probe(const char *key, long ver_and_cmd, long *ret, int *err, long *elapsed_ns);
long da_selinux_label_probe(const char *label, int *out_errno);
long da_legacy_prctl_probe(long option, long arg2, long arg3, long arg4, long arg5);
int da_nativebridge_error();
long da_ptrace_parent_eventmsg();
long da_mem_read(unsigned long addr, void *buf, size_t len);
long da_text_read(unsigned long addr, void *buf, size_t len);
int da_solist(std::vector<std::string> *out);
int da_rwx_self_probe();
long da_elf_read_at_vaddr(const char *path, unsigned long vaddr, unsigned char *buf, size_t len);
int da_elf_relocations(const char *path, std::vector<std::string> *out);

#define DA_PKG(method) Java_com_detectany_core_nativeplatform_##method

extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM * /*vm*/, void * /*reserved*/) {
    return JNI_VERSION_1_6;
}

// ---------- NativePlatform ----------

extern "C" JNIEXPORT jstring JNICALL DA_PKG(NativePlatform_nativeVersion)(JNIEnv *env, jobject) {
    return env->NewStringUTF("detectany-native/0.2.0");
}

// ---------- SyscallJni：三路执行器（stat/access 的 libc 与 svc 两路） ----------
// 约定：statXxx 返回 long[9] = [tag, errno, dev, ino, mode, uid, gid, size, mtimeSec]
//       tag: 0=成功, 1=errno；accessXxx 返回 long[2] = [tag, errno]

static jlongArray pack_stat(JNIEnv *env, long ret, int errnoValue, const struct stat &st) {
    jlong out[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
    if (ret == 0) {
        out[0] = 0;
        out[2] = static_cast<jlong>(st.st_dev);
        out[3] = static_cast<jlong>(st.st_ino);
        out[4] = static_cast<jlong>(st.st_mode);
        out[5] = static_cast<jlong>(st.st_uid);
        out[6] = static_cast<jlong>(st.st_gid);
        out[7] = static_cast<jlong>(st.st_size);
        out[8] = static_cast<jlong>(st.st_mtime);
    } else {
        out[0] = 1;
        out[1] = errnoValue;
    }
    jlongArray arr = env->NewLongArray(9);
    env->SetLongArrayRegion(arr, 0, 9, out);
    return arr;
}

static jlongArray stat_common(JNIEnv *env, jstring jpath, long (*fn)(int, const char *, struct stat *, int), bool rawSvc) {
    const char *path = env->GetStringUTFChars(jpath, nullptr);
    struct stat st = {};
    errno = 0;
    const long ret = fn(AT_FDCWD, path, &st, 0);
    int e = errno;
    if (rawSvc && ret != 0 && ret >= -4095L) {
        e = static_cast<int>(-ret);  // 裸 svc 不写 errno —— 从负返回值反推
    }
    env->ReleaseStringUTFChars(jpath, path);
    return pack_stat(env, ret, e, st);
}

extern "C" JNIEXPORT jlongArray JNICALL DA_PKG(SyscallJni_statSvc)(JNIEnv *env, jobject, jstring jpath) {
    return stat_common(env, jpath, da_svc_fstatat, true);
}

extern "C" JNIEXPORT jlongArray JNICALL DA_PKG(SyscallJni_statLibc)(JNIEnv *env, jobject, jstring jpath) {
    return stat_common(env, jpath, da_libc_fstatat, false);
}

static jlongArray access_common(JNIEnv *env, jstring jpath, jint mode, long (*fn)(int, const char *, int), bool rawSvc) {
    const char *path = env->GetStringUTFChars(jpath, nullptr);
    errno = 0;
    const long ret = fn(AT_FDCWD, path, static_cast<int>(mode));
    int e = errno;
    if (rawSvc && ret != 0 && ret >= -4095L) {
        e = static_cast<int>(-ret);
    }
    env->ReleaseStringUTFChars(jpath, path);
    jlong out[2] = {(ret == 0) ? 0LL : 1LL, e};
    jlongArray arr = env->NewLongArray(2);
    env->SetLongArrayRegion(arr, 0, 2, out);
    return arr;
}

extern "C" JNIEXPORT jlongArray JNICALL DA_PKG(SyscallJni_accessSvc)(JNIEnv *env, jobject, jstring jpath, jint mode) {
    return access_common(env, jpath, mode, da_svc_faccessat, true);
}

extern "C" JNIEXPORT jlongArray JNICALL DA_PKG(SyscallJni_accessLibc)(JNIEnv *env, jobject, jstring jpath, jint mode) {
    return access_common(env, jpath, mode, da_libc_faccessat, false);
}

extern "C" JNIEXPORT jboolean JNICALL DA_PKG(SyscallJni_svcNrAllowed)(JNIEnv *, jobject, jlong nr) {
    return da_svc_nr_allowed(nr) ? JNI_TRUE : JNI_FALSE;
}

// ---------- ElfJni：磁盘自解析（不经 dlsym） ----------

extern "C" JNIEXPORT jlong JNICALL DA_PKG(ElfJni_exportValue)(JNIEnv *env, jobject, jstring jpath, jstring jsymbol) {
    const char *path = env->GetStringUTFChars(jpath, nullptr);
    const char *symbol = env->GetStringUTFChars(jsymbol, nullptr);
    const unsigned long value = da_elf_export_value(path, symbol);
    env->ReleaseStringUTFChars(jsymbol, symbol);
    env->ReleaseStringUTFChars(jpath, path);
    return static_cast<jlong>(value);
}

extern "C" JNIEXPORT jlong JNICALL DA_PKG(ElfJni_mappedBase)(JNIEnv *env, jobject, jstring jpath) {
    const char *path = env->GetStringUTFChars(jpath, nullptr);
    const unsigned long base = da_maps_base(path);
    env->ReleaseStringUTFChars(jpath, path);
    return static_cast<jlong>(base);
}

// 仅用于验证（任务 2.3）：dlsym 实测地址，与磁盘自解析的期望地址交叉比对。
// 生产判定路径不使用 dlsym。
extern "C" JNIEXPORT jlong JNICALL DA_PKG(ElfJni_dlsymAddress)(JNIEnv *env, jobject, jstring jsymbol) {
    const char *symbol = env->GetStringUTFChars(jsymbol, nullptr);
    void *addr = dlsym(RTLD_DEFAULT, symbol);
    env->ReleaseStringUTFChars(jsymbol, symbol);
    return reinterpret_cast<jlong>(addr);
}

// ---------- ProbeJni：C2/C6/C8 行为与结构探针 ----------

extern "C" JNIEXPORT jlongArray JNICALL DA_PKG(SyscallJni_statfsSvc)(JNIEnv *env, jobject, jstring jpath) {
    const char *path = env->GetStringUTFChars(jpath, nullptr);
    unsigned long f_type = 0, bsize = 0, blocks = 0;
    errno = 0;
    const long r = da_svc_statfs(path, &f_type, &bsize, &blocks);
    const int e = errno;
    env->ReleaseStringUTFChars(jpath, path);
    jlong out[5] = {(r == 0) ? 0LL : 1LL, e, static_cast<jlong>(f_type), static_cast<jlong>(bsize), static_cast<jlong>(blocks)};
    jlongArray arr = env->NewLongArray(5);
    env->SetLongArrayRegion(arr, 0, 5, out);
    return arr;
}

static jobjectArray to_string_array(JNIEnv *env, const std::vector<std::string> &v) {
    const jclass stringCls = env->FindClass("java/lang/String");
    const jobjectArray arr = env->NewObjectArray(static_cast<jsize>(v.size()), stringCls, nullptr);
    for (size_t i = 0; i < v.size(); i++) {
        env->SetObjectArrayElement(arr, static_cast<jsize>(i), env->NewStringUTF(v[i].c_str()));
    }
    return arr;
}

extern "C" JNIEXPORT jobjectArray JNICALL DA_PKG(ProbeJni_fdNames)(JNIEnv *env, jobject) {
    std::vector<std::string> names;
    da_fd_names(&names);
    return to_string_array(env, names);
}

// 返回 String[]：元素 0 = "ret=<r>;errno=<e>"，后续 = 新增 fd 名
extern "C" JNIEXPORT jobjectArray JNICALL DA_PKG(ProbeJni_ksuProbe)(JNIEnv *env, jobject,
                                                                    jlong m1, jlong m2, jlong m3, jlong arg4) {
    long ret = 0;
    int err = 0;
    std::vector<std::string> new_fds;
    da_ksu_probe(m1, m2, m3, arg4, &ret, &err, &new_fds);
    std::vector<std::string> out;
    char head[96];
    snprintf(head, sizeof(head), "ret=%ld;errno=%d", ret, err);
    out.emplace_back(head);
    for (const auto &f : new_fds) out.push_back(f);
    return to_string_array(env, out);
}

extern "C" JNIEXPORT jlongArray JNICALL DA_PKG(ProbeJni_apatchProbe)(JNIEnv *env, jobject,
                                                                     jstring jkey, jlong cmd) {
    const char *key = env->GetStringUTFChars(jkey, nullptr);
    long ret = 0, elapsed = 0;
    int err = 0;
    da_apatch_probe(key, cmd, &ret, &err, &elapsed);
    env->ReleaseStringUTFChars(jkey, key);
    jlong out[3] = {ret, err, elapsed};
    jlongArray arr = env->NewLongArray(3);
    env->SetLongArrayRegion(arr, 0, 3, out);
    return arr;
}

extern "C" JNIEXPORT jlongArray JNICALL DA_PKG(ProbeJni_selinuxLabelProbe)(JNIEnv *env, jobject, jstring jlabel) {
    const char *label = env->GetStringUTFChars(jlabel, nullptr);
    int e = 0;
    const long r = da_selinux_label_probe(label, &e);
    env->ReleaseStringUTFChars(jlabel, label);
    jlong out[2] = {r, e};
    jlongArray arr = env->NewLongArray(2);
    env->SetLongArrayRegion(arr, 0, 2, out);
    return arr;
}

extern "C" JNIEXPORT jint JNICALL DA_PKG(ProbeJni_nativebridgeError)(JNIEnv *, jobject) {
    return da_nativebridge_error();
}

extern "C" JNIEXPORT jlongArray JNICALL DA_PKG(ProbeJni_prctlProbe)(JNIEnv *env, jobject,
                                                                     jlong option, jlong a2, jlong a3, jlong a4, jlong a5) {
    errno = 0;
    const long r = da_legacy_prctl_probe(option, a2, a3, a4, a5);
    const int e = errno;
    jlong out[2] = {r, e};
    jlongArray arr = env->NewLongArray(2);
    env->SetLongArrayRegion(arr, 0, 2, out);
    return arr;
}

extern "C" JNIEXPORT jlong JNICALL DA_PKG(ProbeJni_ptraceParentEventmsg)(JNIEnv *, jobject) {
    return da_ptrace_parent_eventmsg();
}

extern "C" JNIEXPORT jbyteArray JNICALL DA_PKG(ProbeJni_memRead)(JNIEnv *env, jobject, jlong addr, jint len) {
    if (len <= 0 || len > 65536) return nullptr;
    std::vector<unsigned char> buf(static_cast<size_t>(len));
    const long n = da_mem_read(static_cast<unsigned long>(addr), buf.data(), buf.size());
    if (n <= 0) return nullptr;
    const jbyteArray arr = env->NewByteArray(static_cast<jsize>(n));
    env->SetByteArrayRegion(arr, 0, static_cast<jsize>(n), reinterpret_cast<const jbyte *>(buf.data()));
    return arr;
}

extern "C" JNIEXPORT jbyteArray JNICALL DA_PKG(ProbeJni_textRead)(JNIEnv *env, jobject, jlong addr, jint len) {
    if (len <= 0 || len > 65536) return nullptr;
    std::vector<unsigned char> buf(static_cast<size_t>(len));
    const long n = da_text_read(static_cast<unsigned long>(addr), buf.data(), buf.size());
    if (n <= 0) return nullptr;
    const jbyteArray arr = env->NewByteArray(static_cast<jsize>(n));
    env->SetByteArrayRegion(arr, 0, static_cast<jsize>(n), reinterpret_cast<const jbyte *>(buf.data()));
    return arr;
}

extern "C" JNIEXPORT jlongArray JNICALL DA_PKG(ProbeJni_supercallTiming)(JNIEnv *env, jobject, jint iterations) {
    long tr = 0, ftr = 0, pid = 0;
    da_supercall_timing(&tr, &ftr, &pid, iterations);
    jlong out[3] = {tr, ftr, pid};
    jlongArray arr = env->NewLongArray(3);
    env->SetLongArrayRegion(arr, 0, 3, out);
    return arr;
}

extern "C" JNIEXPORT jobjectArray JNICALL DA_PKG(ProbeJni_solist)(JNIEnv *env, jobject) {
    std::vector<std::string> list;
    da_solist(&list);
    return to_string_array(env, list);
}

extern "C" JNIEXPORT jint JNICALL DA_PKG(ProbeJni_rwxSelfProbe)(JNIEnv *, jobject) {
    return da_rwx_self_probe();
}

// ---------- ElfJni 扩展（C7） ----------

extern "C" JNIEXPORT jbyteArray JNICALL DA_PKG(ElfJni_readAtVaddr)(JNIEnv *env, jobject,
                                                                   jstring jpath, jlong vaddr, jint len) {
    const char *path = env->GetStringUTFChars(jpath, nullptr);
    std::vector<unsigned char> buf(static_cast<size_t>(len));
    const long n = da_elf_read_at_vaddr(path, static_cast<unsigned long>(vaddr), buf.data(), buf.size());
    env->ReleaseStringUTFChars(jpath, path);
    if (n <= 0) return nullptr;
    const jbyteArray arr = env->NewByteArray(static_cast<jsize>(n));
    env->SetByteArrayRegion(arr, 0, static_cast<jsize>(n), reinterpret_cast<const jbyte *>(buf.data()));
    return arr;
}

extern "C" JNIEXPORT jobjectArray JNICALL DA_PKG(ElfJni_relocations)(JNIEnv *env, jobject, jstring jpath) {
    const char *path = env->GetStringUTFChars(jpath, nullptr);
    std::vector<std::string> relocs;
    da_elf_relocations(path, &relocs);
    env->ReleaseStringUTFChars(jpath, path);
    return to_string_array(env, relocs);
}

// ---------- PropJni：属性访问（API 24 兼容） ----------

extern "C" JNIEXPORT jobjectArray JNICALL DA_PKG(PropJni_propList)(JNIEnv *env, jobject) {
    std::vector<std::string> props;
    da_prop_list(&props);
    const jclass stringCls = env->FindClass("java/lang/String");
    const jobjectArray arr = env->NewObjectArray(static_cast<jsize>(props.size()), stringCls, nullptr);
    for (size_t i = 0; i < props.size(); i++) {
        env->SetObjectArrayElement(arr, static_cast<jsize>(i), env->NewStringUTF(props[i].c_str()));
    }
    return arr;
}

extern "C" JNIEXPORT jstring JNICALL DA_PKG(PropJni_propGet)(JNIEnv *env, jobject, jstring jkey) {
    const char *key = env->GetStringUTFChars(jkey, nullptr);
    char value[PROP_VALUE_MAX];
    int truncated = 0;
    const int rc = da_prop_get(key, value, sizeof(value), &truncated);
    env->ReleaseStringUTFChars(jkey, key);
    if (rc != 0) return nullptr;
    // 截断约定：Kotlin 侧以 value.length == PROP_VALUE_MAX-1(91) 判「疑似截断」
    return env->NewStringUTF(value);
}
