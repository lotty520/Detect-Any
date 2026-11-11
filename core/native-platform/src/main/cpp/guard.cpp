#include <errno.h>
#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <memory>

#include "svc_arch.h"

// 任务 6.1/6.2：自保护 native 层。
// 预期值「加密分散存储」：签名摘要与 DEX CRC 均拆成两段常量、运行时异或还原，
// 且常数时间比较——smali 层看不到明文预期值。
// 占位常量在发布装配时由构建脚本替换（与发布签名/DEX 一一对应）。

long da_raw_ptrace(long request, long pid, long addr, long data);

namespace {

// 预期 APK 签名证书 sha256（占位；发布时替换）：
constexpr unsigned char SIG_A[32] = {
    0x5a, 0x11, 0xc3, 0x7f, 0x9b, 0x02, 0x4d, 0xe8,
    0x33, 0xa0, 0x66, 0x1d, 0xcf, 0x54, 0x90, 0x2e,
    0x77, 0x0b, 0x21, 0xf6, 0x18, 0x8d, 0xa4, 0x35,
    0xc9, 0x60, 0x03, 0xbe, 0xd2, 0x4f, 0x17, 0x8a,
};
constexpr unsigned char SIG_B[32] = {
    0x35, 0x62, 0x18, 0x31, 0x0d, 0x99, 0xe1, 0x4c,
    0x7a, 0x2f, 0xd1, 0x93, 0x60, 0x11, 0xf5, 0x68,
    0x88, 0x3d, 0x52, 0x0b, 0xe6, 0x29, 0x5b, 0xca,
    0x16, 0x8f, 0x74, 0x25, 0x43, 0x99, 0x06, 0xd5,
};

// 预期 classes.dex CRC32（占位；发布时替换），两段异或：
constexpr uint32_t CRC_A = 0x3fa2c910u;
constexpr uint32_t CRC_B = 0x6c17d5e8u;

void assemble_sig(unsigned char out[32]) {
    for (int i = 0; i < 32; i++) out[i] = SIG_A[i] ^ SIG_B[i];
}

// P3（2026-11-11）：占位哨兵——首字节若仍是占位特征值，release 装配未完成，
// 上层应降级 SelfGuard 而非用占位常量误报 repackaged(A)。
// 占位 XOR 首字节 = 0x5a^0x35 = 0x6f；发布装配时替换常量后此函数自然返回 false。
jboolean da_sig_is_placeholder() {
    unsigned char buf[32];
    assemble_sig(buf);
    return buf[0] == 0x6f ? JNI_TRUE : JNI_FALSE;
}

// CRC 占位哨兵：占位 XOR = 0x53b51cf8；发布装配替换常量后自然返回 false
jboolean da_crc_is_placeholder() {
    return (CRC_A ^ CRC_B) == 0x53b51cf8u ? JNI_TRUE : JNI_FALSE;
}

}  // namespace

// ---- GuardJni（com.detectany.selfguard）----

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_detectany_selfguard_GuardJni_assembleExpectedSignature(JNIEnv *env, jobject) {
    unsigned char buf[32];
    assemble_sig(buf);
    const jbyteArray arr = env->NewByteArray(32);
    env->SetByteArrayRegion(arr, 0, 32, reinterpret_cast<const jbyte *>(buf));
    return arr;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_detectany_selfguard_GuardJni_assembleExpectedDexCrc(JNIEnv *, jobject) {
    return static_cast<jlong>(static_cast<uint32_t>(CRC_A ^ CRC_B));
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_detectany_selfguard_GuardJni_signatureIsPlaceholder(JNIEnv *, jobject) {
    return da_sig_is_placeholder();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_detectany_selfguard_GuardJni_crcIsPlaceholder(JNIEnv *, jobject) {
    return da_crc_is_placeholder();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_detectany_selfguard_GuardJni_constantTimeEquals(JNIEnv *env, jobject,
                                                          jbyteArray ja, jbyteArray jb) {
    const jsize na = env->GetArrayLength(ja);
    const jsize nb = env->GetArrayLength(jb);
    if (na <= 0 || nb <= 0 || na != nb) return JNI_FALSE;
    std::unique_ptr<unsigned char[]> a(new unsigned char[na]);
    std::unique_ptr<unsigned char[]> b(new unsigned char[na]);
    env->GetByteArrayRegion(ja, 0, na, reinterpret_cast<jbyte *>(a.get()));
    env->GetByteArrayRegion(jb, 0, na, reinterpret_cast<jbyte *>(b.get()));
    unsigned char diff = 0;
    for (jsize i = 0; i < na; i++) diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    return diff == 0 ? JNI_TRUE : JNI_FALSE;
}

// ---- 调试器探针（任务 6.2）：fork 子进程 PTRACE_ATTACH 父进程 ----
// 父进程已被调试器附加时，子进程的 ATTACH 返回 -EPERM。
// 返回：0 = 无调试器；1 = 有调试器；-1 = 探针不可执行。
extern "C" JNIEXPORT jint JNICALL
Java_com_detectany_selfguard_GuardJni_debuggerProbe(JNIEnv *env, jobject) {
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;
    const pid_t parent = getppid();
    const pid_t child = fork();
    if (child < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (child == 0) {
        close(pipefd[0]);
        errno = 0;
        const long r = da_raw_ptrace(16 /*PTRACE_ATTACH*/, parent, 0, 0);
        int flag;
        if (r == 0) {
            int status = 0;
            waitpid(parent, &status, 0);
            da_raw_ptrace(17 /*PTRACE_DETACH*/, parent, 0, 0);
            flag = 0;
        } else if (errno == EPERM) {
            flag = 1;  // 已被调试器占用
        } else {
            flag = -1;
        }
        const uint32_t v = static_cast<uint32_t>(flag);
        if (write(pipefd[1], &v, sizeof(v)) != static_cast<ssize_t>(sizeof(v))) _exit(3);
        _exit(0);
    }
    close(pipefd[1]);
    uint32_t v = 0xFFFFFFFFu;
    const ssize_t n = read(pipefd[0], &v, sizeof(v));
    close(pipefd[0]);
    int status = 0;
    waitpid(child, &status, 0);
    if (n != static_cast<ssize_t>(sizeof(v))) return -1;
    return static_cast<jint>(v);
}
