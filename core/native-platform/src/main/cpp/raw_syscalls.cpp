#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>

#include "svc_arch.h"

// 任务 2.1/2.2：裸 svc 三路执行器 + syscall 守卫。
//
// 守卫原则（specs/signal-collection「兼容门控强制」）：
// - 原生层只放行显式白名单内的 syscall 号 —— Kotlin 层(ProbeCap)做版本×内核×targetSdk
//   门控，本层是纵深防御：即使上层误调用，白名单外的号也拒绝执行。
// - statx 一类「白名单外 = SIGSYS 杀进程」的调用在本项目任何路径都不会发起。
// - 全部裸 syscall 必须经 guard_* 入口，禁止在别处直接调 da_syscall*。

namespace {

// 与 Kotlin 侧 com.detectany.core.nativeplatform.SyscallAllowlist 保持镜像（双端各自静态定义，
// 单测断言两集合一致）。语义：三路 diff 最小集 + 显式探针号（全部只读/无副作用或被内核安全检查前置拦截）。
constexpr long kAllowedNrs[] = {
#if defined(__aarch64__)
    56L,    // openat
    57L,    // close
    79L,    // newfstatat
    48L,    // faccessat
    43L,    // statfs（C2 statfs 交叉）
    142L,   // reboot（C8 KSU supercall 探针：无 CAP_SYS_BOOT 时内核先返回 -EPERM，无副作用）
    167L,   // prctl（C8 旧版 KSU 探针）
    117L,   // ptrace（C8 父进程注入残留探针）
    45L,    // APatch supercall（复用 truncate 号；无 superkey 时退化为 truncate 失败）
#else
    322L,   // openat (arm32)
    6L,     // close (arm32)
    300L,   // fstatat64/newfstatat (arm32)
    334L,   // faccessat (arm32)
    266L,   // statfs64 (arm32)
    88L,    // reboot (arm32)
    172L,   // prctl (arm32)
    26L,    // ptrace (arm32)
    46L,    // APatch supercall (arm32: __NR3264_truncate)
#endif
};

bool nr_allowed(long nr) {
    for (long allowed : kAllowedNrs) {
        if (allowed == nr) return true;
    }
    return false;
}

long guarded(long nr, long a0, long a1, long a2, long a3, bool need4) {
    if (!nr_allowed(nr)) {
        // 不可能的路径：直接拒绝而不发起调用（绝不试探）
        return -EPERM;
    }
    return need4 ? da_syscall4(nr, a0, a1, a2, a3) : da_syscall3(nr, a0, a1, a2);
}

int errno_of(long ret) {
    return (ret < 0 && ret >= -4095L) ? static_cast<int>(-ret) : 0;
}

}  // namespace

// ---- 裸 svc 路径（供 JNI 导出） ----

long da_svc_fstatat(int dirfd, const char *path, struct stat *st, int flags) {
#if defined(__aarch64__)
    constexpr long kNr = 79L;
#else
    constexpr long kNr = 300L;
#endif
    return guarded(kNr, dirfd, reinterpret_cast<long>(path), reinterpret_cast<long>(st), flags, true);
}

long da_svc_faccessat(int dirfd, const char *path, int mode) {
#if defined(__aarch64__)
    constexpr long kNr = 48L;
#else
    constexpr long kNr = 334L;
#endif
    return guarded(kNr, dirfd, reinterpret_cast<long>(path), mode, 0, false);
}

long da_svc_openat(int dirfd, const char *path, int flags, int mode) {
#if defined(__aarch64__)
    constexpr long kNr = 56L;
#else
    constexpr long kNr = 322L;
#endif
    return guarded(kNr, dirfd, reinterpret_cast<long>(path), flags, mode, true);
}

long da_svc_close(int fd) {
#if defined(__aarch64__)
    constexpr long kNr = 57L;
#else
    constexpr long kNr = 6L;
#endif
    return guarded(kNr, fd, 0, 0, 0, false);
}

// ---- libc 对照路径（同一批事实，经 libc 包装，可被 PLT/GOT hook） ----

long da_libc_fstatat(int dirfd, const char *path, struct stat *st, int flags) {
    return fstatat(dirfd, path, st, flags);
}

long da_libc_faccessat(int dirfd, const char *path, int mode) {
    return faccessat(dirfd, path, mode, 0);
}

long da_libc_openat(int dirfd, const char *path, int flags, int mode) {
    return openat(dirfd, path, flags, mode);
}

// 守卫可见性（供调试/JNI 查询）
bool da_svc_nr_allowed(long nr) { return nr_allowed(nr); }

// ---- C2：statfs 交叉（f_type 魔数判别 tmpfs/overlay/fuse） ----

long da_svc_statfs(const char *path, unsigned long *f_type, unsigned long *bsize, unsigned long *blocks) {
#if defined(__aarch64__)
    constexpr long kNr = 43L;
    struct statfs st {};
    const long ret = guarded(kNr, reinterpret_cast<long>(path), reinterpret_cast<long>(&st), 0, 0, false);
#else
    constexpr long kNr = 266L;
    struct statfs64 st {};
    const long ret = guarded(kNr, reinterpret_cast<long>(path), reinterpret_cast<long>(&st), sizeof(st), 0, true);
#endif
    if (ret == 0) {
        *f_type = static_cast<unsigned long>(st.f_type);
        *bsize = static_cast<unsigned long>(st.f_bsize);
        *blocks = static_cast<unsigned long>(st.f_blocks);
    }
    return ret;
}

// ---- C8：行为探针（裸 svc） ----

// KSU 系 supercall：reboot(0xDEADBEEF, 0xCAFEBABE, magic3, arg4)。
// 原厂内核：无 CAP_SYS_BOOT → -EPERM（内核在解析 magic 前拦截，无副作用）。
// KSU v2.0+：kprobe pre_handler 匹配双魔数 → task_work 安装 anon_inode:[ksu_driver] fd。
long da_ksu_reboot_supercall(long magic1, long magic2, long magic3, long arg4) {
#if defined(__aarch64__)
    constexpr long kNr = 142L;
#else
    constexpr long kNr = 88L;
#endif
    return guarded(kNr, magic1, magic2, magic3, arg4, true);
}

// 旧版 KSU（<=v1.0.5）prctl 探针：prctl(0xDEADBEEF, arg2..arg5)。
long da_legacy_prctl_probe(long option, long arg2, long arg3, long arg4, long arg5) {
#if defined(__aarch64__)
    constexpr long kNr = 167L;
#else
    constexpr long kNr = 172L;
#endif
    if (!nr_allowed(kNr)) return -EPERM;
    return da_syscall5(kNr, option, arg2, arg3, arg4, arg5);
}

// APatch supercall：syscall(45, superkey, ver_and_cmd, arg3, arg4)。
// 无 superkey 时原厂/未授权均退化为 truncate 失败；计时侧信道由上层叠加。
long da_apatch_supercall(const char *key, long ver_and_cmd, long arg3, long arg4) {
#if defined(__aarch64__)
    constexpr long kNr = 45L;
#else
    constexpr long kNr = 46L;
#endif
    return guarded(kNr, reinterpret_cast<long>(key), ver_and_cmd, arg3, arg4, true);
}

// ftruncate 裸调用（syscall 46，APatch 不 hook 此调用——用于时序基线对比）
long da_svc_ftruncate(int fd, long length) {
#if defined(__aarch64__)
    constexpr long kNr = 46L;
#else
    constexpr long kNr = 46L; // arm32 ftruncate 也是 46
#endif
    return guarded(kNr, fd, length, 0, 0, true);
}

// ---- 时序侧信道：syscall 45 (被 APatch hook) vs 46 (未被 hook) ----
// APatch 的 supercall handler 在 syscall 45 上做 superkey 字符串比对后
// 才 fall through 到真实 truncate → 可测量的额外开销。
// 返回 long[4]: [truncate_median_ns, ftruncate_median_ns, getpid_median_ns, iterations]
int da_supercall_timing(long *out_truncate_ns, long *out_ftruncate_ns, long *out_getpid_ns, int iterations) {
    if (iterations <= 0 || iterations > 10000) iterations = 1000;

    struct timespec ts {};
    auto now_ns = [&ts]() -> long {
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return ts.tv_sec * 1000000000L + ts.tv_nsec;
    };

    // ---- truncate (syscall 45, APatch hooked) ----
    long total_tr = 0;
    for (int i = 0; i < iterations; i++) {
        long t0 = now_ns();
        da_apatch_supercall("detectany_timing_probe_not_a_key", 0, 0, 0);
        total_tr += now_ns() - t0;
    }
    *out_truncate_ns = total_tr / iterations;

    // ---- ftruncate (syscall 46, NOT hooked) ----
    long total_ftr = 0;
    for (int i = 0; i < iterations; i++) {
        long t0 = now_ns();
        da_svc_ftruncate(-1, 0); // invalid fd → EBADF, same cost class
        total_ftr += now_ns() - t0;
    }
    *out_ftruncate_ns = total_ftr / iterations;

    // ---- getpid (baseline, cheapest syscall) ----
    long total_pid = 0;
    for (int i = 0; i < iterations; i++) {
        long t0 = now_ns();
#if defined(__aarch64__)
        guarded(172L /*getpid*/, 0, 0, 0, 0, false); // 172 on arm64
#else
        guarded(20L /*getpid*/, 0, 0, 0, 0, false);   // 20 on arm32
#endif
        total_pid += now_ns() - t0;
    }
    *out_getpid_ns = total_pid / iterations;

    return 0;
}

// ptrace 裸调用（C8 父进程残留探针用）
long da_raw_ptrace(long request, long pid, long addr, long data) {
#if defined(__aarch64__)
    constexpr long kNr = 117L;
#else
    constexpr long kNr = 26L;
#endif
    return guarded(kNr, request, pid, addr, data, true);
}
