#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

// 任务 3.6/3.8 的行为与结构探针。全部只读或无副作用；SELinux label 探针写入的
// 是必然不存在的 label（EINVAL/EPERM 语义判定），绝不会成功改变自身上下文。

long da_ksu_reboot_supercall(long magic1, long magic2, long magic3, long arg4);
long da_apatch_supercall(const char *key, long ver_and_cmd, long arg3, long arg4);
long da_raw_ptrace(long request, long pid, long addr, long data);

namespace {

std::vector<std::string> scan_fds() {
    std::vector<std::string> names;
    DIR *d = opendir("/proc/self/fd");
    if (d == nullptr) return names;
    struct dirent *de;
    char link[512];
    while ((de = readdir(d)) != nullptr) {
        if (de->d_name[0] == '.') continue;
        snprintf(link, sizeof(link), "/proc/self/fd/%s", de->d_name);
        char buf[512];
        const ssize_t n = readlink(link, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            names.emplace_back(buf);
        }
    }
    closedir(d);
    return names;
}

long now_ns() {
    struct timespec ts {};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<long>(ts.tv_sec) * 1000000000L + ts.tv_nsec;
}

}  // namespace

// ---- fd 表扫描（KSU anon_inode 检出 + C6 fd readlink 复用） ----
int da_fd_names(std::vector<std::string> *out) {
    *out = scan_fds();
    return 0;
}

// ---- KSU supercall 探针：reboot 双魔数 → fd 表 diff（fork 隔离） ----
// 实测（API 35 模拟器，2026-11）：reboot(142) 不在 untrusted_app 的 seccomp 白名单，
// app 进程直接裸调会 SIGSYS 杀进程 —— 必须 fork：子进程探测并经 pipe 回传，父进程收割。
// 子进程被 SIGSYS 杀死 = seccomp 阻断 → 探针不可判定（返回 -2），不是证据。
// Android 7 无 seccomp，probe 直达内核（原厂 -EPERM，KSU 安装 anon_inode fd）。
// 返回：0 = 子进程完成探测；-1 = fork/pipe 失败；-2 = 子进程被 seccomp SIGSYS。
int da_ksu_probe(long magic1, long magic2, long magic3, long arg4,
                 long *ret, int *err, std::vector<std::string> *new_fds) {
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;
    const pid_t child = fork();
    if (child < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (child == 0) {
        close(pipefd[0]);
        const auto before = scan_fds();
        errno = 0;
        const long r = da_ksu_reboot_supercall(magic1, magic2, magic3, arg4);
        const int e = errno;
        const auto after = scan_fds();
        char head[96];
        snprintf(head, sizeof(head), "ret=%ld;errno=%d\n", r, e);
        if (write(pipefd[1], head, strlen(head)) < 0) _exit(3);
        for (const auto &name : after) {
            if (std::find(before.begin(), before.end(), name) == before.end()) {
                char line[513];
                snprintf(line, sizeof(line), "%s\n", name.c_str());
                if (write(pipefd[1], line, strlen(line)) < 0) _exit(3);
            }
        }
        close(pipefd[1]);
        _exit(0);
    }
    close(pipefd[1]);
    // 父进程：读 pipe + 收割
    std::string report;
    char buf[512];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        report += buf;
    }
    close(pipefd[0]);
    int status = 0;
    waitpid(child, &status, 0);
    if (WIFSIGNALED(status) && WTERMSIG(status) == 31 /*SIGSYS*/) {
        *ret = 0;
        *err = 0;
        new_fds->clear();
        return -2;  // seccomp 阻断：不可判定
    }
    // 解析子进程报告
    size_t pos = 0;
    bool first = true;
    while (pos < report.size()) {
        size_t nl = report.find('\n', pos);
        if (nl == std::string::npos) nl = report.size();
        std::string line = report.substr(pos, nl - pos);
        pos = nl + 1;
        if (line.empty()) continue;
        if (first) {
            *ret = strtol(line.c_str() + 4, nullptr, 10);
            const char *ep = strstr(line.c_str(), "errno=");
            if (ep != nullptr) *err = atoi(ep + 6);
            first = false;
        } else {
            new_fds->push_back(line);
        }
    }
    return 0;
}

// ---- APatch supercall 探针：syscall(45, key, ver_and_cmd) + 计时 ----
int da_apatch_probe(const char *key, long ver_and_cmd, long *ret, int *err, long *elapsed_ns) {
    errno = 0;
    const long t0 = now_ns();
    *ret = da_apatch_supercall(key, ver_and_cmd, 0, 0);
    *elapsed_ns = now_ns() - t0;
    *err = errno;
    return 0;
}

// ---- SELinux errno 语义探针（PayPal 2026 向量）----
// 向 /proc/thread-self/attr/current 写入探测 label：
//   EINVAL = label 不存在（类型未定义）；EPERM = label 存在但禁止写入。
// errno 差即证明对应 SELinux 域（如 u:r:magisk:s0）是否存在于策略中。
// 返回：>=0 写入 syscall 返回值；-1 = open 失败（errno 透传给调用方）。
long da_selinux_label_probe(const char *label, int *out_errno) {
    const char *kPaths[] = {"/proc/thread-self/attr/current", nullptr};
    char fallback[128];
    const long tid = static_cast<long>(gettid());
    snprintf(fallback, sizeof(fallback), "/proc/self/task/%ld/attr/current", tid);
    int fd = -1;
    for (const char *p : kPaths) {
        fd = open(p, O_WRONLY | O_CLOEXEC);
        if (fd >= 0) break;
    }
    if (fd < 0) {
        fd = open(fallback, O_WRONLY | O_CLOEXEC);
    }
    if (fd < 0) {
        *out_errno = errno;
        return -1;
    }
    errno = 0;
    const long r = write(fd, label, strlen(label));
    *out_errno = errno;
    close(fd);
    return r;
}

// ---- NativeBridgeError() 粘滞标志（ZN/ReZygisk 向量）----
// dlopen libnativebridge → dlsym NativeBridgeError → 调用。
// 返回：-1 = 库/符号不可用（不可判定）；0 = 无错误标志；1 = had_error 为真（曾尝试加载 NativeBridge）。
int da_nativebridge_error() {
    const char *kCandidates[] = {
        "/apex/com.android.art/lib64/libnativebridge.so",
        "/apex/com.android.art/lib/libnativebridge.so",
        "libnativebridge.so",
    };
    void *handle = nullptr;
    for (const char *path : kCandidates) {
        handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        if (handle != nullptr) break;
    }
    if (handle == nullptr) return -1;
    using Fn = bool (*)();
    const auto fn = reinterpret_cast<Fn>(dlsym(handle, "NativeBridgeError"));
    if (fn == nullptr) {
        dlclose(handle);
        return -1;
    }
    const bool hadError = fn();
    dlclose(handle);
    return hadError ? 1 : 0;
}

// ---- 父进程 ptrace 注入残留（DetectZygisk 向量）----
// fork 子进程 → PTRACE_ATTACH 父进程 → PTRACE_GETEVENTMSG 读取遗留事件消息。
// 若本进程曾被 zygote 注入（ZN/ReZygisk/NeoZygisk），msg == zygote pid。
// 返回：>=0 = 读到的 eventmsg；-1 = 探针不可执行。
long da_ptrace_parent_eventmsg() {
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
        // 子进程
        close(pipefd[0]);
        long msg = -1;
        errno = 0;
        if (da_raw_ptrace(16 /*PTRACE_ATTACH*/, parent, 0, 0) == 0) {
            int status = 0;
            waitpid(parent, &status, 0);
            errno = 0;
            if (da_raw_ptrace(0x4201 /*PTRACE_GETEVENTMSG*/, parent, 0,
                              reinterpret_cast<long>(&msg)) != 0) {
                msg = -1;
            }
            da_raw_ptrace(17 /*PTRACE_DETACH*/, parent, 0, 0);
        }
        const auto m = static_cast<uint64_t>(msg);
        if (write(pipefd[1], &m, sizeof(m)) != static_cast<ssize_t>(sizeof(m))) {
            _exit(2);
        }
        _exit(0);
    }
    // 父进程
    close(pipefd[1]);
    uint64_t msg = 0xFFFFFFFFFFFFFFFFULL;
    const ssize_t n = read(pipefd[0], &msg, sizeof(msg));
    close(pipefd[0]);
    int status = 0;
    waitpid(child, &status, 0);
    return (n == static_cast<ssize_t>(sizeof(msg))) ? static_cast<long>(msg) : -1;
}

// ---- 自身内存安全读取（C7 GOT/prologue 用；process_vm_readv 读自身不崩溃） ----
long da_mem_read(unsigned long addr, void *buf, size_t len) {
    struct iovec local {buf, len};
    struct iovec remote {reinterpret_cast<void *>(addr), len};
    return process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
}

// ---- linker 权威加载列表（dl_iterate_phdr，对抗 maps 抹除）----
// 返回 "name\tload_bias" 列表；与 maps 交叉：链表有而 maps 无 = 隐藏映射（B 级证据）。
struct SoListSink {
    std::vector<std::string> *out;
};

int da_solist_cb(struct dl_phdr_info *info, size_t /*size*/, void *data) {
    auto *out = static_cast<std::vector<std::string> *>(data);
    char line[640];
    const char *name = (info->dlpi_name != nullptr && info->dlpi_name[0] != '\0') ? info->dlpi_name : "[anon-linker]";
    snprintf(line, sizeof(line), "%s\t%lu", name, static_cast<unsigned long>(info->dlpi_addr));
    out->emplace_back(line);
    return 0;
}

int da_solist(std::vector<std::string> *out) {
    out->clear();
    dl_iterate_phdr(da_solist_cb, out);
    return 0;
}

// ---- RWX 自探针（对抗 maps 读取被 hook 抹除）----
// mmap 匿名页 → mprotect 加可执行 → 检查 maps 是否能看到该地址区间。
// 返回：1 = 可见（maps 读取可信）；0 = 不可见（maps 被篡改，强证据）；-1 = 分配失败。
int da_rwx_self_probe() {
    void *page = mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return -1;
    if (mprotect(page, 4096, PROT_READ | PROT_EXEC) != 0) {
        munmap(page, 4096);
        return -1;
    }
    const unsigned long start = reinterpret_cast<unsigned long>(page);
    int visible = 0;
    FILE *f = fopen("/proc/self/maps", "re");
    if (f != nullptr) {
        char line[1024];
        while (fgets(line, sizeof(line), f) != nullptr) {
            unsigned long s = strtoul(line, nullptr, 16);
            unsigned long e = strtoul(strchr(line, '-') + 1, nullptr, 16);
            if (start >= s && start < e) {
                visible = 1;
                break;
            }
        }
        fclose(f);
    }
    munmap(page, 4096);
    return visible;
}
