#pragma once

// 裸 svc 系统调用（design.md D3）：不经过 libc 包装，绕开 PLT/GOT hook。
// 仅支持本项目构建的 ABI（arm64-v8a / armeabi-v7a）。

#if defined(__aarch64__)

static inline long da_syscall1(long nr, long a0) {
    register long x8 asm("x8") = nr;
    register long x0 asm("x0") = a0;
    asm volatile("svc #0" : "=r"(x0) : "r"(x8), "r"(x0) : "memory", "cc");
    return x0;
}

static inline long da_syscall3(long nr, long a0, long a1, long a2) {
    register long x8 asm("x8") = nr;
    register long x0 asm("x0") = a0;
    register long x1 asm("x1") = a1;
    register long x2 asm("x2") = a2;
    asm volatile("svc #0" : "=r"(x0) : "r"(x8), "r"(x0), "r"(x1), "r"(x2) : "memory", "cc");
    return x0;
}

static inline long da_syscall4(long nr, long a0, long a1, long a2, long a3) {
    register long x8 asm("x8") = nr;
    register long x0 asm("x0") = a0;
    register long x1 asm("x1") = a1;
    register long x2 asm("x2") = a2;
    register long x3 asm("x3") = a3;
    asm volatile("svc #0" : "=r"(x0) : "r"(x8), "r"(x0), "r"(x1), "r"(x2), "r"(x3) : "memory", "cc");
    return x0;
}

static inline long da_syscall5(long nr, long a0, long a1, long a2, long a3, long a4) {
    register long x8 asm("x8") = nr;
    register long x0 asm("x0") = a0;
    register long x1 asm("x1") = a1;
    register long x2 asm("x2") = a2;
    register long x3 asm("x3") = a3;
    register long x4 asm("x4") = a4;
    asm volatile("svc #0" : "=r"(x0) : "r"(x8), "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4) : "memory", "cc");
    return x0;
}

#elif defined(__arm__)

static inline long da_syscall1(long nr, long a0) {
    register long r7 asm("r7") = nr;
    register long r0 asm("r0") = a0;
    asm volatile("svc #0" : "=r"(r0) : "r"(r7), "r"(r0) : "memory", "cc");
    return r0;
}

static inline long da_syscall5(long nr, long a0, long a1, long a2, long a3, long a4) {
    register long r7 asm("r7") = nr;
    register long r0 asm("r0") = a0;
    register long r1 asm("r1") = a1;
    register long r2 asm("r2") = a2;
    register long r3 asm("r3") = a3;
    register long r4 asm("r4") = a4;
    asm volatile("svc #0" : "=r"(r0) : "r"(r7), "r"(r0), "r"(r1), "r"(r2), "r"(r3), "r"(r4) : "memory", "cc");
    return r0;
}

static inline long da_syscall3(long nr, long a0, long a1, long a2) {
    register long r7 asm("r7") = nr;
    register long r0 asm("r0") = a0;
    register long r1 asm("r1") = a1;
    register long r2 asm("r2") = a2;
    asm volatile("svc #0" : "=r"(r0) : "r"(r7), "r"(r0), "r"(r1), "r"(r2) : "memory", "cc");
    return r0;
}

static inline long da_syscall4(long nr, long a0, long a1, long a2, long a3) {
    register long r7 asm("r7") = nr;
    register long r0 asm("r0") = a0;
    register long r1 asm("r1") = a1;
    register long r2 asm("r2") = a2;
    register long r3 asm("r3") = a3;
    asm volatile("svc #0" : "=r"(r0) : "r"(r7), "r"(r0), "r"(r1), "r"(r2), "r"(r3) : "memory", "cc");
    return r0;
}

#else
#error "detectany_native only supports arm64-v8a / armeabi-v7a"
#endif
