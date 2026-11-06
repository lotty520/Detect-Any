cmake_minimum_required(VERSION 3.22.1)
project(detectany_native LANGUAGES C CXX)

# 唯一的 native 库：采集器探针基座（裸 svc 三路执行器/seccomp 守卫/ELF 自解析）
add_library(detectany_native SHARED
        native.cpp
        raw_syscalls.cpp
        elf_inspect.cpp
        props.cpp
        probes.cpp
        guard.cpp)

target_link_libraries(detectany_native log)

target_compile_options(detectany_native PRIVATE
        -Wall
        -Wextra
        -fvisibility=hidden
        -ffunction-sections
        -fdata-sections)

# arm32：r7 在 Thumb 构建中是帧指针保留寄存器，裸 svc 需要以 r7 传系统调用号 —— 释放它
if (${ANDROID_ABI} STREQUAL "armeabi-v7a")
    target_compile_options(detectany_native PRIVATE -fomit-frame-pointer)
endif ()

# 任务 1.2 硬性要求（design.md D7）：
# 1) 16KB 页对齐（Android 15+ 设备强制；NDK r25 需显式 linker flags）
# 2) 不动态依赖系统 libcrypto/libssl —— 本库只链 log，加密全部位于 Kotlin 层(BouncyCastle)
# 3) 保留标准 ELF 节头 —— 不传任何 strip/节剔除参数，加固混淆时同样必须保留
target_link_options(detectany_native PRIVATE
        "-Wl,-z,max-page-size=16384"
        "-Wl,-z,common-page-size=16384"
        "-Wl,--gc-sections"
        "-Wl,--hash-style=both")
