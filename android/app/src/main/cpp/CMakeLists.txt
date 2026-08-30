cmake_minimum_required(VERSION 3.22.1)
project(ergou_argon2 C)

# 仅用参考（portable）填充路径，避免 SIMD 目标依赖；并行由 pthread（bionic libc）提供。
add_library(ergou_argon2 SHARED
        ergou_argon2.c
        argon2/argon2.c
        argon2/core.c
        argon2/ref.c
        argon2/encoding.c
        argon2/thread.c
        argon2/blake2/blake2b.c
)

target_include_directories(ergou_argon2 PRIVATE
        argon2
        argon2/blake2
)

# Android NDK 的 jni.h 已由工具链提供；pthread 内置于 bionic libc，无需额外链接。

# 16 KB 页面大小兼容：将 ELF 的 LOAD 段对齐到 16 KB 边界。
# 自 Android 15 起，Google Play 要求所有原生库支持 16 KB 页面；未设置时
# lld 默认按 4 KB（0x1000）对齐，会导致 LOAD 段 p_align 不满足 16 KB 校验。
target_link_options(ergou_argon2 PRIVATE -Wl,-z,max-page-size=16384)
