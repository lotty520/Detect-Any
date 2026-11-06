package com.detectany.selfguard

import com.detectany.core.nativeplatform.NativePlatform

/** 自保护 native 桥（guard.cpp）。 */
object GuardJni {
    init { NativePlatform.ensureLoaded() }

    /** 还原预期 APK 签名摘要（XOR 分散常量，发布装配时替换）。 */
    external fun assembleExpectedSignature(): ByteArray

    /** 还原预期 classes.dex CRC32。 */
    external fun assembleExpectedDexCrc(): Long

    /** 常数时间比较（抗时序侧信道）。 */
    external fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean

    /** 调试器探针：0 无 / 1 有 / -1 不可判定。 */
    external fun debuggerProbe(): Int
}
