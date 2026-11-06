package com.detectany.core.nativeplatform

import java.util.concurrent.atomic.AtomicBoolean

/**
 * native 基座入口：加载唯一 native 库，暴露各 JNI 桥接对象。
 */
object NativePlatform {
    private val loaded = AtomicBoolean(false)

    fun ensureLoaded() {
        if (loaded.compareAndSet(false, true)) {
            System.loadLibrary("detectany_native")
        }
    }

    /** native 库版本（连通性验证用）。 */
    external fun nativeVersion(): String
}
