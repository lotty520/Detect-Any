package com.detectany.core.nativeplatform

/**
 * 属性访问桥（任务 2.4）：统一走 API 24 兼容的 __system_property_read 路径。
 */
object PropJni {
    init { NativePlatform.ensureLoaded() }

    /** 全量 "key=value" 枚举。 */
    external fun propList(): Array<String>

    /** 单键读取；null = 键不存在。值长度 91 视为疑似截断（PROP_VALUE_MAX=92）。 */
    external fun propGet(key: String): String?
}

/** 属性观测视图 + 截断处理。 */
class SystemPropertiesBridge {
    data class PropValue(val key: String, val value: String, val possiblyTruncated: Boolean)

    fun get(key: String): PropValue? {
        val v = PropJni.propGet(key) ?: return null
        return PropValue(key, v, possiblyTruncated = v.length >= PROP_VALUE_MAX - 1)
    }

    fun list(): Map<String, String> = PropJni.propList().associate { line ->
        val idx = line.indexOf('=')
        if (idx <= 0) line to "" else line.substring(0, idx) to line.substring(idx + 1)
    }

    companion object {
        const val PROP_VALUE_MAX = 92
    }
}
