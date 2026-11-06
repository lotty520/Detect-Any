package com.detectany.compat.platform

/**
 * 内核版本（uname release 解析结果）。
 * 形如 "3.18.35-perf+" / "4.4.302-g1234ab" / "5.15.104-android13-4k"。
 */
data class KernelVersion(val major: Int, val minor: Int, val patch: Int) : Comparable<KernelVersion> {

    override fun compareTo(other: KernelVersion): Int = comparator.compare(this, other)

    companion object {
        private val comparator = compareBy(
            KernelVersion::major,
            KernelVersion::minor,
            KernelVersion::patch,
        )

        /** 解析 uname release 串；无法识别时返回 null（调用方按最保守策略处理）。 */
        fun parse(release: String): KernelVersion? {
            val head = release.substringBefore('-')
            val parts = head.split('.')
            if (parts.size < 2) return null
            val major = parts[0].toIntOrNull() ?: return null
            val minor = parts[1].toIntOrNull() ?: return null
            val patch = parts.getOrNull(2)?.takeWhile { it.isDigit() }?.toIntOrNull() ?: 0
            return KernelVersion(major, minor, patch)
        }
    }
}
