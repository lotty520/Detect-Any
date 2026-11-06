package com.detectany.core.nativeplatform

/**
 * 归一化的 stat 观测：三路（Java/libc/svc）可比。
 */
sealed interface StatOutcome {
    data class Ok(
        val dev: Long,
        val ino: Long,
        val mode: Long,
        val uid: Long,
        val gid: Long,
        val size: Long,
        val mtimeSec: Long,
    ) : StatOutcome

    data class Errno(val code: Int) : StatOutcome

    val exists: Boolean get() = this is Ok
}

/** JNI long[9] → StatOutcome。 */
fun parseStatArray(arr: LongArray): StatOutcome {
    require(arr.size == 9) { "stat array must have 9 elements" }
    return if (arr[0] == 0L) {
        StatOutcome.Ok(
            dev = arr[2], ino = arr[3], mode = arr[4],
            uid = arr[5], gid = arr[6], size = arr[7], mtimeSec = arr[8],
        )
    } else {
        StatOutcome.Errno(arr[1].toInt())
    }
}
