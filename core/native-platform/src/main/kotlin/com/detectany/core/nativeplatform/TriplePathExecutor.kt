package com.detectany.core.nativeplatform

import java.io.File

/**
 * 三路调用执行器（任务 2.1 / specs/signal-collection「三路执行观测」）：
 * 同一路径的同一事实分别经 Java API、libc 包装、裸 svc 执行，
 * svc vs libc 逐字段不一致 = 强 hook 证据；Java vs native 语义不一致 = 中证据。
 */
class TriplePathExecutor(
    private val backend: SyscallBackend,
    private val javaView: JavaStatView = FileJavaStatView(),
) {

    /** Java 路视图（host 单测可桩替换）。 */
    fun interface JavaStatView {
        fun stat(path: String): StatOutcome
    }

    /** 生产实现：java.io.File（Framework API 路径，可被 Java 层 hook）。 */
    class FileJavaStatView : JavaStatView {
        override fun stat(path: String): StatOutcome {
            val f = File(path)
            return if (f.exists()) {
                StatOutcome.Ok(
                    dev = -1, // Java API 不暴露 st_dev
                    ino = -1,
                    mode = if (f.isDirectory) 0x4000 else 0x8000,
                    uid = -1,
                    gid = -1,
                    size = f.length(),
                    mtimeSec = f.lastModified() / 1000L,
                )
            } else {
                StatOutcome.Errno(ENOENT)
            }
        }
    }

    enum class MismatchKind { SVC_LIBC_FIELDS, SVC_LIBC_EXISTENCE, SVC_LIBC_ERRNO, JAVA_NATIVE_EXISTENCE, JAVA_NATIVE_SIZE }

    data class Mismatch(val kind: MismatchKind, val detail: String)

    data class TripleDiff(
        val path: String,
        val svc: StatOutcome,
        val libc: StatOutcome,
        val svcVsLibc: Mismatch?,
        val javaVsNative: Mismatch?,
    ) {
        val clean: Boolean get() = svcVsLibc == null && javaVsNative == null
    }

    fun probe(path: String): TripleDiff {
        val svc = backend.statSvc(path)
        val libc = backend.statLibc(path)
        return TripleDiff(
            path = path,
            svc = svc,
            libc = libc,
            svcVsLibc = compareSvcLibc(path, svc, libc),
            javaVsNative = compareJavaNative(path, javaView.stat(path), svc),
        )
    }

    private fun compareSvcLibc(path: String, svc: StatOutcome, libc: StatOutcome): Mismatch? {
        return when {
            svc is StatOutcome.Ok && libc is StatOutcome.Ok -> {
                val diffs = buildList {
                    if (svc.dev != libc.dev) add("dev(${libc.dev}->${svc.dev})")
                    if (svc.ino != libc.ino) add("ino(${libc.ino}->${svc.ino})")
                    if (svc.mode != libc.mode) add("mode(${libc.mode}->${svc.mode})")
                    if (svc.uid != libc.uid) add("uid(${libc.uid}->${svc.uid})")
                    if (svc.gid != libc.gid) add("gid(${libc.gid}->${svc.gid})")
                    if (svc.size != libc.size) add("size(${libc.size}->${svc.size})")
                    if (svc.mtimeSec != libc.mtimeSec) add("mtime(${libc.mtimeSec}->${svc.mtimeSec})")
                }
                if (diffs.isEmpty()) null else Mismatch(MismatchKind.SVC_LIBC_FIELDS, diffs.joinToString(","))
            }

            svc.exists != libc.exists ->
                Mismatch(MismatchKind.SVC_LIBC_EXISTENCE, "svc=${svc.existsStr} libc=${libc.existsStr} path=$path")

            svc is StatOutcome.Errno && libc is StatOutcome.Errno && svc.code != libc.code ->
                Mismatch(MismatchKind.SVC_LIBC_ERRNO, "svc errno=${svc.code} libc errno=${libc.code}")

            else -> null
        }
    }

    private fun compareJavaNative(path: String, java: StatOutcome, svc: StatOutcome): Mismatch? {
        if (java.exists != svc.exists) {
            return Mismatch(MismatchKind.JAVA_NATIVE_EXISTENCE, "java=${java.existsStr} svc=${svc.existsStr} path=$path")
        }
        if (java is StatOutcome.Ok && svc is StatOutcome.Ok && java.size != svc.size) {
            return Mismatch(MismatchKind.JAVA_NATIVE_SIZE, "java size=${java.size} svc size=${svc.size} path=$path")
        }
        return null
    }

    private val StatOutcome.existsStr: String get() = if (exists) "exists" else "missing"

    companion object {
        const val ENOENT = 2
    }
}
