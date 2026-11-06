package com.detectany.core.nativeplatform

/**
 * 三路执行器的 native 侧后端抽象（host 单测以桩替换，真机用 JNI 实现）。
 */
interface SyscallBackend {
    fun statLibc(path: String): StatOutcome
    fun statSvc(path: String): StatOutcome
}

/** 生产实现：直接调 JNI。 */
object JniSyscallBackend : SyscallBackend {
    override fun statLibc(path: String): StatOutcome = parseStatArray(SyscallJni.statLibc(path))
    override fun statSvc(path: String): StatOutcome = parseStatArray(SyscallJni.statSvc(path))
}
