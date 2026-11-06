package com.detectany.core.nativeplatform

/**
 * C2/C6/C8 行为与结构探针桥。
 */
object ProbeJni {
    init { NativePlatform.ensureLoaded() }

    /** /proc/self/fd 全量 readlink 显示名。 */
    external fun fdNames(): Array<String>

    /**
     * KSU 系 supercall 探针（reboot 双魔数）。
     * 返回 String[]：元素 0 = "ret=…;errno=…"，其余 = 新增 fd 名（如 anon_inode:[ksu_driver]）。
     */
    external fun ksuProbe(magic1: Long, magic2: Long, magic3: Long, arg4: Long): Array<String>

    /** APatch supercall：long[3] = [ret, errno, elapsedNs]。 */
    external fun apatchProbe(key: String, verAndCmd: Long): LongArray

    /** SELinux errno 语义探针：long[2] = [write返回, errno]；-1 = open 失败。 */
    external fun selinuxLabelProbe(label: String): LongArray

    /** NativeBridgeError()：-1 不可判定 / 0 无标志 / 1 had_error 为真。 */
    external fun nativebridgeError(): Int

    /** 旧版 KSU prctl 探针：long[2] = [ret, errno]。原厂内核对未知 option 返回 -EINVAL。 */
    external fun prctlProbe(option: Long, a2: Long, a3: Long, a4: Long, a5: Long): LongArray

    /** 父进程 ptrace 注入残留：>=0 为 eventmsg（== zygote pid 即注入）；-1 不可执行。 */
    external fun ptraceParentEventmsg(): Long

    /** 自身内存安全读取（process_vm_readv 自身）。 */
    external fun memRead(addr: Long, len: Int): ByteArray?

    /** linker 权威加载列表："name\tload_bias"。 */
    external fun solist(): Array<String>

    /** RWX 自探针：1 maps 可信 / 0 maps 被篡改 / -1 分配失败。 */
    external fun rwxSelfProbe(): Int
}
