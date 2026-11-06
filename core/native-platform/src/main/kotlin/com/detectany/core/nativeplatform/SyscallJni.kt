package com.detectany.core.nativeplatform

/**
 * JNI 桥：libc 路与裸 svc 路的 stat/access。
 * Java 路在 [TriplePathExecutor] 中由 [JavaStatView] 提供。
 */
object SyscallJni {
    init { NativePlatform.ensureLoaded() }

    /** long[9] = [tag, errno, dev, ino, mode, uid, gid, size, mtimeSec] */
    external fun statSvc(path: String): LongArray

    /** long[9]，同上，经 libc（可被 PLT/GOT hook）。 */
    external fun statLibc(path: String): LongArray

    /** long[2] = [tag, errno] */
    external fun accessSvc(path: String, mode: Int): LongArray

    /** long[2]，经 libc。 */
    external fun accessLibc(path: String, mode: Int): LongArray

    /** long[5] = [tag, errno, f_type, bsize, blocks]（C2 statfs 交叉） */
    external fun statfsSvc(path: String): LongArray

    /** native 层守卫：白名单外 syscall 号一律拒绝（纵深防御）。 */
    external fun svcNrAllowed(nr: Long): Boolean
}
