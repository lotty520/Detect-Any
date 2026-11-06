package com.detectany.collectors.behavior

import com.detectany.core.model.Collector
import com.detectany.core.model.CollectorId
import com.detectany.core.model.CollectorResult
import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import com.detectany.core.model.ScanInput
import com.detectany.core.nativeplatform.JniSyscallBackend
import com.detectany.core.nativeplatform.ProbeJni
import com.detectany.core.nativeplatform.TriplePathExecutor

/**
 * C8 接口行为（任务 3.8）：KSU reboot supercall / APatch syscall45 / 旧 prctl /
 * SELinux errno 语义 / 三路 diff / NativeBridgeError / ptrace 注入残留。
 * 全部 magic/参数可经特征数据下发（Phase 1 用内置默认值）。
 */
class BehaviorCollector(
    private val ksuMagic1: Long = KSU_MAGIC1,
    private val ksuMagic2: Long = KSU_MAGIC2,
    private val apatchSuperkey: String = "su",
    private val apatchHelloCmd: Long = APATCH_HELLO_CMD,
    private val legacyPrctlOption: Long = LEGACY_KSU_OPTION,
    private val tripleExecutor: TriplePathExecutor = TriplePathExecutor(JniSyscallBackend),
) : Collector {

    /** 特征数据装配工厂（specs：magic MUST 来自特征数据，MUST NOT 编译期写死）。 */
    constructor(
        supercalls: List<com.detectany.core.model.SupercallSpec>,
        tripleExecutor: TriplePathExecutor = TriplePathExecutor(JniSyscallBackend),
    ) : this(
        ksuMagic1 = supercalls.firstOrNull { it.family == "ksu_reboot" }?.magic1 ?: KSU_MAGIC1,
        ksuMagic2 = supercalls.firstOrNull { it.family == "ksu_reboot" }?.magic2 ?: KSU_MAGIC2,
        apatchSuperkey = supercalls.firstOrNull { it.family == "apatch_supercall" }?.superkey ?: "su",
        apatchHelloCmd = supercalls.firstOrNull { it.family == "apatch_supercall" }?.helloCmd ?: APATCH_HELLO_CMD,
        legacyPrctlOption = supercalls.firstOrNull { it.family == "legacy_ksu_prctl" }?.magic1 ?: LEGACY_KSU_OPTION,
        tripleExecutor = tripleExecutor,
    )

    override val id: CollectorId = CollectorId.C8_BEHAVIOR

    override fun collect(input: ScanInput): CollectorResult = try {
        val findings = mutableListOf<Finding>()
        findings += BehaviorProbes.ksuSupercall(ksuMagic1, ksuMagic2)
        findings += BehaviorProbes.apatchSupercall(apatchSuperkey, apatchHelloCmd)
        findings += BehaviorProbes.legacyPrctl(legacyPrctlOption)
        findings += BehaviorProbes.selinuxLabelSemantics()
        findings += BehaviorProbes.nativebridgeSticky()
        findings += BehaviorProbes.ptraceResidue(tripleExecutor)
        CollectorResult(
            collector = id,
            status = CollectorResult.Status.OK,
            findings = findings,
            meta = BehaviorProbes.lastMeta,
        )
    } catch (e: Throwable) {
        CollectorResult(collector = id, status = CollectorResult.Status.BLOCKED, meta = mapOf("error" to (e.message ?: e.javaClass.simpleName)))
    }

    companion object {
        const val KSU_MAGIC1 = 0xDEADBEEFL
        const val KSU_MAGIC2 = 0xCAFEBABEL

        /** APatch ver_and_cmd：(KP 版本 << 32) | (0x1158 << 16) | SUPERCALL_HELLO(0x1000) */
        const val APATCH_HELLO_CMD = (0x1158L shl 16) or 0x1000L

        /** 旧版 KSU prctl option（v1.0.5 及以前） */
        const val LEGACY_KSU_OPTION = 0xDEADBEEFL

        /** SELinux 探测 label 集（PayPal 2026 向量） */
        val SELINUX_PROBE_LABELS = mapOf(
            "magisk" to "u:r:magisk:s0",
            "ksu_file" to "u:r:ksu_file:s0",
            "lsposed" to "u:r:lsposed:s0",
        )
        const val SELINUX_CONTROL_LABEL = "u:r:detectany_nonexistent_control:s0"
    }
}

/** 行为探针（采集层薄封装；判定常量进 Finding，规则层可复核）。 */
object BehaviorProbes {

    internal var lastMeta: Map<String, String> = emptyMap()

    /** KSU 系：reboot 双魔数 → fd 表新增 anon_inode（未授权命令 -EPERM 可区分）。 */
    fun ksuSupercall(magic1: Long, magic2: Long): List<Finding> {
        val out = ProbeJni.ksuProbe(magic1, magic2, 0L, 0L)
        val head = out.firstOrNull() ?: return emptyList()
        val ret = Regex("ret=(-?\\d+)").find(head)?.groupValues?.get(1)?.toLongOrNull()
        val errno = Regex("errno=(-?\\d+)").find(head)?.groupValues?.get(1)?.toIntOrNull()
        val newFds = out.drop(1)
        lastMeta = lastMeta + ("ksuRet" to head)
        return buildList {
            newFds.filter { it.contains("ksu_driver") }.forEach { fd ->
                add(
                    Finding(
                        ruleId = "behavior.ksu_supercall",
                        collector = CollectorId.C8_BEHAVIOR,
                        confidence = Confidence.B,
                        category = Finding.Category.ROOT_KERNEL,
                        framework = "ksu",
                        detail = "reboot 双魔数探针获得 fd: $fd（KSU v2.0+ supercall 安装）",
                        raw = mapOf("fd" to fd, "ret" to (ret?.toString() ?: "?"), "errno" to (errno?.toString() ?: "?")),
                    ),
                )
            }
        }
    }

    /** APatch：syscall 45 + 0x1158 布局；SUPERCALL_HELLO 返回 0x11581158 为强命中。 */
    fun apatchSupercall(superkey: String, helloCmd: Long = BehaviorCollector.APATCH_HELLO_CMD): List<Finding> {
        val r = ProbeJni.apatchProbe(superkey, helloCmd)
        val ret = r[0]
        lastMeta = lastMeta + mapOf("apatchRet" to ret.toString(), "apatchErrno" to r[1].toString(), "apatchNs" to r[2].toString())
        return if (ret == APATCH_HELLO_MAGIC) {
            listOf(
                Finding(
                    ruleId = "behavior.apatch_supercall",
                    collector = CollectorId.C8_BEHAVIOR,
                    confidence = Confidence.B,
                    category = Finding.Category.ROOT_KERNEL,
                    framework = "apatch",
                    detail = "APatch supercall HELLO 返回 0x11581158",
                    raw = mapOf("ret" to ret.toString(16)),
                ),
            )
        } else {
            emptyList() // 无 superkey 时退化为 truncate 失败；计时侧信道进 meta 供规则层统计
        }
    }

    private const val APATCH_HELLO_MAGIC = 0x11581158L

    /**
     * 旧版 KSU（存量老内核）：prctl(0xDEADBEEF)。
     * 原厂内核的裸 svc 返回 -EINVAL 本体（-22，errno 不置位）——API 35 实测；
     * 返回其他值（0/正数/版本号）即为被 hook 的旧版 KSU 存量特征。
     */
    fun legacyPrctl(option: Long = BehaviorCollector.LEGACY_KSU_OPTION): List<Finding> {
        val r = ProbeJni.prctlProbe(option, 2L, 0L, 0L, 0L)
        val ret = r[0]
        lastMeta = lastMeta + mapOf("legacyPrctlRet" to ret.toString(), "legacyPrctlErrno" to r[1].toString())
        return if (ret != -EINVAL.toLong()) {
            listOf(
                Finding(
                    ruleId = "behavior.legacy_prctl",
                    collector = CollectorId.C8_BEHAVIOR,
                    confidence = Confidence.C,
                    category = Finding.Category.ROOT_KERNEL,
                    framework = "ksu",
                    detail = "prctl(0xDEADBEEF) 返回 $ret errno=${r[1]}（原厂应为 -EINVAL；旧版 KSU 存量特征）",
                    raw = mapOf("ret" to ret.toString(), "errno" to r[1].toString()),
                ),
            )
        } else {
            emptyList()
        }
    }

    private const val EINVAL = 22

    /**
     * SELinux errno 语义：EINVAL=label 不存在 / EPERM=label 存在但禁止。
     * 对照 label 必须返回 EINVAL 才认为机制可用（部分 ROM 对 attr 写入有别的行为）。
     */
    fun selinuxLabelSemantics(): List<Finding> {
        val control = ProbeJni.selinuxLabelProbe(BehaviorCollector.SELINUX_CONTROL_LABEL)
        if (control[0] < 0L || control[1].toInt() != EINVAL) return emptyList() // 机制不可用，不采信
        return buildList {
            for ((name, label) in BehaviorCollector.SELINUX_PROBE_LABELS) {
                val r = ProbeJni.selinuxLabelProbe(label)
                if (r[0] < 0L) continue
                if (r[1].toInt() == EPERM) {
                    add(
                        Finding(
                            ruleId = "behavior.selinux_label.$name",
                            collector = CollectorId.C8_BEHAVIOR,
                            confidence = Confidence.B,
                            category = when (name) {
                                "lsposed" -> Finding.Category.HOOK
                                else -> Finding.Category.ROOT_KERNEL
                            },
                            framework = name,
                            detail = "SELinux 域存在: $label（EPERM vs 对照 EINVAL）",
                            raw = mapOf("label" to label, "errno" to "1"),
                        ),
                    )
                }
            }
        }
    }

    private const val EPERM = 1

    /** NativeBridgeError() 粘滞标志（ZN/ReZygisk）。 */
    fun nativebridgeSticky(): List<Finding> {
        val r = ProbeJni.nativebridgeError()
        lastMeta = lastMeta + ("nativebridgeError" to r.toString())
        return if (r == 1) {
            listOf(
                Finding(
                    ruleId = "behavior.nativebridge_sticky",
                    collector = CollectorId.C8_BEHAVIOR,
                    confidence = Confidence.B,
                    category = Finding.Category.ZYGISK,
                    framework = null,
                    detail = "NativeBridgeError()=true（曾尝试加载 NativeBridge，属性还原后仍暴露）",
                    raw = mapOf("hadError" to "true"),
                ),
            )
        } else {
            emptyList()
        }
    }

    /** ptrace 残留 + 三路 diff（父进程 = zygote，eventmsg==zygote pid 即注入）。 */
    fun ptraceResidue(executor: TriplePathExecutor): List<Finding> {
        val findings = mutableListOf<Finding>()
        runCatching {
            val msg = ProbeJni.ptraceParentEventmsg()
            val ppid = readPpid()
            lastMeta = lastMeta + mapOf("ptraceMsg" to msg.toString(), "ppid" to ppid.toString())
            if (msg >= 0 && ppid > 0 && msg == ppid) {
                findings.add(
                    Finding(
                        ruleId = "behavior.ptrace_residue", // A4: NeoZygisk ≥10-30 清除残留，对该分支即将失效；ReZygisk 仍 A 级
                        collector = CollectorId.C8_BEHAVIOR,
                        confidence = Confidence.A,
                        category = Finding.Category.ZYGISK,
                        framework = null,
                        detail = "父进程(zygote=$ppid)存在注入残留 eventmsg（ZN/ReZygisk/NeoZygisk 形态）",
                        raw = mapOf("msg" to msg.toString(), "ppid" to ppid.toString()),
                    ),
                )
            }
        }
        // 三路 diff（接口行为的一致性证据）
        for (path in listOf("/system/lib64/libc.so", "/system/bin/sh", "/data/local/tmp")) {
            runCatching {
                val diff = executor.probe(path)
                diff.svcVsLibc?.let { m ->
                    findings.add(
                        Finding(
                            ruleId = "behavior.triple_diff",
                            collector = CollectorId.C8_BEHAVIOR,
                            confidence = Confidence.A,
                            category = Finding.Category.HOOK,
                            framework = null,
                            detail = "三路 diff 不一致 @ $path: ${m.kind} ${m.detail}",
                            raw = mapOf("path" to path, "kind" to m.kind.name),
                        ),
                    )
                }
            }
        }
        return findings
    }

    private fun readPpid(): Long {
        val stat = runCatching { java.io.File("/proc/self/stat").readText() }.getOrNull() ?: return -1
        // 格式：pid (comm) state ppid ...；comm 可能含空格，取最右括号后第 2 个字段
        val after = stat.substringAfterLast(')')
        return after.trim().split(Regex("\\s+")).getOrNull(1)?.toLongOrNull() ?: -1
    }
}
