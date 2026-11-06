# Detect-Any 监测项总目录

> 数据来源：2026-11-06 三路全网复核 + 实机验证。
> 每项标注：能力域 / 置信级 / 数据源（内置特征库或代码内联）/ 状态。

---

## 总览

| 维度 | 数量 |
|---|---|
| 覆盖框架 | 19 个（含分叉/继任者） |
| 能力域 | 7 个 |
| 特征库条目（可热更新） | 30 条 |
| 代码内联检测项 | 28 条 |
| 规则 | 20 条 |
| **总计监测项** | **58 项** |

---

## 一、文件与挂载环境（C1 路径探测 + C2 挂载取证）

### C1 特征路径（特征库 v3 · 12 条）

| ID | 路径 | 框架 | 置信 |
|---|---|---|---|
| path.debug_ramdisk.magisk | /debug_ramdisk/.magisk/socket | magisk | C |
| path.zygisk.monitor | /debug_ramdisk/zygisk/monitor.sock | zygisknext | C |
| path.zygisk.zygisk | /debug_ramdisk/zygisk/zygisk.sock | zygisknext | C |
| path.zygisk.dev_cp64 | /dev/zygisk/cp64.sock | zygisknext | C |
| path.zygisk.dev_cp32 | /dev/zygisk/cp32.sock | zygisknext | C |
| path.rezygisk.dir | /data/adb/rezygisk | rezygisk | C |
| path.ksu.modules | /data/adb/ksu | ksu | C |
| path.apatch.ap | /data/adb/ap | apatch | C |
| path.riru.dir | /data/adb/riru | — (存量) | C |
| path.su.system | /system/bin/su | — | C |
| path.su.system_xbin | /system/xbin/su | — | C |
| path.su.sbin | /sbin/su | — | C |

### C1 三路一致性（代码内联 · 2 类）

| 检测项 | 说明 | 置信 |
|---|---|---|
| triple.svc_libc.* | svc vs libc 层间不一致 = hook 证据 | **A** |
| triple.java_native.* | Java API vs native 不一致 | B |

### C2 挂载取证（代码内联 · 6 类）

| 检测项 | 说明 | 置信 |
|---|---|---|
| mount.overlay.* | overlay 挂载条目（模块挂载形态） | B |
| mount.source_magisk | 挂载 source 含 magisk | C |
| mount.debug_ramdisk | /debug_ramdisk/.magisk* 子路径挂载 | C |
| mount.too_clean | 挂载条目数显著低于同机型基线（隐藏栈） | B |
| mount.stdev_deviation.* | st_dev 四路采样与基线不符（PayPal 向量） | **A** |
| mount.fstype_cross.* | mountinfo fstype vs statfs f_type 不一致（susfs） | B ⬇（降权：v2.x umount 一致化） |

---

## 二、系统属性一致性（C3 属性快照）

### 特征库条目（2 条）

| ID | 前缀 | 值条件 | 框架 | 置信 |
|---|---|---|---|---|
| prop.init_svc_magisk | init.svc.magisk | — | magisk | C |
| prop.riru_bridge | ro.dalvik.vm.native.bridge | 含 libriruloader | — | C |

### 代码内联（3 类）

| 检测项 | 说明 | 置信 |
|---|---|---|
| prop.debuggable | ro.debuggable=1 | C |
| prop.test_keys | ro.build.tags 含 test-keys | C |
| prop.build_pair.* | Build 侧 vs bootimage 镜像侧成对属性不一致（PIF） | B |
| prop.area_anomaly.* | /dev/__properties__/ 文件不可读或 size=0（resetprop 痕迹） | B |

---

## 三、网络与端点（C4）

### 特征库条目（6 条）

| ID | 名称 | 框架 | 置信 |
|---|---|---|---|
| sock.ksud | ksud（抽象 socket） | ksu | C |
| sock.zygiskd | zygiskd | zygisknext | C |
| sock.zygiskd64 | zygiskd64 | zygisknext | C |
| sock.lsposed | lsposed | lsposed | C |
| sock.fs.zygisk_monitor | /debug_ramdisk/zygisk/monitor.sock | zygisknext | C |
| sock.fs.magisk_socket | /debug_ramdisk/.magisk/socket | magisk | C |

> C4 受 ProbeCap 门控：Android 10+ /proc/net/unix EACCES → 自动降级（不误报）

---

## 四、应用与包指纹（C5）

### 特征库条目（11 条 · v3 新增 4）

| ID | 候选包名 | DEX 探针（any 命中） | 框架 | 置信 |
|---|---|---|---|---|
| app.magisk | com.topjohnwu.magisk | libmagisk, magiskinit, magiskpolicy | magisk | B |
| app.ksu | me.weishu.kernelsu(+.pr) | ksu_driver, KernelSU | ksu | B |
| app.ksunext | com.rifsxd.ksunext | rifsxd, KernelSU | ksunext | B |
| app.sukisu | com.sukisu.ultra 等 3 变体 | sukisu, KernelSU | sukisu | B |
| app.apatch | me.bmax.apatch | superkey, KernelPatch | apatch | B |
| app.trustmealready | mfsx.xposed.trustmealready | —（混淆，纯包名） | trustmealready | C |
| app.zygiskdetect | com.example.zygiskdetect | zygisk, ZygiskDetect | zygiskdetect | B |
| **app.vector** ★新 | org.lsposed.vector | Vector, lsposed | vector | B |
| **app.neozygisk** ★新 | moe.neozygisk | NeoZygisk, zygiskd | neozygisk | B |
| **app.nyazygisk** ★新 | nk.be.nyazygisk | NyaZygisk, zygiskd | nyazygisk | B |

### 匹配逻辑

- certPins 非空 → 证书钉住优先（签名不匹配排除误报）
- dexStrings 非空 → **any 命中即 B**（2026-11-06 修正：包名不进 dex 池，containsAll 导致漏检）
- 均空 → 纯包名 C 级

---

## 五、内存与注入痕迹（C6）

| 检测项 | 说明 | 置信 |
|---|---|---|
| mem.injected_memfd | memfd 显示名含 zygisk/lsposed/jit-cache | B |
| mem.known_path | maps 含 lspd/riru/XposedBridge.jar/libzygisk/edxp | C |
| mem.libart_cow | libart 可执行段存在 Private_Dirty COW 脏页 | B |
| mem.fd_data_adb | fd readlink 指向 /data/adb | B |
| mem.hidden_mapping | linker 链表存在但 maps 不可见（maps 抹除） | B |
| mem.maps_tampered | RWX 自探针映射在 maps 中不可见 | **A** |

> ⚠️ NyaZygisk v2.5-r1 已实现从 maps 和 solist 双隐藏

---

## 六、完整性与自保护（C7 + SelfGuard）

| 检测项 | 说明 | 置信 |
|---|---|---|
| integrity.prologue.* | 自身 JNI 入口 prologue 内存≠磁盘（A 级物理不变量） | **A** |
| integrity.got_hooked.* | GOT 槽位解析地址 ≠ 磁盘期望（排除 IFUNC） | **A** |
| integrity.got_anon.* | GOT 解析到匿名区（蹦床特征） | **A** |
| selfguard.repackaged_signature | APK 签名摘要 ≠ XOR 预期（重打包） | **A** |
| selfguard.dex_crc | classes.dex CRC32 ≠ XOR 预期（代码篡改） | B |
| selfguard.tracer_pid | TracerPid > 0（被跟踪） | B |
| selfguard.debugger_attached | 子进程 PTRACE_ATTACH 返回 EPERM（调试器） | B |

---

## 七、内核接口行为（C8）

| 检测项 | 说明 | 置信 | 备注 |
|---|---|---|---|
| behavior.ksu_supercall | reboot(0xDEADBEEF,0xCAFEBABE) → anon_inode:[ksu_driver] | B | fork 隔离 + SIGSYS handler |
| behavior.apatch_supercall | syscall(45, superkey, 0x1158 布局) HELLO 返回 0x11581158 | B | 无 key 时计时降级 |
| behavior.legacy_prctl | prctl(0xDEADBEEF) 原厂返回 -EINVAL 被改 | C | 旧版 KSU 存量 |
| behavior.selinux_label.* | 写探测 label：EPERM=域存在 / EINVAL=不存在 | B | PayPal 向量 |
| behavior.nativebridge_sticky | NativeBridgeError()=true（粘滞标志） | B | ZN/ReZygisk 向量 |
| behavior.ptrace_residue | 父进程 eventmsg == zygote PID | **A** | ⚠️ NeoZygisk ≥10-30 清除 |
| behavior.triple_diff | 同一路径三路调用结果不一致 | **A** | 物理不变量 |

### supercall 特征库（3 族）

| family | magic/superkey | 框架 |
|---|---|---|
| ksu_reboot | deadbeef / cafebabe | ksu |
| apatch_supercall | su / helloCmd=11581000 | apatch |
| legacy_ksu_prctl | deadbeef | ksu（≤v1.0.5） |

---

## 八、硬件证明（C9 Attestation）

| 检测项 | 说明 | 置信 |
|---|---|---|
| attest.keybox_revoked | 证书链序列号命中 CRL | **A** |
| attest.cross.bootloader_lock_mismatch | 系统声称锁定但证明 deviceLocked=false | **A** |
| attest.cross.verified_boot_state | verifiedBootState 非 Verified/SelfSigned | **A** |
| attest.cross.patch_level_future | 证明补丁级别晚于系统声称 | **A** |
| attest.cross.strongbox_capability_mismatch | 声称 StrongBox 但机型库无此能力 | **A** |
| attest.software_backed | 软件 attestation（可伪造） | B |
| attest.degraded.first_api_level | < 26 设备只采集不采信 | C |

### 校验规则

- 双根锚定（RSA 2016 过期信任豁免 + ECDSA P-384 2026 新根）
- **RKP-only**：first_api_level ≥ 36 → RSA 链 = 伪造信号（A1 新增）
- 只信链上第一个 attestation 扩展
- attestationApplicationId 绑定（防中继）
- CRL 影子降级警示（CRL-clean ≠ 可信）

---

## 九、规则层（20 条 · 权重表）

| 规则 | 框架/类别 | 匹配前缀 | 权重 |
|---|---|---|---|
| rule.magisk | magisk | app.magisk, mount.source_magisk, mount.debug_ramdisk, path.debug_ramdisk, sock.fs.magisk_socket, prop.init_svc_magisk, mount.stdev_deviation, behavior.selinux_label.magisk | 12 |
| rule.ksu | ksu | behavior.ksu_supercall, app.ksu, path.ksu, sock.ksud, behavior.legacy_prctl, behavior.selinux_label.ksu_file | 14 |
| rule.ksunext | ksunext | app.ksunext | 12 |
| rule.sukisu | sukisu | app.sukisu | 12 |
| rule.apatch | apatch | behavior.apatch_supercall, app.apatch, path.apatch | 14 |
| rule.lsposed | lsposed | sock.lsposed, mem.known_path, behavior.selinux_label.lsposed, path.riru, prop.riru_bridge | 12 |
| rule.zygisknext | zygisknext | behavior.nativebridge_sticky, behavior.ptrace_residue, path.zygisk, sock.zygiskd, sock.fs.zygisk, path.rezygisk, mem.injected_memfd | 12 |
| rule.rezygisk | rezygisk | path.rezygisk | 12 |
| rule.vector ★新 | vector | app.vector | 12 |
| rule.neozygisk ★新 | neozygisk | app.neozygisk | 12 |
| rule.nyazygisk ★新 | nyazygisk | app.nyazygisk | 12 |
| rule.hook | HOOK（通用） | triple.svc_libc, triple.java_native, behavior.triple_diff, integrity.prologue, integrity.got_, mem.maps_tampered, mem.hidden_mapping, mem.fd_data_adb | 15 |
| rule.anti_detect | ANTI_DETECT（隐藏栈） | mount.too_clean, prop.area_anomaly, mount.fstype_cross | 16 |
| rule.su_binary | ROOT_USERSPACE | path.su. | 8 |
| rule.repackaged | REPACKAGED | selfguard.repackaged_signature, selfguard.dex_crc, mem.known_path | 18 |
| rule.trickystore | trickystore | attest.keybox_revoked, attest.cross., attest.software_backed | 18 |
| rule.susfs | susfs | mount.fstype_cross | 16 |
| rule.pif | pif | prop.build_pair. | 12 |
| rule.trustmealready ★新 | trustmealready | app.trustmealready | 12 |
| rule.zygiskdetect ★新 | zygiskdetect | app.zygiskdetect | 10 |

---

## 十、评分模型（2026-11-06 校准）

| 规则 | 说明 |
|---|---|
| **A 级** | 单条命中即可定性（conclusive） |
| **B 级** | **任意域两条 B 共振即可定性**（2026-11-06 校准，原同域限制已放宽） |
| **B + C** | 同域一 B + 一 C 共振定性 |
| **C 级** | 仅加权，永不单独定性 |
| **anti_detect** | 权重 ×1.5（隐藏栈风险高于普通 root） |
| 定性门槛 | conclusive → riskScore ≥ 50 |
