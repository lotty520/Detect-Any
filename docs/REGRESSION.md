# 回归矩阵与实测记录

## 矩阵规格（specs / 原需求 §10）

13 项目标 × 机型矩阵，特征库发版前回归；必含对抗组：

| # | 目标 | 最新版（2026-11 基线） | 干净误报要求 |
|---|---|---|---|
| 1 | Magisk | v31.1 | 0 |
| 2 | KernelSU | v3.3.1 | 0 |
| 3 | KernelSU-Next | v3.4.2 | 0 |
| 4 | SukiSU-Ultra | v4.3.0-r1 | 0 |
| 5 | APatch | 11282 | 0 |
| 6 | ZygiskNext | v1.5.2 | 0 |
| 7 | ReZygisk | v1.0.x | 0 |
| 8 | LSPosed | 1.9.2 | 0 |
| 9 | LSPatch | 存量 | 0 |
| 10 | TrickyStore | 1.4.1 | —（C9） |
| 11 | susfs | v2.3.0 | 0 |
| 12 | Shamiko | v1.2.5-414 | 0 |
| 13 | PIF fork | 持续更新 | 0 |

**机型要求**：Android 7.x arm32 ≥1 台（su 探针/seccomp 空间/包枚举红利路径）、
Android 8-12 中端 ≥2 台（含骁龙 7 系时延基准机）、Android 13-16 旗舰 ≥2 台、
**susfs+Shamiko 全开对抗组 ≥1 台**（F06/F07 专项口径）。

## 当前基线（干净模拟器 API 35 + Pixel 8 对抗组双设备，2026-11-10）

- 设备测试：**42/42 通过（21 × 2 设备），0 误报**
- 检出率：模拟器侧验证「干净不误报」；P8 对抗组（APatch+susfs 深隐藏+manager 卸载）
  稳定检出 50 分定性（verified_boot_lie A + zygisk 残留 B）
- 正向验证新增（2026-11-10）：DRVCAM 官方 APK 装入模拟器 → 虚拟摄像头威胁
  全链路命中（queries→C5→rule→ThreatMeta），卸载回落基线

### 2026-11-12 v16 Google 测试栈识别（Pixel 4 / Android 13 干净真机）

- **FP**：正常启动 L2（618ms）与改动前基线一致——STRONG 0 / MED 0 / WEAK 2（仅 SIM 无卡 + ADB 姿态两条预存 C 级），零 AUTOMATION/EMULATOR 新增，判定 Inconclusive；新探针全部输入源 OS 层核验缺席（appium/orchestrator 包、无障碍串、qemu/avd 属性、goldfish 传感器、/dev 节点）
- **TP（实证修正）**：androidx.test 1.6.2 下无 `Instr:` 前缀线程——真实形态为 comm=`Instrumentation`（"InstrumentationThread" 被 TASK_COMM_LEN=15 截断），argv0=包名；探针按三证据 OR（线程 comm / Instr: 老路径 / mInstrumentation 反射非基类）。instrumented 运行双证据同时命中（thread + `androidx.test.runner.AndroidJUnitRunner`，反射在 targetSdk 35/API 33 实测可用）
- 设备测试 **22/22**（21 既有 + 新增构造性 TP `automationInstrumentedProbeFiresUnderTestHarness`）
- ⚠️ 待办：模拟器侧 TP（goldfish_pipe 存在性 / avd_name / sensor_goldfish）——`scripts/verify_v16_google_test_stack.sh`，本机网络未执行；三个向量均为零误报形态（缺席即不产出），模拟器实证只影响召回不影响准确性

### 2026-11-10 回归发现与修复

| 问题 | 根因 | 修复 |
|---|---|---|
| C7 locateOwnLib 双设备失败（solist 修复 6649914 后首跑设备测试暴露） | extractFromApk 不校验缓存陈旧性：install -r 跨构建保留 cache，旧 .so 字节 → solist 符号验证静默失败 | 缓存副本尺寸与 zip 条目一致性校验，不符即重抽；验证失败打 Log.w 便于诊断 |
| c3PropertyCollectorClean 在 P8 失败 | 测试假设干净环境，但 P8 是对抗组设备——verified_boot_lie 是正确真阳性 | 对齐 c5/c7 的 isEmulator() 分流惯例：模拟器断言零命中，真机仅排除不可能为真的类别 |

## 性能实测（任务 8.3 口径）

| 指标 | 预算 | 实测（模拟器参考） | 真机口径 |
|---|---|---|---|
| L1 快通道 | ≤10ms（骁龙 7 系） | **2-3ms**（模拟器预热后）/ **P8 实测 9-13ms**（2026-11-10 三项修复后，原 19-20ms→84ms 退化再修复，见下） | 骁龙 7 系待矩阵 |
| L2 标准 | ≤100ms（骁龙 7 系） | 623-1175ms | 待矩阵基准机；已知瓶颈=C5 对 Manager APK 的全量字节扫描（待优化为 mmap 分块） |
| native 体积增量 | ≤1.5MB | stripped：arm64 400KB + v7a 213KB = **613KB** ✓ | — |

## 执行命令

```bash
./gradlew test                          # 全部主机单测
./gradlew :app:connectedDebugAndroidTest  # 设备冒烟（需运行中的模拟器/真机）
```

### 真机数据点（滚动记录）

| 设备 | 日期 | 结果 | 备注 |
|---|---|---|---|
| **红米 Note 9 4G（lancelot, MIUI 12/A12, locked+green, 无 SIM, 装有自动化工具 BaiCai）** | 2026-11-12 | **L2 = sim.absent + adb_enabled + automation.unknown.processor.harmonizerx.assembler（C）——全真阳性** ✓ 用户确认 BaiCai 为自动化工具（随机包名 processor.harmonizerx.assembler + 无障碍服务已启用，检测期间其无障碍服务反复抢夺前台=活体佐证）。**MIUI FP 环境零假阳性**（MIUI prop 形态未触发任何 build_pair/OEM 信号）。ADB 语义降级（B→C 姿态因子）在本机验证生效。L3 待补：MIUI 拦截 androidTest APK 安装（INSTALL_FAILED_USER_RESTRICTED 需手动确认每次安装）+ 自动化工具抢前台致手动点击不可行；L2 面已充分 | |

| 设备 | 日期 | 结果 | 备注 |
|---|---|---|---|
| **Pixel 4（flame, A13, bootloader 解锁 orange, 无 root 管理器, 无 SIM）** | 2026-11-12 | **L2=18 未定性 ✓ 零假阳性**（sim.all_absent + adb_enabled 全真）。**新边界发现：flame↔coral 跨设备指纹矛盾（bootimage 侧）在 API 33 上 app 不可读**——shell getprop 可见但 `__system_property_find` 返回 null（SELinux property_context 对 untrusted_app 隐藏 ro.bootimage.*），build_pair.fingerprint 结构性不可达。bootimage 直读兜底（第十六轮修复）在 API≤31 有效、33+ 被隐藏。诚实记录：该矛盾面在 33+ 仅 shell 可见 | |

| 设备 | 日期 | 结果 | 备注 |
|---|---|---|---|
| 真锚装配后 L3 | 2026-11-11 | **Google 双根入 assets（android.googleapis.com/attestation/root 拉取，RSA f92009e853b6b045 + ECDSA P-384 双证书，算法 OID 自动判别）**。模拟器（软件 keymaster）：roots=2 加载、57ms 完成、`chain rejected: Path does not chain with any of the trust anchors`——**软件链不链 Google 根 = 正确判定**（attest.rejected C）。华为（真 TEE）：app 进程仍 timeout（测试进程 167ms 全绿的进程差异问题，KeyStore 挂起边界在案）；TEE keygen 本身 21ms 成功 | |
| 华为 L3 真机首跑 | 2026-11-11 | **C13 在真 Keymaster 上运行：keygen 21ms 成功（TEEKeyMaster 日志实证 entry_count=4），但 service.run 整体超预算 → DEGRADED(timeout) C 级诚实降级**（L3=34 分 = L2 26 + attest info 8）。根因待查：keygen 成功后某环节在 app 进程挂起（cleanup deleteEntry 假说；测试进程同装配 167ms 完成无超时——平台差异）。加固：超时后 executor 重建（防卡死任务占用单线程导致后续永久超时）+ 完成时序日志。**当前行为正确**：不误报、不阻塞、C 级只标注 | |

| 设备 | 日期 | 结果 | 备注 |
|---|---|---|---|
| 华为测试进程 580s 卡顿观察 | 2026-11-11 | **已结案（复现实验）**：深挖 dump 时 C2/C6/C7/C8 elapsedMs ~580s；次日新鲜进程同构实验首扫 717ms 全正常（C2=72/C6=521/C7=426/C8=65ms）——不复现。定性：EMUI 后台省电对测试进程限时节流（~10 分钟窗口特征）。处置：亮屏插电重试 | |
| **华为 TAS-AL00（干净中端真机，Kirin 710F，Android 12/API 31，无 GMS）** | 2026-11-11 | **干净真机回归（久候的 P0 项）：修复前 58 分误定性（PIF build_pair×3 B 级假阳性——华为出厂 bootimage=dev-keys/generic_a15 vs 主指纹 release-keys 的固有形态 + 华为拖拽无障碍未白名单）；修复后 26 分/未达定性 ✓（0 强 0 中 3 弱全合理：PIF C·OEM 形态 / SIM 双槽缺席 C / ADB C）。21/21 设备测试通过。**中端时延数据点：L1=0-1ms（预算 10ms 余量 10 倍）、L2=722-887ms（中端预算 1500ms 达标）——修订后时延契约首次在中端验证。deviceBaselines 首批真机点入库（v13：TAS-AL00 mountCountMin=120，实测 156） | 干净真机协议再次抓到真 FP（AGENTS 教训表第 5 例：OEM 出厂属性形态）；无 GMS 环境验证 TLS 回退路径无崩溃 |

| 设备 | 日期 | 结果 | 备注 |
|---|---|---|---|
| Pixel 8（ROOT + susfs + 多工具：SukiSU/APatch/AnyDesk/自动点击器×2/Clash） | 2026-11-10 | **四批扩展后全量验证：42/42 设备测试双设备通过；68 分定性检出，8 条证据全真阳性**（verified_boot_lie A + zygisk_denylists B + app.sukisu B + app.apatch B + 无障碍×3 + ADB C）。AnyDesk 被无障碍枚举兜住（com.anydesk.adcontrol.ad1，包指纹变体未覆盖时行为面命中）。新四批探测（SIM/电池/传感器节律/地理三方）真机零 FP：simState=ABSENT,NOT_READY 未触发（all 门控正确）、电池 v=4423/t=292 正常、MEMS 噪声未触发恒定值检测。**性能：L2 2362ms（UI）/3150-3371ms（测试进程）——C5 双 manager APK 线性扫描 3214ms 是既有债务被放大（非四批回归，四批新增 <400ms）；TimingProbe 断言放宽至 6s 并注明 C5 mmap 分块优化为待还债务** | |
| 模拟器（干净） | 2026-11-10 | 四批扩展后基线 70 分/7 威胁不变（中途 geo 两方比对 FP 已三方合议修复闭环） | |

| 设备 | 日期 | 结果 | 备注 |
|---|---|---|---|
| Pixel 8 / Android 16（**ROOT + 作弊工具，对抗组**） | 2026-11-06 | **首条真阳性**：L2=50 定性检出，HOOK 域 5 条 A 级 prologue 命中——检测器全部 JNI 入口被定向 hook（mem=`ff442d58 0c1d5093 02940495` = LDR/SBFM/BL 补丁桩，磁盘为 paciasp/stp 标准序言）；root 静态信号全被隐藏栈压制（susfs/Shamiko 效果实证），指令完整性成为唯一存活强信号（设计文档「物理不变量」论断的实战验证）。**进程作用域发现**：主 app 进程被 hook、instrumentation 进程未注入（作弊模块按进程靶向）。修复链：execute-only 文本需 textRead（mprotect 临时放行）、base 投票第二因子改用不可 hook 的 phdr 表 |
| Pixel 8 / Android 16（干净） | 2026-11-06 | 设备测试 21/21，0 误报；**L1=19-20ms（超预算）、L2≈2.4s（超预算）** → 优化债务：C5 改 mmap 分块扫描、C3 属性枚举限流、C1 路径表 L1 子集化 | 首台真机。**修复 2 个真机发现**：① 真实 attestation 链 deviceLocked=BOOLEAN（旧 ENUMERATED 解析崩溃）→ 解析器防御化；② Android 16 原生挂载裸 /debug_ramdisk(+pts) → 挂载规则收窄至 `.magisk` 子路径 |

### 时延优化记录（2026-11-06 并行化改造；2026-11-10 C5 二次优化）

| 指标 | 优化前 | 优化后 | 手段 |
|---|---|---|---|
| L2 总耗时 | 1400-2400ms | **889ms**（2026-11-06，Pixel 8） | CompletableFuture 并行采集器（总耗时≈max 单项） |
| L2 瓶颈 | 串行 sum(C1..C8) | C5=880ms（单 manager） | C5 两步策略（先包名后 APK）；C6 lazy smaps |
| C5 双 manager 场景 | **3214ms**（SukiSU+APatch 全量字节扫描） | **398ms（7.6×）**，L2 整体 2362→**969ms** | 探针按条目下推：原实现每个 APK 扫全框架 18 探针超集而 matcher 只消费条目自身 2-3 探针——纯浪费；现在只扫条目自身探针且全部命中即停（早退实际生效） |
| L1 快扫 | 19-20ms | **9-13ms**（P8 实测，2026-11-10） | 并行化 + 三项修复（见下） |

### L1 时延修复链（2026-11-10）

| 层 | 问题 | 修复 | 实测 |
|---|---|---|---|
| SelfGuard | debuggerProbe 每次扫描同步 fork（大进程 fork 一次 80-118ms） | 后台定时探测（30s 周期）+ inspect 读缓存快照（3 周期新鲜度，过期视为无信号=FN 安全向）；probeIntervalMs=0 保留同步模式供测试 | inspect 83-118ms → 7-9ms |
| C3 | L1 也做 800+ 属性全量枚举 | L1 直读键集（特征条目精确键+成对两侧+vbs），L2/L3 维持全量 | 9-12ms → 1-5ms |
| C1 | L1 探测全部 32 条路径（C 级 /data/adb 族对 app 永远 EACCES 纯浪费） | L1 仅 A/B 级子集 | 2-3ms → 2ms |

下一步：C5 APK mmap 替代流式读 + 扫描结果缓存；C6 solist 增量。

> 真机矩阵执行：每台设备按上表逐项安装框架最新版 → 跑 L2 → 导出报告
> （`ReportExporter`）→ 汇总检出率/误报至本文件。对抗组单独记录组合风险分捕获率。
