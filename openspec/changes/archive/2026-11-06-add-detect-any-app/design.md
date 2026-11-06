# Design

## Context

Detect-Any 当前为空仓库（仅 LICENSE 与 OpenSpec 脚手架），本 change 从零建立工程。设计输入为 2026-11-04 完成的全网调研（5 路检索、348 次抓取，结论均带来源），关键事实：

- **KSU 家族 supercall 已于 v2.0+（2025-11）重写**：`syscall(SYS_reboot, 0xDEADBEEF, 0xCAFEBABE, 0, &fd)` → 内核经 task_work 安装 `anon_inode:[ksu_driver]` fd → 后续命令走 ioctl（type `'K'`，nr 1–22）；未授权命令返回 -EPERM，GET_INFO 对任意进程放行。主线/Next/SukiSU 同魔数，分叉各有扩展 ioctl nr
- **Magisk v31.1 移除 manager hide/repackage/stub**：`com.topjohnwu.magisk` 包名检测复活；KSU-Next/SukiSU 官方发行 spoofed 变体（SukiSU 构建时随机化包名/类名/so 名），包名黑名单对该两家失效，内容级指纹为唯一路径
- **TrickyStore 停在 1.4.1（2025-11）**；此前认定的"XDA v10.0.0.0"实为同帖发布的 PixelFlasher，属误读；生态由 TeeSimulator/TS-OSS 分叉接棒
- **key attestation API 自 API 24 存在**，但 7.x 时代设备（first_api_level < 26）硬件链不保证，软件链密钥硬编码于 AOSP（可伪造）；Google 官方 CRL 为公开 JSON（`android.googleapis.com/attestation/status`）；2026-02-01 起新旧双根并存（旧 RSA 根过期仍信 + ECDSA P-384 新根）
- **8 项 2025-2026 新强信号**（PayPal/春秋/Hunter/decrypthub/看雪等实战出处）：st_dev 设备号采样、SELinux errno 语义（EPERM vs EINVAL）、`NativeBridgeError()` 粘滞标志、fork+`PTRACE_GETEVENTMSG` 注入残留、ART `class_loaders_` 链表计数、`/dev/__properties__/` 属性区空洞、odex 头 dex2oat-cmdline、smaps Private_Dirty COW 脏页
- **对抗节奏**：root 工具更新中位数 2 天（Guardsquare 3 年实测）；「三层调用 diff（Java API vs libc vs 裸 svc）」与「结构类数据矛盾」被验证为最耐对抗的两大类手法
- Android 7 六颗雷：linker namespace 执法元年（全静态链接 + 保留 ELF 节头）、内核 3.10 syscall 真空（memfd/getrandom）、8.0+ seccomp 白名单外 SIGSYS 杀进程（禁 statx）、/proc/net/unix 10+ 对现代 targetSdk EACCES、无 TLS 1.3 且缺 ISRG 根、大量 arm32-only 机型

proposal.md 中标注「建议默认，待确认」的三项：离线优先（服务端 Phase 2）、证据回放视图纳入首版、分叉生态（TeeSimulator/Vector/NeoZygisk）并入特征库条目。

## Goals / Non-Goals

**Goals:**

- 单 APK 离线完成 L1/L2 档检测与 L3 attestation 本机解析（服务端联合判定为 Phase 2 可选）
- minSdk 24（Android 7.0）至 Android 16 全区间运行，版本 × 内核 × targetSdk 三维门控降级
- 特征数据与规则全部服务端可热更新（签名验证），与 App 发版解耦
- 输出 `risk_score + evidence_vector + 分类标签`，每个命中项可回放解释（命中规则、采集器、原始观测值）
- 工业级基线：误处置率 <0.1%、L1 ≤10ms / L2 ≤100ms（中端机）、特征次日生效

**Non-Goals:**

- 不承诺 KPM 存在性与 susfs 完整配置场景的客户端检出（明示边界，C9 兜底）
- Frida/反调试/模拟器对抗属独立需求域，首版不立项（检测点结构为其预留扩展）
- 首版不含服务端组件（Play Integrity 解码、keybox 复用图谱、下发通道服务端实现）
- 不做 SDK 化对外封装（模块边界为其预留，能力以 APP 形态交付）

## Decisions

### D1. Gradle 多模块架构：采集器/规则/特征数据三层物理隔离

```
DetectAny/
├── app/                      # Compose UI:扫描/报告/回放/导出
├── core/
│   ├── model/                # Finding/EvidenceVector/RiskScore 数据模型
│   ├── engine/               # 编排、评分、L1/L2/L3 档位、证据向量组装
│   ├── rules/                # JSON 规则引擎(解析/求值/热装载)
│   └── native-platform/      # JNI 基座(C/C++):裸svc三路执行器、
│                             #   seccomp/内核门控守卫、ELF 自解析、
│                             #   prologue 校验、soinfo/ART 内部结构访问
├── collectors/               # 采集器(纯取证、框架无关、编译期固定)
│   ├── fs-probe/             # C1 路径 + C2 挂载/设备号
│   ├── properties/           # C3 属性快照 + 属性区空洞
│   ├── endpoints/            # C4 socket/网络端点
│   ├── app-fingerprint/      # C5 应用枚举 + APK 内容指纹
│   ├── memory-map/           # C6 maps/fd/smaps/soinfo/class_loaders_
│   ├── code-integrity/       # C7 指令完整性(自身 prologue/GOT)
│   └── behavior-probe/       # C8 supercall/SELinux errno/三路diff/
│                             #   NativeBridge/ptrace 残留
├── feature/
│   ├── attestation/          # C9 key attestation(+Phase 2 Play Integrity)
│   └── report/               # 报告生成/导出/遥测(脱敏)
├── data/
│   └── signature/            # 特征数据:内置基线+增量+签名验证
├── compat/
│   └── platform/             # 门控矩阵、TLS(内置 Conscrypt)、页大小
└── selfguard/                # 自保护:签名校验、反调试、延迟响应
```

**Rationale**：调研证明特征半衰期以周计，唯一高频变化层必须是数据；物理隔离（独立 Gradle 模块）强制执行「新框架不新增采集器，只加规则+数据」的约束。`native-platform` 单独成层是因为三路执行器/seccomp 守卫/ELF 解析是全部采集器的公共依赖，且自身是 C7 的校验对象，必须与业务采集解耦。
**Alternatives**：单模块 + 包隔离（放弃：无法防止特征硬编码回流到 so）；按框架组织模块（放弃：13 框架 × 8 采集器的矩阵无法切成内聚模块，且违背框架无关原则）。

### D2. 采集器清单（C1–C8，2026-11 校准版）

| 采集器 | 内容 | 关键实现约束 |
|---|---|---|
| C1 路径探测 | 特征路径 access/stat/faccessat（含失败码分类 EACCES/ENOENT） | 必须走三路执行器，禁止单路 |
| C2 挂载/设备号 | mountinfo 解析、statfs 交叉（f_type 魔数）、**st_dev 四路采样**（/dev、/proc、/sys、/dev/pts 与基线比对）、挂载数/结构基线偏离 | st_dev 用 newfstatat；「过度干净」（挂载异常少）也输出 `anti_detect_present` 证据 |
| C3 属性快照 | `__system_property_foreach` 全量 KV + **`/dev/__properties__/` 属性区空洞扫描**（权限/属主/SELinux context 异常） | API 24 用 `__system_property_read`（92 字节截断注意），26+ 切 read_callback |
| C4 网络端点 | /proc/net/unix 匹配（门控：7 可读/10+ 不可读时降级）+ connect() 试探 + 文件系统 socket 路径族 | 路径族全部特征数据化（如 `/debug_ramdisk/zygisk/*.sock`、`/dev/zygisk/`） |
| C5 应用指纹 | `<queries>` 声明式枚举 + APK 内容指纹（DEX 字符串/资源/签名组合），覆盖官方 spoofed 变体 | 不申报 QUERY_ALL_PACKAGES（首版）；指纹摘要预计算入特征数据 |
| C6 内存映射 | maps + fd readlink + memfd 显示名（内核门控）+ smaps Private_Dirty + **soinfo 链表遍历** + **ART class_loaders_ 计数** + RWX 自探针（自 mmap 一页验证 maps 读取未被 hook） | Android 10+ 系统 execute-only 段扫描前 mprotect 放开、扫完恢复；TBI 指针 tag 掩码 |
| C7 指令完整性 | 自身敏感函数 prologue 字节 vs 磁盘 ELF 同偏移、GOT/PLT 表项 vs 系统库导出地址、可执行段内存 vs 磁盘 CRC | 校验清单 MUST 覆盖全部采集器自身入口；NEON 字节和做快速路径 |
| C8 接口行为 | **KSU 系：reboot 双魔数 → fd 表新增 `anon_inode:[ksu_driver]` → ioctl GET_INFO**（未授权 -EPERM 可区分）；**APatch：syscall 45 + 0x1158 布局**（无 superkey 时退化为计时侧信道）；旧 prctl 探测（存量老内核）；**SELinux errno 语义**（写探测性 label：EPERM=存在/EINVAL=不存在）；三路 diff（同一事实 Java/libc/裸 svc 结果不一致即 hook）；`NativeBridgeError()` 粘滞标志（与属性交叉，防清零对抗）；**fork 子进程 PTRACE_ATTACH 父进程 + PTRACE_GETEVENTMSG**（=zygote PID 即 ZN/ReZygisk 注入）；sucompat 残余探测 | 全部裸 syscall 经 seccomp 白名单守卫（Android 8+ 白名单外=SIGSYS）；supercall magic 表全部特征数据化 |

**Rationale**：每项均对应调研中「仍有效」或「部分有效（有组合对策）」的向量；`已被对抗` 的纯静态向量降级入弱信号（D4）。
**Alternatives**：把 ptrace 残留/SELinux errno 并入现有 C6/C2（放弃：它们是主动行为探针而非被动取证，生命周期与实现风险不同，独立演进）。

### D3. native-platform：三层执行器 + syscall 守卫

- **三路执行器**：同一事实（stat/openat/access/...）提供 Java API、libc 包装、裸 `svc #0`（AArch64/ARM32/x86_64 三套）三条路径，任意两层结果不一致本身即证据（hook 存在性）
- **syscall 守卫**：所有非白名单 syscall 先经 uname 内核版本 + Android 版本门控；**永远禁止「试探再回退」模式**（Android 9–11 上 statx 等未列白名单的调用以 SIGSYS 杀进程而非返回 ENOSYS）
- **ELF 自解析**：不依赖 dlsym 查询被 hook 的符号，自身解析 ELF/Dynamic 段定位系统库真实导出地址（供 C7 比对）
- 全部加密依赖静态链接（BoringSSL/MbedTLS），保留标准 ELF 节头（Android 7 linker namespace 拒载剥离 so）

**Alternatives**：依赖系统 libcrypto（Android 7 直接不可用）；dladdr/dlsym 查询（可被 PLT hook 篡改）。

### D4. 置信分级（弱/中/强）与评分模型

| 级别 | 语义 | 判定权限 | 成员（2026-11 校准） |
|---|---|---|---|
| **强（A）** | 物理不变量：隐藏行为本身产生、进程内/跨层可验证 | 单信号即可推高风险分 | 三路 diff 不一致；prologue/GOT 完整性；SELinux errno 语义；st_dev 采样；attestation 证书链+CL+appKey 绑定；keybox 复用图谱（P2）；签名 pinning；ptrace 注入残留 |
| **中（B）** | 行为/状态差异：隐藏成本高但可被针对 | 两条 B 或 B+C 共振 | KSU reboot supercall；APatch syscall 45+计时；NativeBridgeError（组合）；挂载交叉+基线偏离；属性区空洞+证明交叉；maps/smaps 特征；class_loaders_ 计数；/proc/modules+基线；susfs 三路统计发散；odex cmdline |
| **弱（C）** | 静态痕迹：常规手段可清除 | 仅加权，不单独触发处置 | 特征路径；socket/进程名；包名（spoofed 变体除外）；init.svc 属性族；栈帧/类名反射；su/busybox 路径 |

- 评分输出：`risk_score(0-100) + evidence_vector(命中规则 ID) + 分类标签(root_kernel / root_userspace / hook / zygisk / attestation_spoof / repackaged / anti_detect_present)`
- `anti_detect_present`（检出隐藏栈本身）风险加权高于普通 root
- 规则置信级别在特征数据中随条目维护（如 `MAGISK_INJ_1` 标记版本区间失效）

**Rationale**：与原需求规格 §7 对齐，但按调研校准成员（prctl 探测降级为存量弱信号、ptrace 残留升强、NativeBridgeError 因已有清零对抗降为中并强制组合）。

### D5. 特征数据 schema 与热更新

- **单一签名的 JSON 文档**（ed25519，公钥内置，增量 ≤200KB/次）：`paths` / `packages`（含内容指纹摘要与 spoofed 变体）/ `supercalls`（family、入口、magic、ioctl nr、版本区间）/ `sockets` / `keybox_blacklist`（证书序列号+来源）/ `device_baselines`（机型 × 挂载数/属性组合/st_dev 预期/StrongBox 能力）/ `expires`（带框架版本区间的失效条目）
- 下发通道 Phase 2 上线；首版内置基线 + 应用内更新（可拆 APK 分发或手动导入）
- 条目全部带 `since`/`until`（框架版本区间）与 `confidence`（A/B/C），规则引用采集器输出 + 条目 ID 求值

**Rationale**：spoofed 包名、仓库迁移、渠道跳变均证明写死特征半衰期以月计；Guardsquare 实测对抗工具中位 2 天一更 → 数据层 MUST 与发版解耦。

### D6. attestation（C9）离线优先设计

- 客户端：`setAttestationChallenge(本地生成 nonce)` 发起，取整条证书链
- 本机解析校验（Phase 1 离线即可用）：链根 MUST 锚定 Google 双根（旧 RSA + 2026-02 起 ECDSA P-384）；**只信链上第一个 attestation 扩展**（OID 1.3.6.1.4.1.11129.2.1.17）；`attestationApplicationId`（tag 709）MUST 匹配自身包名与签名摘要（防中继）；RootOfTrust 字段（verifiedBootState/deviceLocked）+ 补丁级别 vs 系统状态 + StrongBox 声明 vs 机型能力库交叉；证书序列号查 CRL
- CRL：拉取官方 `android.googleapis.com/attestation/status`（按 Cache-Control 节流），离线快照兜底
- 降级：`ro.product.first_api_level < 26` 或链根非 Google → 只采集不采信，降级为 L2 本地信号
- Play Integrity：API 23+ 可用（7.x 判定为软件级），Phase 2 接服务端解码；本机不缓存不解密 verdict

**Rationale**：离线校验可行性由 vvb2060 KeyAttestation app 验证；「不在被测设备上做最终信任判定」的完整版留 Phase 2。
**Alternatives**：纯服务端校验（放弃首版依赖）；只信 Play Integrity（放弃：7.x 上软件级判定区分度不足，PIF 直接作用于该层）。

### D7. 兼容层：版本 × 内核 × targetSdk 门控矩阵

| 维度 | Android 7 现实 | 对策 |
|---|---|---|
| linker namespace | API 24 起拒载系统私有库与剥节头 so | 全静态链接；加固保留节头 |
| syscall | 3.10 缺 memfd/getrandom；8.0+ seccomp 白名单外 SIGSYS | uname+白名单守卫；禁 statx；memfd 内核 ≥3.17 门控（ART 记录旧内核段错误案例）；随机数用 arc4random_buf |
| /proc/net/unix | 7 可读（红利）；10+ 现代 targetSdk EACCES | 版本门控：新版降级 connect() 试探 + maps 扫描 |
| 包枚举 | 7 全量可见；11+ 需 `<queries>` | queries 声明式清单进特征数据 |
| attestation | API 24 有 API 但硬件链不保证 | first_api_level 分级（D6） |
| TLS | 无 TLS 1.3；7.0/7.1.0 缺 ISRG 根 | 内置 Conscrypt + 自有信任锚 + SPKI pinning |
| ABI/页 | arm32 机型存量大；Android 15+ 16KB 页 | v7a+v8a 双 ABI；NDK r28 16KB 对齐；禁硬编码 4096 |

门控矩阵实现为 `compat:platform` 内的单一查询接口（`ProbeCap(api, kernel, targetSdk) → allowed/degraded/blocked`），全部采集器经它取能力，禁止散落的 `Build.VERSION` 判断。

### D8. 自保护与响应策略

- 签名 SHA-256 与关键 DEX CRC 校验放 native 层，预期值加密分散存储
- C7 校验清单覆盖全部采集器入口；selfguard 与 engine 分体混淆
- 反调试：TracerPid 轮询 + 子进程反查（复用 C8 ptrace 探针基础设施）
- 响应：静默记分、延迟响应（不即时崩溃/弹窗，避免给攻击者定位反馈）；APP 形态下报告呈现完整证据（用户即检测者），但导出/遥测通道默认最小化

### D9. 每框架主信号映射（规则库初始版本）

| 框架 | 强 | 中 | 弱 |
|---|---|---|---|
| Magisk v31.x | st_dev、SELinux errno、(C9) | /debug_ramdisk 工件、属性区空洞、挂载交叉 | 包名（复活）、socket、init.svc 族 |
| KSU/Next/SukiSU | (C9) | reboot supercall、sucompat 残余、/proc/modules、基线偏离 | ksud 产物、spoofed 内容指纹 |
| APatch | (C9)；KPM 不承诺 | syscall 45+计时、挂载标记 | `me.bmax.apatch`、`/data/adb/ap` |
| LSPosed | prologue/GOT、三路 diff | class_loaders_ 计数、odex、maps | XposedBridge 类名、栈帧 |
| ZN/ReZygisk | ptrace 残留 | NativeBridgeError、socket 路径族、RWX 自探针 | maps 字符串、进程名 |
| LSPatch | 签名 pinning | DexClassLoader 加载链、嵌入式 lspd | 类名 |
| TrickyStore | 证书链+CRL+（P2 复用图谱） | 证明字段交叉、PIF 属性偏离 | keybox.xml 路径 |
| susfs | —（结构边界） | 三路统计发散、挂载数异常 | — |
| Shamiko | — | 「过度干净」异常分 | — |

## Risks / Trade-offs

- [军备竞赛：B/C 级信号必然被逐个针对] → 长期有效性锚定三类物理不变量（指令字节、syscall 行为、keybox 供应链）+ 特征热更新 + 组合共振判定；对外承诺锚定 L3 组合检出率
- [NativeBridgeError 已有清零对抗、maps 可被抹除] → 强制与属性值等其他运行时副作用组合（中级不单判）；RWX 自探针验证 maps 读取本身未被 hook
- [class_loaders_ 计数需逐 app 基线，自研 app 基线可控但校准成本真实] → 仅用于自进程（本 app 即宿主，基线可出厂校准）；阈值随特征数据更新
- [supercall 探针在未授权 uid 上可能被 susfs 静默/未来版本加过滤] → magic 表按版本批量 + 行为统计（错误码分布/时延）而非单点判定；GET_INFO 放行策略随上游监控
- [attestation 本机解析可被本机 hook 欺骗（被测设备不可信）] → Phase 1 明示该边界并提供导出复核；Phase 2 服务端联合判定；Quarkslab 中继对策（appKey 绑定 + nonce）首版即内建
- [Android 7 arm32 真机回归成本高（3.10 内核矩阵）] → 回归实验室矩阵纳入 2 台 7.x 真机（arm32/arm64 各一）；模拟器仅作冒烟
- [误报：定制 ROM/开发者设备] → 分级响应默认非阻断、证据回放逐项解释、FP 申诉样本回传闭环（<0.1% 验收）
- [Play Integrity 配额（默认 1 万次/天）与 GMS 依赖] → 定位为 Phase 2 可选通道，不作首版依赖

## Migration Plan

绿地项目，无存量迁移。分阶段交付（与原需求规格 §12 对齐）：

1. **Phase 1（本 change 首个可交付）**：工程骨架 + native-platform + C1/C2/C3/C5/C8 核心探针 + 规则引擎 + 内置特征数据 + Magisk/KSU 系/APatch/LSPosed 主信号 + L1/L2 输出 + 报告 UI
2. **Phase 2**：C4/C6/C7 全量、内容指纹全量（spoofed 变体）、C9 离线校验 + CRL、ZN/ReZygisk/LSPatch/TrickyStore/横切项、特征下发通道（服务端）
3. **Phase 3**：机型基线库规模化、keybox 复用图谱（服务端）、Play Integrity、FP 闭环与检出率看板

每阶段以真机回归（13 项 × 机型矩阵，含 susfs+Shamiko 对抗组）作为出阶段门槛。

## Open Questions

- proposal 中三个「建议默认」的最终确认（离线优先 / 证据回放首版 / 分叉生态条目）——不改变架构，可在实施中确认
- supercall magic 表的版本化提取流水线（从各框架源码 tag 自动提取的脚本化程度）——实施期细化
- 遥测上报默认开关与脱敏字段的合规评审结论——上线前确认
- 特征下发通道的托管形态（静态 CDN + 签名文件 vs 轻量 API）——Phase 2 决策
