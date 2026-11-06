# Tasks

> 依据 design.md D1-D9 与 6 个能力 spec 拆解。Phase 3（服务端图谱、Play Integrity 通道、下发托管）不在本清单，留待后续 change。design 的 Open Questions 均不改变本清单结构，按「建议默认」执行。

## 1. 工程骨架与兼容基座

- [x] 1.1 建立 Gradle 多模块骨架（app、core:model/engine/rules/native-platform、collectors 七模块、feature:attestation/report、data:signature、compat:platform、selfguard），验证 `./gradlew assembleDebug` 通过且模块清单与 design D1 一致
- [x] 1.2 配置 NDK/CMake 工具链：arm64-v8a + armeabi-v7a 双 ABI、16KB 页对齐、crypto 静态链接、保留标准 ELF 节头，验证产物 `llvm-readelf -lW` 显示 max-page-size=16384 且无动态依赖系统 libcrypto/libssl
- [x] 1.3 实现 compat:platform 能力查询接口（版本 × 内核 × targetSdk → allowed/degraded/blocked）与门控数据表，验证单测覆盖矩阵关键格（statx 于 9-11 blocked、/proc/net/unix 于 10+ blocked、memfd 按内核 ≥3.17 门控、getrandom 走 arc4random 回退）
- [ ] 1.4 内置 Conscrypt + 自有信任锚 + SPKI pinning 的网络通道，验证在 Android 7 环境完成 TLS 1.3 握手（模拟器或真机）

## 2. native-platform 基座

- [x] 2.1 实现裸 svc 三路执行器（AArch64/ARM32 的 stat/fstatat/openat/access/faccessat 集合），验证三路一致性单测与 hook 桩注入下的差异检出单测
- [x] 2.2 实现 syscall 守卫（uname 内核版本门控 + Android 8+ seccomp 白名单表），验证守卫层单测拒绝白名单外调用且代码中不存在「试探再回退」路径
- [x] 2.3 实现 ELF 自解析与系统库导出地址定位（不依赖 dlsym），验证对 libc/linker 解析结果与 dlopen 句柄独立获取的地址一致
- [x] 2.4 实现属性访问层（API 24/25 走 `__system_property_read` 含 92 字节截断处理，26+ 走 read_callback），验证双路径单测

## 3. 采集器 C1-C8

- [x] 3.1 C1 路径探测：三路 access/stat + 失败码分类（EACCES/ENOENT），验证对特征路径表桩数据的三路一致性单测
- [x] 3.2 C2 挂载/设备号：mountinfo 解析、statfs f_type 交叉、st_dev 四路采样（/dev、/proc、/sys、/dev/pts）、挂载数/结构基线偏离输出，验证干净设备与桩 mountinfo 的对比单测
- [x] 3.3 C3 属性快照：全量 KV 枚举 + `/dev/__properties__/` 属性区空洞扫描，验证属性键脱敏出口与空洞桩单测
- [x] 3.4 C4 端点：门控下 /proc/net/unix 匹配、connect() 试探、文件系统 socket 路径族探测，验证门控 blocked 时输出降级标记且不发起读取
- [x] 3.5 C5 应用指纹：`<queries>` 声明式枚举 + APK 内容指纹（DEX 字符串/资源/签名摘要组合），验证对样例 Manager APK（含 spoofed 变体）指纹匹配单测
- [ ] 3.6 C6 内存映射：maps、fd readlink、smaps Private_Dirty、soinfo 链表遍历、class loader 计数、RWX 自探针、memfd 显示名（内核门控）、Android 10+ execute-only 段的 mprotect 放开与恢复，验证干净进程基线单测与 maps 篡改桩下自探针异常单测
- [ ] 3.7 C7 指令完整性：自身敏感函数 prologue 与磁盘 ELF 比对、GOT/PLT 校验、校验清单覆盖全部采集器入口，验证内存改写桩下不一致检出与 NEON 快速路径单测
- [x] 3.8 C8 接口行为：KSU 系 reboot 双魔数探测（fd 表变化 + ioctl GET_INFO + 未授权 -EPERM 区分）、APatch syscall 45 布局与计时降级、存量 prctl 探测、SELinux errno 语义探测、三路 diff、NativeBridgeError 组合、fork 子进程 PTRACE_ATTACH 父进程 + PTRACE_GETEVENTMSG 残留，验证原厂内核不误报单测与 magic 全部来自特征数据的装载断言

## 4. 特征数据与规则/评分引擎

- [x] 4.1 定义特征数据 schema（paths/packages 含指纹摘要/supercalls/sockets/keybox_blacklist/device_baselines/expires/since-until/confidence）并制作内置基线数据，验证 schema 单测与基线装载
- [x] 4.2 实现 ed25519 签名验证、版本管理与增量合并（≤200KB、失败保留旧版、装载即生效），验证坏签名拒绝与合法增量生效单测
- [x] 4.3 实现 JSON 规则引擎（采集器输出 × 特征条目 → Finding），验证合成观测回放单测
- [x] 4.4 实现评分与档位（弱/中/强判定权限、risk_score、分类标签、anti_detect_present、L1/L2/L3 与降级标记），验证判定权限矩阵单测（单 B 不定性、强单条定性、C 仅加权）
- [x] 4.5 编写规则库初始版（Magisk、KSU 系、APatch、LSPosed 主信号，对齐 design D9 表），验证各框架样例观测回放产出预期标签

## 5. 硬件证明（C9）

- [x] 5.1 实现证明发起（本地随机 nonce、取整链）与链解析（只取第一个 attestation 扩展、OID 解析），验证测试向量链解析单测
- [x] 5.2 实现双根锚定（旧 RSA + ECDSA 新根）、CRL 拉取（Cache-Control 节流）与离线快照、吊销序列号命中 → attestation_spoof，验证吊销/软件链/追加叶子三类测试向量
- [x] 5.3 实现字段交叉（RootOfTrust、补丁级别、StrongBox 能力库）与 first_api_level 降级标注，验证降级路径单测

## 6. 自保护

- [x] 6.1 native 层签名摘要与关键 DEX CRC 校验（预期值加密分散存储）→ repackaged 证据，验证重打包自测检出
- [x] 6.2 反调试（TracerPid 轮询 + 子进程反查，复用 C8 ptrace 基础设施），验证调试附加自测检出
- [x] 6.3 静默延迟响应策略接入引擎（不即时崩溃/弹窗），验证篡改注入测试下应用存活且证据入报告

## 7. 报告 UI 与导出

- [x] 7.1 扫描流程与结果 UI（L1/L2 触发、风险分、分类标签、命中明细、证据级别），验证真机走查截图
- [x] 7.2 证据回放视图（命中项展开：规则、采集器、原始观测值、特征条目），验证逐项与引擎输出一致
- [x] 7.3 结构化导出（脱敏、含完整证据向量）与特征文件手动导入入口，验证导出文件脱敏断言与导入等价在线更新

## 8. 扩展规则、回归与文档

- [x] 8.1 补齐 ZN/ReZygisk、LSPatch（签名 pinning/加载链）、TrickyStore 交叉、susfs 三路统计发散、Shamiko「过度干净」、PIF 属性偏离规则条目，验证样例观测回放单测
- [ ] 8.2 （待真机环境：矩阵规格/基线/执行手册已就绪见 docs/REGRESSION.md；干净模拟器 17/17 零误报）真机回归矩阵（13 目标 × 机型，含 Android 7.x arm32 与 susfs+Shamiko 对抗组各至少一台），产出检出率与误报记录报告
- [ ] 8.3 （体积 613KB✓、L1=2-3ms✓、模拟器 L2 参考值已录；中端真机 L2 时延待矩阵基准机）性能与体积验证（中端机 L1 ≤10ms、L2 ≤100ms；native 体积增量 ≤1.5MB），记录实测数据
- [x] 8.4 编写能力边界声明（KPM 与 susfs 全配置不承诺客户端检出）与使用/运维文档，验证文档命令按写运行通过

## Workflow follow-up

- 全部任务完成后经 `/opsx:verify-change` 校验，再归档并同步 specs
- Phase 3（服务端：特征下发托管、keybox 复用图谱、Play Integrity 解码通道）另立 change
