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

## 当前基线（干净环境，API 35 arm64 模拟器，2026-11-05）

- 设备测试：**17/17 通过，0 误报**
  （8 采集器冒烟 + 6 自保护冒烟 + 2 UI/编排走查 + 1 时延探针）
- 检出率：待真机矩阵（上表）补测——模拟器无 root 栈，仅验证「干净不误报」侧。

## 性能实测（任务 8.3 口径）

| 指标 | 预算 | 实测（模拟器参考） | 真机口径 |
|---|---|---|---|
| L1 快通道 | ≤10ms（骁龙 7 系） | **2-3ms**（3 次预热后） | **Pixel 8(Android 16) 首个真机数据点已录**（见下行）；骁龙 7 系待矩阵 |
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
| Pixel 8 / Android 16（**ROOT + 作弊工具，对抗组**） | 2026-11-06 | **首条真阳性**：L2=50 定性检出，HOOK 域 5 条 A 级 prologue 命中——检测器全部 JNI 入口被定向 hook（mem=`ff442d58 0c1d5093 02940495` = LDR/SBFM/BL 补丁桩，磁盘为 paciasp/stp 标准序言）；root 静态信号全被隐藏栈压制（susfs/Shamiko 效果实证），指令完整性成为唯一存活强信号（设计文档「物理不变量」论断的实战验证）。**进程作用域发现**：主 app 进程被 hook、instrumentation 进程未注入（作弊模块按进程靶向）。修复链：execute-only 文本需 textRead（mprotect 临时放行）、base 投票第二因子改用不可 hook 的 phdr 表 |
| Pixel 8 / Android 16（干净） | 2026-11-06 | 设备测试 21/21，0 误报；**L1=19-20ms（超预算）、L2≈2.4s（超预算）** → 优化债务：C5 改 mmap 分块扫描、C3 属性枚举限流、C1 路径表 L1 子集化 | 首台真机。**修复 2 个真机发现**：① 真实 attestation 链 deviceLocked=BOOLEAN（旧 ENUMERATED 解析崩溃）→ 解析器防御化；② Android 16 原生挂载裸 /debug_ramdisk(+pts) → 挂载规则收窄至 `.magisk` 子路径 |

> 真机矩阵执行：每台设备按上表逐项安装框架最新版 → 跑 L2 → 导出报告
> （`ReportExporter`）→ 汇总检出率/误报至本文件。对抗组单独记录组合风险分捕获率。
