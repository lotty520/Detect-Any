# 假阳性核准体系（FP Certification）

> 原则（AGENTS）：**漏报可恢复，误报毁信任**。本文件把「干净零阳性」从临场手工动作固化为可重复的核准流程。
> 诞生背景：2026-11-12 小米 Android 16 首测抓出两个系统性 FP 族（HyperOS overlay ×24、solist 竞态 ×12，98 分误定性）——证明干净矩阵扫描必须自动化、强制化。

---

## 一、三层证据链

FP 核准 = 三层证据全部成立。任何一层不成立即核准失败。

### L1 输入源核验（静态确定性）

**原理**：每个探针的触发条件是其 OS 级输入的纯函数。干净设备上逐项证明输入缺席 = 结构性不可能误报——比「跑了没报」更强的证据。

| 探针族 | 输入源 | 干净设备核验方式 |
|---|---|---|
| C5 特征库 app.* | 安装包（PackageManager + `<queries>`） | `pm list packages` 逐前缀 grep |
| C3 属性 / C10 qemu/avd | 系统属性 | `getprop` 键级核验（注意键存在≠触发，值条件也要核） |
| C1/C2 路径与挂载 | 文件存在性 / mountinfo | `ls` 指定节点；mountinfo overlay 的 **upperdir 指纹**核验 |
| C10 传感器 | SensorManager | `dumpsys sensors` grep goldfish |
| C11 无障碍 | ENABLED_ACCESSIBILITY_SERVICES 串 | `settings get secure` + 白名单比对 |
| C9/C6 内存/线程 | /proc（native 读） | （动态面，由 L2 覆盖） |

`scripts/fp_certify.sh` 第 1 段自动执行全部核验并打印 PRESENT/ABSENT；任何 PRESENT 于干净设备 = 核准失败，先修探针再谈扫描。

### L2 干净矩阵扫描（动态零阳性）

**设备 × 合法状态矩阵**，每格跑一次 instrumented 全扫，findings 必须完全落在机型基线内。

**判定门槛**（全设备通用）：
1. **0 条 A 级** finding
2. **0 条非预期 B 级**（基线 `testHarness` 内的构造性 TP 除外，如 automation.instrumented）
3. verdict = **Inconclusive**（conclusive=false）
4. riskScore ≤ 机型基线 `maxScore`

**机型基线**（`scripts/baselines/<model>.json`）：记录该机型已定级的合法 OEM/测试形态 findings。**基线外任何 finding = 核准失败**。基线内条目消失 = WARN（基线漂移，需复核定级是否仍成立）。

**合法状态矩阵**（FP 高危正常形态；每项须在 ≥1 干净设备上核准过一次才视为覆盖）：

| 状态 | 为什么高危 | 已核准 |
|---|---|---|
| ADB 调试开 + USB 连接 | 开发者常态；screenshare.adb_enabled(C) 姿态 | ✅ Pixel4/小米 A16（2026-11-12） |
| 无 SIM（WiFi 平板/备机） | sim.all_absent(C) | ✅ 同上 |
| 无障碍开启（TalkBack/密码管理器/OEM 车联） | automation.unknown 误伤 OEM 服务 | ✅ 小米 carlink（华为 pasteboard 2026-11-11） |
| OEM 出厂 overlayfs（/product /oem /system 系） | mount.overlay 误定性 | ✅ 小米 A16（2026-11-12 根因修复） |
| GPU 栈运行时加载（Adreno 等） | solist/maps 竞态 | ✅ 小米 A16（同上） |
| 企业/隐私 VPN 开 | network.vpn_active(C) | ⏳ 待设备 |
| Work Profile（userId≥10） | 容器路径误报 | ⏳（代码已豁免，待实测） |
| 深色 / 大字体（≥1.3） | UI 层（不影响 findings，视觉矩阵覆盖） | ⏳ HyperOS 受限，代码级保证 |
| 系统录屏 / 合法投屏 | screenshare.recording_active | ⏳ API 34 回调路径待实测 |
| 高通/联发科图形栈设备 | 本 session Adreno 教训泛化 | 部分（1 台高通） |

**设备矩阵要求**（对齐 REGRESSION「机型要求」）：
- Pixel 系 ≥1（纯净 AOSP 形态基准）
- 重度定制 OEM ≥2（小米/HyperOS、华为/EMUI——两次 FP 教训来源）
- 三星/vivo/OPO ≥1（如可得）
- 模拟器各 API 级（24/28/33/35）
- Android 7.x arm32 ≥1
- **干净要求**：零 root/自动化包（`fp_certify.sh` L1 自动核验）；对抗组设备不参与 FP 核准（属 TP 侧）

### L3 分级审计（语义正确性）

每个 **A/B 级**信号必须能回答：「为什么该信号在合法环境物理不可能出现？」——写不出的降 C。

- 分级论证基准：`openspec/changes/archive/2026-11-10-close-detection-gaps/calibration.md`（设备类型边界表 §四）
- **新 A/B 级准入门槛**（两次 OEM 教训成文）：物理不变量论证 + **≥2 厂商矩阵实测**后才可定 B；A 级仅限指令字节/syscall 行为/keybox 供应链三类物理不变量
- OEM 形态发现新样本 → 先记入机型基线（C 级观察）→ 矩阵复现 → 才讨论升级

---

## 二、执行流程

### 何时必须跑

| 触发 | 范围 |
|---|---|
| 特征库 bump（DB version 变更） | 全矩阵机型各一次 |
| 任何探针改动（collect 逻辑/分级/判据） | 全矩阵 + 受影响探针的 L1 专项 |
| 发版 tag 前 | 全矩阵 + connected 套件 |
| FP 线上/实测事件 | 单机型即时 → 修复后全矩阵复跑 |

### 命令

```bash
./scripts/fp_certify.sh <serial>          # 全流程：L1 → L2 → 基线 diff → 判定
./scripts/fp_certify.sh <serial> --new    # 新机型引导：打印 findings 供人工定级生成基线
```

### FP 事件响应闭环（模板化 2026-11-12 当天流程）

1. 核准失败 → **不得 commit/tag**
2. 根因分析（diag 测试取证，如 diagSolistVsMaps 先例）
3. 修复（判据重构/降级/白名单——附实证：包路径+分区标志、mountinfo upperdir、竞态实证）
4. 机型基线更新（新形态入 expected）
5. **全矩阵复跑**（防修 A 坏 B）
6. AGENTS Critical Lessons 表补录

### 判定输出

PASS 记录（score/conclusive/findings/时间）追加到 `docs/REGRESSION.md` 对应小节；FAIL 附证据向量。核准记录是发版 tag message「Verified」段的依据。

---

## 三、TP 正确性方法（本轮仅方法论，待对抗组设备实现自动化）

FP 核准只证明「不冤枉好人」；「抓得到坏人」由 TP 侧保证，方法：

1. **对抗组设备**（REGRESSION 13 目标矩阵）：susfs+Shamiko 全开 ≥1 台常备，每特征库发版跑检出率（验收口径：组合风险分捕获 ≥85%）
2. **官方 APK 正向验证**（DRVCAM 先例，2026-11-10）：官方样本装入干净设备 → 全链路命中（queries→C5→rule→ThreatMeta）→ 卸载 → **基线回落**（回落失败=有残留误报，双赢了 FP+TP 验证）
3. **构造性 TP 测试**：`automationInstrumentedProbeFiresUnderTestHarness` 模式——测试环境本身即真阳性场景，断言必中
4. 签名库条目 DEX 探针：每条目的探针字符串必须在**官方发布 APK** 中实测存在（防 Luckin-Coffee 式同名误报 + 防压缩构建漏检）

---

## 四、边界与后续

- CI 目前仅 host 测试（.github/workflows/ci.yml）——设备 FP 任务需 device runner，列为后续
- `deviceBaselines`（签名库字段）是**产品内** too_clean 数据源，与本文 QA 基线（scripts/baselines/）语义分离，勿混用
- HyperOS 类注入受限机型：核准走 instrument 路径（不依赖 UI 点击），已兼容
