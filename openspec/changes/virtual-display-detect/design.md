# Design

## Context

- C12 现有 scrcpy 三向量（`scrcpy_` socket / HID 设备名 / ADB 三条件）均为**进程/通道侧**特征；`--new-display` 的本质特征——「app 运行在非物理屏上」——目前零采集（COVERAGE_ANALYSIS 运行层唯一 C12 缺口行）
- 现有 spec `screen-share-detect` 6 条需求（ADB 姿态 C、scrcpy 工件 A、远程桌面 B/C、注入取证 B、录屏 C、overlay B/C），本 change 以 ADDED 挂靠
- 分级纪律基线：OEM 形态多厂商矩阵验证前不得 B 级（华为/小米两次教训成文于 FP_CERTIFICATION L3 准入）
- minSdk 24：DisplayManager 公开 API（API 17+）全覆盖，无新约束；`Context.getDisplayId()`（API 30+）等新式入口需 ProbeCap 门控取旧式等价（`WindowManager.getDefaultDisplay()`）

## Goals / Non-Goals

**Goals:**
- 「app 在非默认屏运行」成为 C12 第四防线，且按建屏者分类，合法形态与可疑形态分流定级
- 分类特征数据化（新 OEM/投屏形态走特征库更新，不动代码）

**Non-Goals:**
- 不做 hidden API 反射（`Display.TYPE_*`/`DisplayInfo.ownerUid`——非 SDK 接口限制 + 稳定性差）
- 不做 DeX/折叠屏真机矩阵（设备不可得，见 Open Questions；以合法状态矩阵行 + dev-simulate 形态代替首发验证）
- 不做 G6 触摸行为分析（另案）；不做虚拟屏内容级取证

## Decisions

### D1. 采集面只走公开 API

`DisplayManager.getDisplays()`（枚举）、`Display.getName()/getFlags()/getDisplayId()`（属性）、`Settings.Global.getString(..., "overlay_display_devices")`（开发者模拟屏标志——**注意 `OVERLAY_DISPLAY_DEVICES` 常量本身是 hidden API**，必须用字符串键读全局设置，不得引用常量）、`MediaRouter` 路由（投屏归因）。ownerUid 不可得——以「名称 + flags + 路由 + ADB 会话上下文」四特征分类替代 owner 直判。

### D2. 分类器：逐 Display 特征匹配（非全局首命中）

对**每个**非默认 Display 独立执行特征匹配，判定链入 evidence：`legit-cast-oem`（MediaRouter 活跃路由命中**该屏** / 已知系统副屏名称模式）→ `shell-owned`（该屏名称命中 scrcpy/vhd 模式，或无法归因屏 + 同 scan ADB 会话在场）→ `container-app`（名称/特征命中多开引擎建屏模式，与 C10/C5 特征库交叉）→ `dev-simulate`（overlay_display_devices 非空）→ `unknown`。**多虚拟屏并存时逐屏独立归类**——投屏会话在场不得掩蔽同 scan 的 shell 建屏（「先命中 cast 就全判合法」是错误实现）。`shell-owned` 的 ADB 上下文判据只是分类辅助，定性语义对齐「ADB 是姿态不是定性依据」的 2026-11-12 修订。

### D3. 分级纪律：首发全 C，复合才 B，矩阵后议

单信号（虚拟显示器本身）首发全 C。唯一 B 路径是**复合 finding**：`shell-owned` 屏与 ADB 姿态同 scan 共现（两族信号均由 C12 采集，可就地合成）→ 一条 B 级「shell 建屏远程操控」。定性不新增机制——复用 `ScoreModel` 既有共振（同域 B+C 即定性 / 任意两条 B，`ScoreModel.kt` 2026-11-06 校准注释），两族信号在 `framework ?: category` 域键下同属 SCREEN_SHARE。任何类别的单信号升级冻结至 fp_certify 矩阵 ≥2 厂商核验后另案处理。

### D4. 实验室 ground truth：模拟器 + 真实 scrcpy 会话

本机已有 API35 模拟器；`brew install scrcpy` 后以 `--new-display` 真实建屏，`adb shell dumpsys display` 抓取该 Display 的名称/flags/id 真值（dumpsys 是取证手段，app 内不可用——只用于标定分类特征，特征本身必须是 app 可观测面）。开发者模拟屏用 OVERLAY_DISPLAY_DEVICES 真开验证。**scrcpy 建屏的 Display 名称是否含 "scrcpy"、flags 形态如何，是本 change 首个要实证的未知数**——若名称不可区分，分类退化为「unknown 屏 + ADB 上下文」路线，spec 不受影响（unknown 类已覆盖）。

### D5. ProbeCap 门控 Display API 差异

`Context.getDisplayId()`（30+）与旧式 `WindowManager.getDefaultDisplay().getDisplayId()`（17+）双路径；`Display.getFlags()` 个别 flag 常量随 API 引入（如 29+ 系统装饰 flag）——枚举输出原样记录 flags int，判定特征做能力掩码，不做版本硬断言。

## Risks / Trade-offs

- [scrcpy Display 名称不可区分 → shell-owned 类无法命名归因] → D4 实验先行；退化为 unknown+ADB 跨域路线，检测能力不减只是分类粒度降
- [OEM 副屏/DeX 形态多样导致 unknown 误伤合法用户] → 首发全 C weight-only 不定性；fp_certify 矩阵行 + 机型基线渐进吸收；AGENTS 诚实边界文档化
- [MediaRouter API 老化（deprecated）] → 仅用于只读路由枚举，Android 7-16 全段实测覆盖于设备矩阵；异常时该特征静默缺席（分类降级，不 BLOCKED）
- [Display 枚举在部分 ROM 返回滞后/缓存] → 与 solist/maps 竞态教训对齐：单次快照采集，不做跨快照交叉推断，避免自造竞态

## Migration Plan

纯增量：C12 采集器新增输出项，规则引擎新增一条跨域规则；无既有 finding 语义变更，无数据迁移。回滚 = revert 单 commit。

## Open Questions

- DeX/折叠屏真机矩阵可得性（决定 `legit-cast-oem` 白名单首发覆盖度与后续 B 级议题时间点）——不阻塞首发（全 C）
- scrcpy 虚拟屏名称/flags 真值（D4 首个任务实证）——影响分类粒度，不影响 spec 形态
