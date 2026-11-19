# Proposal

## Why

scrcpy `--new-display`（3.x）能在设备上创建一块**物理屏幕不显示的虚拟显示器**，把目标 app 启动到该屏上远程操控——设备持有者看到的屏幕毫无游戏痕迹。这是 C12 屏幕共享域目前唯一列出的运行时缺口（COVERAGE_ANALYSIS 运行层表）。但「检测到虚拟显示器」本身不等于可疑：DeX、投屏（Chromecast/Miracast）、折叠屏副屏、开发者模拟屏都是**合法虚拟显示器**。因此必须**检测 + 分类**同时做——分类正是守住「假阴性可恢复、假阳性毁信任」纪律的唯一途径（对齐华为/小米两次 OEM 误报教训）。

## What Changes

- **C12 采集器新增虚拟显示器枚举**：`DisplayManager` 全量 Display + 自身 Activity 所在 displayId（≠DEFAULT_DISPLAY 即姿态信号）
- **五类分类器**：`shell-owned`（scrcpy vhd/adb 建屏）/ `container-app`（多开/VM 引擎建屏）/ `legit-cast-oem`（投屏/DeX/系统副屏）/ `dev-simulate`（开发者模拟副屏）/ `unknown`——类别进入 evidence 供回放
- **分级纪律**：首发全部 ≤C（weight-only）；`shell-owned` 与 ADB 姿态由规则引擎跨域合围升 B；任何类别升 B 前必须过 fp_certify 多厂商矩阵
- **fp_certify 合法状态矩阵新增一行**：「外接显示器/投屏激活」
- **文档同步**：DETECTION_CATALOG / COVERAGE_ANALYSIS（关闭 C12′ 缺口）/ README covered-targets

## Capabilities

### New Capabilities

（无）

### Modified Capabilities

- `screen-share-detect`: 新增 5 条 ADDED 需求——虚拟显示器枚举与分类、非默认屏姿态、合法类白名单纪律、分类证据可回放、shell 类与 ADB 姿态跨域合围

## Impact

- **代码**：`collectors/screen-share`（枚举+分类器+evidence 模型）、`core/rules`（跨域合围规则）、`compat/platform`（Display API 差异门控）
- **测试**：host 单测（伪造 DisplayManager 数据面）+ 干净模拟器零阳性验证 + fp_certify
- **文档**：DETECTION_CATALOG.md、COVERAGE_ANALYSIS.md（C12′ 行关闭）、README、FP_CERTIFICATION.md（矩阵行）
- **不触碰**：其余 12 个采集器（C1-C11 + C13）、签名库版本、CI、UI
