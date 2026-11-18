# Proposal

## Why

仓库创建两周（2026-11-04），1 star / 0 fork——工程质量与 README 卖相已到位，瓶颈纯粹在分发：尚未在任何渠道曝光过。且推广前发现**分发面已经漂移**：代码已到 v0.4.2（versionCode 6）而 GitHub Releases 停在 v0.1.1（旧版 APK 是新访客唯一可下载的产物）；README 无下载入口；分享到社交平台无预览卡片图。带伤推广等于把最好奇的早期用户引流到过期的产物上，必须先修复再投放。

## What Changes

- **分发面修复（推广前置条件）**：
  - GitHub 仓库 description 从 `"Detect Anything"` 改为一句话卖点；补充 social preview 图（1280×640）
  - 发布 v0.4.2 GitHub Release：装配最新 debug-signed APK 资产 + 结构化 changelog
  - README 顶部新增 "Try it" 区块：直链最新 release APK + demo GIF（L2 扫描→评分仪表盘→Threats 下钻）
- **发布完备性契约（新能力 `release-hygiene`）**：把「每次发版必须产出什么、分发资产必须与哪个版本同步」固化为可校验行为，防止再次出现 code/release 版本漂移
- **渠道投放（一次性运营动作）**：酷安、V2EX（/go/android、/go/programmer）、Show HN、r/androiddev、awesome-android-security 等收录 PR、Android Weekly 提交
- **内容营销**：基于 AGENTS.md 中已沉淀的华为 58 分 / 小米 98 分 FP 取证过程撰写深度文章（中英双版），外平台发布、仓库内留底
- **社区对抗互动**：创建「深度隐藏挑战」pinned issue，把 root/hiding 社区的对抗测试转化为免费验证与流量

无代码、无 API、无依赖变更；不改任何现有 10 个能力契约的行为。

## Capabilities

### New Capabilities

- `release-hygiene`: 对外分发面的完备性与时效性契约——每个 tag release MUST 携带 APK 资产与 changelog；README 下载入口、demo GIF、social preview 等分发资产 MUST 与最新 release 版本同步，禁止出现过期产物持续对外暴露。

### Modified Capabilities

（无——现有 10 个 spec 均为产品检测运行时行为，本 change 不触碰。）

## Impact

- **仓库文件**：`README.md`（Try-it 区块 + GIF）、`docs/RUNBOOK.md`（发布装配清单补「分发面」一节，指向新契约）、新增 `docs/essays/`（文章仓库内留底）、`scripts/`（新增 release 资产核对脚本）
- **GitHub 平台操作（网页手动，本机 gh 未认证）**：description 修改、social preview 上传、v0.4.2 release 发布、pinned issue
- **外部平台（一次性）**：酷安 / V2EX / HN / Reddit / awesome lists / Android Weekly / 掘金·知乎·Medium
- **不受影响**：app 及全部 21 个模块的代码、签名库数据、CI 工作流
