# Design

## Context

- 代码 v0.4.2（versionCode 6），GitHub Releases 停在 v0.1.1（debug-signed APK）；README 已英文化但无下载入口；12 个 topics 已配置；本机 `gh` 未认证（平台侧操作走网页手动）
- `docs/RUNBOOK.md` 的「发布装配清单」定义了 release 构建的自保护 XOR 常量替换与 attestation 双根装配——该流程目前手工、未自动化
- `scripts/` 已有 shell 脚本惯例（fp_certify.sh / tp_certify.sh）；GitHub 公开 API 匿名可用（60 req/h）
- 素材沉淀：AGENTS.md FP 事故表（华为 58 分 / 小米 98 分完整取证）、`docs/FP_CERTIFICATION.md`、`docs/DETECTION_ACCURACY.md`

## Goals / Non-Goals

**Goals:**
- 分发面修复到「任何时刻访客拿到最新一致产物」的稳态，并以脚本可校验
- 一轮完整渠道投放 + 一篇可长期引流的技术文章 + 一个持续运转的对抗反馈入口

**Non-Goals:**
- release-signed APK 与装配清单自动化（XOR 常量替换、双根 PEM）——独立后续 change，本 change 沿用 debug-signed（与 v0.1.1 及 fp_certify 基线一致）
- 不新增 CI workflow（校验脚本先手动跑，进 CI 另议）
- 不做 F-Droid / Play 商店上架

## Decisions

### D1. v0.4.2 APK 沿用 debug-signed

装配清单要求 release 构建按产物替换 `SIG_A/SIG_B`、`CRC_A/CRC_B`，流程未自动化前强上会引入自保护失效风险。debug-signed 与现有认证基线（fp_certify 在 debug 产物上跑）一致。Release notes 明示签名形态并公示 SHA-256；release-signed 列入 roadmap issue。

### D2. 校验脚本 `scripts/check_release_hygiene.sh`（匿名 API、无 gh 依赖）

检查四项：①最新 git tag = latest release tag；②latest release 含 APK 资产；③notes 中 SHA-256 与 asset digest 一致；④README 下载入口为 `releases/latest` 形式。①-③ 违反退出非零（对应 spec 前三条）；GIF 版本标记不一致仅 WARN（对应演示资产条款）。单次 ≤4 个 API 请求，匿名限流足够。

### D3. APK 资产名保留版本号，README 入口链到 `releases/latest` 页面

`Detect-Any-v0.4.2-debug-signed.apk` 保留版本号利于归档与指纹一一对应；GitHub 的 `releases/latest/download/<file>` 需要跨版本固定文件名，与其牺牲归档可读性，不如 README 直接链 `releases/latest` 页面——新版本发布后页面自动指向新 APK，满足 spec「入口自动跟进」条款。

### D4. Demo GIF 在干净模拟器录制，只展示真实信号

录制脚本：Start Scan (L2) → 仪表盘动画 → Threats 下钻一条 qemu 属性证据。`adb screenrecord` → ffmpeg 转 GIF（宽 480，<10MB），存 `screenshots/demo-scan-v18.gif`。**禁止**为演示效果植入伪造 findings——展示的必须是干净模拟器的真实检出（qemu/sdk_gphone），与诚实边界原则一致。

### D5. 文章双版留底仓库，素材以 docs 为唯一事实源

`docs/essays/oem-fp-forensics.zh-CN.md` + `.en.md` 仓库留底，外平台（掘金/知乎、Medium/dev.to）发布。文中每个技术论断（华为六对属性为何全部降 C、小米 HyperOS overlayfs 形态、solist 快照顺序竞态）必须能在 AGENTS.md / FP_CERTIFICATION.md / DETECTION_ACCURACY.md 中溯源，不新造结论。

### D6. 投放顺序强约束：仓库侧全部完成 → 渠道投放

外部投放不可撤回，任何「带伤曝光」（旧 release、无下载入口）都会把首批流量变成差评。顺序：分发面修复 + v0.4.2 release → 校验脚本通过 → 酷安 + V2EX（国内晚间高峰）→ 下周中 Show HN（美东周二-周四上午，Show HN 首发规则、不拉票、作者守帖答疑）→ r/androiddev（注意自推比例 9:1）→ awesome lists PR + Android Weekly 提交。素材差异化：酷安走「扫你自己手机」体验向；HN 走工程诚实向（FP 事故全公开、142 项证据分级）。

### D7. 深度隐藏挑战 pinned issue 作为对抗反馈飞轮

Issue 模板字段：机型/ROM/root 方案/隐藏栈版本 + L2 结果截图 + 检出与漏检清单。只收「干净基线 + 深度隐藏」场景；每个报告按 P 级评估转 feature（漏检）或 FP issue（误报）。命名 `Deep-Hiding Challenge`，置顶。

## Risks / Trade-offs

- [投放放大旧产物流量] → D6 顺序强约束：校验脚本通过前不投放
- [debug-signed 被安全社区质疑] → release notes 明示 + SHA-256 公示 + roadmap issue 兑现路径
- [HN/Reddit 自推违规删帖] → Show HN 首发不拉票；r/androiddev 以技术讨论帖形式参与
- [root 社区天然敌意（检测 vs 隐藏对立）] → 措辞走「猫鼠对抗、质量互证」中性框架，强调 Apache-2.0 开源可审计；D7 把对抗转为免费众测
- [GIF 超 GitHub 渲染上限] → 480 宽 + ffmpeg palette 压缩，超限降帧
- [匿名 API 限流] → 脚本单次 ≤4 请求；被限流时报错退出而非误报 PASS

## Migration Plan

无代码迁移。发布顺序即回滚策略：仓库侧改动（README/脚本/docs）全部可 git revert；v0.4.2 release 若有误可在投放前删除重发；外部平台帖子不可撤回——因此置于最后。

## Open Questions

- 酷安发布账号是否已有（无则需先注册/养号，可能影响 D6 中酷安档期）——不阻塞其余任务
- 文章中文版掘金独家（流量倾斜）vs 掘金+知乎同步（覆盖面）——发布时再定，不影响写作任务
