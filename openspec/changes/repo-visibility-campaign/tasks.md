# Tasks

> 顺序强约束（design D6）：第 1、2 组全部完成并通过校验脚本后，才启动第 4 组外部投放。
> 标注「网页手动」的任务需在 GitHub/外部平台网页操作（本机 gh 未认证），产出以链接/截图为验收物。

## 1. 分发面修复（仓库侧）

- [x] 1.1 编写 `scripts/check_release_hygiene.sh`：匿名 GitHub API 检查四项（最新 tag=latest release tag、latest release 含 APK 资产、notes 含 SHA-256 且与 asset digest 一致、README 下载入口为 `releases/latest` 形式）+ GIF 版本标记 WARN。验证：`bash -n` 通过；在当前仓库运行 MUST 因 release 停在 v0.1.1 而非零退出（脚本阴性对照）
- [x] 1.2 干净模拟器（emulator-5554）录制 demo GIF：Start Scan (L2) → 仪表盘动画 → Threats 下钻一条 qemu 属性证据，`adb screenrecord` + ffmpeg 转 GIF（宽 480、<10MB），存 `screenshots/demo-scan-v18.gif`。验证：GIF 展示的 findings 仅为模拟器真实信号（qemu/sdk_gphone 族），无植入痕迹
- [x] 1.3 README 新增 "Try it" 区块：置于 badges 与 Screenshots 之间，含下载徽章直链 `releases/latest` 页面 + 1.2 的 GIF + 一句话说明（Android 7.0+、无需 root）。验证：GitHub 渲染后 GIF 正常播放、链接可达
- [x] 1.4 制作 social preview（1280×640 PNG，v18 深色扫描页 + 标题排版），仓库留底 `screenshots/social-preview.png`。验证：尺寸/格式正确，交付后由维护者网页上传（网页手动）

## 2. v0.4.2 Release（补齐漂移）

- [x] 2.1 构建 v0.4.2 APK：`./gradlew :app:assembleDebug`（16KB 门禁随 package 自动执行并通过），计算 SHA-256，按 D3 命名 `Detect-Any-v0.4.2-debug-signed.apk`。验证：`verify16kAlignment` PASS 且本地安装可跑 L2
- [x] 2.2 起草 changelog：从 `git log v0.1.1..HEAD` 整理，按新增检测 / FP 修复 / 其他变更三组，标注签名形态说明与 SHA-256。验证：每条变更可对应一个 commit
- [ ] 2.3 GitHub 发布 v0.4.2 Release（网页手动）：APK 资产 + 2.2 notes。验收物：release 页 URL
- [ ] 2.4 复跑 `scripts/check_release_hygiene.sh`。验证：退出码 0（spec 全部条款达成）

## 3. 内容与社区入口

- [x] 3.1 撰写文章 `docs/essays/oem-fp-forensics.md`（用户指示「全部使用英文」——原中文版/英文双版合并为英文单版）：华为六对属性降 C 取证、小米 HyperOS overlayfs 形态、solist 快照顺序竞态。验证：每个技术论断在 AGENTS.md / docs/FP_CERTIFICATION.md / docs/DETECTION_ACCURACY.md 中可溯源，文末含仓库链接
- [x] 3.2 （已合并入 3.1——单英文版，per 用户指示）
- [ ] 3.3 创建「Deep-Hiding Challenge」pinned issue（网页手动）：模板字段机型/ROM/root 方案/隐藏栈/L2 截图/检出与漏检，声明只收干净基线+深度隐藏场景。验收物：issue URL，并在 `CONTRIBUTING.md` 挂链接
- [ ] 3.4 创建 roadmap issue：release-signed APK 与发布装配清单自动化（承接 D1，网页手动）。验收物：issue URL

## 4. 渠道投放（外部、不可撤回；前置：第 2.4 通过）

- [ ] 4.1 酷安动态（体验向：「扫扫你自己的手机」+ APK 下载引导 + 对比表截图）。验收物：动态链接；发布后 24h 记录评论中的机型反馈
- [ ] 4.2 V2EX 分享帖（/go/programmer 或 /go/android，工程叙事：A/B/C 分级 + 诚实边界文档）。验收物：帖子链接
- [ ] 4.3 Show HN（美东周二-周四上午 9-11 点，`Show HN: Detect-Any – ...` 首发标题，守帖答疑≥24h，不拉票）。验收物：帖子链接
- [ ] 4.4 r/androiddev 技术帖（以 FP 工程实践切入，遵守自推比例）。验收物：帖子链接
- [ ] 4.5 向 awesome-android-security（及相邻 awesome 列表）提收录 PR。验收物：PR 链接
- [ ] 4.6 Android Weekly / AndroidDevWeekly 提交（article 或 library 条目，链接 3.2 英文文章或仓库）。验收物：提交确认

## 5. 集成核验

- [ ] 5.1 终态核验：`scripts/check_release_hygiene.sh` 退出码 0；README 渲染检查（GIF 播放、Try-it 链接 200）；4.x 全部验收物链接 curl 可达；`openspec validate --strict` 通过

## Workflow follow-up

- 归档前确认 4.x 外部投放链接已在 tasks 勾选并附 URL
- 运行 archive workflow：`openspec archive` 将 `release-hygiene` delta 并入主 specs，随后 sync specs
- 归档后按 AGENTS.md 惯例提交（不自动 push）
