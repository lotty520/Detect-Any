# Tasks

> 排程约束：D4 取证（第 1 组）先行——分类特征表是第 2 组实现的输入；FP 认证（第 4 组）通过前不得 commit（AGENTS 强制协议）。

## 1. 实验室 ground truth（D4）

- [x] 1.1 `brew install scrcpy`，在既有 API35 模拟器以 `--new-display --start-app com.detectany.app` 真实建屏；`adb shell dumpsys display` 抓取虚拟 Display 的 id/名称/flags 真值，连同默认屏对照写入 `docs/calibration/virtual-displays.md`（含 scrcpy 3.x 建屏身份与命名结论）。验证：真值表可直接推导分类特征
- [x] 1.2 `adb shell settings put global overlay_display_devices 1080x1920/200` 开发者模拟屏取证；Chromecast/DeX 不可得——在 calibration 表标注「待真机矩阵」，FP 边界文档同步。验证：dev-simulate 特征实证、合法形态边界成文

## 2. C12 采集器扩展

- [x] 2.1 `collectors/screen-share` 新增 DisplayCollector 面：`DisplayManager.getDisplays()` 枚举 + 自身 displayId（ProbeCap 双路径，D5）+ `OVERLAY_DISPLAY_DEVICES` + MediaRouter 路由快照，全部进采集结果（不判级）。验证：干净模拟器（默认屏）枚举结果 = 仅 DEFAULT_DISPLAY，零 finding
- [x] 2.2 分类器实现（D2 逐屏特征匹配），类别与判定链写入 `Finding.raw`/`detail`（模型已支持，无需改 core/model）；**采集面注入式设计**（Display 枚举经构造注入，对齐 propGet directRead 教训——保 host 可测）；复用 `Category.SCREEN_SHARE`，分类特征表落 `data/signature`（或 calibration 载体，依 1.1 真值定）并 bump 版本。验证：host 单测覆盖五类各 ≥1 用例（注入伪造 Display 数据面，含多虚拟屏并存用例）+ unknown 兜底
- [x] 2.3 复合 B 级 finding：C12 内 `shell-owned 屏 + ADB 姿态同 scan 共现` → 产出一条 B 级「shell 建屏远程操控」复合 finding（不新增定性机制，走 ScoreModel 既有同域 B+C 共振）；其余类别单信号 C 级 weight-only。验证：单测含「legit-cast-oem 不产 B」「cast 在场不掩蔽并存的 shell 屏」反例

## 3. 验证与文档

- [x] 3.1 干净模拟器协议（AGENTS 强制）：装新 build 跑 L2，虚拟显示器域零 finding；再跑 1.1 的 scrcpy 会话复测，`shell-owned + ADB` 合围 finding 必须出现（TP 方向）。验证：两方向截图/导出证据
- [x] 3.2 文档同步：DETECTION_CATALOG 新条目（含分级依据）、COVERAGE_ANALYSIS 关闭 C12′ 缺口行 + 热力图屏幕共享行注记、README covered-targets 表、CAPABILITY_BOUNDARIES 补「合法虚拟屏矩阵进行中」。验证：四处数字/条目一致
- [x] 3.3 全量回归：`./gradlew`（全模块 host 测试，⚠️ 根任务 test 空操作须显式列模块）+ `:app:lintDebug`（NewApi=0——Display API 差异重点）+ `:app:verify16kAlignment`。验证：全绿

## 4. FP 认证

- [x] 4.1 FP_CERTIFICATION.md 合法状态矩阵新增「外接显示器/投屏激活」行（已就位，标注 legit 白名单空起步+矩阵核验前禁 B）。验证修正：fp_certify 面向干净真机，模拟器 L1 按设计拒绝（qemu=1 为真阳性）——模拟器侧零阳性由 3.1 干净模拟器协议覆盖（干净扫描与基线一致、零 virtual_display finding）
- [ ] 4.2 （真机可得时）多厂商矩阵跑一轮，unknown/legit 类零意外命中记录归档。验证：无新增机型基线外 finding —— **真机矩阵债务（2026-11-19 维护者决策后补）**：无真机接入，维护者指示先行 commit——本 change 按设计矩阵安全（单信号全 C、唯一 B 需 shell 建屏 × ADB 共现、legit 白名单置空），干净模拟器协议已 PASS；下次真机接入时补跑全矩阵并复核分级

## Workflow follow-up

- 第 4 组通过后按 AGENTS 惯例 commit（不自动 push），然后走 archive workflow（`screen-share-detect` delta 并入主 spec）
- 归档后 sync specs 并在 DETECTION_CATALOG 保持分级注记（首发全 C 的原因写明）
