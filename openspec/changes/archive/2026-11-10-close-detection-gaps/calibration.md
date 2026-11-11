# 全面校准报告（close-detection-gaps 全量核对）

> 在 accuracy-review.md 基础上，逐项核对全部 6 个 spec · 26 个 requirements · 100+ 监测项的：
> ① 实施可行性 ② 置信等级准确度 ③ 边界条件完备性 ④ 与既有能力的重叠/冲突

---

## 一、实施可行性审查（6 项不可行/降级）

| # | Spec 条目 | 问题 | 判定 |
|---|---|---|---|
| F1 | instrumentation-detect / Il2Cpp hook detection | **独立检测 APP 不可行**：我们自己的进程没有 libil2cpp.so（那是 Unity 游戏的库）。Il2Cpp 检测只能在嵌入目标游戏的 SDK 模式下工作，独立模式下无检测面。 | ⛔ **从 spec 中移除**，改为「SDK 模式预留项」 |
| F2 | screen-share-detect / `/proc/*/cmdline` 扫 scrcpy-server | **无权限**：非 root app 无法读取其他进程的 `/proc/[pid]/cmdline`。scrcpy-server 是 shell uid 进程，我们 app 的 uid 看不到。 | ⛔ **从 spec 中移除**，仅保留 socket + HID 检测 |
| F3 | behavioral-anomaly / Multi-clock consistency (1s window) | **时延冲突**：L2 预算 ≤1.5s，1 秒时钟测量窗口占 67%。且在扫描期间保持 CPU 自旋会耗电并可能触发 thermal throttling。 | ⚠️ **降级为后台异步**：扫描触发但结果延迟 1s 返回，不阻塞主扫描流程 |
| F4 | screen-share-detect / Input injection forensics | **非扫描时检测**：`FLAG_IS_ACCESSIBILITY_EVENT` 需要收到 touch 事件。独立检测 APP 在后台扫描时不接收触摸。只有用户主动交互时才能检测。 | ⚠️ **改为被动监听模式**：注册 `onTouchEvent` 拦截器，在用户操作时积累证据，而非扫描时一次性检测 |
| F5 | screen-share-detect / Screen recording API (34/35) | **非扫描时检测**：`registerScreenCaptureCallback` / `addScreenRecordingCallback` 是持续回调，需 Activity 生命周期内注册。一次性扫描无法获取。 | ⚠️ **改为持续监控模式**：MainActivity onCreate 时注册回调，Finding 实时上报 |
| F6 | virtual-env-detect / VirtualDisplay 枚举跨应用 | **不可行**：`DisplayManager.getDisplays()` 只能看到公开显示器。其他应用（如 scrcpy `--new-display`）创建的 VirtualDisplay 对我们不可见。 | ⛔ **从 spec 中删除 VirtualDisplay 枚举依赖**；仅用 `getDisplays(PRESENTATION)` 检测外接显示器 |

---

## 二、置信等级终审（逐项校准，含理由）

### instrumentation-detect（Frida 检测）

| 检测项 | Spec 级 | 校准级 | 校准理由 |
|---|---|---|---|
| D-Bus 协议探测 | B | **B** | 可靠但受限于端口扫描范围；hluda 重命名后协议不变 ✓ |
| maps 扫 frida-agent/linjector | B | **B** | 字符串可被重命名；作为第一层快信号合理 |
| 线程名 gum-js-loop | B | **B** | Frida 特有；gmain 单独不出（GLib 共用） |
| 线程名 gmain 单独 | — | **不产出** | GLib 主循环合法使用 |
| RWX 页（连续+特定大小） | A | **B** | JIT/V8 合法使用 RWX；需与 maps 字符串共振才 A |
| RWX + maps 字符串命中 | — | **A** | 双信号共振 = 物理不变量级 |
| Il2Cpp 检测 | B | **SDK-only** | 独立模式不可行 |

### virtual-env-detect（模拟器/VM 检测）

| 检测项 | Spec 级 | 校准级 | 校准理由 |
|---|---|---|---|
| Build.FINGERPRINT 含 generic/goldfish | B | **B** | 标准模拟器可靠；定制 ROM 可能含 generic |
| ro.kernel.qemu=1 | 未列出 | **A** | qemu 标志无法伪装 |
| /dev/qemu_pipe, /dev/vboxguest 存在 | A | **A** | 硬件设备节点，不可软件伪造 |
| 传感器全部缺失 | 未明确 | **C**（需共振） | 低端设备合法缺失 |
| 基带缺失（hasSystemFeature 检查） | 未明确 | **C**（需共振） | WiFi-only 平板合法 |
| Build.CPU_ABI=ARM + cpuinfo=x86 | A | **A** | 架构声明不一致 = 确定模拟器 |
| Build.CPU_ABI=x86 + 合法 x86 设备 | A | **不产出** | Chromebook 等合法 |
| data-dir 路径异常（user=0） | B | **B** | 主用户下路径异常 |
| data-dir 路径异常（user≥10） | B | **不产出** | Work Profile 合法 |
| GL "Translator"/"VBox"/"Bluestacks" | B | **B** | 仅模拟器出现 |
| GL "SwiftShader" | B | **C** | Android Go 低端设备合法 |
| MediaRouter 外接路由 | 未列出 | **C** | Miracast/HDMI 合法投屏 |

### behavioral-anomaly（行为异常）

| 检测项 | Spec 级 | 校准级 | 校准理由 |
|---|---|---|---|
| VPN 存在 | B | **C** | 企业/隐私 VPN 常态 |
| VPN + 已知 MITM CA 证书 | — | **B** | 双信号共振 |
| http.proxyHost 非空 | C | **C** | 企业代理合法 |
| 无障碍已知自动化包 | B | **B** | AutoX.js/EasyClick 等 |
| 无障碍未知服务 | C | **C**（不参与定性） | TalkBack 等白名单外 |
| 时钟差 >100ms/1s (BOOTTIME vs MONOTONIC) | B | **B**（异步执行） | 不阻塞扫描流程 |
| Location.isMock()=true | C | **C** | 弱信号；hook 可去除 flag |

### screen-share-detect（屏幕共享/远程控制）

| 检测项 | Spec 级 | 校准级 | 校准理由 |
|---|---|---|---|
| /proc/net/unix 含 scrcpy_ socket | A | **A** | scrcpy 专属特征 |
| InputDevice 名含 "scrcpy" | A | **A** | scrcpy 专属 |
| ~~app_process cmdline 扫描~~ | A | **⛔ 移除** | 无权限读其他进程 cmdline |
| ADB + USB + 应用前台 | B | **B** | 三条件组合 |
| ADB 单独 | C | **C** | 开发者常用 |
| adb_wifi_enabled | C | **C** | 合法用途 |
| 远程桌面包 + 无障碍启用 | B | **B** | 双信号 |
| 远程桌面包（无障碍未启用） | C | **C** | 合法远程协助 |
| FLAG_IS_ACCESSIBILITY_EVENT | B | **B**（被动监听） | 需用户交互时才能检测 |
| InputDevice.isVirtual() | B | **B**（被动监听） | 同上 |
| API 35 录制回调 | C | **C**（持续监控） | 需 Activity 生命周期 |
| overlay 权限 + 触摸遮蔽 | B | **B** | 双信号 |
| overlay 权限单独 | C | **C** | 过滤器/悬浮球合法 |
| KittyMemory/Dobby maps 命中 | A | **A** | 注入证据（限自进程） |
| 云手机电池/传感器 | C | **C** | 弱信号 |

---

## 三、与既有能力的重叠/冲突检查

| 新检测项 | 既有检测项 | 关系 | 处理 |
|---|---|---|---|
| RWX 页扫描 | C6 内存映射已有 RWX 自探针 | **互补**：C6 检测「maps 被篡改」，新项检测「Frida 注入页特征」 | 扩展 C6 而非新建 |
| maps 字符串扫 frida-agent | C6 mem.known_path（lspd/zygisk） | **同机制**：都是 maps 字符串匹配 | 在 C6 特征库加 frida 关键词，无需新采集器 |
| 线程名扫描 | 无既有对应 | **新增** | 归入 instrumentation-detect 新模块 |
| 无障碍服务枚举 | C5 应用指纹已有 queries 枚举 | **互补**：C5 查包安装，新项查服务启用状态 | 共享 PackageManager 调用结果 |
| 远程桌面包名 | C5 应用指纹 | **同机制**：包名匹配 | 在 C5 特征库加远程桌面条目 |
| 模拟器 Build 属性 | C3 属性快照已有 | **同机制**：属性值匹配 | 在 C3 特征库加模拟器模式 |
| 容器路径检测 | C1 路径探测已有 | **互补**：C1 查特征路径，新项查自身 data-dir 异常 | 归入 virtual-env 模块 |

**结论**：maps 字符串扫描和包名匹配应**扩展现有 C5/C6** 而非新建采集器，避免功能重复和采集时序不一致。仅在确实需要新机制（线程名、D-Bus、传感器、时钟）时才新建模块。

---

## 四、边界条件完备性

### API 版本边界

| 检测项 | 最低 API | 备注 |
|---|---|---|
| D-Bus 端口探测 | 24 | 无版本限制 |
| InputDevice 枚举 | 24 | 无版本限制 |
| Settings.canDrawOverlays | 23 | OK |
| MotionEvent.FLAG_IS_ACCESSIBILITY_EVENT | 16 | OK |
| MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED | 29 | API 24-28 用旧 flag |
| registerScreenCaptureCallback | 34 | API < 34 不产出 |
| addScreenRecordingCallback | 35 | API < 35 不产出 |
| Location.isMock() | 31 | API < 31 用 isFromMockProvider() |
| ConnectivityManager.hasTransport(VPN) | 21 | OK |
| Settings.Global.ADB_ENABLED | 24 | 公开 API |
| Settings.Global "adb_wifi_enabled" | 30 | Android 11+，hidden key by string |
| SensorManager.getSensorList | 24 | OK |
| PackageManager.hasSystemFeature(TELEPHONY) | 24 | OK |

### 设备类型边界

| 设备类型 | 影响的检测项 | 处理 |
|---|---|---|
| WiFi-only 平板 | 基带缺失 → 误报模拟器 | C 级 + 需共振 |
| Android Go 低端机 | SwiftShader → 误报模拟器 | 降 C 级 |
| 无陀螺仪手机 | 传感器缺失 → 误报模拟器 | C 级 + 需共振 |
| Chromebook x86 | CPU x86 → 误报模拟器 | CPU_ABI 交叉验证 |
| 企业 Work Profile | data-dir 路径异常 → 误报容器 | user ≥ 10 不产出 |
| Instant App | 沙箱路径 → 可能误报容器 | 检查 isInstantApp |
| Samsung DeX | UI_MODE_TYPE_DESK → 外接显示器 | 不产出（合法投屏） |
| 视障用户 TalkBack | 无障碍枚举 → 误报自动化 | 白名单 com.google.android.marvin.* |

---

## 五、最终修正的 spec 修改指令

| Spec | 操作 | 详情 |
|---|---|---|
| instrumentation-detect | **移除** | Il2Cpp requirement（SDK 模式预留项，独立模式不可行） |
| screen-share-detect | **移除** | app_process cmdline 扫描（无权限）；VirtualDisplay 跨应用枚举（不可见） |
| screen-share-detect | **标注** | Input injection → 被动监听模式；Screen recording → 持续监控模式 |
| behavioral-anomaly | **标注** | Multi-clock → 异步后台执行（不阻塞扫描流程） |
| virtual-env-detect | **新增** | ro.kernel.qemu=1 作为 A 级信号 |
| virtual-env-detect | **新增** | MediaRouter 外接路由检测（C 级） |
| virtual-env-detect | **标注** | 传感器/基带/SwiftShader → C 级需共振；CPU x86 → 需 CPU_ABI 交叉 |
| 全部 | **合并** | maps frida 字符串 + 远程桌面/作弊工具包名 → 扩展 C5/C6 特征库（不新建模块） |
