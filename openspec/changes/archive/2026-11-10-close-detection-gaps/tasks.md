# Tasks

> 依据 design.md D1-D5 与 5 个能力 spec 拆解。特征库升级 v3→v4（30+ 条目）。

## 1. Frida 检测（instrumentation-detect）

- [x] 1.1 实现 D-Bus 协议探测器：全端口 TCP connect → 发送 `\0AUTH\r\n` → 响应模式匹配 Frida 特征。原生层实现（避免 libc PLT hook），验证单测含标准 Frida 响应向量与正常服务响应排除
- [x] 1.2 实现 maps/线程名扫描器：/proc/self/maps 扫 frida-agent/linjector/gadget 模式 + /proc/self/task/*/comm 扫 gum-js-loop/gmain/pool-frida，验证桩数据匹配与重命名排除
- [x] 1.3 实现 RWX 页特征扫描器：解析 maps 找连续 RWX 页 + 大小/对齐模式匹配 Frida agent 典型布局，验证干净设备零误报与注入桩检出
- [x] 1.4 创建 `collectors/instrument-probe` 模块，整合 D1-D3 探针 → Finding（instrumentation 分类），验证采集器输出三防线的独立证据项

## 2. 虚拟环境检测（virtual-env-detect）

- [x] 2.1 实现模拟器构建属性检测器：Build.FINGERPRINT/MODEL/PRODUCT/HARDWARE/BRAND 匹配特征库模式（generic/sdk_gphone/vbox/nox/goldfish/ttVM/ldplayer），验证特征库条目匹配与正常设备排除
- [x] 2.2 实现硬件痕迹检测器：/dev/qemu_pipe、/dev/vboxguest、传感器缺失、基带缺失检测，验证模拟器环境检出与真机零误报
- [x] 2.3 实现 GL 渲染器指纹：通过 OpenGL ES 查询 GL_RENDERER/GL_VENDOR 并匹配模拟器字符串，验证 GPU 调用不崩溃（API 24 兼容）
- [x] 2.4 实现容器检测器：data-dir 路径异常 + getPackageCodePath vs sourceDir 不匹配 + 已知容器包名匹配，验证 Parallel Space/VMOS 场景桩测试
- [x] 2.5 创建 `collectors/virtual-env` 模块，整合 2.1-2.4 → Finding（virtual_env/emulator 分类），验证采集器输出四维独立证据项

## 3. 行为异常检测（behavioral-anomaly）

- [x] 3.1 实现 VPN/代理检测：ConnectivityManager.hasTransport(TRANSPORT_VPN) + System.getProperty(http.proxyHost)，验证桩测试与干净设备零误报
- [x] 3.2 实现无障碍服务枚举：Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES 解析 + 特征库已知自动化包名匹配，验证已知包(B)与未知包(C)分级
- [x] 3.3 实现多时钟一致性检测：100ms 窗口采样 elapsedRealtimeNanos/nanoTime/currentTimeMillis 三源差值，验证正常漂移 <5ms 与加速桩 >50ms 检出
- [x] 3.4 实现 GPS mock 检测：Location.isMock()/isFromMockProvider() 检查，验证桩测试
  > 实际交付路线调整（2026-11-10）：运行时 isMock 需定位权限（隐私敏感不申请），改为伪造定位应用包指纹（特征库 v8 app.fakegps），Camera2 特征探测同因 FP 风险缓办
- [x] 3.5 创建 `collectors/behavior-check` 模块，整合 3.1-3.4 → Finding（network_mitm/automation/speed_hack/gps_spoof 分类）

## 4. 特征库 v4 + 规则扩展

- [x] 4.1 特征库升级 v3→v4：新增 30+ 条目——内存编辑器（guardian.aurora、ceserver、八门/烧饼/葫芦侠）、脚本自动化（AutoX.js、EasyClick、按键精灵、MacroDroid）、VM/沙箱（VMOS、光速、X8、Parallel Space）、IAP（Lucky Patcher）、模拟器构建属性模式、无障碍自动化包名清单
- [x] 4.2 规则引擎扩展：新增 rule.frida、rule.emulator、rule.virtual_env、rule.network_mitm、rule.automation、rule.speed_hack、rule.gps_spoof + 对应 matchRuleIdPrefixes
- [x] 4.3 评分模型扩展：Finding.Category 枚举新增 INSTRUMENTATION/VIRTUAL_ENV/EMULATOR/NETWORK_MITM/AUTOMATION/SPEED_HACK/GPS_SPOOF + 权重设定
- [x] 4.4 `<queries>` 清单扩展：新增 30+ 作弊工具包名

## 4.5 屏幕共享/远程控制检测（screen-share-detect）

- [x] 4.5.1 实现 ADB 会话检测：ADB_ENABLED + adb_wifi_enabled + BATTERY_PLUGGED_USB 三条件组合，验证三条件同时满足(B)与单独满足(C)分级
- [x] 4.5.2 实现 scrcpy 特征检测：/proc/net/unix 扫 scrcpy_ 前缀 + /proc/*/cmdline 扫 com.genymobile.scrcpy.Server + InputDevice 枚举找 "scrcpy" 设备名，验证三路独立 A 级
- [x] 4.5.3 实现远程桌面包指纹：特征库 v4 新增 AnyDesk/TeamViewer×3/AirDroid×2/Vysor/ChromeRemoteDesktop/SmartMirroring/RedFinger×2/DuoDuoYun 包名 + 已知无障碍服务组件名，验证安装+无障碍(B)与仅安装(C)
- [x] 4.5.4 实现输入注入取证：MotionEvent.FLAG_IS_ACCESSIBILITY_EVENT + InputDevice.isVirtual() + deviceId==0 检测（需在 UI 层 hook onTouchEvent），验证合成事件桩测试
  > 部分交付：isVirtual+deviceId 已落地 C12 checkInputDevices；MotionEvent 标志位需持续监听（G6，COVERAGE_ANALYSIS 在案缓办）
- [x] 4.5.5 实现屏幕录制检测（API 34+）：registerScreenCaptureCallback + addScreenRecordingCallback 门控到 API ≥34；API < 34 无 Finding
- [x] 4.5.6 实现 overlay/tapjacking 检测：canDrawOverlays（含已知过滤器白名单）+ FLAG_WINDOW_IS_OBSCURED + mod menu 原生库指纹（KittyMemory/Dobby），验证过滤器(C)与注入(A)分级
- [x] 4.5.7 创建 `collectors/screen-share` 模块，整合 4.5.1-4.5.6 → Finding（screen_share/remote_control/overlay_injection 分类）

## 5. 引擎集成 + 回归

- [x] 5.1 ScanOrchestrator 接入三个新采集器（并行引擎自动调度）
- [x] 5.2 模拟器环境全套冒烟：模拟器上跑 L2 → 模拟器/virtual_env 域应命中；真机上跑 L2 → 新域零误报
- [x] 5.3 性能验证：新采集器并入后 L2 总耗时 ≤1.5s（Pixel 8）
- [x] 5.4 全量回归：主机单测 + 双设备设备测试 + 16KB 门禁
- [x] 5.5 更新 docs/DETECTION_CATALOG.md（58→90+ 项）与 docs/CHEATING_THREAT_MODEL.md 覆盖率
