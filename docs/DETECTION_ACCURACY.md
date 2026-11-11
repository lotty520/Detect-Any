# 检测项准确性清单（2026-11-10 全量定级）

> 分级标准：**双验证**=真阳性+干净侧均有实证；**TP侧**=仅真阳性验证；
> **FP侧**=仅干净不误报验证（TP 未见过）；**未验证**=两侧均无实证；
> **不可达**=平台门控（现代 Android）；**未接线**=建成未接入生产；
> **策展**=机会型条目（宽松权限环境才可能命中，死探测为设计行为）。

## 一、真阳性已实证（TP 侧证据链）

| 检测项 | 证据 |
|---|---|
| prop.verified_boot_lie (A) | P8 深隐藏对抗组，2026-11-09 起多次稳定命中 |
| prop.zygisk_denylists (B) | P8 对抗组稳定命中 |
| app.sukisu / app.apatch (B) | P8 双 manager 包指纹命中（2026-11-10） |
| automation.unknown.* (C) | P8 三个非白名单无障碍服务命中（含 AnyDesk 变体兜底） |
| screenshare.adb_session / adb_enabled | P8 + 模拟器双环境命中 |
| app.fakecamera (C) | DRVCAM 官方 APK 正向验证（2026-11-10 装入→命中→卸载回落） |
| integrity.prologue.* (A) | 2026-11-06 P8 5×A 级真命中（定向 hook 被字节比对捕获） |
| emulator.* 族（qemu/build/hw/gl） | 干净模拟器 7 威胁即真阳性（模拟器确实是模拟器） |
| **frida.maps / frida.thread 族（B）** | **2026-11-11 云端式验证**：模拟器 adb root + frida-server 17.26.2 注入 app 进程 → 3×B 命中（frida-agent maps + gum-js-loop/gmain 线程名 + 第三防线） |
| **screenshare.scrcpy_hid（A）** | **2026-11-11 云端式验证**：scrcpy 5.0.1 uhid 键鼠模式 → InputDevice "scrcpy"×2 → A 级命中 |
| **screenshare.scrcpy_socket（A）** | permissive 模式实证（abstract socket @scrcpy_XXX 可见）；Enforcing API35 走门控不可达——与 ProbeCap 语义一致 |
| **path 族 6 族（C）** | permissive 模式实证：mkdir /data/adb/{ksu,tricky_store,ap,lspd,modules,pif.json} + chmod 755 → KernelSU/APatch(×2)/ZygiskNext/LSPosed/TrickyStore/PIF 六族全命中 |

## 二、仅 FP 侧验证（干净不误报已证，真阳性从未见过）⚠️ 准确性盲区

| 检测项 | 级别 | 盲区说明 |
|---|---|---|
| frida.*（maps/thread/rwx/dbus） | B | 从未在装 Frida 的设备上正向验证——四防线仅有主机桩测试 |
| behavior.ksu_supercall / legacy_prctl | A/B | P8 是 APatch——KSU reboot 探针从未在 KSU 设备真命中 |
| behavior.apatch_supercall | B | P8 superkey 未知——syscall45 HELLO 从未真响应验证 |
| mem.known_path / injected_memfd / hidden_mapping / libart_cow / fd_data_adb | B/C | LSPosed/Zygisk 内存痕迹从未在真注入环境验证（P8 深隐藏不注入我进程） |
| screenshare.scrcpy_socket / scrcpy_hid / virtual_input | A/B | 从未连接真实 scrcpy 验证 |
| screenshare.recording_active | B | 系统录屏回调从未被真实录屏触发验证 |
| triple.svc_libc.* / java_native.* | A/B | 11-06 命中史为 prologue；三路 diff 的 TP 实证未见记录 |
| integrity.got_hooked / got_anon | A | 同上，GOT 槽位比对无 TP 史 |
| mem.maps_tampered（RWX 自探针） | A | 依赖 maps 篡改场景，无 TP 验证设备 |
| behavior.nativebridge_sticky / ptrace_residue / selinux_label.* | B/C | ZN/NyaZygisk/SELinux 域探针无对应真机 |
| emulator.cpu_mismatch / virtual.container.path | C | 无对应环境 |
| prop.area_anomaly | B | resetprop 痕迹扫描无对抗组验证 |
| mount.overlay.* / source_magisk / debug_ramdisk / fstype_cross | B/C | Magisk 挂载形态从未在真 Magisk 设备验证（P8 是 susfs 全隐藏） |
| fs.susfs | B | P8 的 susfs 隐藏了 /proc/filesystems——非隐藏 susfs 设备未测 |
| speedhack.clock_drift | B | 干净侧漂移 0ms 已证；加速外挂真机未测 |
| attest.cross.* / keybox_revoked / software_backed | A/B | 断链未接线（见 COVERAGE ⓪） |

## 三、不可达 / 未接线 / 策展

| 类别 | 条目 | 说明 |
|---|---|---|
| 策展（死探测为设计） | /data/adb 族路径 ×16 | **双锁实证（2026-11-11）**：stock Enforcing 下 SELinux MAC 拦截（root chmod 755 DAC 放行仍 EACCES——adb_data_file 域）；仅 permissive/定制 ROM/API≤8 可达。permissive 下六族全部真命中 |
| 策展（历史版本） | path.debug_ramdisk.magisk（until v26.x） | 数据策展字段，v27+ 设备自然 miss |
| 不可达 | frida.dbus 多端口枚举 | API28+ /proc/net/tcp EACCES（spec 已注明，27042 恒探测） |
| 不可达 | sock.* 全部 6 条（现代设备） | /proc/net/unix 门控 DEGRADED；API≤8 或宽松环境可达 |
| 未接线 | mount.too_clean / stdev_deviation | 无机型基线（deviceBaselines 空） |
| 未接线 | attest.* 三条 | ScanOrchestrator 未调用 |

## 四、FP 侧验证完备项（干净双环境零误报实证）

battery×3 / sim×3 / geo / network.global_proxy / vpn_owner / sensor_constant /
prop.build_pair×6 / debuggable / test_keys / adb_session（开发者场景已知取舍）——
均在模拟器 70/7 基线 + P8 真机零 FP 实证（2026-11-10 四批扩展逐批验证）。

## 五、结论与处置

1. **TP 侧矩阵缺失是当前最大准确性盲区**：142 项中约 40 项仅有 FP 侧证据。
   REGRESSION 开篇的「13 项目标 × 机型矩阵」即为设计好的 TP 验证计划，从未执行
   （仅 P8 对抗组单点）。**建议：按矩阵补齐 Magisk/KSU/scrcpy/Frida 真机各一台的正向验证**。
2. 分级纪律已达标：无越权分级（第十一轮后），A 级全部有物理不变量论证。
3. 不可达/未接线项已全部在 spec/catalog 标注，无虚假承诺残留。