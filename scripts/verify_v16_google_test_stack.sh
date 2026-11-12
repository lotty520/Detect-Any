#!/usr/bin/env bash
# v16 Google 测试栈识别 —— 一键实证 + 验证脚本（在有模拟器的机器上运行）
#
# 用途：
#   1. C10 新向量实证（goldfish_pipe / avd_name / goldfish 传感器名 / qemu prop）
#   2. Instr: 线程特征实证（am instrument 运行中抓取线程 comm + cmdline）
#   3. AGENTS 干净模拟器验证流程（预存信号不变 + 新增仅 EMULATOR 域）
#   4. 真机零误报检查（avd_name 键缺失 / 传感器无 goldfish / 无 automation.instrumented）
#
# 用法：
#   ./scripts/verify_v16_google_test_stack.sh emulator-5554          # 模拟器全流程
#   ./scripts/verify_v16_google_test_stack.sh f4c2cef504 --realdevice # 真机 FP 检查
set -u

PKG=com.detectany.app
SERIAL="${1:?用法: $0 <adb-serial> [--realdevice]}"
MODE="${2:-}"
A="adb -s $SERIAL"
APK=app/build/outputs/apk/debug/app-debug.apk
TESTAPK=app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk

echo "== 0. 前置 =="
$A wait-for-device
until [ "$($A shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; do sleep 2; done
echo "booted."

echo "== 1. C10 新向量 guest 侧实证 =="
$A shell getprop ro.kernel.qemu
$A shell getprop ro.boot.qemu.avd_name
$A shell getprop ro.kernel.qemu.avd_name
$A shell getprop ro.hardware
echo "-- /dev 节点（shell 视角）--"
$A shell ls -l /dev/qemu_pipe /dev/goldfish_pipe /dev/socket/qemud 2>&1
echo "-- 传感器名（goldfish 命名实证）--"
$A shell dumpsys sensors 2>/dev/null | grep -ioE '"?(goldfish|virtio)[^",]*' | sort -u | head
echo "-- 内核 cmdline --"
$A shell cat /proc/cmdline

echo "== 2. Instr: 特征实证（instrumented 运行窗口内抓取）=="
$A shell am force-stop $PKG
($A shell am instrument -w -e class ${PKG}.ReportUiSmokeTest#activityLaunchesAndScreenshotCaptured \
    ${PKG}.test/androidx.test.runner.AndroidJUnitRunner >/dev/null 2>&1) &
for i in $(seq 1 40); do
  PID=$($A shell pidof $PKG 2>/dev/null | tr -d '\r')
  [ -n "$PID" ] && break; sleep 0.5
done
if [ -n "${PID:-}" ]; then
  echo "instrumented pid=$PID"
  echo "-- cmdline（argv0 是否 Instr: 前缀）--"
  $A shell cat /proc/$PID/cmdline | tr '\0' ' '; echo
  echo "-- 线程 comm 含 instr --"
  $A shell "for t in /proc/$PID/task/*; do c=\$(cat \$t/comm 2>/dev/null); case \"\$c\" in [Ii]nstr:*) echo \"\$c\";; esac; done"
  $A shell ps -T -p $PID 2>/dev/null | grep -i instr
else
  echo "!! 未捕获 instrumented 进程（测试可能太快结束——重跑一次）"
fi
wait

echo "== 3. 正常启动扫描（新探针在非 instrument 启动下必须零产出）=="
$A install -r -t "$APK" >/dev/null && $A install -r -t "$TESTAPK" >/dev/null

# v18 UI：坐标动态推导（按文本取 bounds 中心）——布局重排不再破坏脚本
tap_by_text() { # $1 = 节点文本子串
  $A shell uiautomator dump /sdcard/tap.xml >/dev/null 2>&1
  # bounds 带逗号格式（HyperOS/新 uiautomator）：[l,t][r,b]
  local raw=$($A shell cat /sdcard/tap.xml | tr '<' '\n<' | tr -d '\r' | grep -F "$1" | head -1 | grep -oE 'bounds="\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]"' | grep -oE '[0-9]+')
  if [ -z "$raw" ]; then echo "!! 未找到节点: $1"; return 1; fi
  local l=$(echo $raw | awk '{print $1}'); local t=$(echo $raw | awk '{print $2}')
  local r=$(echo $raw | awk '{print $3}'); local b=$(echo $raw | awk '{print $4}')
  $A shell input tap $(( (l + r) / 2 )) $(( (t + b) / 2 ))
}

$A shell am force-stop $PKG
$A shell am start -n $PKG/.MainActivity >/dev/null
sleep 3
tap_by_text "Start Scan"    # v18：分段选择器默认 L2，直接启动
sleep 10
tap_by_text "Threats"       # 底部 tab（匹配 label 节点）
sleep 2
$A shell uiautomator dump /sdcard/verify.xml >/dev/null 2>&1
$A shell cat /sdcard/verify.xml | grep -oE '(automation\.instrumented|emulator\.avd_name|emulator\.sensor_goldfish|emulator\.hw\.qemu|app\.appium|app\.test_orchestrator|automation\.known[^"< ]*)' | sort | uniq -c
echo "-- 完整 threats 文本 --"
$A shell cat /sdcard/verify.xml | grep -oE '[^<>]{6,120}' | grep -vE '^\s*$' | head -60

if [ "$MODE" = "--realdevice" ]; then
  echo "== 4. 真机 FP 检查 =="
  echo "-- avd_name 必须为空 --"
  $A shell getprop ro.boot.qemu.avd_name; $A shell getprop ro.kernel.qemu.avd_name
  echo "-- 传感器不得含 goldfish --"
  $A shell dumpsys sensors 2>/dev/null | grep -ic goldfish
  echo "-- /dev 无 goldfish/qemu 节点 --"
  $A shell ls /dev/goldfish_pipe /dev/qemu_pipe 2>&1
  echo "-- 上面扫描输出中不应出现 automation.instrumented / emulator.avd_name / emulator.sensor_goldfish --"
fi

echo "== 5. connected 全量（断言内置：干净模拟器非模拟器域零命中）=="
./gradlew :app:connectedDebugAndroidTest || echo "!! connected 测试失败——查看报告"
