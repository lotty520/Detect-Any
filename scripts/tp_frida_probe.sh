#!/usr/bin/env bash
# B6 对抗实测：frida 变体注入下的 C9 残存检测测量（P8 root 对抗机）
#
# 协议（每变体一轮）：
#   0. 控制轮：不跑 frida，扫描一次 → 控制基线（设备本身 root 产生的 findings）
#   1. root 起 frida-server 变体（默认端口 27042）
#   2. 启动 app → host 附加 keepalive（注入存续 30s 窗口）
#   3. 窗口内 adb 点 Start Scan（Pixel 原生系统 input 可用）→ 出报告
#   4. Settings → Export → 拉取 JSON → 提取 C9 域 findings
#   5. 与控制轮 diff = 该变体被检出的信号；缺失即盲区
# 变体：vanilla（基线 TP）/ hluda-sim（精准改名，模拟 strongR/Florida）/ renamed（全量洗）
#
# 用法: ./scripts/tp_frida_probe.sh <serial> [--port 27042]
set -u
cd "$(dirname "$0")/.."
SERIAL="${1:?用法: $0 <serial> [--port N]}"
PORT=27042
[ "${2:-}" = "--port" ] && PORT="${3:-27042}"
A="adb -s $SERIAL"
PKG=com.detectany.app
ADV=.adversarial
OUT=$ADV/results
mkdir -p "$OUT"

echo "=========================================================="
echo " TP frida-probe · $SERIAL · port $PORT · $(date '+%F %T')"
echo "=========================================================="

# 设备侧与 host 侧工具检查
$A shell su -c id >/dev/null 2>&1 || { echo "ENV-ERROR: 无 root"; exit 3; }
command -v frida >/dev/null || { echo "ENV-ERROR: host 无 frida CLI"; exit 3; }
python3 -c "import frida" 2>/dev/null || { echo "ENV-ERROR: 无 python frida 模块"; exit 3; }

# UI 点击（comma-aware bounds）
tap() {
  for i in 1 2 3; do
    $A shell uiautomator dump /sdcard/t.xml >/dev/null 2>&1; sleep 1
    local r=$($A shell cat /sdcard/t.xml 2>/dev/null | tr '<' '\n<' | tr -d '\r' | grep -F "$1" | head -1 | grep -oE 'bounds="\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]"' | grep -oE '[0-9]+' | tr '\n' ' ')
    [ -n "$r" ] && { read -r l t rr b <<< "$r"; $A shell input tap $(( (l+rr)/2 )) $(( (t+b)/2 )); return 0; }
  done
  echo "  !! tap MISS: $1"; return 1
}

# 扫描 + 导出 + 拉取；$1=标签
run_scan_export() {
  local tag=$1
  $A shell am force-stop $PKG
  $A shell am start -n $PKG/.MainActivity >/dev/null; sleep 4
  tap "Start Scan" || return 1
  sleep 12
  # 导出报告：Settings → Export structured report
  tap "Settings" || return 1; sleep 2
  tap "Export structured report" || return 1; sleep 3
  local newest=$($A shell "ls -t /sdcard/Android/data/$PKG/files/ 2>/dev/null | head -1" | tr -d '\r')
  [ -n "$newest" ] || { echo "  !! 无导出文件"; return 1; }
  $A pull "/sdcard/Android/data/$PKG/files/$newest" "$OUT/scan-$tag.json" >/dev/null
  echo "  → $OUT/scan-$tag.json"
}

# 提取 C9/注入域 findings（相对控制轮的 delta 由调用侧 diff）
findings_of() { python3 -c "
import json,sys
d=json.load(open('$1'))
for f in d.get('findings',[]):
    if f['collector']=='C9_INSTRUMENTATION' or 'frida' in f['ruleId'] or 'mem.' in f['ruleId'] or 'integrity' in f['ruleId']:
        print(f\"{f['ruleId']}({f['confidence']})\")"; }

start_server() { # $1=变体文件名（本地路径）
  $A push "$1" /data/local/tmp/fsp >/dev/null
  $A shell su -c "chmod 755 /data/local/tmp/fsp; killall fsp 2>/dev/null; nohup /data/local/tmp/fsp -l 0.0.0.0:$PORT >/dev/null 2>&1 &" >/dev/null
  sleep 2
  $A shell su -c "pgrep -f fsp" >/dev/null && echo "  server running (port $PORT)" || { echo "  !! server 未启动（变体可能改名致无法运行——本身即实验数据）"; return 1; }
}
stop_server() { $A shell su -c "killall fsp" >/dev/null 2>&1; sleep 1; }

attach_and_scan() { # $1=标签
  local tag=$1
  $A shell am start -n $PKG/.MainActivity >/dev/null; sleep 3
  python3 "$ADV/attach_keepalive.py" $PKG 35 >"$OUT/attach-$tag.log" 2>&1 &
  local att=$!
  sleep 3
  if ! grep -q attached "$OUT/attach-$tag.log" 2>/dev/null; then
    echo "  !! attach 失败: $(tail -2 "$OUT/attach-$tag.log" 2>/dev/null)"; kill $att 2>/dev/null; return 1
  fi
  echo "  attached ✓ 开始扫描"
  tap "Start Scan" && sleep 12
  tap "Settings"; sleep 2; tap "Export structured report"; sleep 3
  local newest=$($A shell "ls -t /sdcard/Android/data/$PKG/files/ 2>/dev/null | head -1" | tr -d '\r')
  [ -n "$newest" ] && $A pull "/sdcard/Android/data/$PKG/files/$newest" "$OUT/scan-$tag.json" >/dev/null && echo "  → scan-$tag.json"
  kill $att 2>/dev/null; wait $att 2>/dev/null
}

$A install -r -t app/build/outputs/apk/debug/app-debug.apk >/dev/null 2>&1 || { echo "ENV-ERROR: 安装失败"; exit 3; }

# ---- 0. 控制轮（无 frida） ----
echo "--- [0] 控制轮（无注入） ---"
run_scan_export control

# ---- 1..N 变体轮 ----
for variant in vanilla hluda-sim renamed; do
  echo "--- [$variant] ---"
  stop_server
  if start_server "$ADV/frida-server-$variant"; then
    attach_and_scan "$variant" || true
  else
    echo "  [DATA] $variant 无法启动——记录为规避成本（全量洗串破坏二进制）"
  fi
  stop_server
done

# ---- 汇总 ----
echo ""
echo "================ 残存检测汇总 ================"
for tag in control vanilla hluda-sim renamed; do
  f="$OUT/scan-$tag.json"
  echo "[$tag]"; [ -f "$f" ] && findings_of "$f" | sed 's/^/    /' || echo "    (无报告)"
done
echo "提示: vanilla 应命中最多；hluda-sim 相对 vanilla 缺失的 = 改名即盲的信号；"
echo "      仍存于 hluda-sim 的 = 改名免疫信号（RWX/D-Bus/其他）——加固目标。"
