#!/usr/bin/env bash
# 假阳性核准（FP Certification）—— docs/FP_CERTIFICATION.md 的自动化执行器
#
# 用法：
#   ./scripts/fp_certify.sh <serial>          # 全流程：L1 输入源核验 → L2 全扫 → 基线 diff → PASS/FAIL
#   ./scripts/fp_certify.sh <serial> --new    # 新机型引导：打印 findings 供人工定级后生成基线
#
# 退出码：0=PASS  1=FAIL（附证据）  2=新机型（无基线，需人工定级）  3=环境错误
#
# 兼容性：不依赖 UI 点击（HyperOS 等 input 注入受限机型可用——扫描走 am instrument）；
#        不依赖 jq（macOS 裸机可跑）。
set -u
cd "$(dirname "$0")/.."

SERIAL="${1:?用法: $0 <serial> [--new]}"
MODE="${2:-}"
A="adb -s $SERIAL"
PKG=com.detectany.app
APK=app/build/outputs/apk/debug/app-debug.apk
TESTAPK=app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
BASE_DIR=scripts/baselines

echo "=================================================================="
echo " FP Certification · $SERIAL"
echo "=================================================================="

MODEL=$($A shell getprop ro.product.model 2>/dev/null | tr -d '\r')
API=$($A shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')
[ -n "$MODEL" ] || { echo "ENV-ERROR: 设备不可达"; exit 3; }
echo "device: $MODEL (API $API)  $(date '+%F %T')"

L1_FAIL=0

# ---------- L1：输入源核验（静态确定性） ----------
echo ""
echo "--- L1 输入源核验 ---"

l1() { # $1=项名 $2=期望(ABSENT/EMPTY/ZERO) $3=实际值
  local name=$1 expect=$2 val="$3"
  if [ -z "$val" ]; then echo "  [OK]   $name ($expect)"
  else echo "  [FAIL] $name ($expect) → 实际: $(echo "$val" | head -c 120)"; L1_FAIL=1; fi
}

pkgs=$($A shell pm list packages 2>/dev/null | tr -d '\r' | grep -iE "magisk|kernelsu|me\.weishu|sukisu|apatch|lsposed|lspatch|appium|hidemyapplist|autojs|zygisk|riru" | head -5)
l1 "root/hook/automation 包" ABSENT "$pkgs"

qemu=$($A shell getprop ro.kernel.qemu 2>/dev/null | tr -d '\r' | grep -x "1")
l1 "ro.kernel.qemu=1" ABSENT "$qemu"
avdn=$($A shell getprop ro.boot.qemu.avd_name 2>/dev/null | tr -d '\r')
l1 "ro.boot.qemu.avd_name" EMPTY "$avdn"

goldfish=$($A shell dumpsys sensors 2>/dev/null | tr -d '\r' | grep -ci goldfish | grep -v '^0$')
l1 "goldfish 传感器" ZERO "$goldfish"

devnodes=$($A shell "ls /dev/qemu_pipe /dev/goldfish_pipe 2>/dev/null" | tr -d '\r')
l1 "/dev qemu/goldfish 节点" ABSENT "$devnodes"

modoverlay=$($A shell cat /proc/self/mountinfo 2>/dev/null | tr -d '\r' | grep " overlay " | grep -c "/data/adb" | grep -v '^0$')
l1 "overlay 的 /data/adb upperdir 指纹（模块挂载）" ZERO "$modoverlay"

# 信息项（不判 PASS/FAIL，供记录）
echo "  [info] 无障碍服务: $($A shell settings get secure enabled_accessibility_services 2>/dev/null | tr -d '\r' | cut -c1-100)"
echo "  [info] overlay 挂载总数: $($A shell cat /proc/self/mountinfo 2>/dev/null | tr -d '\r' | grep -c ' overlay ')"

if [ "$L1_FAIL" = 1 ]; then
  echo ""
  echo "L1 FAIL：输入源不干净或探针判据被证伪——先修探针/换设备，再做扫描。"
  exit 1
fi
echo "  → L1 全部通过（结构性不可能误报）"

# ---------- L2：instrumented 全扫 ----------
echo ""
echo "--- L2 干净全扫 ---"
$A install -r -t "$APK" >/dev/null 2>&1 || { echo "ENV-ERROR: 主包安装失败（设备侧确认弹窗？）"; exit 3; }
$A install -r -t "$TESTAPK" >/dev/null 2>&1 || { echo "ENV-ERROR: 测试包安装失败"; exit 3; }

REPORT=""
for attempt in 1 2; do
  $A shell am force-stop $PKG 2>/dev/null
  $A logcat -c 2>/dev/null
  timeout 300 $A shell am instrument -w -e class com.detectany.app.ReportUiSmokeTest#orchestratorFullScanRunsCleanOnEmulator \
    $PKG.test/androidx.test.runner.AndroidJUnitRunner >/dev/null 2>&1
  REPORT=$($A logcat -d 2>/dev/null | grep "SCAN-REPORT" | tail -1 | sed 's/^.*SCAN-REPORT: //' | tr -d '\r')
  [ -n "$REPORT" ] && break
  echo "  (第 $attempt 次扫描未出报告——重试)"
done
[ -n "$REPORT" ] || { echo "ENV-ERROR: 扫描报告未生成"; exit 3; }

SCORE=$(echo "$REPORT" | grep -oE 'score=[0-9]+' | cut -d= -f2)
CONCL=$(echo "$REPORT" | grep -oE 'conclusive=(true|false)' | cut -d= -f2)
FINDINGS=$(echo "$REPORT" | sed 's/.*findings=[0-9]* //' | sed 's/\[[^]]*\]//g')  # 去取证 detail
echo "  score=$SCORE conclusive=$CONCL findings=$(echo "$FINDINGS" | tr ';' '\n' | grep -c . || true)"
echo "$FINDINGS" | tr ';' '\n' | sed 's/^ *//' | grep -v '^$' | sed 's/^/    /'

# ---------- 基线定位 ----------
BASE=""
for cand in "$BASE_DIR/$MODEL.json" "$BASE_DIR/$(echo "$MODEL" | tr '[:upper:]' '[:lower:]').json" "$BASE_DIR/$(echo "$MODEL" | tr -d ' ' | tr '[:upper:]' '[:lower:]').json"; do
  [ -f "$cand" ] && BASE="$cand" && break
done

if [ -z "$BASE" ]; then
  cat <<EOF

[NEW-DEVICE] 机型「$MODEL」无基线（$BASE_DIR/）。

  1. 对上面每条 finding 人工定级：测试环境构造项 → testHarness；合法 OEM 形态 → expected；
     任何存疑项先按 FP 处理（修探针），不拍脑袋入基线
  2. 生成 $BASE_DIR/$(echo "$MODEL" | tr ' ' '_').json：
     { "model": "$MODEL", "api": $API, "recorded": "$(date '+%F')",
       "testHarness": ["automation.instrumented(B)"],
       "expected": ["prefix(C)"], "maxScore": $((SCORE + 10)), "conclusive": false }
  3. 重跑本脚本应 PASS
EOF
  exit 2
fi

# ---------- 基线 diff（awk 单趟匹配：条目 "prefix(C)" 命中 = ruleId 前缀 + 置信一致） ----------
echo ""
echo "--- 基线 diff ($BASE) ---"
RESULT=$(awk -v findings="$FINDINGS" -v basefile="$BASE" '
BEGIN {
  n = split(findings, F, ";")
  # 读基线全部条目（testHarness + expected），标记 harness
  harness = 0
  while ((getline line < basefile) > 0) {
    if (line ~ /"testHarness"/) harness = 1
    if (line ~ /"expected"/) harness = 0
    while (match(line, /"[^"]+\([ABC]\)"/)) {
      ent = substr(line, RSTART + 1, RLENGTH - 2)
      sub(/\)[[:space:]]*$/, "", ent)
      split(ent, p, "(")
      m = ++cnt; P[m] = p[1]; C[m] = p[2]; H[m] = harness
      line = substr(line, RSTART + RLENGTH)
    }
    if (line ~ /"maxScore"/) { match(line, /[0-9]+/); maxscore = substr(line, RSTART, RLENGTH) }
  }
  unmatched = 0
  for (i = 1; i <= n; i++) {
    f = F[i]; gsub(/^[[:space:]]+|[[:space:]]+$/, "", f)
    if (f == "") continue
    rid = f; sub(/\(.*/, "", rid)
    conf = f; sub(/.*\(/, "", conf); sub(/\).*/, "", conf)
    hit = 0
    for (j = 1; j <= cnt; j++) {
      if (index(rid, P[j]) == 1 && conf == C[j]) {
        printf "  [OK]   %s (%s)\n", f, (H[j] ? "harness 构造项" : "expected 合法形态")
        hit = 1; used[j] = 1; break
      }
    }
    if (!hit) { printf "  [FAIL] %s ← 基线外（FP 嫌疑）\n", f; unmatched++; if (conf == "A") aplus++ }
  }
  drift = 0
  for (j = 1; j <= cnt; j++) if (!used[j] && !H[j]) { drift++ }
  if (drift > 0) printf "  [WARN] %d 条 expected 基线条目本次未出现（漂移，复核定级）\n", drift
  printf "STATS %d %d %d %d\n", unmatched, aplus + 0, maxscore + 0, drift
}' )
echo "$RESULT" | grep -v '^STATS'
STATS=$(echo "$RESULT" | grep '^STATS')
UNMATCHED=$(echo "$STATS" | awk '{print $2}')
APLUS=$(echo "$STATS" | awk '{print $3}')
BASE_MAX=$(echo "$STATS" | awk '{print $4}')

# ---------- 门槛判定 ----------
echo ""
echo "--- 判定 ---"
VERDICT=PASS
[ "$APLUS" -gt 0 ] && { echo "  [FAIL] 存在 A 级 finding ×$APLUS"; VERDICT=FAIL; }
[ "$UNMATCHED" -gt 0 ] && { echo "  [FAIL] 基线外 finding ×$UNMATCHED"; VERDICT=FAIL; }
[ -n "$BASE_MAX" ] && [ "$SCORE" -gt "$BASE_MAX" ] 2>/dev/null && { echo "  [FAIL] score $SCORE > 基线 maxScore $BASE_MAX"; VERDICT=FAIL; }
[ "$CONCL" = "true" ] && { echo "  [FAIL] conclusive=true"; VERDICT=FAIL; }
[ "$VERDICT" = "PASS" ] && echo "  门槛全过：0 A 级 / 0 基线外 / score≤${BASE_MAX:-n/a} / Inconclusive"

echo ""
echo "=================================================================="
if [ "$VERDICT" = "PASS" ]; then
  echo " ✓ FP CERTIFIED · $MODEL · score=$SCORE Inconclusive · $(date '+%F %T')"
  echo "   核准记录请追加至 docs/REGRESSION.md 对应小节"
  exit 0
else
  echo " ✗ FP CERTIFICATION FAILED · $MODEL · 不得 commit/tag（响应闭环：docs/FP_CERTIFICATION.md §二）"
  exit 1
fi
