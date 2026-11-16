#!/usr/bin/env bash
# TP 对抗组核准（docs/FP_CERTIFICATION.md §三 的自动化执行器）—— fp_certify.sh 的对偶：
#   FP 侧证明「不冤枉好人」；本脚本证明「抓得到坏人」——对抗设备上的检出面必须完整。
#
# 用法：
#   ./scripts/tp_certify.sh <serial>                 # 按 scripts/tp-profiles/<model>.json 核准
#   ./scripts/tp_certify.sh <serial> --new           # 新对抗机引导：打印实测 findings 供建档
#
# profile 格式（scripts/tp-profiles/39011FDJH00G5G.json 为 P8 实测范例）：
#   { "model": "...", "setup": "APatch+SukiSU+HMA+点击器（对抗组配置描述）",
#     "mustHit": ["verified_boot_lie(A)", "app.sukisu(B)", ...],   # 缺一即 FAIL（检出面退化）
#     "minScore": 50, "mustConclusive": true }
#
# 退出码：0=PASS  1=FAIL  2=新机型（无 profile，--new 引导）  3=环境错误
set -u
cd "$(dirname "$0")/.."

SERIAL="${1:?用法: $0 <serial> [--new]}"
A="adb -s $SERIAL"
PKG=com.detectany.app
APK=app/build/outputs/apk/debug/app-debug.apk
TESTAPK=app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
PROF_DIR=scripts/tp-profiles

echo "=================================================================="
echo " TP Certification（对抗组检出面核准）· $SERIAL"
echo "=================================================================="

MODEL=$($A shell getprop ro.product.model 2>/dev/null | tr -d '\r')
[ -n "$MODEL" ] || { echo "ENV-ERROR: 设备不可达"; exit 3; }
echo "device: $MODEL  $(date '+%F %T')"

$A install -r -t "$APK" >/dev/null 2>&1 || { echo "ENV-ERROR: 主包安装失败"; exit 3; }
$A install -r -t "$TESTAPK" >/dev/null 2>&1 || { echo "ENV-ERROR: 测试包安装失败"; exit 3; }

REPORT=""
for attempt in 1 2; do
  $A shell am force-stop $PKG 2>/dev/null
  $A logcat -c 2>/dev/null
  $A shell am instrument -w -e class com.detectany.app.ReportUiSmokeTest#orchestratorFullScanRunsCleanOnEmulator \
    $PKG.test/androidx.test.runner.AndroidJUnitRunner >/dev/null 2>&1
  REPORT=$($A logcat -d 2>/dev/null | grep "SCAN-REPORT" | tail -1 | sed 's/^.*SCAN-REPORT: //' | tr -d '\r')
  [ -n "$REPORT" ] && break
done
[ -n "$REPORT" ] || { echo "ENV-ERROR: 扫描报告未生成"; exit 3; }

SCORE=$(echo "$REPORT" | grep -oE 'score=[0-9]+' | cut -d= -f2)
CONCL=$(echo "$REPORT" | grep -oE 'conclusive=(true|false)' | cut -d= -f2)
FINDINGS=$(echo "$REPORT" | sed 's/.*findings=[0-9]* //' | sed 's/\[[^]]*\]//g')
echo "  score=$SCORE conclusive=$CONCL findings=$(echo "$FINDINGS" | tr ';' '\n' | grep -c . || true)"
echo "$FINDINGS" | tr ';' '\n' | sed 's/^ *//' | grep -v '^$' | sed 's/^/    /'

PROFILE=""
for cand in "$PROF_DIR/$MODEL.json" "$PROF_DIR/$(echo "$MODEL" | tr '[:upper:]' '[:lower:]').json"; do
  [ -f "$cand" ] && PROFILE="$cand" && break
done

if [ -z "$PROFILE" ]; then
  cat <<EOF

[NEW-ADVERSARIAL] 机型「$MODEL」无 profile（$PROF_DIR/）。
按实测 findings 建 mustHit（对抗配置的核心检出锚点，建议含至少一条 A 级）+ minScore + mustConclusive，
写入 $PROF_DIR/$MODEL.json 后重跑。检出面退化（mustHit 缺失）= 特征库/探针回归的 TP 侧告警。
EOF
  exit 2
fi
echo "  profile: $PROFILE"

RESULT=$(awk -v findings="$FINDINGS" -v prof="$PROFILE" '
BEGIN {
  n = split(findings, F, ";")
  while ((getline line < prof) > 0) {
    if (line ~ /"mustHit"/) inMust = 1; else if (line ~ /\]/) inMust = 0
    if (inMust && match(line, /"[^"]+\([ABC]\)"/)) {
      ent = substr(line, RSTART + 1, RLENGTH - 2)
      m = ++cnt; P[m] = ent; used[m] = 0
      line = substr(line, RSTART + RLENGTH)
    }
    if (line ~ /"minScore"/) { match(line, /[0-9]+/); minscore = substr(line, RSTART, RLENGTH) + 0 }
    if (line ~ /"mustConclusive"/) mustconcl = (line ~ /true/)
  }
  missing = 0
  for (j = 1; j <= cnt; j++) {
    hit = 0
    for (i = 1; i <= n; i++) {
      f = F[i]; gsub(/^[[:space:]]+|[[:space:]]+$/, "", f); if (f == "") continue
      rid = f; sub(/\(.*/, "", rid); conf = f; sub(/.*\(/, "", conf); sub(/\).*/, "", conf)
      ep = P[j]; ec = ep; sub(/.*\(/, "", ec); sub(/\).*/, "", ec); sub(/\(.*/, "", ep)
      if (index(rid, ep) == 1 && conf == ec) { hit = 1; break }
    }
    if (hit) printf "  [HIT]   %s\n", P[j]
    else { printf "  [MISS]  %s ← 检出面退化（TP 回归告警）\n", P[j]; missing++ }
  }
  printf "STATS %d %d %d\n", missing + 0, minscore, mustconcl ? 1 : 0
}')
echo "$RESULT" | grep -v '^STATS'
STATS=$(echo "$RESULT" | grep '^STATS')
MISSING=$(echo "$STATS" | awk '{print $2}')
MINSCORE=$(echo "$STATS" | awk '{print $3}')
MUSTCONCL=$(echo "$STATS" | awk '{print $4}')

echo ""
echo "--- 判定 ---"
VERDICT=PASS
[ "$MISSING" -gt 0 ] && { echo "  [FAIL] mustHit 缺失 ×$MISSING"; VERDICT=FAIL; }
[ -n "$MINSCORE" ] && [ "$MINSCORE" -gt 0 ] && [ "$SCORE" -lt "$MINSCORE" ] 2>/dev/null && { echo "  [FAIL] score $SCORE < minScore $MINSCORE"; VERDICT=FAIL; }
[ "$MUSTCONCL" = "1" ] && [ "$CONCL" != "true" ] && { echo "  [FAIL] 应定性未定性"; VERDICT=FAIL; }
[ "$VERDICT" = "PASS" ] && echo "  检出面完整：mustHit 全中 / score≥${MINSCORE:-n/a} / conclusive"

echo ""
if [ "$VERDICT" = "PASS" ]; then
  echo " ✓ TP CERTIFIED · $MODEL · score=$SCORE · $(date '+%F %T')"
  exit 0
else
  echo " ✗ TP CERTIFICATION FAILED · $MODEL —— 探针/特征库改动造成检出退化（回滚或修复后重跑）"
  exit 1
fi
