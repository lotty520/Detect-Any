#!/usr/bin/env bash
# Release hygiene gate — enforces the release-hygiene capability contract
# (openspec/specs/release-hygiene after archive; see change repo-visibility-campaign)
#
# Usage:
#   ./scripts/check_release_hygiene.sh                # repo resolved from origin remote
#   ./scripts/check_release_hygiene.sh -r owner/repo  # explicit repo (e.g. in CI checkout)
#
# Checks (spec requirement → verdict):
#   1. latest git tag == latest GitHub Release tag            → FAIL on mismatch
#   2. latest release carries at least one .apk asset         → FAIL when absent
#   3. release notes publish the SHA-256 of every .apk asset  → FAIL on missing/mismatched hash
#   4. README download entry uses releases/latest             → FAIL when absent
#   W. demo GIF version marker vs README UI version           → WARN only (never fails)
#
# Exit codes: 0=PASS  1=HYGIENE FAIL  2=ENV ERROR (network, rate limit, no tags)
# No jq dependency (macOS bare-metal friendly); JSON parsed via python3.
# Anonymous GitHub API: <=3 requests per run (limit 60/h). Rate limit exits 2, never false-PASS.
set -u
cd "$(dirname "$0")/.."

REPO=""
if [ "${1:-}" = "-r" ] && [ -n "${2:-}" ]; then REPO=$2; fi
if [ -z "$REPO" ]; then
  REMOTE=$(git remote get-url origin 2>/dev/null) || { echo "ENV-ERROR: no origin remote"; exit 2; }
  REPO=$(echo "$REMOTE" | sed -E 's#.*github\.com[:/]##; s#\.git$##')
fi

echo "=================================================================="
echo " Release Hygiene Gate · $REPO"
echo "=================================================================="

# ---------- authoritative tag list ----------
git fetch --tags origin --quiet 2>/dev/null || { echo "ENV-ERROR: git fetch --tags failed"; exit 2; }
LATEST_TAG=$(git tag -l | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -1)
[ -n "$LATEST_TAG" ] || { echo "ENV-ERROR: no semantic version tags found"; exit 2; }
echo "latest git tag: $LATEST_TAG"

# ---------- latest release via anonymous API ----------
TMP_JSON=$(mktemp) || exit 2
trap 'rm -f "$TMP_JSON"' EXIT
HTTP=000
for attempt in 1 2 3; do
  HTTP=$(curl -s --max-time 20 -w '%{http_code}' -o "$TMP_JSON" \
    "https://api.github.com/repos/$REPO/releases/latest")
  [ "$HTTP" != "000" ] && break
  echo "(network attempt $attempt failed with HTTP 000, retrying after 3s)"
  sleep 3
done
if [ "$HTTP" = "000" ]; then
  echo "ENV-ERROR: GitHub API unreachable after 3 attempts — aborting, no false PASS"; exit 2
fi
if [ "$HTTP" = "403" ]; then
  echo "ENV-ERROR: GitHub API refused (rate limit?) — aborting, no false PASS"; exit 2
fi
if [ "$HTTP" != "200" ]; then
  echo "FAIL  [1] no latest release (HTTP $HTTP) — code is at $LATEST_TAG with no release at all"
  exit 1
fi

read -r REL_TAG APK_COUNT HASH_OK <<<"$(python3 - "$TMP_JSON" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
tag = d.get('tag_name', '')
apks = [a for a in d.get('assets', []) if a['name'].endswith('.apk')]
body = (d.get('body') or '').lower()
# every apk asset digest must appear in the release notes
ok = all((a.get('digest') or '').split('sha256:')[-1].lower() in body for a in apks)
print(tag, len(apks), int(ok))
PYEOF
)"

FAILS=0

# [1] release must not lag behind tags
if [ "$REL_TAG" != "$LATEST_TAG" ]; then
  echo "FAIL  [1] release lag: latest tag $LATEST_TAG vs latest release ${REL_TAG:-<none>}"
  FAILS=$((FAILS + 1))
else
  echo "PASS  [1] latest release tag matches: $REL_TAG"
fi

# [2] release must carry an APK asset
if [ "${APK_COUNT:-0}" -lt 1 ]; then
  echo "FAIL  [2] latest release has no .apk asset"
  FAILS=$((FAILS + 1))
else
  echo "PASS  [2] latest release carries $APK_COUNT apk asset(s)"
fi

# [3] notes must publish SHA-256 of every apk asset
if [ "${APK_COUNT:-0}" -ge 1 ]; then
  if [ "${HASH_OK:-0}" != "1" ]; then
    echo "FAIL  [3] release notes missing/mismatched SHA-256 for an apk asset"
    FAILS=$((FAILS + 1))
  else
    echo "PASS  [3] release notes publish SHA-256 for every apk asset"
  fi
fi

# [4] README download entry must auto-track the latest release
if grep -q 'releases/latest' README.md; then
  echo "PASS  [4] README download entry uses releases/latest"
else
  echo "FAIL  [4] README has no releases/latest download entry"
  FAILS=$((FAILS + 1))
fi

# [W] demo GIF version marker vs README-declared UI version (WARN only)
GIF=$(ls screenshots/demo-scan-*.gif 2>/dev/null | head -1)
if [ -n "$GIF" ]; then
  GIF_VER=$(echo "$GIF" | sed -E 's/.*demo-scan-(v[0-9]+)\.gif/\1/')
  if grep -q "UI $GIF_VER" README.md; then
    echo "PASS  [W] demo GIF $GIF_VER matches README UI version"
  else
    echo "WARN  [W] demo GIF is $GIF_VER but README declares another UI version — refresh the GIF"
  fi
else
  echo "WARN  [W] no screenshots/demo-scan-*.gif found — record one (see change repo-visibility-campaign D4)"
fi

echo "------------------------------------------------------------------"
if [ "$FAILS" -gt 0 ]; then
  echo "RESULT: FAIL ($FAILS violation(s))"; exit 1
fi
echo "RESULT: PASS"; exit 0
