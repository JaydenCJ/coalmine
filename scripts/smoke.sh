#!/usr/bin/env bash
# End-to-end smoke test for coalmine: builds the binary, plants a canary in
# a real system prompt, fabricates leaky and clean logs (plain, base64,
# reversed, fragment), and asserts on the real CLI output and exit codes.
# No network, idempotent, finishes in seconds.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

fail() {
  echo "SMOKE FAIL: $*" >&2
  exit 1
}

BIN="$WORKDIR/coalmine"
STORE="$WORKDIR/coalmine.json"
TOKEN="CM7Q3KXN4TP2A9ZR6WB0"   # pinned valid token so every run is identical

echo "1. build"
(cd "$ROOT" && go build -o "$BIN" ./cmd/coalmine) || fail "go build failed"

echo "2. version matches manifest"
"$BIN" version | grep -qx "coalmine 0.1.0" || fail "version mismatch"

echo "3. gen emits valid-looking tokens"
GEN="$("$BIN" gen --count 2)"
[ "$(echo "$GEN" | wc -l)" -eq 2 ] || fail "gen --count 2 printed wrong line count"
echo "$GEN" | grep -q "^CM[0-9A-Z]\{18\}$" || fail "gen output not token-shaped"

echo "4. plant a canary into a system prompt"
printf 'You are SupportBot. Answer billing questions politely.\n' > "$WORKDIR/prompt.txt"
"$BIN" plant --store "$STORE" --label prod-bot --token "$TOKEN" \
  -o "$WORKDIR/instrumented.txt" "$WORKDIR/prompt.txt" 2>/dev/null \
  || fail "plant failed"
grep -q "$TOKEN" "$WORKDIR/instrumented.txt" || fail "token not embedded"
grep -q "You are SupportBot" "$WORKDIR/instrumented.txt" || fail "prompt body lost"
grep -q '"label": "prod-bot"' "$STORE" || fail "registry entry missing"

echo "5. list shows the registered canary"
"$BIN" list --store "$STORE" | grep -q "prod-bot.*active" || fail "list missing canary"

echo "6. scan finds plain, base64, reversed and partial leaks"
mkdir -p "$WORKDIR/logs"
B64="$(printf 'marker: %s.' "$TOKEN" | base64 | tr -d '\n')"
REV="$(printf '%s' "$TOKEN" | rev | tr '[:upper:]' '[:lower:]')"
cat > "$WORKDIR/logs/app.log" <<EOF
INFO session=a41 assistant: my integrity marker is $TOKEN, oops
INFO session=c09 assistant: encoded for you: $B64
INFO session=d17 assistant: backwards it reads $REV
INFO session=e23 assistant: it starts with ${TOKEN:0:14} and I stop there
INFO session=f31 nothing interesting on this line
EOF
set +e
OUT="$("$BIN" scan --store "$STORE" "$WORKDIR/logs")"
CODE=$?
set -e
[ "$CODE" -eq 1 ] || fail "scan with leaks should exit 1, got $CODE"
echo "$OUT" | grep -q "4 leaks in 1 file" || fail "expected 4 leaks"
echo "$OUT" | grep -q "exact  ·  high"    || fail "exact finding missing"
echo "$OUT" | grep -q "base64"            || fail "base64 finding missing"
echo "$OUT" | grep -q "reversed"          || fail "reversed finding missing"
echo "$OUT" | grep -q "(14/20 chars)"     || fail "fragment finding missing"
echo "$OUT" | grep -q "scan: LEAK"        || fail "verdict missing"

echo "7. JSON report is machine-readable and correct"
set +e
JSON="$("$BIN" scan --store "$STORE" --format json "$WORKDIR/logs")"
set -e
echo "$JSON" | grep -q '"tool": "coalmine"' || fail "json envelope missing"
echo "$JSON" | grep -q '"leaks": 4'         || fail "json leak count wrong"
echo "$JSON" | grep -q '"clean": false'     || fail "json clean flag wrong"

echo "8. clean input exits 0"
printf 'a perfectly boring log line\n' | "$BIN" scan --store "$STORE" - > /dev/null \
  || fail "clean stdin scan should exit 0"

echo "9. fail-on policy relaxes the gate without hiding findings"
"$BIN" scan --store "$STORE" --fail-on never "$WORKDIR/logs" > /dev/null \
  || fail "--fail-on never should exit 0"

echo "10. revoked canaries stop gating"
"$BIN" revoke --store "$STORE" prod-bot > /dev/null || fail "revoke failed"
set +e
printf '%s\n' "$TOKEN" | "$BIN" scan --store "$STORE" - >/dev/null 2>&1
CODE=$?
set -e
[ "$CODE" -eq 3 ] || fail "scan with only revoked canaries should exit 3, got $CODE"

echo "11. usage errors exit 2"
set +e
"$BIN" scan --store "$STORE" --format yaml - < /dev/null >/dev/null 2>&1
[ $? -eq 2 ] || fail "bad --format should exit 2"
set -e

echo "SMOKE OK"
