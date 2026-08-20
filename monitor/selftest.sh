#!/bin/bash
# selftest.sh -- runnable acceptance test for monitor/monitor.py.
# Exercises every case in specs/03-monitor-app.md's acceptance criteria plus
# the audit-mandated F10 rule from specs/00-frozen-interfaces.md (a running
# copy must show WARN, never FAIL, no matter how long it's been running).
#
# Exits 0 iff every check passes. Never touches /Volumes or a real MONITOR_SRC
# install; runs the backend against a throwaway fixture dir via SNAP_STATE_DIR.
set -u

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MONITOR_PY="$PROJECT_DIR/monitor/monitor.py"
PY=/usr/bin/python3
PORT="${SNAP_TEST_PORT:-7788}"

# GUARD: 7788 is the PRODUCTION monitor's port once the LaunchAgent is installed.
# Without this check the suite silently binds nothing, every curl hits the LIVE
# server, and all assertions are made against real archive state instead of the
# fixtures -- which reads as a wall of failures (or, worse, false passes).
# Observed for real on 2026-08-19 immediately after cutover.
if command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "FATAL: port $PORT is already in use -- almost certainly the production" >&2
  echo "       Snapshot Monitor LaunchAgent (com.example.agentsnapshot.monitor)." >&2
  echo "       This suite would test THAT server instead of its own fixtures." >&2
  echo "       Re-run with a free port, e.g.:  SNAP_TEST_PORT=7899 $0" >&2
  exit 2
fi
BASE="http://127.0.0.1:${PORT}"

D="$(mktemp -d)"
mkdir -p "$D/state"
SERVER_LOG="$D/server.log"
SERVER_PID=""
FAIL=0

pass() { printf '  [PASS] %s\n' "$1"; }
fail() { printf '  [FAIL] %s\n' "$1"; FAIL=1; }

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
    fi
}
trap cleanup EXIT

start_server() {
    SNAP_STATE_DIR="$D/state" SNAP_LOG=/dev/null SNAP_PORT="$PORT" \
        "$PY" "$MONITOR_PY" >"$SERVER_LOG" 2>&1 &
    SERVER_PID=$!
    for _ in $(seq 1 50); do
        if curl -s -o /dev/null "$BASE/api/status"; then
            return 0
        fi
        sleep 0.1
    done
    echo "server did not come up" >&2
    cat "$SERVER_LOG" >&2
    return 1
}

stop_server() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
    fi
    SERVER_PID=""
}

now_iso() { date +%Y-%m-%dT%H:%M:%S%z; }

write_healthy_status() {
    local ts="$1"
    cat > "$D/state/status.json" <<J
{"schema":1,"ts":"$ts","pass_kind":"mirror","engine_pid":1,"primary_mounted":true,"replica_mounted":true,
 "primary_total_kb":13672177624,"primary_used_kb":12311404,"primary_free_kb":13658487616,"primary_iused":236735,
 "replica_total_kb":13672177624,"replica_used_kb":12308976,"replica_free_kb":13658490044,"replica_iused":236708,
 "primary_snapshots":["2026-08-19_153705"],"replica_snapshots":["2026-08-19_153705"],
 "latest_primary":"2026-08-19_153705","latest_replica":"2026-08-19_153705",
 "pending":[],"unsettled":[],"incoming":[],
 "last_copy":{"snapshot":"2026-08-19_153705","started":"x","finished":"x","rc":0,"files":146219,"bytes":0,"link_dest":null},
 "last_deep_verify":null,"mirror_running":false,"healthy":true,"problems":[],"notes":[]}
J
}

echo "== monitor/selftest.sh =="
echo "state dir: $D/state"
echo "port: $PORT"
echo

# ---------------------------------------------------------------------------
echo "[1] healthy fixture -> display_state == ok"
write_healthy_status "$(now_iso)"
printf '{"ts":"%s","event":"copied","snapshot":"2026-08-19_153705","detail":""}\n' "$(now_iso)" > "$D/state/events.jsonl"
start_server || { fail "server failed to start"; exit 1; }

OUT="$(curl -s "$BASE/api/status")"
echo "$OUT" | "$PY" -c 'import sys,json; d=json.load(sys.stdin); assert d["display_state"]=="ok", d' \
    && pass "healthy -> ok  ($(echo "$OUT" | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["display_state"])'))" \
    || fail "healthy fixture did not report ok: $OUT"

# ---------------------------------------------------------------------------
echo "[2a] stale 20 min (1200s), mirror_running=false -> warn"
write_healthy_status "$("$PY" -c "
import datetime
print((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1200)).astimezone().strftime('%Y-%m-%dT%H:%M:%S%z'))
")"
OUT="$(curl -s "$BASE/api/status")"
STATE="$(echo "$OUT" | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["display_state"])')"
[ "$STATE" = "warn" ] && pass "20-min-stale -> warn" || fail "20-min-stale -> expected warn, got $STATE ($OUT)"

echo "[2b] stale 40 min (2400s), mirror_running=false -> fail"
write_healthy_status "$("$PY" -c "
import datetime
print((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=2400)).astimezone().strftime('%Y-%m-%dT%H:%M:%S%z'))
")"
OUT="$(curl -s "$BASE/api/status")"
STATE="$(echo "$OUT" | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["display_state"])')"
[ "$STATE" = "fail" ] && pass "40-min-stale -> fail" || fail "40-min-stale -> expected fail, got $STATE ($OUT)"

echo "[2c] AUDIT RULE: mirror_running=true, ts 40 min old (2400s > 1800) -> warn, NEVER fail"
TS40="$("$PY" -c "
import datetime
print((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=2400)).astimezone().strftime('%Y-%m-%dT%H:%M:%S%z'))
")"
"$PY" - "$D/state/status.json" "$TS40" <<'PYEOF'
import json, sys
path, ts = sys.argv[1], sys.argv[2]
d = json.load(open(path))
d["ts"] = ts
d["mirror_running"] = True
d["pending"] = ["2026-08-19_180000"]
json.dump(d, open(path, "w"))
PYEOF
OUT="$(curl -s "$BASE/api/status")"
STATE="$(echo "$OUT" | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["display_state"])')"
[ "$STATE" = "warn" ] && pass "long-running copy (mirror_running=true, 40min old ts) -> warn (never fail)" \
    || fail "long-running copy -> expected warn, got $STATE ($OUT)"

# ---------------------------------------------------------------------------
echo "[3] healthy:false with problems[] -> fail; problems text appears in HTML"
"$PY" - "$D/state/status.json" "$(now_iso)" <<'PYEOF'
import json, sys
path, ts = sys.argv[1], sys.argv[2]
d = json.load(open(path))
d["ts"] = ts
d["mirror_running"] = False
d["pending"] = []
d["healthy"] = False
d["problems"] = ["P8 free space < 50 GB on replica volume"]
json.dump(d, open(path, "w"))
PYEOF
OUT="$(curl -s "$BASE/api/status")"
STATE="$(echo "$OUT" | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["display_state"])')"
[ "$STATE" = "fail" ] && pass "healthy:false -> fail" || fail "healthy:false -> expected fail, got $STATE ($OUT)"

HTML="$(curl -s "$BASE/")"
echo "$HTML" | grep -qi "P8 free space" \
    && pass "problems[] text present verbatim in HTML" \
    || fail "problem text not found in HTML output"
echo "$HTML" | grep -qi "banner" \
    && pass "HTML contains a banner element" \
    || fail "no banner element found in HTML"

# ---------------------------------------------------------------------------
echo "[3b] notes[] nonempty (healthy:true) -> warn"
"$PY" - "$D/state/status.json" "$(now_iso)" <<'PYEOF'
import json, sys
path, ts = sys.argv[1], sys.argv[2]
d = json.load(open(path))
d["ts"] = ts
d["healthy"] = True
d["problems"] = []
d["mirror_running"] = False
d["pending"] = ["2026-08-19_180000"]
d["notes"] = ["pending nonempty"]
json.dump(d, open(path, "w"))
PYEOF
OUT="$(curl -s "$BASE/api/status")"
STATE="$(echo "$OUT" | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["display_state"])')"
[ "$STATE" = "warn" ] && pass "notes[] nonempty -> warn" || fail "notes[] nonempty -> expected warn, got $STATE ($OUT)"

# ---------------------------------------------------------------------------
echo "[4] missing status.json -> fail, HTTP 200, page degrades (no crash)"
rm -f "$D/state/status.json"
HTTP_CODE="$(curl -s -o /tmp/_bm_status_out.$$ -w '%{http_code}' "$BASE/api/status")"
OUT="$(cat /tmp/_bm_status_out.$$)"; rm -f /tmp/_bm_status_out.$$
[ "$HTTP_CODE" = "200" ] && pass "missing status.json -> HTTP 200" || fail "missing status.json -> HTTP $HTTP_CODE"
echo "$OUT" | grep -q '"fail"' && pass "missing status.json -> \"fail\" present" || fail "missing status.json -> no fail in $OUT"
HTML_CODE="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/")"
[ "$HTML_CODE" = "200" ] && pass "/ still serves 200 with status.json missing (no crash)" \
    || fail "/ returned $HTML_CODE with status.json missing"

# ---------------------------------------------------------------------------
echo "[5] events endpoint: limit + newest-first"
> "$D/state/events.jsonl"
for i in 1 2 3 4 5 6 7 8; do
    TS="$("$PY" -c "
import datetime
print((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=$((80-10*i)))).astimezone().strftime('%Y-%m-%dT%H:%M:%S%z'))
")"
    printf '{"ts":"%s","event":"detected","snapshot":"stamp-%d","detail":"n=%d"}\n' "$TS" "$i" "$i" >> "$D/state/events.jsonl"
done
# trailing partial line -- must be skipped, not crash
printf '{"ts":"2026-01-01T00:00:00+0000","event":"detected","snapshot":"partial"' >> "$D/state/events.jsonl"

OUT="$(curl -s "$BASE/api/events?n=5")"
echo "$OUT" | "$PY" -c '
import sys, json
d = json.load(sys.stdin)
assert isinstance(d, list), d
assert len(d) == 5, ("wrong length", len(d), d)
assert d[0]["snapshot"] == "stamp-8", ("not newest-first", d)
assert d[-1]["snapshot"] == "stamp-4", ("wrong tail", d)
' && pass "n=5 returns 5 items, newest-first (stamp-8 .. stamp-4)" \
    || fail "events n=5 assertion failed: $OUT"

OUT_ALL="$(curl -s "$BASE/api/events?n=500")"
echo "$OUT_ALL" | "$PY" -c '
import sys, json
d = json.load(sys.stdin)
assert len(d) == 8, ("partial trailing line leaked through or count wrong", len(d), d)
' && pass "trailing partial JSONL line skipped (no 500, correct count)" \
    || fail "events full-list assertion failed: $OUT_ALL"

# ---------------------------------------------------------------------------
echo "[6] malformed status.json -> fail, no traceback in server log"
printf 'garbage not json{{{' > "$D/state/status.json"
OUT="$(curl -s "$BASE/api/status")"
STATE="$(echo "$OUT" | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["display_state"])' 2>/dev/null)"
[ "$STATE" = "fail" ] && pass "malformed status.json -> fail" || fail "malformed status.json -> expected fail, got '$STATE' ($OUT)"
HTML_CODE="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/")"
[ "$HTML_CODE" = "200" ] && pass "/ still serves 200 with malformed status.json" || fail "/ returned $HTML_CODE"
if grep -qi "Traceback (most recent call last)" "$SERVER_LOG"; then
    fail "traceback found in server log for malformed status.json"
else
    pass "no traceback in server log"
fi

# ---------------------------------------------------------------------------
# Second-audit F10 rules (specs/00-frozen-interfaces.md, current revision).
# ---------------------------------------------------------------------------

write_running_status() {
    # $1=ts $2=mirror_running(true/false) $3=mirror_running_seconds(number, "null", or "absent")
    local ts="$1" running="$2" mrs="$3"
    "$PY" - "$D/state/status.json" "$ts" "$running" "$mrs" <<'PYEOF'
import json, sys
path, ts, running, mrs = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
d = json.load(open(path))
d["ts"] = ts
d["healthy"] = True
d["problems"] = []
d["notes"] = []
d["mirror_running"] = (running == "true")
if mrs == "absent":
    d.pop("mirror_running_seconds", None)
elif mrs == "null":
    d["mirror_running_seconds"] = None
else:
    d["mirror_running_seconds"] = float(mrs)
json.dump(d, open(path, "w"))
PYEOF
}

ts_ago() {
    "$PY" -c "
import datetime
print((datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(seconds=$1)).astimezone().strftime('%Y-%m-%dT%H:%M:%S%z'))
"
}

echo "[9] stale_seconds clamp: future ts (clock skew) -> clamped to 0, NEVER reads as fresh/ok"
FUTURE_TS=$(ts_ago -172798)   # matches audit repro FG5 exactly (now + 172798s)
write_healthy_status "$FUTURE_TS"
OUT="$(curl -s "$BASE/api/status")"
echo "$OUT" | "$PY" -c '
import sys, json
d = json.load(sys.stdin)
assert d["display_state"] != "ok", ("future ts must NOT be ok/green", d)
assert d["stale_seconds"] == 0 or d["stale_seconds"] == 0.0, ("stale_seconds must clamp to 0, not negative", d["stale_seconds"])
assert any("future" in n for n in d.get("monitor_notes", [])), ("expected a monitor_notes entry about the future ts", d)
' && pass "future ts (FG5 repro, -172798s) -> clamped to 0, display_state='$(echo "$OUT" | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["display_state"])')' (not ok), monitor_notes flags it" \
    || fail "future-ts clamp assertion failed: $OUT"

echo "[9n] NEGATIVE CONTROL: prove the clamp is what makes [9] pass (revert it, show the bug reproduces)"
VULN_PY="$D/monitor_vulnerable.py"
"$PY" - "$MONITOR_PY" "$VULN_PY" <<'PYEOF'
import sys
src_path, out_path = sys.argv[1], sys.argv[2]
src = open(src_path).read()
old = '''    monitor_notes = []
    if raw_stale_seconds < 0:
        stale_seconds = 0.0
        monitor_notes.append(
            "status timestamp is %.0fs in the future (clock skew or a bad write) -- "
            "treating as 0s stale, not fresh" % (-raw_stale_seconds)
        )
    else:
        stale_seconds = raw_stale_seconds'''
new = '''    monitor_notes = []
    stale_seconds = raw_stale_seconds  # VULNERABLE: pre-audit, unclamped (FG5)'''
assert old in src, "could not locate the clamp block to revert -- monitor.py structure changed"
vuln = src.replace(old, new, 1)
assert vuln != src
open(out_path, "w").write(vuln)
PYEOF
VULN_PORT=$((PORT + 1))
SNAP_STATE_DIR="$D/state" SNAP_LOG=/dev/null SNAP_PORT="$VULN_PORT" "$PY" "$VULN_PY" >"$D/vuln_server.log" 2>&1 &
VULN_PID=$!
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:${VULN_PORT}/api/status" && break; sleep 0.1; done
VULN_OUT="$(curl -s "http://127.0.0.1:${VULN_PORT}/api/status")"
VULN_STATE="$(echo "$VULN_OUT" | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["display_state"])')"
kill "$VULN_PID" 2>/dev/null; wait "$VULN_PID" 2>/dev/null
echo "  pre-fix (unclamped) code on the SAME future-ts fixture reports: display_state=$VULN_STATE  stale_seconds=$(echo "$VULN_OUT" | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["stale_seconds"])')"
REAL_OUT="$(curl -s "$BASE/api/status")"
REAL_STATE="$(echo "$REAL_OUT" | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["display_state"])')"
echo "  current (fixed) code on the SAME fixture reports:            display_state=$REAL_STATE"
if [ "$VULN_STATE" = "ok" ] && [ "$REAL_STATE" != "ok" ]; then
    pass "negative control confirms the clamp is load-bearing: reverting it reproduces FG5 (green on a future ts); the shipped code does not"
else
    fail "negative control did not demonstrate the expected before/after difference (vuln=$VULN_STATE real=$REAL_STATE)"
fi

echo "[10] SUPPRESS_CAP: mirror_running=true, mirror_running_seconds UNDER cap (3600s), ts stale 5000s -> still warn"
write_running_status "$(ts_ago 5000)" true 3600
OUT="$(curl -s "$BASE/api/status")"
STATE="$(echo "$OUT" | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["display_state"])')"
[ "$STATE" = "warn" ] && pass "under cap (3600s < 21600s) -> warn (suppression still applies)" \
    || fail "under-cap case -> expected warn, got $STATE ($OUT)"

echo "[11] SUPPRESS_CAP BREACH (FG6 repro): mirror_running=true, mirror_running_seconds OVER cap (25000s), ts stale 2400s -> fail"
write_running_status "$(ts_ago 2400)" true 25000
OUT="$(curl -s "$BASE/api/status")"
STATE="$(echo "$OUT" | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["display_state"])')"
[ "$STATE" = "fail" ] && pass "over cap (25000s > 21600s) + stale>1800 -> fail (a copy cannot claim to run forever)" \
    || fail "over-cap case -> expected fail, got $STATE ($OUT)"

echo "[11b] SUPPRESS_CAP BREACH, but stale_seconds <= 1800 -> still NOT fail (cap alone isn't sufficient, matches the AND in the formula)"
write_running_status "$(ts_ago 600)" true 25000
OUT="$(curl -s "$BASE/api/status")"
STATE="$(echo "$OUT" | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["display_state"])')"
[ "$STATE" = "warn" ] && pass "over cap but only 600s stale -> warn, not fail (fail needs stale_seconds>1800 too)" \
    || fail "over-cap-but-fresh case -> expected warn, got $STATE ($OUT)"

echo "[12] mirror_running_seconds ABSENT (older STATUS) -> no crash; treated as no-signal (suppression preserved)"
write_running_status "$(ts_ago 2592000)" true absent   # 30 days stale, matches FG6's scenario shape
OUT="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/status")"
[ "$OUT" = "200" ] && pass "absent mirror_running_seconds -> HTTP 200 (no crash)" || fail "absent field -> HTTP $OUT"
STATE="$(curl -s "$BASE/api/status" | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["display_state"])' 2>/dev/null)"
[ -n "$STATE" ] && pass "absent mirror_running_seconds -> parsed cleanly, display_state=$STATE (documented DECISION: absent = no signal = suppression preserved, not auto-fail)" \
    || fail "absent mirror_running_seconds -> response did not parse: $(curl -s "$BASE/api/status")"

echo "[12b] mirror_running_seconds explicit null -> no crash, same treatment as absent"
write_running_status "$(ts_ago 5000)" true null
OUT="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/status")"
[ "$OUT" = "200" ] && pass "null mirror_running_seconds -> HTTP 200 (no crash)" || fail "null field -> HTTP $OUT"

echo "[13] last_copy.detail surfaces without crashing when present on a failed copy"
"$PY" - "$D/state/status.json" "$(now_iso)" <<'PYEOF'
import json, sys
p, ts = sys.argv[1], sys.argv[2]
d = json.load(open(p))
d["ts"] = ts
d["healthy"] = False
d["mirror_running"] = False
d["problems"] = ["P4 copy failed"]
d["last_copy"] = {"snapshot": "2026-08-19_180000", "started": "x", "finished": "x", "rc": 1,
                   "files": 0, "bytes": 0, "link_dest": None, "detail": "rsync exited 255: too many open files"}
json.dump(d, open(p, "w"))
PYEOF
OUT="$(curl -s "$BASE/api/status")"
echo "$OUT" | "$PY" -c 'import sys,json; d=json.load(sys.stdin); assert d["last_copy"]["detail"]=="rsync exited 255: too many open files", d' \
    && pass "last_copy.detail passed through /api/status unchanged" \
    || fail "last_copy.detail assertion failed: $OUT"
HTML="$(curl -s "$BASE/")"
echo "$HTML" | grep -q "too many open files" \
    && pass "last_copy.detail text present in the served HTML" \
    || fail "last_copy.detail text not found in HTML"

echo "[14] long problems[] list (P1..P14, worst case) -> HTTP 200, all present verbatim, banner has scroll containment CSS"
"$PY" - "$D/state/status.json" "$(now_iso)" <<'PYEOF'
import json, sys
p, ts = sys.argv[1], sys.argv[2]
d = json.load(open(p))
d["ts"] = ts
d["healthy"] = False
d["mirror_running"] = False
d["problems"] = ["P%d synthetic problem for legibility test at long length" % i for i in range(1, 15)]
json.dump(d, open(p, "w"))
PYEOF
CODE="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/")"
[ "$CODE" = "200" ] && pass "14-problem fixture -> HTTP 200" || fail "14-problem fixture -> HTTP $CODE"
HTML="$(curl -s "$BASE/")"
MISSING=0
for i in $(seq 1 14); do
    echo "$HTML" | grep -q "P$i synthetic problem" || MISSING=$((MISSING+1))
done
[ "$MISSING" -eq 0 ] && pass "all 14 problems present verbatim in HTML" || fail "$MISSING of 14 problems missing from HTML"
echo "$HTML" | grep -q "max-height" && pass "banner has overflow containment CSS (max-height/scroll, not unbounded growth)" \
    || fail "banner overflow containment CSS not found"

echo "[15] BUG-2 regression (escaping): dangerous sequences in problems[]/last_copy.detail/event snapshot survive intact"
"$PY" - "$D/state/status.json" "$(now_iso)" <<'PYEOF'
import json, sys
p, ts = sys.argv[1], sys.argv[2]
d = json.load(open(p))
d["ts"] = ts
d["healthy"] = False
d["mirror_running"] = False
d["problems"] = [
    "P4 copy failed: <!--<script>alert(1)</script> on file 'Weird</script>Name.step'",
    "P11 orphan partial: lone bracket < in relpath",
]
d["last_copy"] = {"snapshot": "2026-08-19_180000", "started": "x", "finished": "x", "rc": 1,
                   "files": 0, "bytes": 0, "link_dest": None,
                   "detail": "rsync exited 255: <!--<script>evil()</script> too many open files"}
json.dump(d, open(p, "w"))
PYEOF
# events.jsonl may already end in an unterminated partial line from an
# earlier fixture (section [5] deliberately leaves one, sans trailing
# newline, to test partial-line handling) -- guarantee our append starts on
# its own line rather than silently concatenating onto that partial line.
printf '\n{"ts":"%s","event":"copy_failed","snapshot":"<!--<script>x</script>-evil","detail":"boom"}\n' "$(now_iso)" >> "$D/state/events.jsonl"

HTML="$(curl -s "$BASE/")"
echo "$HTML" | "$PY" -c '
import sys, re, json
html = sys.stdin.read()
n_open = len(re.findall(r"(?i)<script\b", html))
n_close = len(re.findall(r"(?i)</script\s*>", html))
assert n_open == 2, ("expected exactly 2 <script tags, got", n_open)
assert n_close == 2, ("expected exactly 2 </script> tags, got", n_close)
m = re.search(r"<script id=\"bootstrap\" type=\"application/json\">(.*?)</script>", html, re.S)
assert m, "bootstrap script tag not found / not well-formed"
boot = m.group(1)
assert "<" not in boot and ">" not in boot and "&" not in boot, "raw HTML-meaningful char leaked into bootstrap JSON"
decoded = json.loads(boot)
problems = decoded["status"]["problems"]
assert any("<!--<script>alert(1)</script>" in x for x in problems), "dangerous problems[] string not preserved verbatim"
assert any("Weird</script>Name.step" in x for x in problems), "embedded </script> in data not preserved verbatim"
assert "<!--<script>evil()</script>" in decoded["status"]["last_copy"]["detail"], "last_copy.detail dangerous string not preserved"
assert decoded["events"][0]["snapshot"] == "<!--<script>x</script>-evil", "event snapshot dangerous string not preserved verbatim"
assert "__BM_LOADED__" in html, "main UI script marker missing -- suggests the script got swallowed"
' && pass "BUG-2 fixed: well-formed HTML (exactly 2 script tags), zero raw <,>,& in bootstrap JSON, dangerous strings preserved verbatim, main UI script intact" \
    || fail "BUG-2 regression check failed"

"$PY" - "$MONITOR_PY" > "$D/bug2_unit.log" 2>&1 <<'PYEOF'
import sys, json
MONITOR_PY = sys.argv[1]
ns = {}
src = open(MONITOR_PY).read()
exec(compile(src, MONITOR_PY, "exec"), ns)
_script_safe_json = ns["_script_safe_json"]

payload = {"status": {"problems": [
    "orphan_partial on primary: <!--<script>alert(1)</script> Redesign #1.step",
    "verify mismatch in </script> boundary case",
    "lone angle bracket: 5 < 10 free GB remaining",
]}}

def old_escape(obj):
    return json.dumps(obj).replace("</", "<\\/")

new_out = _script_safe_json(payload)
old_out = old_escape(payload)
decoded = json.loads(new_out)
assert decoded == payload, "round-trip mismatch: new escaping corrupted the data"
assert "<!--<script" in old_out, "expected OLD code to leak this substring (that's the bug being regression-tested)"
assert "<!--<script" not in new_out, "NEW code must not leak this substring"
assert new_out.count("<") == 0 and new_out.count(">") == 0 and new_out.count("&") == 0, \
    "NEW code must contain zero raw <, >, & characters"
print("old escaping leaks '<!--<script':", "<!--<script" in old_out)
print("new escaping leaks '<!--<script':", "<!--<script" in new_out)
print("new escaping raw <,>,& count:", new_out.count("<"), new_out.count(">"), new_out.count("&"))
print("JSON round-trip exact match:", decoded == payload)
PYEOF
if [ $? -eq 0 ] && grep -q "raw <,>,& count: 0 0 0" "$D/bug2_unit.log"; then
    pass "BUG-2 unit-level negative control: old '</'-only escaping leaks '<!--<script'; new escaping does not (0 raw <,>,& chars; exact JSON round-trip)"
else
    fail "BUG-2 unit check did not pass: $(cat "$D/bug2_unit.log" 2>/dev/null)"
fi

stop_server

# ---------------------------------------------------------------------------
echo "[7] port-already-bound -> nonzero exit, clear message"
write_healthy_status "$(now_iso)"
SNAP_STATE_DIR="$D/state" SNAP_LOG=/dev/null SNAP_PORT="$PORT" "$PY" "$MONITOR_PY" >"$D/server1.log" 2>&1 &
FIRST_PID=$!
for _ in $(seq 1 50); do curl -s -o /dev/null "$BASE/api/status" && break; sleep 0.1; done
SNAP_STATE_DIR="$D/state" SNAP_LOG=/dev/null SNAP_PORT="$PORT" "$PY" "$MONITOR_PY" >"$D/server2.log" 2>&1
SECOND_RC=$?
kill "$FIRST_PID" 2>/dev/null; wait "$FIRST_PID" 2>/dev/null
[ "$SECOND_RC" -ne 0 ] && pass "second instance on bound port exits nonzero (rc=$SECOND_RC)" \
    || fail "second instance on bound port exited 0 (should fail)"
grep -qi "cannot bind\|already running\|address already in use" "$D/server2.log" \
    && pass "clear message printed on bind failure" \
    || fail "no clear bind-failure message: $(cat "$D/server2.log")"

# ---------------------------------------------------------------------------
echo "[8] backend down (no server running) -> app-facing endpoints simply refuse to connect"
if curl -s -o /dev/null --max-time 1 "$BASE/api/status"; then
    fail "expected connection refused with no server running, but got a response"
else
    pass "connection refused as expected with backend down (UI's fetch-failure path handles this client-side)"
fi

echo
if [ "$FAIL" -eq 0 ]; then
    echo "ALL CHECKS PASSED"
    exit 0
else
    echo "ONE OR MORE CHECKS FAILED"
    exit 1
fi
