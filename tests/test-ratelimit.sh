#!/bin/bash
# tests/test-ratelimit.sh — acceptance suite for trigger rate limiting on both dispatchers.
#
# Everything runs under a scratch HOME on the boot disk. The real ~/.ssh,
# ~/Library state dirs, /Volumes, and repo dispatch scripts are fingerprinted at
# start and checked at end (T20-style). bin/snapshot and the archive engine are
# stubbed; no backup or replica pass can start.
#
# Exit 0 iff every assertion passes.
#
#   bash tests/test-ratelimit.sh

set -u

REPO=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
DISPATCH="$REPO/bin/snapshot-dispatch"
MIRROR="$REPO/archive-host/mirror.sh"
KEY_LIB="$REPO/bin/snapshot-key-lib.sh"

if [ ! -x "$DISPATCH" ] || [ ! -x "$MIRROR" ] || [ ! -r "$KEY_LIB" ]; then
  printf 'test-ratelimit: missing dispatch scripts or key library\n' >&2
  exit 3
fi

REAL_HOME="${HOME:-}"
SCRATCH=${RATELIMIT_SELFTEST_SCRATCH:-${TMPDIR:-/tmp}/agent-snapshot-ratelimit-selftest}
RUN="$SCRATCH/run.$$"
MARKER="$RUN/.start-marker"

mkdir -p "$RUN" || exit 3
: > "$MARKER"

if [ -z "${RATELIMIT_SELFTEST_SANDBOX:-}" ]; then
  export RATELIMIT_SELFTEST_SANDBOX=1
fi

# Baselines for T20 — real environment, before any mutation.
REAL_AK="$REAL_HOME/.ssh/authorized_keys"
REAL_AK_HASH=""
if [ -f "$REAL_AK" ]; then
  REAL_AK_HASH=$(md5 -q "$REAL_AK" 2>/dev/null || md5sum "$REAL_AK" | awk '{print $1}')
else
  REAL_AK_HASH="__missing__"
fi
REAL_SOURCE_STATE="$REAL_HOME/Library/Application Support/agent-snapshot/state"
REAL_ARCHIVE_STATE="$REAL_HOME/Library/AgentSnapshot"
REAL_SOURCE_STATE_FP=$(find "$REAL_SOURCE_STATE" -type f 2>/dev/null | sort | xargs stat -f '%N %m %z' 2>/dev/null | md5 -q 2>/dev/null || echo "__missing__")
REAL_ARCHIVE_STATE_FP=$(find "$REAL_ARCHIVE_STATE" -type f 2>/dev/null | sort | xargs stat -f '%N %m %z' 2>/dev/null | md5 -q 2>/dev/null || echo "__missing__")
LAUNCHAGENTS_FP=$(find "$REAL_HOME/Library/LaunchAgents" -type f 2>/dev/null | sort | xargs stat -f '%N %m %z' 2>/dev/null | md5 -q 2>/dev/null || true)
REPO_FP=$(md5 -q "$DISPATCH" "$MIRROR" "$KEY_LIB" 2>/dev/null | md5 -q 2>/dev/null || true)
DAS_BEFORE=$(df -k /Volumes/SnapArchive /Volumes/SnapMirror 2>/dev/null | awk '{print $3, $6, $9}'; \
             ls -1 /Volumes/SnapArchive/snapshots /Volumes/SnapMirror/snapshots 2>/dev/null)

TOTAL=0
FAILED=0
CURTEST="(init)"

cleanup() { rm -rf "$RUN" 2>/dev/null; }
onsig() { cleanup; exit 130; }
trap cleanup EXIT
trap onsig INT TERM

ok()  { TOTAL=$((TOTAL+1)); printf '  PASS  %s\n' "$1"; }
bad() { TOTAL=$((TOTAL+1)); FAILED=$((FAILED+1)); printf '  FAIL  %s\n' "$1"; }
aeq() { if [ "$2" = "$3" ]; then ok "$1 [$3]"; else bad "$1  expected=<$2> got=<$3>"; fi; }
ane() { if [ "$2" != "$3" ]; then ok "$1 [$3]"; else bad "$1  expected NOT <$2>"; fi; }
ahas(){ case "$3" in *"$2"*) ok "$1";; *) bad "$1  <<$3>> does not contain <$2>";; esac; }
anot(){ case "$3" in *"$2"*) bad "$1  <<$3>> unexpectedly contains <$2>";; *) ok "$1";; esac; }
agt() { if [ "${3:-0}" -gt "$2" ] 2>/dev/null; then ok "$1 [$3 > $2]"; else bad "$1  expected > $2, got $3"; fi; }
head_() { printf '\n=== %s\n' "$1"; CURTEST="$1"; }

# Stub archive engine — never runs a real mirror/deep-verify pass.
cat > "$RUN/stub-engine.sh" <<'STUBEOF'
#!/bin/bash
exit 0
STUBEOF
chmod +x "$RUN/stub-engine.sh"
export AGENT_SNAPSHOT_ENGINE="$RUN/stub-engine.sh"

# shellcheck disable=SC1090
source "$KEY_LIB"

cat > "$RUN/q.py" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
v = eval(sys.argv[2], {"d": d, "len": len, "sorted": sorted, "set": set, "str": str, "any": any, "int": int})
if isinstance(v, bool):        print("true" if v else "false")
elif v is None:                print("null")
elif isinstance(v, (list, dict)): print(json.dumps(v))
else:                          print(v)
PYEOF

Q() { /usr/bin/python3 "$RUN/q.py" "$1" "$2" 2>/dev/null; }

history_count() {
  local path=$1
  if [ ! -f "$path" ]; then
    echo 0
    return
  fi
  Q "$path" 'len(d.get("entries", []))'
}

seed_source_history() {
  local path=$1 lane=$2 count=$3 age_sec=$4 mode=${5:-snap}
  /usr/bin/python3 - "$path" "$lane" "$count" "$age_sec" "$mode" <<'PY'
import json, os, sys, time
path, lane, count, age_sec, mode = sys.argv[1:6]
now = int(time.time())
entries = []
for i in range(int(count)):
    entries.append({
        "ts": now - int(age_sec) - i,
        "mode": mode,
        "client": "seed@test",
        "lane": lane,
    })
data = {"schema": 1, "lane": lane, "entries": entries}
os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
with open(path, "w") as fh:
    json.dump(data, fh, indent=1, sort_keys=True)
    fh.write("\n")
os.chmod(path, 0o600)
PY
}

age_history_entries() {
  local path=$1 age_sec=$2
  /usr/bin/python3 - "$path" "$age_sec" <<'PY'
import json, os, sys, time
path, age_sec = sys.argv[1], int(sys.argv[2])
now = int(time.time())
try:
    with open(path) as fh:
        data = json.load(fh)
except (IOError, OSError, ValueError):
    sys.exit(0)
entries = data.get("entries") or []
for e in entries:
    if isinstance(e, dict):
        e["ts"] = now - age_sec
with open(path, "w") as fh:
    json.dump(data, fh, indent=1, sort_keys=True)
    fh.write("\n")
PY
}

writer_layout() {
  local sustain=${1:-2}
  mkdir -p "$HOME/Library/Application Support/agent-snapshot/bin" \
           "$HOME/Library/Application Support/agent-snapshot/conf" \
           "$HOME/Library/Caches/agent-snapshot" \
           "$HOME/test-source"
  printf 'probe\n' > "$HOME/test-source/f.txt"
  printf '#!/bin/bash\nexit 0\n' > "$HOME/Library/Application Support/agent-snapshot/bin/snapshot"
  chmod +x "$HOME/Library/Application Support/agent-snapshot/bin/snapshot"
  cat > "$HOME/Library/Application Support/agent-snapshot/conf/snapshot.conf" <<CONF
STAGE="$HOME/Library/Caches/agent-snapshot"
SOURCE="$HOME/test-source"
SNAP_ENABLED=false
VAULT_ENABLED=false
SNAP_RATE_BURST_COUNT=3
SNAP_RATE_BURST_WINDOW_SEC=600
SNAP_RATE_SUSTAIN_COUNT=$sustain
SNAP_RATE_SUSTAIN_WINDOW_SEC=3600
CONF
}

archive_layout() {
  mkdir -p "$ROOT/state"
  export SNAP_STATE_DIR="$ROOT/state"
  export SNAP_LOG="$ROOT/mirror.log"
}

newroot() {
  ROOT="$RUN/$1"
  HOME="$ROOT/home"
  export HOME
  rm -rf "$ROOT"
  mkdir -p "$ROOT"
  writer_layout 2
  archive_layout
  unset SSH_ORIGINAL_COMMAND SSH_CLIENT SSH_CONNECTION BUSY_PID HL_PID 2>/dev/null || true
}

src_dispatch() {
  # shellcheck disable=SC2068
  env SSH_ORIGINAL_COMMAND="${SSH_ORIGINAL_COMMAND:-snap}" \
      SSH_CLIENT="${SSH_CLIENT:-127.0.0.1 12345 22}" \
      "$DISPATCH" >"$ROOT/out.txt" 2>"$ROOT/err.txt"
  RC=$?
}

src_state_dir() {
  printf '%s\n' "$HOME/Library/Application Support/agent-snapshot/state"
}

src_history() {
  printf '%s/trigger-history.json\n' "$(src_state_dir)"
}

src_deny() {
  printf '%s/last-rate-limit.json\n' "$(src_state_dir)"
}

arch_dispatch() {
  local mode=${1:-mirror}
  local -a env_args
  env_args=(SNAP_STATE_DIR="$SNAP_STATE_DIR" AGENT_SNAPSHOT_ENGINE="$AGENT_SNAPSHOT_ENGINE")
  if [ -n "${AGENT_SNAPSHOT_KICK:-}" ]; then
    env_args+=(AGENT_SNAPSHOT_KICK="$AGENT_SNAPSHOT_KICK")
  fi
  if [ -n "${SSH_CONNECTION+x}" ] && [ -n "${SSH_CONNECTION:-}" ]; then
    env_args+=(SSH_CONNECTION="$SSH_CONNECTION" SSH_CLIENT="${SSH_CLIENT:-127.0.0.1 12345 22}")
  elif [ -z "${SSH_CONNECTION+x}" ]; then
    # Default forced-SSH simulation when the caller did not touch SSH_CONNECTION.
    env_args+=(SSH_CONNECTION="127.0.0.1 12345 192.0.2.1 22" SSH_CLIENT="127.0.0.1 12345 22")
  fi
  if [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then
    env_args+=(SSH_ORIGINAL_COMMAND="$SSH_ORIGINAL_COMMAND")
  fi
  # shellcheck disable=SC2068
  env "${env_args[@]}" "$MIRROR" "$mode" >"$ROOT/out.txt" 2>"$ROOT/err.txt"
  RC=$?
}

arch_history() {
  printf '%s/trigger-history.json\n' "$SNAP_STATE_DIR"
}

arch_deny() {
  printf '%s/last-rate-limit.json\n' "$SNAP_STATE_DIR"
}

hold_source_busy() {
  local stage="$HOME/Library/Caches/agent-snapshot"
  mkdir -p "$stage/.lock"
  ( sleep 300 ) &
  BUSY_PID=$!
  printf '%s\n' "$BUSY_PID" > "$stage/.pid"
}

release_source_busy() {
  [ -n "${BUSY_PID:-}" ] && kill "$BUSY_PID" 2>/dev/null && wait "$BUSY_PID" 2>/dev/null || true
  rm -f "$HOME/Library/Caches/agent-snapshot/.pid"
  unset BUSY_PID
}

hold_archive_busy() {
  cat > "$RUN/holdlock.py" <<'HLPY'
import fcntl, os, sys, time
lock, secs, ready = sys.argv[1], float(sys.argv[2]), sys.argv[3]
fd = os.open(lock, os.O_CREAT | os.O_RDWR, 0o644)
fcntl.flock(fd, fcntl.LOCK_EX)
open(ready, "w").write("held\n")
time.sleep(secs)
HLPY
  rm -f "$ROOT/.held"
  /usr/bin/python3 "$RUN/holdlock.py" "$SNAP_STATE_DIR/mirror.pid" 300 "$ROOT/.held" &
  HL_PID=$!
  local i=0
  while [ ! -f "$ROOT/.held" ] && [ $i -lt 200 ]; do i=$((i+1)); sleep 0.01; done
}

release_archive_busy() {
  [ -n "${HL_PID:-}" ] && kill "$HL_PID" 2>/dev/null && wait "$HL_PID" 2>/dev/null || true
  unset HL_PID
}

assert_source_deny_fields() {
  local path=$1
  aeq "$CURTEST: deny artifact exists" "yes" "$([ -f "$path" ] && echo yes || echo no)"
  aeq "$CURTEST: deny schema" "1" "$(Q "$path" 'd["schema"]')"
  aeq "$CURTEST: deny mode" "snap" "$(Q "$path" 'd["mode"]')"
  ahas "$CURTEST: deny reason present" "sustain" "$(Q "$path" 'd["reason"]')" || \
    ahas "$CURTEST: deny reason present" "burst" "$(Q "$path" 'd["reason"]')"
  agt "$CURTEST: deny burst_count numeric" "-1" "$(Q "$path" 'int(d["burst_count"])')"
  agt "$CURTEST: deny sustain_count numeric" "-1" "$(Q "$path" 'int(d["sustain_count"])')"
  ahas "$CURTEST: deny client recorded" "127.0.0.1" "$(Q "$path" 'd["client"]')"
  agt "$CURTEST: deny retry_after_ts future" "$(date +%s)" "$(Q "$path" 'int(d["retry_after_ts"])')"
  ahas "$CURTEST: deny iso timestamp" "T" "$(Q "$path" 'd["iso"]')"
}

assert_archive_deny_fields() {
  local path=$1 mode=$2
  aeq "$CURTEST: deny artifact exists" "yes" "$([ -f "$path" ] && echo yes || echo no)"
  aeq "$CURTEST: deny schema" "1" "$(Q "$path" 'd["schema"]')"
  aeq "$CURTEST: deny mode" "$mode" "$(Q "$path" 'd["mode"]')"
  ahas "$CURTEST: deny reason present" "burst" "$(Q "$path" 'd["reason"]')"
  aeq "$CURTEST: deny count field (P16)" "4" "$(Q "$path" 'd["count"]')"
  aeq "$CURTEST: deny limit field (P16)" "4" "$(Q "$path" 'd["limit"]')"
  aeq "$CURTEST: deny window_sec field (P16)" "300" "$(Q "$path" 'd["window_sec"]')"
  ahas "$CURTEST: deny client recorded" "127.0.0.1" "$(Q "$path" 'd["client"]')"
  ahas "$CURTEST: deny iso timestamp" "T" "$(Q "$path" 'd["iso"]')"
  agt "$CURTEST: deny ts present" "0" "$(Q "$path" 'int(d["ts"])')"
}

########################################################################################
head_ "S01 source burst: 3 admitted, 4th denied 78 (sustain raised)"
newroot s01
writer_layout 999
HIST="$(src_history)"
i=1
while [ $i -le 3 ]; do
  SSH_ORIGINAL_COMMAND=snap src_dispatch
  aeq "burst admit $i rc" 0 "$RC"
  i=$((i+1))
done
SSH_ORIGINAL_COMMAND=snap src_dispatch
aeq "burst deny rc" 78 "$RC"
aeq "history holds 3 entries" "3" "$(history_count "$HIST")"
DENY="$(src_deny)"
aeq "burst deny reason" "burst" "$(Q "$DENY" 'd["reason"]')"
anot "burst deny is not sustain" "sustain" "$(Q "$DENY" 'd["reason"]')"

########################################################################################
head_ "S02 source sustain: default sustain=2, 3rd denied 78 with reason sustain"
newroot s02
HIST="$(src_history)"
SSH_ORIGINAL_COMMAND=snap src_dispatch
aeq "sustain admit 1 rc" 0 "$RC"
SSH_ORIGINAL_COMMAND=snap src_dispatch
aeq "sustain admit 2 rc" 0 "$RC"
SSH_ORIGINAL_COMMAND=snap src_dispatch
aeq "sustain deny rc" 78 "$RC"
aeq "history holds 2 entries" "2" "$(history_count "$HIST")"
DENY="$(src_deny)"
aeq "sustain deny reason is sustain" "sustain" "$(Q "$DENY" 'd["reason"]')"
anot "sustain deny is not burst" "burst" "$(Q "$DENY" 'd["reason"]')"

########################################################################################
head_ "S03 source probe: never rate-limited, no history"
newroot s03
HIST="$(src_history)"
i=1
while [ $i -le 12 ]; do
  SSH_ORIGINAL_COMMAND=probe src_dispatch
  aeq "probe run $i rc (probe may fail checks but not 78)" "not78" \
      "$([ "$RC" -ne 78 ] && echo not78 || echo 78)"
  i=$((i+1))
done
aeq "probe wrote no history file" "0" "$(history_count "$HIST")"

########################################################################################
head_ "S04 source probe-auth: never rate-limited, no history"
newroot s04
HIST="$(src_history)"
i=1
while [ $i -le 12 ]; do
  SSH_ORIGINAL_COMMAND=probe-auth src_dispatch
  aeq "probe-auth run $i rc" 0 "$RC"
  i=$((i+1))
done
aeq "probe-auth wrote no history" "0" "$(history_count "$HIST")"
ahas "probe-auth output" "probe-auth: OK" "$(cat "$ROOT/out.txt")"

########################################################################################
head_ "S05 source unknown mode exits 77"
newroot s05
SSH_ORIGINAL_COMMAND='rm -rf /' src_dispatch
aeq "unknown mode rc" 77 "$RC"
ahas "refused message" "refused" "$(cat "$ROOT/err.txt")"

########################################################################################
head_ "S06 source busy: exit 79, no quota consumed"
newroot s06
HIST="$(src_history)"
hold_source_busy
BEFORE="$(history_count "$HIST")"
SSH_ORIGINAL_COMMAND=snap src_dispatch
release_source_busy
aeq "busy rc" 79 "$RC"
aeq "history count unchanged under busy" "$BEFORE" "$(history_count "$HIST")"
anot "busy did not write deny artifact" "yes" "$([ -f "$(src_deny)" ] && echo yes || echo no)"

########################################################################################
head_ "S07 source window expiry: aged entries no longer count"
newroot s07
HIST="$(src_history)"
seed_source_history "$HIST" "source-forced" 2 7200 snap
age_history_entries "$HIST" 7200
SSH_ORIGINAL_COMMAND=snap src_dispatch
aeq "post-expiry admit rc" 0 "$RC"
aeq "pruned stale entries; one fresh entry remains" "1" "$(history_count "$HIST")"
MINE=$(/usr/bin/python3 - "$HIST" <<'PY'
import json, sys, time
d = json.load(open(sys.argv[1]))
now = int(time.time())
print(all(int(e.get("ts", 0)) >= now - 120 for e in d.get("entries", [])))
PY
)
aeq "remaining entry is within the active window" "True" "$MINE"

########################################################################################
head_ "S08 source denial artifact fields"
newroot s08
HIST="$(src_history)"
SSH_ORIGINAL_COMMAND=snap src_dispatch
src_dispatch
SSH_ORIGINAL_COMMAND=snap src_dispatch
assert_source_deny_fields "$(src_deny)"

########################################################################################
head_ "A01 archive AGENT_SNAPSHOT_KICK=1: unlimited, no history"
newroot a01
HIST="$(arch_history)"
export AGENT_SNAPSHOT_KICK=1
export SSH_CONNECTION="127.0.0.1 12345 192.0.2.1 22"
i=1
while [ $i -le 20 ]; do
  arch_dispatch mirror
  aeq "kick run $i rc" 0 "$RC"
  i=$((i+1))
done
aeq "kick wrote no history" "0" "$(history_count "$HIST")"
unset AGENT_SNAPSHOT_KICK

########################################################################################
head_ "A02 archive forced mirror: 5th within 5 min denied 78"
newroot a02
HIST="$(arch_history)"
export SSH_CONNECTION="127.0.0.1 12345 192.0.2.1 22"
i=1
while [ $i -le 4 ]; do
  arch_dispatch mirror
  aeq "mirror admit $i rc" 0 "$RC"
  i=$((i+1))
done
arch_dispatch mirror
aeq "mirror 5th rc" 78 "$RC"
aeq "mirror history holds 4 entries" "4" "$(history_count "$HIST")"
assert_archive_deny_fields "$(arch_deny)" mirror

########################################################################################
head_ "A03 archive forced deep-verify: 3rd within 24h denied 78"
newroot a03
HIST="$(arch_history)"
export SSH_CONNECTION="127.0.0.1 12345 192.0.2.1 22"
i=1
while [ $i -le 2 ]; do
  arch_dispatch deep-verify
  aeq "deep-verify admit $i rc" 0 "$RC"
  i=$((i+1))
done
arch_dispatch deep-verify
aeq "deep-verify 3rd rc" 78 "$RC"
aeq "deep-verify history holds 2 entries" "2" "$(history_count "$HIST")"
DENY="$(arch_deny)"
aeq "deep-verify deny mode" "deep-verify" "$(Q "$DENY" 'd["mode"]')"
aeq "deep-verify deny count (P16)" "2" "$(Q "$DENY" 'd["count"]')"
aeq "deep-verify deny limit (P16)" "2" "$(Q "$DENY" 'd["limit"]')"
aeq "deep-verify deny window_sec (P16)" "86400" "$(Q "$DENY" 'd["window_sec"]')"

########################################################################################
head_ "A04 archive lane independence: mirror saturation does not deny deep-verify"
newroot a04
HIST="$(arch_history)"
seed_source_history "$HIST" "archive-forced-mirror" 4 10 mirror
export SSH_CONNECTION="127.0.0.1 12345 192.0.2.1 22"
arch_dispatch deep-verify
aeq "deep-verify admitted while mirror lane full rc" 0 "$RC"
MINE=$(/usr/bin/python3 - "$HIST" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(sum(1 for e in d.get("entries", []) if e.get("lane") == "archive-forced-deep-verify"))
PY
)
aeq "deep-verify lane got its own entry" "1" "$MINE"

########################################################################################
head_ "A05 archive lane independence: deep-verify saturation does not deny mirror"
newroot a05
HIST="$(arch_history)"
seed_source_history "$HIST" "archive-forced-deep-verify" 2 10 deep-verify
export SSH_CONNECTION="127.0.0.1 12345 192.0.2.1 22"
arch_dispatch mirror
aeq "mirror admitted while deep-verify lane full rc" 0 "$RC"
MINE=$(/usr/bin/python3 - "$HIST" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(sum(1 for e in d.get("entries", []) if e.get("lane") == "archive-forced-mirror"))
PY
)
aeq "mirror lane got its own entry" "1" "$MINE"

########################################################################################
head_ "A06 archive local invocation: never denied without SSH_CONNECTION"
newroot a06
HIST="$(arch_history)"
SSH_CONNECTION=""
export SSH_CONNECTION
i=1
while [ $i -le 10 ]; do
  arch_dispatch mirror
  aeq "local mirror run $i rc" 0 "$RC"
  i=$((i+1))
done
aeq "local path wrote no rate-limit history" "0" "$(history_count "$HIST")"

########################################################################################
head_ "A07 archive probe-auth succeeds while engine busy lock held"
newroot a07
hold_archive_busy
unset SSH_CONNECTION
arch_dispatch probe-auth
release_archive_busy
aeq "probe-auth rc under busy lock" 0 "$RC"
ahas "probe-auth ok line" "probe-auth: OK" "$(cat "$ROOT/out.txt")"
aeq "probe-auth wrote no history" "0" "$(history_count "$(arch_history)")"

########################################################################################
head_ "A08 archive legacy/unrecognized SSH command routes to mirror"
newroot a08
unset SSH_CONNECTION
export SSH_ORIGINAL_COMMAND="/Users/youruser/Library/AgentSnapshot/mirror.sh"
arch_dispatch
aeq "legacy full-path rc" 0 "$RC"
export SSH_ORIGINAL_COMMAND="rm -rf /; echo pwned"
arch_dispatch
aeq "injection-mapped rc" 0 "$RC"
anot "injection did not execute" "pwned" "$(cat "$ROOT/out.txt")"
arch_dispatch totally-unknown-mode
aeq "unknown argv maps to mirror rc" 0 "$RC"

########################################################################################
head_ "T20 no writes outside the sandbox"
if [ -f "$REAL_AK" ]; then
  NOW_AK=$(md5 -q "$REAL_AK" 2>/dev/null || md5sum "$REAL_AK" | awk '{print $1}')
else
  NOW_AK="__missing__"
fi
aeq "real ~/.ssh/authorized_keys unchanged" "$REAL_AK_HASH" "$NOW_AK"
LAUNCHAGENTS_NOW=$(find "$REAL_HOME/Library/LaunchAgents" -type f 2>/dev/null | sort | xargs stat -f '%N %m %z' 2>/dev/null | md5 -q 2>/dev/null || true)
aeq "~/Library/LaunchAgents unchanged" "$LAUNCHAGENTS_FP" "$LAUNCHAGENTS_NOW"
NOW_SOURCE_FP=$(find "$REAL_SOURCE_STATE" -type f 2>/dev/null | sort | xargs stat -f '%N %m %z' 2>/dev/null | md5 -q 2>/dev/null || echo "__missing__")
aeq "real source trigger-history state dir unchanged" "$REAL_SOURCE_STATE_FP" "$NOW_SOURCE_FP"
NOW_ARCHIVE_FP=$(find "$REAL_ARCHIVE_STATE" -type f 2>/dev/null | sort | xargs stat -f '%N %m %z' 2>/dev/null | md5 -q 2>/dev/null || echo "__missing__")
aeq "real archive AgentSnapshot state unchanged" "$REAL_ARCHIVE_STATE_FP" "$NOW_ARCHIVE_FP"
REPO_NOW=$(md5 -q "$DISPATCH" "$MIRROR" "$KEY_LIB" 2>/dev/null | md5 -q 2>/dev/null || true)
aeq "repo dispatch scripts unchanged by selftest run" "$REPO_FP" "$REPO_NOW"
OUTSIDE=$(find "$REAL_HOME/.ssh" "$REAL_HOME/Library/LaunchAgents" \
               "$REAL_HOME/Library/Application Support/agent-snapshot/state" \
               "$REAL_HOME/Library/AgentSnapshot" \
               -newer "$MARKER" 2>/dev/null | head -5)
aeq "nothing newer than marker under real state or ssh" "" "$OUTSIDE"
DAS_AFTER=$(df -k /Volumes/SnapArchive /Volumes/SnapMirror 2>/dev/null | awk '{print $3, $6, $9}'; \
            ls -1 /Volumes/SnapArchive/snapshots /Volumes/SnapMirror/snapshots 2>/dev/null)
aeq "DAS volumes unchanged (df + snapshot dirs)" "$DAS_BEFORE" "$DAS_AFTER"

########################################################################################
printf '\n========================================\n'
printf 'ratelimit selftest: %d assertions, %d failed\n' "$TOTAL" "$FAILED"
if [ "$FAILED" -eq 0 ]; then
  printf 'RESULT: PASS\n'
  exit 0
fi
printf 'RESULT: FAIL\n'
exit 1
