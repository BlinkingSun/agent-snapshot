#!/bin/bash
# tests/test-rotation.sh — acceptance suite for snapshot-key-rotate (writer role).
#
# Everything runs under a scratch HOME on the boot disk. The real ~/.ssh,
# ~/Library/LaunchAgents, and repo files are fingerprinted at start and checked
# at end (T20-style). ssh is stubbed; no network calls are made.
#
# Exit 0 iff every assertion passes.
#
#   bash tests/test-rotation.sh

set -u

REPO=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
BIN="$REPO/bin"
ROTATE="$BIN/snapshot-key-rotate"
KEY_LIB="$BIN/snapshot-key-lib.sh"

if [ ! -x "$ROTATE" ] || [ ! -r "$KEY_LIB" ]; then
  printf 'test-rotation: missing %s or %s\n' "$ROTATE" "$KEY_LIB" >&2
  exit 3
fi

REAL_HOME="${HOME:-}"
SCRATCH=${ROTATION_SELFTEST_SCRATCH:-${TMPDIR:-/tmp}/agent-snapshot-rotation-selftest}
RUN="$SCRATCH/run.$$"
MARKER="$RUN/.start-marker"

mkdir -p "$RUN" || exit 3
: > "$MARKER"

# Refuse if we would inherit the operator's real HOME without our sandbox override.
if [ -z "${ROTATION_SELFTEST_SANDBOX:-}" ]; then
  export ROTATION_SELFTEST_SANDBOX=1
fi

# Baselines for T20 — taken BEFORE any mutation, against the real environment.
REAL_AK="$REAL_HOME/.ssh/authorized_keys"
REAL_AK_HASH=""
if [ -f "$REAL_AK" ]; then
  REAL_AK_HASH=$(md5 -q "$REAL_AK" 2>/dev/null || md5sum "$REAL_AK" | awk '{print $1}')
else
  REAL_AK_HASH="__missing__"
fi
LAUNCHAGENTS_FP=$(find "$REAL_HOME/Library/LaunchAgents" -type f 2>/dev/null | sort | xargs stat -f '%N %m %z' 2>/dev/null | md5 -q 2>/dev/null || true)
REPO_FP=$(md5 -q "$REPO/bin/snapshot-key-rotate" "$REPO/bin/snapshot-key-lib.sh" 2>/dev/null | md5 -q 2>/dev/null || true)

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

# Stub ssh — mode-aware probe control (probe-auth vs operational probe/mirror).
# ROT_SSH_PROBE_AUTH_RESULT overrides cutover auth probe; ROT_SSH_PROBE_RESULT
# controls full operational probe/mirror (and legacy fallback for all modes).
mkdir -p "$RUN/bin"
cat > "$RUN/bin/ssh" <<'SSHEOF'
#!/bin/bash
MODE="${@: -1}"
if [ -n "${ROT_SSH_CALL_LOG:-}" ]; then
  printf '%s\n' "$MODE" >> "$ROT_SSH_CALL_LOG"
fi

_ssh_stub_result() {
  case "$1" in
    probe-auth) printf '%s' "${ROT_SSH_PROBE_AUTH_RESULT:-${ROT_SSH_PROBE_RESULT:-ok}}" ;;
    probe|mirror) printf '%s' "${ROT_SSH_PROBE_RESULT:-ok}" ;;
    *) printf '%s' "${ROT_SSH_PROBE_RESULT:-ok}" ;;
  esac
}

case "$(_ssh_stub_result "$MODE")" in
  fail|1) exit 1 ;;
  *) exit 0 ;;
esac
SSHEOF
chmod +x "$RUN/bin/ssh"

# ln hook: at stable-symlink flip time, read pending active from state.json and
# assert its authorized_keys line is already present (ordering safety rail).
cat > "$RUN/bin/ln" <<'LNEOF'
#!/bin/bash
REAL=/bin/ln
if [ "${ROT_HOOK_LN:-}" = "1" ] && [ "${1:-}" = "-sfn" ] && [ -n "${ROT_STABLE_LINK:-}" ]; then
  link="${@: -1}"
  if [ "$link" = "$ROT_STABLE_LINK" ] && [ -n "${ROT_STATE_FILE:-}" ]; then
    comment=$(/usr/bin/python3 - "$ROT_STATE_FILE" <<'PY'
import json, sys
with open(sys.argv[1]) as fh:
    d = json.load(fh)
active = d.get("active") or ""
prefix = d.get("authorized_keys_comment_prefix") or "agent-snapshot"
print("%s:%s" % (prefix, active) if active else "")
PY
)
    if [ -n "$comment" ]; then
      # shellcheck disable=SC1090
      . "${ROT_KEY_LIB:?}"
      if asnap_ak_has "${ROT_AK_FILE:?}" "$comment"; then
        : > "${ROT_FLIP_OK_MARKER:?}"
      else
        : > "${ROT_FLIP_BAD_MARKER:?}"
      fi
    fi
  fi
fi
exec "$REAL" "$@"
LNEOF
chmod +x "$RUN/bin/ln"

export PATH="$RUN/bin:$PATH"
export ROT_KEY_LIB="$KEY_LIB"

# shellcheck disable=SC1090
source "$KEY_LIB"

# ---------- sandbox helpers ----------

OTHER_PUB=""
OTHER_PLAIN_PUB=""
UNRELATED_FILE=""

seed_unrelated_ak() {
  local ak="$HOME/.ssh/authorized_keys"
  mkdir -p "$HOME/.ssh"
  chmod 700 "$HOME/.ssh"

  ssh-keygen -t ed25519 -N "" -C "other-forced-job" -f "$RUN/other-key" >/dev/null 2>&1
  ssh-keygen -t ed25519 -N "" -C "operator-laptop-plain" -f "$RUN/plain-key" >/dev/null 2>&1
  OTHER_PUB="$RUN/other-key.pub"
  OTHER_PLAIN_PUB="$RUN/plain-key.pub"

  {
    printf '%s\n' \
      'restrict,command="/bin/bash '\''/usr/local/bin/other-backup.sh'\''",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty '"$(tr -s ' ' < "$OTHER_PUB")"
    cat "$OTHER_PLAIN_PUB"
    printf '# comment line that must survive\n'
  } > "$ak"
  chmod 600 "$ak"

  UNRELATED_FILE="$HOME/.ssh/.unrelated-canonical"
  /usr/bin/python3 - "$ak" "$UNRELATED_FILE" <<'PY'
import sys
lines = open(sys.argv[1]).read().splitlines()
# First three lines are the seeded unrelated entries; our rotation lines append after.
open(sys.argv[2], "w").write("\n".join(lines[:3]) + "\n")
PY
}

assert_unrelated_unchanged() {
  local label=$1 ak="$HOME/.ssh/authorized_keys" canon now
  canon=$(cat "$UNRELATED_FILE")
  now=$(/usr/bin/python3 - "$ak" <<'PY'
import sys
lines = open(sys.argv[1]).read().splitlines()
print("\n".join(lines[:3]) + ("\n" if len(lines) >= 3 else ""))
PY
)
  aeq "$label: unrelated AK prefix byte-identical" "$canon" "$now"
  ahas "$label: other forced-command line present" "other-backup.sh" "$(cat "$ak")"
  ahas "$label: plain key line present" "operator-laptop-plain" "$(cat "$ak")"
  ahas "$label: comment line present" "# comment line that must survive" "$(cat "$ak")"
}

writer_layout() {
  mkdir -p "$HOME/Library/Application Support/agent-snapshot/bin" \
           "$HOME/Library/Application Support/agent-snapshot/conf" \
           "$HOME/Library/Caches/agent-snapshot"
  printf '#!/bin/bash\nexit 0\n' > "$HOME/Library/Application Support/agent-snapshot/bin/snapshot-dispatch"
  chmod +x "$HOME/Library/Application Support/agent-snapshot/bin/snapshot-dispatch"
  cat > "$HOME/Library/Application Support/agent-snapshot/conf/snapshot.conf" <<CONF
STAGE="$HOME/Library/Caches/agent-snapshot"
KEY_ROTATION_DAYS=90
KEY_OVERLAP_HOURS=72
KEY_ROTATION_APPLY_AK=true
CONF
}

newroot() {
  ROOT="$RUN/$1"
  HOME="$ROOT/home"
  export HOME
  rm -rf "$ROOT"
  mkdir -p "$ROOT"
  writer_layout
  seed_unrelated_ak
  unset ROT_SSH_PROBE_RESULT ROT_SSH_PROBE_AUTH_RESULT ROT_SSH_CALL_LOG \
        ROT_HOOK_LN ROT_STABLE_LINK ROT_STATE_FILE \
        ROT_AK_FILE ROT_FLIP_OK_MARKER ROT_FLIP_BAD_MARKER ACTIVE REGISTRY 2>/dev/null || true
  export ROT_SSH_PROBE_RESULT=ok
}

kr() {
  # shellcheck disable=SC2068
  "$ROTATE" --role writer "$@" >"$ROOT/out.txt" 2>"$ROOT/err.txt"
  RC=$?
}

make_legacy_key() {
  local priv="$HOME/.ssh/id_ed25519_agent_snapshot"
  ssh-keygen -t ed25519 -N "" -C "agent-snapshot" -f "$priv" >/dev/null 2>&1
  chmod 600 "$priv" "${priv}.pub"
  LEGACY_PUB_BYTES=$(cat "${priv}.pub")
}

sync_registry() {
  REGISTRY="$(asnap_registry_dir)"
  ACTIVE="$(state_field active)"
}

bootstrap_once() {
  kr bootstrap --apply-authorized-keys
  aeq "bootstrap rc" 0 "$RC"
  sync_registry
  aeq "state.json created" "yes" "$([ -f "$REGISTRY/state.json" ] && echo yes || echo no)"
}

stable_pub_bytes() {
  local link target dir
  link="$HOME/.ssh/id_ed25519_agent_snapshot"
  target="$(readlink "$link" 2>/dev/null || true)"
  [ -n "$target" ] || { cat "${link}.pub" 2>/dev/null; return; }
  case "$target" in
    /*) cat "${target}.pub" ;;
    *) dir="$(dirname "$link")"; cat "$dir/$target.pub" ;;
  esac
}

ak_line_count() {
  if [ ! -f "$HOME/.ssh/authorized_keys" ]; then
    echo 0
    return
  fi
  /usr/bin/wc -l < "$HOME/.ssh/authorized_keys" | tr -dc '0-9'
}

ak_backup_count() {
  ls -1 "$HOME/.ssh/authorized_keys.bak-"* 2>/dev/null | wc -l | tr -d ' '
}

latest_ak_backup() {
  ls -1t "$HOME/.ssh/authorized_keys.bak-"* 2>/dev/null | head -1
}

symlink_target() {
  readlink "$HOME/.ssh/id_ed25519_agent_snapshot" 2>/dev/null || true
}

state_field() {
  /usr/bin/python3 - "$REGISTRY/state.json" "$1" <<'PY'
import json, sys
path, field = sys.argv[1], sys.argv[2]
with open(path) as fh:
    d = json.load(fh)
v = d.get(field)
print("" if v is None else v)
PY
}

age_key_days() {
  local key_id=$1 epoch now
  key_id=${1:-$(state_field active)}
  epoch=$(asnap_mtime "$REGISTRY/keys/$key_id")
  now=$(date +%s)
  /usr/bin/python3 - "$epoch" "$now" <<'PY'
import sys
start, now = int(sys.argv[1]), int(sys.argv[2])
print(max(0, (now - start) // 86400))
PY
}

set_key_age_days() {
  local key_id=$1 days=$2 epoch
  key_id=${1:-$(state_field active)}
  epoch=$(/usr/bin/python3 - "$days" <<'PY'
import sys, time
days = int(sys.argv[1])
print(int(time.time()) - days * 86400)
PY
)
  /usr/bin/python3 - "$REGISTRY/keys/$key_id" "$epoch" <<'PY'
import os, sys
path, epoch = sys.argv[1], int(sys.argv[2])
os.utime(path, (epoch, epoch))
pub = path + ".pub"
if os.path.exists(pub):
    os.utime(pub, (epoch, epoch))
PY
}

set_overlap_expired() {
  /usr/bin/python3 - "$REGISTRY/state.json" <<'PY'
import json, sys, datetime
path = sys.argv[1]
with open(path) as fh:
    d = json.load(fh)
past = (datetime.datetime.now().astimezone() - datetime.timedelta(hours=1)).isoformat(timespec="seconds")
d["overlap_until"] = past
with open(path, "w") as fh:
    json.dump(d, fh, indent=1, sort_keys=True)
    fh.write("\n")
PY
}

append_active_ak_line() {
  local active=$1 comment line pub
  active=${1:-$(state_field active)}
  comment="agent-snapshot:$active"
  pub="$REGISTRY/keys/$active.pub"
  line=$(asnap_ak_line "$HOME/Library/Application Support/agent-snapshot/bin/snapshot-dispatch" "$pub" "$comment")
  asnap_ak_append "$HOME/.ssh/authorized_keys" "$line"
}

hold_busy_lock() {
  local stage="$HOME/Library/Caches/agent-snapshot"
  mkdir -p "$stage"
  # Hold a subshell alive so kill -0 succeeds on the recorded pid.
  ( sleep 300 ) &
  BUSY_PID=$!
  printf '%s\n' "$BUSY_PID" > "$stage/.pid"
}

release_busy_lock() {
  [ -n "${BUSY_PID:-}" ] && kill "$BUSY_PID" 2>/dev/null && wait "$BUSY_PID" 2>/dev/null || true
  rm -f "$HOME/Library/Caches/agent-snapshot/.pid"
  unset BUSY_PID
}

count_bare_agent_snapshot_lines() {
  if [ ! -f "$HOME/.ssh/authorized_keys" ]; then
    echo 0
    return
  fi
  /usr/bin/python3 - "$HOME/.ssh/authorized_keys" <<'PY'
import sys
path = sys.argv[1]
try:
    lines = open(path).read().splitlines()
except IOError:
    print(0)
    sys.exit(0)
count = 0
for line in lines:
    parts = line.strip().split()
    if parts and not line.lstrip().startswith("#") and parts[-1] == "agent-snapshot":
        count += 1
print(count)
PY
}

append_bare_agent_snapshot_line() {
  local key_id=${1:-$(state_field active)}
  local forced_cmd=${2:-$HOME/Library/Application Support/agent-snapshot/bin/snapshot-dispatch}
  local pub="$REGISTRY/keys/$key_id.pub"
  local line
  line=$(asnap_ak_line "$forced_cmd" "$pub" "agent-snapshot")
  asnap_ak_append "$HOME/.ssh/authorized_keys" "$line"
}

ak_file_digest() {
  if [ ! -f "$HOME/.ssh/authorized_keys" ]; then
    echo "__missing__"
    return
  fi
  md5 -q "$HOME/.ssh/authorized_keys" 2>/dev/null || md5sum "$HOME/.ssh/authorized_keys" | awk '{print $1}'
}

induce_split_brain() {
  local state_active=$1
  /usr/bin/python3 - "$REGISTRY/state.json" "$state_active" <<'PY'
import json, sys
path, active = sys.argv[1], sys.argv[2]
with open(path) as fh:
    d = json.load(fh)
d["active"] = active
d["previous"] = None
d["overlap_until"] = None
with open(path, "w") as fh:
    json.dump(d, fh, indent=1, sort_keys=True)
    fh.write("\n")
PY
}

ssh_modes_called() {
  [ -f "${ROT_SSH_CALL_LOG:-}" ] || return 0
  cat "$ROT_SSH_CALL_LOG"
}

########################################################################################
head_ "T01 bootstrap: legacy flat key -> registry, symlink, idempotent"
newroot t01
make_legacy_key
PUB_BEFORE="$LEGACY_PUB_BYTES"
kr bootstrap --apply-authorized-keys
aeq "bootstrap rc" 0 "$RC"
REGISTRY="$(asnap_registry_dir)"
aeq "registry dir exists" "yes" "$([ -d "$REGISTRY" ] && echo yes || echo no)"
aeq "stable symlink is a symlink" "yes" "$([ -L "$HOME/.ssh/id_ed25519_agent_snapshot" ] && echo yes || echo no)"
TARGET="$(symlink_target)"
ahas "symlink points into registry keys/" "agent-snapshot/keys/" "$TARGET"
PUB_AFTER=$(stable_pub_bytes)
aeq "public key byte-identical after bootstrap" "$PUB_BEFORE" "$PUB_AFTER"
sync_registry
ACTIVE="$(state_field active)"
ane "legacy flat private key file removed from stable path" "file" \
    "$([ -f "$HOME/.ssh/id_ed25519_agent_snapshot" ] && [ ! -L "$HOME/.ssh/id_ed25519_agent_snapshot" ] && echo file || echo symlink)"
ACTIVE="$(state_field active)"
ahas "active key id recorded" "key-legacy-" "$ACTIVE"
kr bootstrap --apply-authorized-keys
aeq "bootstrap re-run rc" 0 "$RC"
aeq "bootstrap idempotent: same active key" "$ACTIVE" "$(state_field active)"
assert_unrelated_unchanged "T01 after bootstrap"

########################################################################################
head_ "T02 rotate happy path: append+verify BEFORE flip, overlap coexistence"
newroot t02
make_legacy_key
bootstrap_once
append_active_ak_line "$ACTIVE"
sleep 1
assert_unrelated_unchanged "T02 before rotate"
OLD_TARGET="$(symlink_target)"
OLD_ACTIVE="$ACTIVE"
AK_BEFORE=$(ak_line_count)
BACKUPS_BEFORE=$(ak_backup_count)

export ROT_HOOK_LN=1
export ROT_STABLE_LINK="$HOME/.ssh/id_ed25519_agent_snapshot"
export ROT_STATE_FILE="$REGISTRY/state.json"
export ROT_AK_FILE="$HOME/.ssh/authorized_keys"
export ROT_FLIP_OK_MARKER="$ROOT/flip-ok"
export ROT_FLIP_BAD_MARKER="$ROOT/flip-bad"
rm -f "$ROT_FLIP_OK_MARKER" "$ROT_FLIP_BAD_MARKER"
OLD_COMMENT="agent-snapshot:$OLD_ACTIVE"

kr rotate --apply-authorized-keys
aeq "rotate rc" 0 "$RC"
NEW_ACTIVE="$(state_field active)"
PREV="$(state_field previous)"
ane "active key changed" "$OLD_ACTIVE" "$NEW_ACTIVE"
aeq "previous key recorded" "$OLD_ACTIVE" "$PREV"
aeq "ln hook: AK present before symlink flip" "yes" \
    "$([ -f "$ROT_FLIP_OK_MARKER" ] && echo yes || echo no)"
anot "ln hook: flip before AK present" "yes" \
    "$([ -f "$ROT_FLIP_BAD_MARKER" ] && echo yes || echo no)"
LOG="$(cat "$REGISTRY/rotation.log" 2>/dev/null)"
APPEND_LINE=$(grep -n "appended and verified AK line" "$REGISTRY/rotation.log" 2>/dev/null | head -1 | cut -d: -f1)
FLIP_LINE=$(grep -n "flipped symlink to" "$REGISTRY/rotation.log" 2>/dev/null | tail -1 | cut -d: -f1)
if [ -n "$APPEND_LINE" ] && [ -n "$FLIP_LINE" ] && [ "$APPEND_LINE" -lt "$FLIP_LINE" ]; then
  ok "rotation.log: append+verify logged before flip [$APPEND_LINE < $FLIP_LINE]"
else
  bad "rotation.log: append+verify logged before flip  expected append<flip got append=$APPEND_LINE flip=$FLIP_LINE"
fi
asnap_ak_has "$HOME/.ssh/authorized_keys" "agent-snapshot:$NEW_ACTIVE" && ok "new AK line present [yes]" || bad "new AK line present  expected yes got no"
asnap_ak_has "$HOME/.ssh/authorized_keys" "$OLD_COMMENT" && ok "previous AK line still present during overlap [yes]" || bad "previous AK line still present during overlap  expected yes got no"
aeq "AK line count increased by 1" "$((AK_BEFORE + 1))" "$(ak_line_count)"
aeq "symlink now points at new key" "$NEW_ACTIVE" "$(basename "$(symlink_target)")"
BACKUPS_AFTER=$(ak_backup_count)
agt "rotate created at least one AK backup" "$BACKUPS_BEFORE" "$BACKUPS_AFTER"
BAK="$(latest_ak_backup)"
aeq "latest backup exists" "yes" "$([ -n "$BAK" ] && echo yes || echo no)"
if [ -n "$BAK" ]; then
  aeq "backup holds pre-append authorized_keys (line count)" "$AK_BEFORE" "$(wc -l < "$BAK" | tr -dc '0-9')"
fi
assert_unrelated_unchanged "T02 after rotate"

########################################################################################
head_ "T03 rotate rollback: failing probe restores symlink, state, AK count"
newroot t03
make_legacy_key
bootstrap_once
append_active_ak_line "$ACTIVE"
OLD_TARGET="$(symlink_target)"
OLD_ACTIVE="$ACTIVE"
AK_BEFORE=$(ak_line_count)
STATE_BEFORE=$(md5 -q "$REGISTRY/state.json" 2>/dev/null || md5sum "$REGISTRY/state.json" | awk '{print $1}')

export ROT_SSH_PROBE_RESULT=fail
kr rotate --apply-authorized-keys
aeq "rotate with failing probe rc" 1 "$RC"
ahas "stderr mentions rollback" "rolled back" "$(cat "$ROOT/err.txt")"
aeq "symlink target restored" "$(basename "$OLD_TARGET")" "$(basename "$(symlink_target)")"
STATE_AFTER=$(md5 -q "$REGISTRY/state.json" 2>/dev/null || md5sum "$REGISTRY/state.json" | awk '{print $1}')
aeq "state.json restored to pre-rotate" "$STATE_BEFORE" "$STATE_AFTER"
aeq "AK line count restored" "$AK_BEFORE" "$(ak_line_count)"
aeq "only one agent-snapshot keyed AK line after rollback" "1" \
    "$(grep -cE ' agent-snapshot:key-' "$HOME/.ssh/authorized_keys" 2>/dev/null | tr -dc '0-9' || echo 0)"
aeq "active key unchanged in state" "$OLD_ACTIVE" "$(state_field active)"
aeq "overlap_until cleared after rollback" "" "$(state_field overlap_until)"
aeq "previous cleared after rollback" "" "$(state_field previous)"
export ROT_SSH_PROBE_RESULT=ok
assert_unrelated_unchanged "T03 after failed rotate"

########################################################################################
head_ "T04 finalize: overlap guard, previous-only removal, active line preserved"
newroot t04
make_legacy_key
bootstrap_once
append_active_ak_line "$ACTIVE"
kr rotate --apply-authorized-keys
aeq "setup rotate rc" 0 "$RC"
NEW_ACTIVE="$(state_field active)"
OLD_ACTIVE="$(state_field previous)"
NEW_COMMENT="agent-snapshot:$NEW_ACTIVE"
OLD_COMMENT="agent-snapshot:$OLD_ACTIVE"

kr finalize
aeq "finalize refused while overlap active rc" 1 "$RC"
ahas "finalize overlap refusal message" "overlap window still active" "$(cat "$ROOT/err.txt")"
asnap_ak_has "$HOME/.ssh/authorized_keys" "$OLD_COMMENT" && ok "previous AK line still present before forced finalize [yes]" || bad "previous AK line still present before forced finalize  expected yes got no"

set_overlap_expired
kr finalize --apply-authorized-keys
aeq "finalize after expiry rc" 0 "$RC"
anot "previous AK line removed" "$OLD_COMMENT" "$(cat "$HOME/.ssh/authorized_keys")"
asnap_ak_has "$HOME/.ssh/authorized_keys" "$NEW_COMMENT" && ok "active AK line preserved after finalize [yes]" || bad "active AK line preserved after finalize  expected yes got no"
aeq "state previous cleared" "" "$(state_field previous)"
assert_unrelated_unchanged "T04 after finalize"

########################################################################################
head_ "T05 rotate-if-due: young no-op, old rotates, unbootstrapped safe"
newroot t05
make_legacy_key
bootstrap_once
append_active_ak_line "$ACTIVE"
set_key_age_days "$ACTIVE" 10
kr rotate-if-due --apply-authorized-keys
aeq "young key rotate-if-due rc" 0 "$RC"
aeq "young key: active unchanged" "$ACTIVE" "$(state_field active)"
anot "young key: no rotation log entry" "rotate: OK" "$(cat "$REGISTRY/rotation.log" 2>/dev/null)"

set_key_age_days "$ACTIVE" 120
kr rotate-if-due --apply-authorized-keys
aeq "old key rotate-if-due rc" 0 "$RC"
ane "old key: active changed" "$ACTIVE" "$(state_field active)"
assert_unrelated_unchanged "T05 after rotate-if-due on old key"

# unbootstrapped install: bootstrap only, no AK destruction
newroot t05b
make_legacy_key
UNRELATED_CANON=$(cat "$UNRELATED_FILE")
kr rotate-if-due --apply-authorized-keys
aeq "unbootstrapped rotate-if-due rc" 0 "$RC"
aeq "unbootstrapped: registry bootstrapped" "yes" "$([ -f "$(asnap_registry_dir)/state.json" ] && echo yes || echo no)"
aeq "unbootstrapped: unrelated canonical prefix untouched" "$UNRELATED_CANON" "$(cat "$UNRELATED_FILE")"
assert_unrelated_unchanged "T05 unbootstrapped bootstrap only"

########################################################################################
head_ "T06 busy refusal: exit 79 while writer stage lock is held"
newroot t06
make_legacy_key
bootstrap_once
append_active_ak_line "$ACTIVE"
hold_busy_lock
kr rotate --apply-authorized-keys
release_busy_lock
aeq "busy rotate rc" 79 "$RC"
ahas "busy message" "run in progress" "$(cat "$ROOT/err.txt")"
aeq "active key unchanged under busy" "$ACTIVE" "$(state_field active)"
assert_unrelated_unchanged "T06 after busy refusal"

########################################################################################
head_ "T07 backups: every AK edit leaves timestamped .bak- with pre-edit content"
newroot t07
make_legacy_key
bootstrap_once
append_active_ak_line "$ACTIVE"
sleep 1
AK0=$(ak_line_count)
BACKUPS0=$(ak_backup_count)
kr rotate --apply-authorized-keys
aeq "rotate for backup test rc" 0 "$RC"
agt "rotate increased AK backup count" "$BACKUPS0" "$(ak_backup_count)"
B1=$(latest_ak_backup)
aeq "append backup filename pattern" "yes" "$(basename "$B1" | grep -E '^authorized_keys\.bak-[0-9]{8}-[0-9]{6}$' >/dev/null && echo yes || echo no)"
aeq "rotate backup line count matches pre-rotate AK" "$AK0" "$(wc -l < "$B1" | tr -dc '0-9')"

PREV_ACTIVE="$(state_field previous)"
PREV_COMMENT="agent-snapshot:$PREV_ACTIVE"
AK1=$(ak_line_count)
BACKUPS1=$(ak_backup_count)
sleep 1
set_overlap_expired
kr finalize --apply-authorized-keys
aeq "finalize for backup test rc" 0 "$RC"
agt "finalize increased AK backup count" "$BACKUPS1" "$(ak_backup_count)"
B2=$(latest_ak_backup)
ane "finalize backup path differs from rotate backup" "$B1" "$B2"
aeq "remove backup line count matches pre-remove" "$AK1" "$(wc -l < "$B2" | tr -dc '0-9')"
ahas "remove backup still contains removed comment" "$PREV_COMMENT" "$(cat "$B2")"
assert_unrelated_unchanged "T07 after backup edits"

########################################################################################
head_ "T08 non-interference: unrelated AK lines survive every operation"
newroot t08
make_legacy_key
assert_unrelated_unchanged "T08 seed"
bootstrap_once
assert_unrelated_unchanged "T08 after bootstrap"
append_active_ak_line "$ACTIVE"
assert_unrelated_unchanged "T08 after append active line"
kr rotate --apply-authorized-keys
assert_unrelated_unchanged "T08 after rotate"
set_overlap_expired
kr finalize --apply-authorized-keys
assert_unrelated_unchanged "T08 after finalize"
export ROT_SSH_PROBE_RESULT=fail
kr rotate --apply-authorized-keys
export ROT_SSH_PROBE_RESULT=ok
assert_unrelated_unchanged "T08 after failed rotate"
kr rotate-if-due --apply-authorized-keys
assert_unrelated_unchanged "T08 after rotate-if-due"

########################################################################################
head_ "T09 split-brain refusal: finalize and rotate-if-due refuse without AK mutation"
newroot t09
make_legacy_key
bootstrap_once
append_active_ak_line "$ACTIVE"
kr rotate --apply-authorized-keys
aeq "setup rotate rc" 0 "$RC"
OLD_ACTIVE="$ACTIVE"
NEW_ACTIVE="$(state_field active)"
SYMLINK_KEY="$(basename "$(symlink_target)")"
aeq "setup: symlink on new key" "$NEW_ACTIVE" "$SYMLINK_KEY"
induce_split_brain "$OLD_ACTIVE"
aeq "split-brain: state active is old key" "$OLD_ACTIVE" "$(state_field active)"
ane "split-brain: symlink still on new key" "$OLD_ACTIVE" "$(basename "$(symlink_target)")"
AK_DIGEST="$(ak_file_digest)"
kr status
ahas "status pending reports SPLIT-BRAIN" "SPLIT-BRAIN" "$(cat "$ROOT/out.txt")"
kr finalize --apply-authorized-keys
aeq "finalize rc under split-brain" 1 "$RC"
ahas "finalize stderr SPLIT-BRAIN" "SPLIT-BRAIN" "$(cat "$ROOT/err.txt")"
aeq "finalize: authorized_keys unchanged" "$AK_DIGEST" "$(ak_file_digest)"
kr rotate-if-due --apply-authorized-keys
aeq "rotate-if-due rc under split-brain" 1 "$RC"
ahas "rotate-if-due stderr SPLIT-BRAIN" "SPLIT-BRAIN" "$(cat "$ROOT/err.txt")"
aeq "rotate-if-due: authorized_keys unchanged" "$AK_DIGEST" "$(ak_file_digest)"
asnap_ak_has "$HOME/.ssh/authorized_keys" "agent-snapshot:$OLD_ACTIVE" && ok "split-brain: old structured AK line preserved [yes]" || bad "split-brain: old structured AK line preserved  expected yes got no"
asnap_ak_has "$HOME/.ssh/authorized_keys" "agent-snapshot:$NEW_ACTIVE" && ok "split-brain: new structured AK line preserved [yes]" || bad "split-brain: new structured AK line preserved  expected yes got no"
assert_unrelated_unchanged "T09 after split-brain refusals"

########################################################################################
head_ "T10 legacy bare-comment cleanup: remove, refuse collateral, refuse ambiguous"
newroot t10pos
make_legacy_key
bootstrap_once
append_bare_agent_snapshot_line "$ACTIVE"
append_active_ak_line "$ACTIVE"
BARE_BEFORE=$(count_bare_agent_snapshot_lines)
aeq "positive setup: one bare agent-snapshot line" "1" "$BARE_BEFORE"
OLD_ACTIVE="$ACTIVE"
kr rotate --apply-authorized-keys
aeq "positive: rotate rc after legacy cleanup" 0 "$RC"
aeq "positive: bare agent-snapshot line removed" "0" "$(count_bare_agent_snapshot_lines)"
asnap_ak_has "$HOME/.ssh/authorized_keys" "agent-snapshot:$OLD_ACTIVE" && ok "positive: previous structured line kept during overlap [yes]" || bad "positive: previous structured line kept during overlap  expected yes got no"
asnap_ak_has "$HOME/.ssh/authorized_keys" "agent-snapshot:$(state_field active)" && ok "positive: new structured line present [yes]" || bad "positive: new structured line present  expected yes got no"
assert_unrelated_unchanged "T10 positive after legacy cleanup"

newroot t10coll
make_legacy_key
bootstrap_once
append_active_ak_line "$ACTIVE"
append_bare_agent_snapshot_line "$ACTIVE" "/usr/local/bin/other-backup.sh"
COLLATERAL_LINE='restrict,command="/bin/bash '\''/usr/local/bin/other-backup.sh'\''"'
BARE_BEFORE=$(count_bare_agent_snapshot_lines)
kr rotate --apply-authorized-keys
aeq "collateral: rotate rc (legacy cleanup refused)" 75 "$RC"
ahas "collateral: operator told forced command differs" "forced command differs" "$(cat "$ROOT/err.txt")"
aeq "collateral: bare line count unchanged" "$BARE_BEFORE" "$(count_bare_agent_snapshot_lines)"
ahas "collateral: other-job line still present" "other-backup.sh" "$(cat "$HOME/.ssh/authorized_keys")"
asnap_ak_has "$HOME/.ssh/authorized_keys" "agent-snapshot" && ok "collateral: bare comment line preserved [yes]" || bad "collateral: bare comment line preserved  expected yes got no"
assert_unrelated_unchanged "T10 collateral after refused cleanup"

newroot t10multi
make_legacy_key
bootstrap_once
append_bare_agent_snapshot_line "$ACTIVE"
ssh-keygen -t ed25519 -N "" -C "agent-snapshot" -f "$RUN/extra-bare-key" >/dev/null 2>&1
line=$(asnap_ak_line "$HOME/Library/Application Support/agent-snapshot/bin/snapshot-dispatch" "$RUN/extra-bare-key.pub" "agent-snapshot")
asnap_ak_append "$HOME/.ssh/authorized_keys" "$line"
append_active_ak_line "$ACTIVE"
BARE_BEFORE=$(count_bare_agent_snapshot_lines)
aeq "ambiguous setup: two bare agent-snapshot lines" "2" "$BARE_BEFORE"
kr rotate --apply-authorized-keys
aeq "ambiguous: rotate rc (legacy cleanup refused)" 75 "$RC"
ahas "ambiguous: refuse multiple bare lines message" "multiple lines with bare comment" "$(cat "$ROOT/err.txt")"
aeq "ambiguous: bare line count unchanged" "$BARE_BEFORE" "$(count_bare_agent_snapshot_lines)"
assert_unrelated_unchanged "T10 ambiguous after refused cleanup"

########################################################################################
head_ "T11 probe-auth gating: cutover auth probe only; operational probe must not block rotate"
newroot t11
make_legacy_key
bootstrap_once
append_active_ak_line "$ACTIVE"
export ROT_SSH_PROBE_AUTH_RESULT=ok
export ROT_SSH_PROBE_RESULT=fail
export ROT_SSH_CALL_LOG="$ROOT/ssh-calls.log"
: > "$ROT_SSH_CALL_LOG"
kr rotate --apply-authorized-keys
aeq "rotate succeeds when operational probe stub fails" 0 "$RC"
MODES="$(ssh_modes_called)"
ahas "cutover ssh mode is probe-auth" "probe-auth" "$MODES"
case "$MODES" in
  *$'\n'probe$*|*$'\n'probe$'\n'*|$'\n'probe) bad "cutover must not invoke full operational probe  got modes=<<$MODES>>" ;;
  *) ok "cutover did not invoke full operational probe" ;;
esac
kr probe
aeq "explicit operational probe fails when stubbed" 1 "$RC"

newroot t11rollback
make_legacy_key
bootstrap_once
append_active_ak_line "$ACTIVE"
OLD_ACTIVE="$ACTIVE"
OLD_TARGET="$(symlink_target)"
AK_BEFORE=$(ak_line_count)
STATE_BEFORE=$(md5 -q "$REGISTRY/state.json" 2>/dev/null || md5sum "$REGISTRY/state.json" | awk '{print $1}')
unset ROT_SSH_PROBE_AUTH_RESULT
export ROT_SSH_PROBE_RESULT=fail
export ROT_SSH_CALL_LOG="$ROOT/ssh-calls.log"
: > "$ROT_SSH_CALL_LOG"
kr rotate --apply-authorized-keys
aeq "probe-auth failure rotate rc" 1 "$RC"
ahas "probe-auth failure triggers rollback message" "rolled back" "$(cat "$ROOT/err.txt")"
anot "probe-auth rollback not mislabeled catastrophic" "CATASTROPHIC" "$(cat "$ROOT/err.txt")"
ahas "cutover attempted probe-auth" "probe-auth" "$(ssh_modes_called)"
aeq "probe-auth failure: symlink restored" "$(basename "$OLD_TARGET")" "$(basename "$(symlink_target)")"
aeq "probe-auth failure: state restored" "$STATE_BEFORE" "$(md5 -q "$REGISTRY/state.json" 2>/dev/null || md5sum "$REGISTRY/state.json" | awk '{print $1}')"
aeq "probe-auth failure: AK line count restored" "$AK_BEFORE" "$(ak_line_count)"
aeq "probe-auth failure: active key unchanged" "$OLD_ACTIVE" "$(state_field active)"
export ROT_SSH_PROBE_AUTH_RESULT=ok
export ROT_SSH_PROBE_RESULT=ok
assert_unrelated_unchanged "T11 after probe-auth rollback"

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
REPO_NOW=$(md5 -q "$REPO/bin/snapshot-key-rotate" "$REPO/bin/snapshot-key-lib.sh" 2>/dev/null | md5 -q 2>/dev/null || true)
aeq "repo rotation scripts unchanged by selftest run" "$REPO_FP" "$REPO_NOW"
OUTSIDE=$(find "$REAL_HOME/.ssh" "$REAL_HOME/Library/LaunchAgents" -newer "$MARKER" 2>/dev/null | head -5)
aeq "nothing newer than marker under real ~/.ssh or LaunchAgents" "" "$OUTSIDE"

########################################################################################
printf '\n========================================\n'
printf 'rotation selftest: %d assertions, %d failed\n' "$TOTAL" "$FAILED"
if [ "$FAILED" -eq 0 ]; then
  printf 'RESULT: PASS\n'
  exit 0
fi
printf 'RESULT: FAIL\n'
exit 1
