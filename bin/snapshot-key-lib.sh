#!/bin/bash
# snapshot-key-lib.sh — shared helpers for rate-limit admission and authorized_keys
# editing used by snapshot-dispatch, mirror.sh, and snapshot-key-rotate.
#
# WHY mkdir locking: macOS ships no flock(1) binary (see bin/snapshot). Portable
# mutual exclusion uses atomic mkdir(2): only one process creates the lock directory;
# the winner writes its PID inside. Dead PIDs are stolen so stale locks recover.
#
# Source this file; it defines functions only (no side effects at source time).

# ---------- paths ----------

asnap_appdir() {
  printf '%s\n' "$HOME/Library/Application Support/agent-snapshot"
}

asnap_state_dir() {
  local d old_umask
  d="$(asnap_appdir)/state"
  if [ ! -d "$d" ]; then
    old_umask=$(umask)
    umask 077
    mkdir -p "$d"
    umask "$old_umask"
  fi
  printf '%s\n' "$d"
}

asnap_registry_dir() {
  printf '%s\n' "$HOME/.ssh/agent-snapshot"
}

asnap_mtime() {
  local path=$1
  /usr/bin/python3 - "$path" <<'PY'
import os, sys
path = sys.argv[1]
try:
    print(int(os.path.getmtime(path)))
except OSError:
    pass
PY
}

# ---------- locking (portable; NO flock(1)) ----------

_asnap_lock_stale() {
  local lockdir=$1 owner
  owner=""
  if [ -f "$lockdir/pid" ]; then
    owner=$(tr -dc '0-9' < "$lockdir/pid" 2>/dev/null || true)
  fi
  if [ -z "$owner" ]; then
    return 0
  fi
  kill -0 "$owner" 2>/dev/null && return 1
  return 0
}

asnap_lock_acquire() {
  local lockdir=$1
  local timeout=${2-}
  local deadline owner
  deadline=0
  if [ -n "$timeout" ]; then
    deadline=$(( $(date +%s) + timeout ))
  fi
  while :; do
    if mkdir "$lockdir" 2>/dev/null; then
      printf '%s\n' "$$" > "$lockdir/pid"
      return 0
    fi
    if _asnap_lock_stale "$lockdir"; then
      rm -rf "$lockdir" 2>/dev/null || true
      continue
    fi
    if [ "$deadline" -ne 0 ] && [ "$(date +%s)" -ge "$deadline" ]; then
      return 1
    fi
    sleep 0.05 2>/dev/null || sleep 1
  done
}

asnap_lock_release() {
  local lockdir=$1 owner
  [ -d "$lockdir" ] || return 0
  owner=$(tr -dc '0-9' < "$lockdir/pid" 2>/dev/null || true)
  if [ "$owner" = "$$" ]; then
    rm -rf "$lockdir"
  fi
}

# ---------- atomic write ----------

asnap_write_atomic() {
  local path=$1
  local dir tmp old_umask
  dir=$(dirname "$path")
  mkdir -p "$dir" || return 1
  tmp=$(mktemp "${dir}/.tmp-asnap.XXXXXX") || return 1
  if ! cat > "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  old_umask=$(umask)
  umask 077
  chmod 0600 "$tmp" 2>/dev/null || true
  umask "$old_umask"
  mv -f "$tmp" "$path"
}

# ---------- admission control ----------

# Flock probe for file locks (e.g. archive mirror.pid). rc 0 = held by another process (busy).
asnap_flock_busy() {
  local lock_path=$1
  /usr/bin/python3 - "$lock_path" <<'PY'
import fcntl, os, sys
path = sys.argv[1]
try:
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o644)
except OSError:
    sys.exit(1)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except (IOError, OSError):
    os.close(fd)
    sys.exit(0)
try:
    fcntl.flock(fd, fcntl.LOCK_UN)
finally:
    os.close(fd)
sys.exit(1)
PY
}

_asnap_is_busy() {
  local busy_lock=$1 stage pidfile pid
  [ -n "$busy_lock" ] || return 1
  # Archive engine holds flock(LOCK_EX) on a regular file (mirror.pid).
  if [ -f "$busy_lock" ]; then
    asnap_flock_busy "$busy_lock"
    return $?
  fi
  # mkdir lockdir (portable lock) with pid inside.
  if [ -d "$busy_lock" ] && [ -f "$busy_lock/pid" ]; then
    pid=$(tr -dc '0-9' < "$busy_lock/pid" 2>/dev/null || true)
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
    return $?
  fi
  # Source writer: busy_lock is STAGE/.lock; live run advertises STAGE/.pid.
  stage=$(dirname "$busy_lock")
  pidfile="$stage/.pid"
  if [ ! -f "$pidfile" ]; then
    return 1
  fi
  pid=$(tr -dc '0-9' < "$pidfile" 2>/dev/null || true)
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

asnap_admit() {
  local history_json=$1 lock_dir=$2 busy_lock=$3 lane=$4 mode=$5 client=$6
  local burst_limit=$7 burst_window=$8 sustain_limit=$9 sustain_window=${10}
  local deny_json=${11}
  local py_rc

  if ! asnap_lock_acquire "$lock_dir"; then
    return 1
  fi

  if [ -n "$busy_lock" ] && _asnap_is_busy "$busy_lock"; then
    asnap_lock_release "$lock_dir"
    return 79
  fi

  /usr/bin/python3 - "$history_json" "$lane" "$mode" "$client" \
      "$burst_limit" "$burst_window" "$sustain_limit" "$sustain_window" \
      "$deny_json" <<'PY'
import json, os, sys, time, tempfile
from datetime import datetime, timezone

history_path, lane, mode, client = sys.argv[1:5]
burst_limit = int(sys.argv[5])
burst_window = int(sys.argv[6])
sustain_limit = int(sys.argv[7])
sustain_window = int(sys.argv[8])
deny_path = sys.argv[9]
now = int(time.time())
max_window = max(burst_window, sustain_window)
cutoff = now - max_window

def load_history():
    file_lane = None
    try:
        with open(history_path, "r") as fh:
            data = json.load(fh)
    except (IOError, OSError, ValueError):
        data = {"schema": 1, "lane": lane, "entries": []}
    if not isinstance(data, dict):
        data = {"schema": 1, "lane": lane, "entries": []}
    file_lane = data.get("lane")
    entries = data.get("entries")
    if not isinstance(entries, list):
        entries = []
    pruned = [e for e in entries if isinstance(e, dict) and int(e.get("ts", 0)) >= cutoff]
    pruned.sort(key=lambda e: int(e.get("ts", 0)))
    if len(pruned) > 64:
        pruned = pruned[-64:]
    data["schema"] = 1
    data["lane"] = lane
    data["entries"] = pruned
    data["_file_lane"] = file_lane
    return data

def entry_lane(entry, file_lane):
    el = entry.get("lane")
    if el:
        return el
    # Backward compatible: legacy entries without per-entry lane inherit file-level lane,
    # or the requesting lane when the file predates lane metadata (single-lane callers).
    if file_lane:
        return file_lane
    return lane

def lane_entries(entries, file_lane):
    return [e for e in entries if entry_lane(e, file_lane) == lane]

def count_window(entries, window):
    floor = now - window
    return sum(1 for e in entries if int(e.get("ts", 0)) >= floor)

def oldest_in_window(entries, window):
    floor = now - window
    ts = [int(e.get("ts", 0)) for e in entries if int(e.get("ts", 0)) >= floor]
    return min(ts) if ts else now

def write_deny(reason, burst_count, sustain_count, retry_after_ts):
    iso = datetime.fromtimestamp(now, tz=timezone.utc).astimezone().isoformat(timespec="seconds")
    payload = {
        "schema": 1,
        "ts": now,
        "iso": iso,
        "mode": mode,
        "reason": reason,
        "burst_count": burst_count,
        "sustain_count": sustain_count,
        "client": client,
        "retry_after_ts": retry_after_ts,
    }
    d = os.path.dirname(deny_path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-asnap.", dir=d)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(payload, fh, indent=1, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, deny_path)
        os.chmod(deny_path, 0o600)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

data = load_history()
file_lane = data.pop("_file_lane", None)
entries = data["entries"]
mine = lane_entries(entries, file_lane)
burst_count = count_window(mine, burst_window)
sustain_count = count_window(mine, sustain_window)

if burst_count >= burst_limit:
    retry = oldest_in_window(mine, burst_window) + burst_window
    write_deny("burst", burst_count, sustain_count, retry)
    sys.exit(78)
if sustain_count >= sustain_limit:
    retry = oldest_in_window(mine, sustain_window) + sustain_window
    write_deny("sustain", burst_count, sustain_count, retry)
    sys.exit(78)

entries.append({"ts": now, "mode": mode, "client": client, "lane": lane})
entries.sort(key=lambda e: int(e.get("ts", 0)))
if len(entries) > 64:
    entries = entries[-64:]
data["entries"] = entries

d = os.path.dirname(history_path) or "."
os.makedirs(d, exist_ok=True)
fd, tmp = tempfile.mkstemp(prefix=".tmp-asnap.", dir=d)
try:
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, indent=1, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, history_path)
    os.chmod(history_path, 0o600)
except BaseException:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    raise

sys.exit(0)
PY
  py_rc=$?
  asnap_lock_release "$lock_dir"
  return "$py_rc"
}

# Rewrite asnap_admit deny artifact into the P16 field set engine.py reads (count/limit/window_sec).
asnap_rewrite_p16_deny() {
  local deny_json=$1 rate_limit=$2 rate_window=$3
  /usr/bin/python3 - "$deny_json" "$rate_limit" "$rate_window" <<'PY' | asnap_write_atomic "$deny_json"
import json, sys, time
from datetime import datetime, timezone

path, limit, window = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
try:
    with open(path, "r") as fh:
        raw = json.load(fh)
except (IOError, OSError, ValueError):
    raw = {}

reason = raw.get("reason", "burst")
if reason == "sustain":
    count = raw.get("sustain_count", raw.get("count", 0))
else:
    count = raw.get("burst_count", raw.get("count", 0))

ts = int(raw.get("ts", time.time()))
iso = raw.get("iso")
if not iso:
    iso = datetime.fromtimestamp(ts, tz=timezone.utc).astimezone().isoformat(timespec="seconds")

payload = {
    "schema": 1,
    "ts": ts,
    "iso": iso,
    "mode": raw.get("mode", "mirror"),
    "reason": reason,
    "count": count,
    "limit": limit,
    "window_sec": window,
    "client": raw.get("client", ""),
}
print(json.dumps(payload, indent=1, sort_keys=True))
print()
PY
}

asnap_emit_rate_deny() {
  local prefix=$1 mode=$2 deny_json=$3
  local line detail
  detail=$(
    /usr/bin/python3 - "$deny_json" <<'PY' 2>/dev/null || true
import json, sys
with open(sys.argv[1], "r") as fh:
    d = json.load(fh)
print("%s count=%s limit=%s window_sec=%s client=%s"
      % (d.get("reason", "?"), d.get("count"), d.get("limit"),
         d.get("window_sec"), d.get("client", "")))
PY
  )
  line="${prefix}: DENIED rate-limit mode=$mode $detail"
  echo "$line" >&2
  if [ -n "${SNAP_LOG:-}" ]; then
    printf '%s  %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$line" >> "$SNAP_LOG"
  fi
}

# ---------- authorized_keys (safe editing) ----------

_asnap_ak_restore() {
  local ak_file=$1 backup=$2
  [ -n "$backup" ] && [ -f "$backup" ] || return 1
  mv -f "$backup" "$ak_file" || return 1
}

_asnap_ak_backup() {
  local ak_file=$1 backup base old_umask seq
  base="${ak_file}.bak-$(date +%Y%m%d-%H%M%S)"
  seq=0
  while :; do
    if [ "$seq" -eq 0 ]; then
      backup="$base"
    else
      backup=$(printf '%s-%02d' "$base" "$seq")
    fi
    if [ ! -e "$backup" ]; then
      break
    fi
    seq=$((seq + 1))
    if [ "$seq" -gt 9999 ]; then
      return 1
    fi
  done
  if [ ! -f "$ak_file" ]; then
    : > "$ak_file"
  fi
  cp -p "$ak_file" "$backup" || return 1
  old_umask=$(umask)
  umask 077
  chmod 0600 "$backup" 2>/dev/null || true
  umask "$old_umask"
  printf '%s\n' "$backup"
}

_asnap_ak_line_count() {
  local ak_file=$1
  if [ ! -f "$ak_file" ]; then
    echo 0
    return 0
  fi
  /usr/bin/wc -l < "$ak_file" | tr -dc '0-9'
}

_asnap_ak_comment_matches() {
  local line=$1 comment=$2
  /usr/bin/python3 - "$line" "$comment" <<'PY'
import sys
line = sys.argv[1].strip()
comment = sys.argv[2]
if not line or line.startswith("#"):
    sys.exit(1)
parts = line.split()
if parts and parts[-1] == comment:
    sys.exit(0)
sys.exit(1)
PY
}

asnap_ak_line() {
  local forced_command=$1 pub_file=$2 comment=$3
  local keytype keydata rest
  if [ ! -f "$pub_file" ]; then
    return 1
  fi
  read -r keytype keydata rest < "$pub_file" || return 1
  [ -n "$keytype" ] && [ -n "$keydata" ] || return 1
  printf 'restrict,command="/bin/bash '\''%s'\''",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty %s %s %s\n' \
    "$forced_command" "$keytype" "$keydata" "$comment"
}

asnap_ak_has() {
  local ak_file=$1 comment=$2
  local line
  [ -f "$ak_file" ] || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    if _asnap_ak_comment_matches "$line" "$comment"; then
      return 0
    fi
  done < "$ak_file"
  return 1
}

asnap_ak_append() {
  local ak_file=$1 line=$2
  local backup before after
  [ -n "$line" ] || return 1
  backup=$(_asnap_ak_backup "$ak_file") || return 1
  before=$(_asnap_ak_line_count "$ak_file")
  printf '%s\n' "$line" >> "$ak_file" || return 1
  chmod 0600 "$ak_file" 2>/dev/null || true
  after=$(_asnap_ak_line_count "$ak_file")
  if [ "$((after - before))" -ne 1 ]; then
    _asnap_ak_restore "$ak_file" "$backup" || return 1
    return 1
  fi
  return 0
}

asnap_ak_remove() {
  local ak_file=$1 comment=$2
  local backup before after expected removed tmp
  [ -n "$comment" ] || return 1
  backup=$(_asnap_ak_backup "$ak_file") || return 1
  before=$(_asnap_ak_line_count "$ak_file")
  expected=$(/usr/bin/python3 - "$ak_file" "$comment" <<'PY'
import sys
path, comment = sys.argv[1], sys.argv[2]
try:
    with open(path, "r") as fh:
        lines = fh.readlines()
except IOError:
    print(0)
    sys.exit(0)
count = 0
for line in lines:
    parts = line.strip().split()
    if parts and not line.lstrip().startswith("#") and parts[-1] == comment:
        count += 1
print(count)
PY
) || { _asnap_ak_restore "$ak_file" "$backup" || return 1; return 1; }

  tmp=$(mktemp "$(dirname "$ak_file")/.tmp-asnap-ak.XXXXXX") || {
    _asnap_ak_restore "$ak_file" "$backup" || return 1
    return 1
  }
  removed=0
  while IFS= read -r line || [ -n "$line" ]; do
    if _asnap_ak_comment_matches "$line" "$comment"; then
      removed=$((removed + 1))
      continue
    fi
    printf '%s\n' "$line" >> "$tmp"
  done < "$ak_file"
  if [ "$removed" -ne "$expected" ]; then
    rm -f "$tmp"
    _asnap_ak_restore "$ak_file" "$backup" || return 1
    return 1
  fi
  mv -f "$tmp" "$ak_file" || {
    rm -f "$tmp"
    _asnap_ak_restore "$ak_file" "$backup" || return 1
    return 1
  }
  chmod 0600 "$ak_file" 2>/dev/null || true
  after=$(_asnap_ak_line_count "$ak_file")
  if [ "$((before - after))" -ne "$expected" ]; then
    _asnap_ak_restore "$ak_file" "$backup" || return 1
    return 1
  fi
  return 0
}
