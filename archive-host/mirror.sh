#!/bin/bash
# ENTRYPOINT — sshd forced-command allowlist dispatcher. $SSH_ORIGINAL_COMMAND is matched against
# mirror|deep-verify|handshake|probe-auth only and is NEVER executed; anything else (including the
# legacy full-path string) -> mirror. Bare invocation (the writer's post-snapshot kick) -> mirror.
# `handshake` reuses this SAME ssh-to-localhost path (not a bare launchd ProgramArguments call)
# because handshake.py reads the primary DAS volume, and launchd cannot read USB DAS volumes
# directly (TCC) -- only a process spawned by sshd can, the same reason mirror/deep-verify already
# go through here instead of running engine.py directly.
ulimit -n 65535 2>/dev/null || true
here=$(cd -- "$(dirname -- "$0")" && pwd -P) || exit 3
mode=${1:-}; [ -n "$mode" ] || mode=${SSH_ORIGINAL_COMMAND:-}
case "$mode" in probe-auth)
  echo "probe-auth: OK role=replica host=$(hostname -s)"
  exit 0
  ;;
esac
KEY_LIB="$HOME/Library/Application Support/agent-snapshot/bin/snapshot-key-lib.sh"
[ -r "$KEY_LIB" ] || KEY_LIB="$(cd "$here/.." && pwd -P)/bin/snapshot-key-lib.sh"
[ -r "$KEY_LIB" ] || { echo "mirror.sh: missing rate-limit library $KEY_LIB" >&2; exit 1; }
# shellcheck disable=SC1090
source "$KEY_LIB"
case "$mode" in mirror|deep-verify|handshake) ;; *) mode=mirror ;; esac
_engine() {
  if [ "$mode" = "handshake" ]; then
    exec /usr/bin/python3 "$here/handshake.py"
  fi
  if [ -n "${AGENT_SNAPSHOT_ENGINE:-}" ]; then
    # shellcheck disable=SC2086
    exec $AGENT_SNAPSHOT_ENGINE "$mode"
  fi
  exec /usr/bin/python3 "$here/engine.py" "$mode"
}
[ "${AGENT_SNAPSHOT_KICK:-}" = "1" ] && _engine
[ -z "${SSH_CONNECTION:-}" ] && _engine
STATE="${SNAP_STATE_DIR:-$HOME/Library/AgentSnapshot}"
old_umask=$(umask); umask 077; mkdir -p "$STATE"; umask "$old_umask"
case "$mode" in
  mirror)
    LANE=archive-forced-mirror
    RATE_LIMIT=${SNAP_RATE_MIRROR_BURST_COUNT:-4}
    RATE_WINDOW=${SNAP_RATE_MIRROR_BURST_WINDOW_SEC:-300}
    ;;
  deep-verify)
    LANE=archive-forced-deep-verify
    RATE_LIMIT=${SNAP_RATE_VERIFY_COUNT:-2}
    RATE_WINDOW=${SNAP_RATE_VERIFY_WINDOW_SEC:-86400}
    ;;
  handshake)
    # Own lane, own generous budget: a ~60s launchd poll must never be denied by mirror's own
    # burst budget, and a stuck/duplicate handshake timer must never be able to starve mirror's.
    LANE=archive-forced-handshake
    RATE_LIMIT=${SNAP_RATE_HANDSHAKE_BURST_COUNT:-6}
    RATE_WINDOW=${SNAP_RATE_HANDSHAKE_BURST_WINDOW_SEC:-240}
    ;;
esac
HISTORY="$STATE/trigger-history.json"
HISTORY_LOCK="$STATE/trigger-history.lockdir"
DENY_JSON="$STATE/last-rate-limit.json"
# handshake gets NO busy-lock: mirror.pid tracks the ENGINE's flock, which a copy can hold for
# hours -- sharing it would silently block every handshake poll for the entire duration of any
# copy, exactly when live connectivity monitoring matters most. handshake.py is fast and
# effectively idempotent (reads current state, probes, writes its own result), so a bare
# overlapping run is harmless; the rate-limit burst budget above is its only real protection
# against a runaway/duplicate timer.
if [ "$mode" = "handshake" ]; then
  BUSY_LOCK=""
else
  BUSY_LOCK="$STATE/mirror.pid"
fi
asnap_admit "$HISTORY" "$HISTORY_LOCK" "$BUSY_LOCK" "$LANE" "$mode" \
  "${SSH_CLIENT:-}" "$RATE_LIMIT" "$RATE_WINDOW" "$RATE_LIMIT" "$RATE_WINDOW" "$DENY_JSON"
admit_rc=$?
if [ "$admit_rc" -eq 79 ]; then
  echo "mirror.sh: busy — engine already running (lock $BUSY_LOCK)" >&2
  # Do NOT exit here. A lock-held pass must still refresh STATUS ts, set mirror_running:true and
  # compute the lock-held health subset (P1/P13/P14) before exiting 2 (SEMANTICS.md). Exiting 79
  # here short-circuited engine.py's heartbeat_status(), which turned a healthy long copy RED at
  # minute 30 and starved those health rules entirely. engine.py's own flock handles the busy case
  # and exits 2. _engine always execs, so there is no fall-through. Rate-limit denial is rc 78
  # below and is UNAFFECTED.
  _engine
fi
if [ "$admit_rc" -eq 78 ]; then
  asnap_rewrite_p16_deny "$DENY_JSON" "$RATE_LIMIT" "$RATE_WINDOW"
  asnap_emit_rate_deny mirror.sh "$mode" "$DENY_JSON"
  exit 78
fi
if [ "$admit_rc" -ne 0 ]; then
  echo "mirror.sh: rate-limit admission failed (rc=$admit_rc)" >&2
  exit 1
fi
_engine
