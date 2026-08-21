#!/bin/bash
# ENTRYPOINT — sshd forced-command allowlist dispatcher. $SSH_ORIGINAL_COMMAND is matched against
# mirror|deep-verify|probe-auth only and is NEVER executed; anything else (including legacy full-path) -> mirror.
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
case "$mode" in mirror|deep-verify) ;; *) mode=mirror ;; esac
_engine() {
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
esac
HISTORY="$STATE/trigger-history.json"
HISTORY_LOCK="$STATE/trigger-history.lockdir"
DENY_JSON="$STATE/last-rate-limit.json"
BUSY_LOCK="$STATE/mirror.pid"
asnap_admit "$HISTORY" "$HISTORY_LOCK" "$BUSY_LOCK" "$LANE" "$mode" \
  "${SSH_CLIENT:-}" "$RATE_LIMIT" "$RATE_WINDOW" "$RATE_LIMIT" "$RATE_WINDOW" "$DENY_JSON"
admit_rc=$?
if [ "$admit_rc" -eq 79 ]; then
  echo "mirror.sh: busy — engine already running (lock $BUSY_LOCK)" >&2
  exit 79
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
