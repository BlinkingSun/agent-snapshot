#!/bin/bash
# ENTRYPOINT. Installed at ~/Library/AgentSnapshot/mirror.sh — the sshd forced-command
# target pinned by the authorized_keys entry. ALLOWLIST DISPATCHER ONLY: $SSH_ORIGINAL_COMMAND is
# matched against a fixed mode list and is NEVER executed as a shell line. Anything unrecognised
# (including the legacy full-path string the current plist sends) maps to `mirror`.
ulimit -n 65535 2>/dev/null || true
here=$(cd -- "$(dirname -- "$0")" && pwd -P) || exit 3
mode=${1:-}
[ -n "$mode" ] || mode=${SSH_ORIGINAL_COMMAND:-}
case "$mode" in
  mirror|deep-verify) ;;
  *) mode=mirror ;;
esac
exec /usr/bin/python3 "$here/engine.py" "$mode"
