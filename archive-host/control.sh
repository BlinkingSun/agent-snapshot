#!/bin/bash
# ENTRYPOINT for the on/off-switch control key ONLY -- forced-command target for a dedicated,
# narrowly-scoped authorized_keys line. Deliberately SEPARATE from mirror.sh: widening mirror.sh
# itself to accept enable/disable would let this key ALSO reach mirror/deep-verify (mirror.sh
# defaults any unrecognized mode to "mirror"), which defeats the point of a narrowly-scoped key.
# $SSH_ORIGINAL_COMMAND is matched against a closed allowlist and is NEVER executed as a shell
# command -- anything outside {enable, disable} is refused, matching snapshot-dispatch's own
# refusal idiom (exit 77) on the writer side of this same system.
here=$(cd -- "$(dirname -- "$0")" && pwd -P) || exit 3
mode="${SSH_ORIGINAL_COMMAND:-}"
case "$mode" in
  enable|disable) ;;
  *)
    echo "control.sh: refused (allowed: enable | disable)" >&2
    exit 77
    ;;
esac
exec /usr/bin/python3 "$here/engine.py" "$mode"
