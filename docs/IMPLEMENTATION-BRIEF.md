# Implementation Brief — binding contract for all implementing agents

Read `docs/SECURITY-HARDENING-PLAN.md` first for the full rationale. This brief
carries the **binding decisions and exact API contract**. Where this brief and the
plan disagree, **this brief wins** (it includes the operator's final calls made after
the plan was written).

---

## Operator decisions (final — do not re-litigate)

1. **Source sustain threshold = 2 per hour.** Confirmed. Do not use the draft's 5.
2. **Key rotation MUST be fully automated.** The operator will not hand-append lines.
   Therefore `KEY_ROTATION_APPLY_AK` **defaults to `true`** and rotation edits
   `authorized_keys` itself, with the safety rails in §4 below.
   *Install stays print-only* — the one-time setup line is still a human gate; only
   the recurring rotation is automated. This distinction is deliberate.
3. Everything else in the plan proceeds as written, including all 12 adversarial
   corrections (already folded into the plan text).

---

## Platform gotchas — MANDATORY, these break silently if ignored

1. **macOS has no `flock(1)` binary.** Do not write `flock -x ...` in shell. Use the
   portable atomic-`mkdir` lock provided by the library (`asnap_lock_acquire`).
   `bin/snapshot` itself already documents this trap.
2. **macOS `/bin/bash` is 3.2.** No associative arrays, no `${var^^}`, no `mapfile`.
   Empty arrays under `set -u` need `${a[@]+"${a[@]}"}`.
3. **`date -r <epoch>`** works on macOS BSD date; `date -d` does NOT. For portability
   helpers, prefer epoch arithmetic over date parsing.
4. **`stat`** flags differ (BSD `-f %m` vs GNU `-c %Y`). Avoid `stat` where possible;
   the library provides `asnap_mtime`.
5. Python 3 IS available (`/usr/bin/python3`) and `engine.py` already relies on it —
   use it for JSON manipulation in shell rather than hand-rolling a JSON parser.

---

## The shared library: `bin/snapshot-key-lib.sh`

Every other script sources this. **This API is frozen** — implement exactly these
names and signatures; other agents are coding against them right now.

```bash
# ---------- paths ----------
asnap_appdir            # -> "$HOME/Library/Application Support/agent-snapshot"
asnap_state_dir         # -> "<appdir>/state"          (created 0700 on demand)
asnap_registry_dir      # -> "$HOME/.ssh/agent-snapshot"
asnap_mtime <path>      # -> epoch seconds, portable; "" if missing

# ---------- locking (portable; NO flock(1)) ----------
asnap_lock_acquire <lockdir> [timeout_sec]   # rc 0 acquired, rc 1 timeout.
                                             # atomic mkdir; writes pid inside;
                                             # steals a lock whose pid is dead.
asnap_lock_release <lockdir>

# ---------- atomic write ----------
asnap_write_atomic <path>   # content on STDIN; temp+rename in same dir; chmod 0600

# ---------- admission control (rate limit + busy, ONE atomic decision) ----------
# Performs, under a single held lock, in this order:
#   1. busy check   -> rc 79, records NOTHING   (skipped when busy_lock is "")
#   2. rate windows -> rc 78, writes deny_file
#   3. otherwise    -> appends the trigger to history, rc 0
# This ordering under one lock is the TOCTOU fix from the adversarial review;
# do not split it back into two separate steps.
asnap_admit <history_json> <lock_dir> <busy_lock_or_empty> <lane> <mode> <client> \
            <burst_count> <burst_window_sec> <sustain_count> <sustain_window_sec> \
            <deny_json>
# History format: {"schema":1,"lane":"<lane>","entries":[{"ts":<int>,"mode":"..","client":".."}]}
# Prune entries older than max(window) on every call; hard-cap 64 entries.

# ---------- authorized_keys (safe editing) ----------
asnap_ak_line <forced_command> <pub_file> <comment>   # -> the full AK line, stdout
asnap_ak_has <ak_file> <comment>                      # rc 0 if a line with that exact comment exists
asnap_ak_append <ak_file> <line>                      # backup, append, verify +1 line; rc!=0 on any doubt
asnap_ak_remove <ak_file> <comment>                   # backup, remove ONLY exact-comment lines,
                                                      # verify expected delta; rc!=0 on any doubt
# Backups: "<ak_file>.bak-YYYYmmdd-HHMMSS", chmod 0600. NEVER rewrite the whole file
# from a template; never touch a line you did not match by exact comment.
```

`asnap_ak_line` must emit exactly (single-quoting the path, `restrict` first):

```
restrict,command="/bin/bash '<forced_command>'",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty <keytype> <keydata> <comment>
```

---

## Config variables (exact names)

Source (`conf/snapshot.conf`):

```bash
SNAP_RATE_BURST_COUNT=3
SNAP_RATE_BURST_WINDOW_SEC=600
SNAP_RATE_SUSTAIN_COUNT=2          # operator-confirmed; NOT 5
SNAP_RATE_SUSTAIN_WINDOW_SEC=3600

KEY_ROTATION_ENABLED=true
KEY_ROTATION_DAYS=90
KEY_OVERLAP_HOURS=72
KEY_ROTATION_APPLY_AK=true         # automated by operator decision
```

Archive (env or `mirror.sh` constants):

```bash
SNAP_RATE_MIRROR_BURST_COUNT=4
SNAP_RATE_MIRROR_BURST_WINDOW_SEC=300
SNAP_RATE_VERIFY_COUNT=2
SNAP_RATE_VERIFY_WINDOW_SEC=86400
```

## Exit codes (exact)

| Code | Meaning |
|---|---|
| 77 | unrecognized mode (existing, unchanged) |
| **78** | rate-limit denial (new) |
| **79** | busy — a run is already active (new) |

## State file paths (exact)

| Path | Owner |
|---|---|
| `<appdir>/state/trigger-history.json` + `.lockdir` + `last-rate-limit.json` | source dispatch |
| `~/Library/AgentSnapshot/trigger-history.json` + `.lockdir` + `last-rate-limit.json` | archive mirror.sh |
| `~/.ssh/agent-snapshot/{state.json,rotation.log,keys/}` | key rotation, both roles |

Lanes: `source-forced`, `archive-forced-mirror`, `archive-forced-deep-verify`.

---

## §4 — Automated rotation safety rails (non-negotiable)

Because rotation now edits `authorized_keys` unattended, every one of these is required:

1. **Never flip the stable symlink until the new key's line is confirmed present**
   in `authorized_keys` (`asnap_ak_has`). Append → verify → *then* flip. The draft
   pseudocode that flips first is wrong; do not follow it.
2. **Timestamped backup before every edit** (`asnap_ak_append` / `asnap_ak_remove`
   do this — do not bypass them).
3. **Probe after cutover.** If the probe fails: restore the previous symlink target,
   remove the just-added line, restore state.json, and exit non-zero loudly.
4. **Never remove the active key's line.** `finalize` only ever removes the
   *previous* key's exact comment, and only after the overlap window has elapsed.
5. **Refuse to rotate while a snapshot run is active** — check the same busy lock the
   dispatcher uses (`STAGE/.lock`), not `.pid` alone.
6. **Never touch any AK line that isn't ours.** Match on our exact comment prefix
   (`agent-snapshot:` / `agent-snapshot-replica:`) only. Other forced-command jobs
   on the same machine are load-bearing.

---

## File ownership — DO NOT EDIT FILES OUTSIDE YOUR ASSIGNMENT

Multiple agents are working in this repo simultaneously. Touching a file assigned to
another agent will corrupt their work. If you believe a file outside your assignment
needs a change, **say so in your final report instead of making the change**.

| Agent | Owns (exclusive write access) |
|---|---|
| A1 | `bin/snapshot-key-lib.sh` |
| A2 | `archive-host/engine.py` |
| A3 | `conf/snapshot.conf.example` |
| A4 | `launchd/com.agent-snapshot.key-rotate.plist.template`, `launchd/com.agent-snapshot-replica.key-rotate.plist.template` |
| A5 | `docs/KEY-ROTATION.md` |
| B1 | `bin/snapshot-dispatch` |
| B2 | `archive-host/mirror.sh` |
| B3 | `bin/snapshot-key-rotate` |
| B4 | `bin/snapshot-install` |
| C1 | `tests/test-ratelimit.sh` |
| C2 | `tests/test-rotation.sh` |
| C3 | `docs/SAFETY.md`, `README.md` |
| C4 | `AGENT-SETUP.md`, `archive-host/README.md` |

Everything not listed is read-only for everyone.
