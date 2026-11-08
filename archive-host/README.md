# archive-host — replica engine install

This half runs on the machine with the two DAS drives attached (the archive
host — a separate box in two-machine mode, the same machine in single-machine
mode). It copies dated snapshots from the PRIMARY volume to the MIRROR volume,
verifies them, prunes by age with hard guardrails, and feeds the monitor.

Read [SEMANTICS.md](SEMANTICS.md) first — it states precisely what is and is
not guaranteed (short version: deleting on the primary never wipes the mirror,
and the engine is structurally incapable of passing a deletion to rsync).

## Files

| file | role |
|---|---|
| `engine.py` | the replica engine — stdlib-only Python 3.9+, runs on `/usr/bin/python3` |
| `mirror.sh` | entrypoint + allowlist dispatcher (`mirror` \| `deep-verify` \| `handshake` \| `probe-auth`); the sshd forced-command target |
| `handshake.py` | ~60 s writer-reachability probe -> `handshake.json`; drives the on/off switch and upload-stall detection |
| `control.sh` | forced-command target for a separate, narrowly-scoped key that can ONLY run `enable` / `disable` |
| `selftest.sh` | 468-assertion acceptance suite |

## Configuration

Environment variables (set in the LaunchAgent or the wrapper):

| var | default | meaning |
|---|---|---|
| `SNAP_PRIMARY` | `/Volumes/SnapArchive` | primary DAS volume (writer's target) |
| `SNAP_REPLICA` | `/Volumes/SnapMirror` | mirror DAS volume |
| `SNAP_STATE_DIR` | `~/Library/AgentSnapshot` | status.json + events.jsonl + lock |
| `SNAP_LOG` | `~/Library/Logs/agent-snapshot.log` | engine log |
| `SNAP_MIN_FREE_GB` | (engine default) | mirror free-space floor |
| `SNAP_VERIFY_SAMPLE` | 200 | files content-hashed per deep-verify |
| `SNAP_FORCE_DEEP_VERIFY` | unset | `1` runs an explicit `deep-verify` even inside the monthly interval guard |
| `SNAP_MBP_HOST` | `youruser@writer-host` | (`handshake.py`) ssh target for the writer's read-only `probe-auth` |
| `SNAP_MBP_KEY` | `~/.ssh/id_ed25519_agentsnapshot_probe` | (`handshake.py`) probe key; its writer-side `authorized_keys` line must force `probe-auth` |

**Deep-verify runs monthly, inside the mirror pass that promotes the early-morning
snapshot** (stamp hour 03-06), once the last success is 28 days old — no separate
LaunchAgent. P13 fires at 35 days. Copies wait while it runs and resume afterwards.
See SEMANTICS.md (c) for why, and what monthly coverage does and does not give you.

Safety constants live at the top of `engine.py`, deliberately not env-tunable:
`PRUNE_AGE_DAYS = 100` and `MAX_PRUNES_PER_PASS = 2`. **Keep `PRUNE_AGE_DAYS`
above the writer's `SNAP_RETENTION` plus margin** (defaults: 100 vs 90). If you
raise the writer's retention, raise this with it — the mirror must always
outlive the primary, or the P9 "possible primary data loss" window collapses.

**`VERIFY_SWEEP_DAYS` (90) and `VERIFY_MAX_OLDER_PER_PASS` (8) couple deep-verify
coverage to backup *cadence*, not just retention.** Coverage is "every promoted
snapshot content-checked at least once within `VERIFY_SWEEP_DAYS`" — at 1
backup/day that's ~90 snapshots and a cheap nightly rotation; at 4 backups/day
it's ~360 snapshots, and without this scaling, three quarters of them would be
pruned having never been content-verified at all. **Raising backup frequency
therefore raises deep-verify's per-pass cost**, not just its target count: each
older target is a full two-sided walk plus sampled hashing (~2-3 min per
~150k-file snapshot over USB in the reference deployment), so a nightly pass
at the default ceiling can run 30-70 minutes at 4×/day cadence versus a couple
minutes at 1×/day. Budget the schedule accordingly; the engine logs an
explicit advisory if the cost ceiling ever forces coverage below the sweep
target rather than silently verifying less than it claims.

## Rate limiting (macOS forced-command path only)

When `mirror.sh` is invoked over the replica forced-command SSH key
(`$SSH_CONNECTION` set), it enforces separate caps before `engine.py` starts:

| mode | max triggers | window | why these numbers |
|---|---|---|---|
| `mirror` | **4** | **300 s** (5 min) | The reference poll LaunchAgent uses `StartInterval` **300** — one legitimate forced `mirror` every 5 minutes (12/hour from launchd alone). Four in five minutes allows a poll plus a few retries without touching normal polling; a fifth back-to-back forced trigger is denied (exit **78**). |
| `deep-verify` | **2** | **86400 s** (24 h) | The scheduled monthly sweep runs inside a `mirror` pass, so this lane only carries manual runs. Two per day is ample; a third forced deep-verify in 24 h is denied. |
| `handshake` | **6** | **240 s** | Own lane, own budget: a ~60 s poll must never be denied by `mirror`'s budget, and a runaway handshake timer must never starve it. No busy-lock (a copy can hold the engine lock for hours). |

Denials write `~/Library/AgentSnapshot/last-rate-limit.json`. The engine
surfaces them as health rule **P16** on the monitor (see below). When a run is
already active (busy), `mirror.sh` does not exit: it hands the pass to
`engine.py`, whose own lock refreshes status and computes the lock-held health
rules, then exits **2**. No history slot is consumed by a busy bounce.

**Linux archive hosts** (plain cron invoking `mirror.sh` locally, no forced-command
SSH hop) are **outside this gate**, consistent with them already being outside
replica key rotation.

### ⚠️ `AGENT_SNAPSHOT_KICK=1` — deploy with the writer kick string

The writer's post-snapshot kick runs `mirror.sh` **directly on the archive
host shell** via normal `SNAP_SSH` — not through the replica forced-command
key. Without an explicit exemption, those kicks look like forced `mirror`
traffic and **count toward the 4-per-5-minute cap**, which breaks immediate
replica passes during burst testing.

**The single most common upgrade mistake:** shipping the `mirror.sh` rate gate
without updating the writer's `REPLICA_KICK` in `conf/snapshot.conf` (or the
reverse). **Deploy both in the same change.**

Required writer-side string (from `conf/snapshot.conf.example`):

```bash
REPLICA_KICK='AGENT_SNAPSHOT_KICK=1 nohup "$HOME/Library/AgentSnapshot/mirror.sh" >/dev/null 2>&1 &'
```

When `AGENT_SNAPSHOT_KICK=1`, `mirror.sh` skips rate limiting, writes **no**
history entry, and runs immediately — the intended path for legitimate kicks.
Holders of the replica forced-command key alone cannot set this env var (they
never reach a shell). Holders of `SNAP_SSH` could — that trust boundary
predates this change; see `docs/SAFETY.md` §2.

## Health rules (monitor)

The engine computes `problems[]` on every health pass. **`healthy` is true iff
`problems` is empty.** Rules **P1–P15** cover mounts, sync, verify cadence,
copy stalls, and related replica state — see `engine.py` and `SEMANTICS.md`.

**P16 — forced-command rate-limit denial:** when `mirror.sh` denies a forced
trigger (exit 78), it writes `last-rate-limit.json`. The next engine health
pass adds:

```
P16 forced-command trigger rate-limited (<mode>): <reason> at <iso> — possible abuse of replica key
```

A `rate_limited` event is appended to `events.jsonl`. **P16 clears when no new
denial lands within 24 h** (or an operator deletes `last-rate-limit.json`) —
a day-old P16 after a stopped test burst is expected, not a stuck bug.

## Install

```sh
mkdir -p ~/Library/AgentSnapshot
install -m 755 mirror.sh engine.py ~/Library/AgentSnapshot/
```

On **macOS** archive hosts, also install the key-rotation CLI (same path layout
as the writer — rotation touches `~/.ssh`, not TCC-protected volumes):

```sh
mkdir -p "$HOME/Library/Application Support/agent-snapshot/bin"
install -m 755 ../bin/snapshot-key-rotate ../bin/snapshot-key-lib.sh \
  "$HOME/Library/Application Support/agent-snapshot/bin/"
```

### Schedule (poll + reboot-safe)

```sh
cat > ~/Library/LaunchAgents/com.example.agentsnapshot.mirror.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.example.agentsnapshot.mirror</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/ssh</string>
    <string>-i</string><string>/Users/youruser/.ssh/id_ed25519_agentsnapshot_replica</string>
    <string>-o</string><string>IdentitiesOnly=yes</string>
    <string>-o</string><string>BatchMode=yes</string>
    <string>localhost</string>
    <string>mirror</string>
  </array>
  <key>StartInterval</key><integer>300</integer>
  <key>RunAtLoad</key><true/>
  <key>ProcessType</key><string>Background</string>
</dict></plist>
PLIST
```

There is **no** separate deep-verify LaunchAgent: the monthly sweep runs inside
the mirror pass (see Configuration).

Add the handshake poll — the same ssh-to-localhost shape, `handshake` instead of
`mirror`, every 60 s:

```sh
sed -e 's/agentsnapshot.mirror/agentsnapshot.handshake/' \
    -e 's|<string>mirror</string>|<string>handshake</string>|' \
    -e 's|<integer>300</integer>|<integer>60</integer>|' \
    ~/Library/LaunchAgents/com.example.agentsnapshot.mirror.plist \
    > ~/Library/LaunchAgents/com.example.agentsnapshot.handshake.plist
```

The probe key (`SNAP_MBP_KEY`) needs its own line in the **writer's**
`authorized_keys`, forced to the read-only probe:
`restrict,command="… snapshot-dispatch probe-auth" ssh-ed25519 AAAA… agentsnapshot-probe`.

Optional remote on/off switch: a third key whose archive-host `authorized_keys`
line forces `control.sh`, which accepts only `enable` / `disable`.

Render and load the weekly replica key-rotation job from the repo template
(Sunday 05:45 local — same slot as the writer):

```sh
REPO=/path/to/agent-snapshot   # adjust
sed -e "s|__APPDIR__|$HOME/Library/Application Support/agent-snapshot|g" \
    -e "s|__HOME__|$HOME|g" \
    "$REPO/launchd/com.agent-snapshot-replica.key-rotate.plist.template" \
    > ~/Library/LaunchAgents/com.agent-snapshot-replica.key-rotate.plist
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/com.agent-snapshot-replica.key-rotate.plist \
  2>/dev/null || launchctl load -w ~/Library/LaunchAgents/com.agent-snapshot-replica.key-rotate.plist
```

### Why the ssh hop, here too

On macOS a launchd-spawned process **cannot open removable volumes** (TCC) —
the engine would see both drives unmounted. Route the job through
ssh-to-localhost exactly like the writer: dedicated key, and in
`~/.ssh/authorized_keys` on the archive host:

```
restrict,command="/bin/bash '/Users/youruser/Library/AgentSnapshot/mirror.sh'" ssh-ed25519 AAAA... agentsnapshot-replica
```

`mirror.sh` maps `SSH_ORIGINAL_COMMAND` onto the closed allowlist
(`mirror` | `deep-verify` | `handshake` | `probe-auth`; anything else safely
runs `mirror`). Grant sshd
Full Disk Access once, as on the source machine. On a Linux archive host none
of this is needed — plain cron works.

### Replica key registry bootstrap

After the one-time replica `authorized_keys` append (same human gate as the
writer install), migrate the flat key and confirm rotation is scheduled:

```sh
APPDIR="$HOME/Library/Application Support/agent-snapshot"

"$APPDIR/bin/snapshot-key-rotate" bootstrap --role replica
"$APPDIR/bin/snapshot-key-rotate" status --role replica

launchctl list | grep com.agent-snapshot-replica.key-rotate
launchctl print "gui/$(id -u)/com.agent-snapshot-replica.key-rotate" 2>/dev/null | grep -E 'state|runs|last exit' || true
```

Expected: active key id, stable symlink
`~/.ssh/id_ed25519_agentsnapshot_replica` →
`~/.ssh/agent-snapshot/keys/…`, weekly job
`com.agent-snapshot-replica.key-rotate` loaded. Recurring rotation is automated
(`KEY_ROTATION_APPLY_AK=true` on deployments that set it in writer conf; replica
hosts use the same CLI defaults). Subcommands: `status|bootstrap|rotate|finalize|rotate-if-due`
with `--role replica`. Operator detail: `docs/KEY-ROTATION.md`.

### The no-arguments contract

The writer's post-snapshot kick invokes the entrypoint with **no arguments**
(it defaults to `mirror`). Keep that behavior if you modify `mirror.sh`;
breaking it fails silently, because the writer reports success either way.

## Verify the install

```sh
# acceptance suite (468 assertions; uses its own scratch dir, never your volumes):
./selftest.sh
# one manual pass against the real volumes:
ssh -i ~/.ssh/id_ed25519_agentsnapshot_replica -o IdentitiesOnly=yes localhost mirror
cat ~/Library/AgentSnapshot/status.json | python3 -m json.tool | head -30
```

`healthy` is true **iff** `problems` is empty. Then install the monitor:
[../monitor/MONITOR.md](../monitor/MONITOR.md).
