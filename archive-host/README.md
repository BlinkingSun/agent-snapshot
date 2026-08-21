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
| `mirror.sh` | entrypoint + allowlist dispatcher (`mirror` \| `deep-verify`); the sshd forced-command target |
| `selftest.sh` | 430-assertion acceptance suite |

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

## Install

```sh
mkdir -p ~/Library/AgentSnapshot
install -m 755 mirror.sh engine.py ~/Library/AgentSnapshot/
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

Add a second LaunchAgent for `deep-verify` on a daily `StartCalendarInterval`
(e.g. 03:15).

### Why the ssh hop, here too

On macOS a launchd-spawned process **cannot open removable volumes** (TCC) —
the engine would see both drives unmounted. Route the job through
ssh-to-localhost exactly like the writer: dedicated key, and in
`~/.ssh/authorized_keys` on the archive host:

```
restrict,command="/bin/bash '/Users/youruser/Library/AgentSnapshot/mirror.sh'" ssh-ed25519 AAAA... agentsnapshot-replica
```

`mirror.sh` maps `SSH_ORIGINAL_COMMAND` onto the closed allowlist
(`mirror` | `deep-verify`; anything else safely runs `mirror`). Grant sshd
Full Disk Access once, as on the source machine. On a Linux archive host none
of this is needed — plain cron works.

### The no-arguments contract

The writer's post-snapshot kick invokes the entrypoint with **no arguments**
(it defaults to `mirror`). Keep that behavior if you modify `mirror.sh`;
breaking it fails silently, because the writer reports success either way.

## Verify the install

```sh
# acceptance suite (430 assertions; uses its own scratch dir, never your volumes):
./selftest.sh
# one manual pass against the real volumes:
ssh -i ~/.ssh/id_ed25519_agentsnapshot_replica -o IdentitiesOnly=yes localhost mirror
cat ~/Library/AgentSnapshot/status.json | python3 -m json.tool | head -30
```

`healthy` is true **iff** `problems` is empty. Then install the monitor:
[../monitor/MONITOR.md](../monitor/MONITOR.md).
