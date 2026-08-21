# AGENT-SETUP — install runbook

You are (probably) an AI agent installing agent-snapshot for a user. Follow the
phases in order. **Do not skip a verification gate**; each gate proves the
previous phase before the next one builds on it. Every step is also
human-followable.

## Phase 0 — ask the user, before touching anything

Collect these answers (do not guess them):

1. **What directory should be protected?** (`SOURCE`, e.g. `~/Desktop`)
2. **Two machines or one?**
   - *Two (recommended):* which machine is the archive host, and what is its
     ssh target (`user@host`)? Passwordless ssh from source → archive host must
     already work, with the user's normal key.
   - *One:* the DAS drives are attached to this machine; the archive target is
     `localhost`.
3. **Where are the DAS volumes mounted?** Primary (snapshots) and mirror
   (replica), e.g. `/Volumes/SnapArchive` and `/Volumes/SnapMirror`. Confirm
   they are directly-attached drives, **not** network mounts — this system is
   DAS-only by design.
4. **What times should backups run?** (daily `HH:MM` per enabled leg)
5. **Optional vault leg?** A second host for compressed archives — ssh target,
   `posix` or `windows`, directory, retention days.
6. **Retention:** days of snapshot history (default 90).

## Phase 1 — install the writer (source machine)

```bash
git clone https://github.com/BlinkingSun/agent-snapshot.git
cd agent-snapshot
bin/snapshot-install \
  --source "<SOURCE>" \
  --snap-ssh "<user@archive-host | localhost>" \
  --snap-dir "<PRIMARY_VOLUME>/agent-snapshot" \
  --snap-time "<HH:MM>" \
  [--vault-ssh "<user@vault-host>" --vault-os <posix|windows> \
   --vault-dir "<DIR>" --vault-time "<HH:MM>"]
```

The installer prints ONE `authorized_keys` line. **Show it to the user, then
append it** to `~/.ssh/authorized_keys` on the source machine:

```bash
# APPEND — never overwrite. Existing entries may be load-bearing
# (other forced-command jobs, other automation). Verify count before/after:
wc -l ~/.ssh/authorized_keys
printf '%s\n' '<THE PRINTED LINE>' >> ~/.ssh/authorized_keys
wc -l ~/.ssh/authorized_keys   # must be exactly +1
```

**This is the last time a human appends an `authorized_keys` line by hand.**
Recurring key rotation is automated (`KEY_ROTATION_APPLY_AK=true` in
`conf/snapshot.conf`): the weekly job edits `authorized_keys` itself with
timestamped backups and safety rails. That tradeoff was chosen because a
rotation schedule that still needs a human to append a line never actually
rotates.

### Key registry bootstrap (writer)

Right after the one-time `authorized_keys` append, bring the flat install key
into the rotation registry and confirm the weekly job is loaded:

```bash
APPDIR="$HOME/Library/Application Support/agent-snapshot"

"$APPDIR/bin/snapshot-key-rotate" bootstrap --role writer
"$APPDIR/bin/snapshot-key-rotate" status --role writer

launchctl list | grep com.agent-snapshot.key-rotate
# expect com.agent-snapshot.key-rotate listed (not "-	0	com.agent-snapshot.key-rotate")
launchctl print "gui/$(id -u)/com.agent-snapshot.key-rotate" 2>/dev/null | grep -E 'state|runs|last exit' || true
```

Expected from `status`: an active key id, stable symlink
`~/.ssh/id_ed25519_agent_snapshot` pointing at
`~/.ssh/agent-snapshot/keys/…`, no pending rotation action on a fresh install.
The launchd label is `com.agent-snapshot.key-rotate`; it runs
`snapshot-key-rotate rotate-if-due --role writer` weekly (Sunday 05:45 local in
the shipped template).

Then ensure the transport prerequisites (user-visible, may need the user's
hands for System Settings):

- System Settings → General → Sharing → **Remote Login: ON**
- System Settings → Privacy & Security → **Full Disk Access → sshd** (or
  "Remote Login" toggle "Allow full disk access for remote users")

## GATE 1 — the probe must pass

```bash
ssh -i ~/.ssh/id_ed25519_agent_snapshot -o IdentitiesOnly=yes localhost probe
```

Expected: `T1..T5 = OK` and `probe: OVERALL rc=0`.

**Probe is exempt from rate limiting** — it is read-only and never triggers
`prune_snap_to_fit()`. You can run probe as often as needed during setup (and
during the rate-limit gate below) without consuming snap quota or risking denial.

| Failure | Meaning | Fix |
|---|---|---|
| connection refused | Remote Login off | enable it |
| `T1/T2/T3 FAIL ... not permitted` | sshd lacks Full Disk Access | grant it, retry |
| `T4/T5 FAIL` | archive/vault host unreachable | fix ssh/network first |
| `refused (allowed: ...)` | authorized_keys line wrong | re-append the exact printed line |

Do not continue until the probe is clean.

## GATE 1b — rate limiting denies abuse, then recovers

The writer dispatcher caps `snap|vault|both` at **3 per 10 minutes** and **2
per hour** (defaults in `conf/snapshot.conf`). Deliberately tripping the limit
during setup is **safe**: a denial (exit **78**) writes audit state only and
does **not** run `bin/snapshot` — no snapshot is taken and no prune path runs.
You are proving the gate works, not damaging data.

**Step 1 — probe stays unlimited** (confirms exemption):

```bash
for n in 1 2 3 4 5; do
  ssh -i ~/.ssh/id_ed25519_agent_snapshot -o IdentitiesOnly=yes localhost probe \
    || { echo "probe $n failed unexpectedly"; break; }
done
# all five should succeed (rc=0 each)
```

**Step 2 — trip the sustain limit** (2 allowed per hour; 3rd denied):

Each trigger must **finish** before the next. If a snapshot is still running,
the dispatcher returns **79** (busy) and consumes **no** rate slot — that is
not the test you want.

```bash
ssh -i ~/.ssh/id_ed25519_agent_snapshot -o IdentitiesOnly=yes localhost snap
# wait until it completes (monthly log shows finished rc=0, or stage lock gone)

ssh -i ~/.ssh/id_ed25519_agent_snapshot -o IdentitiesOnly=yes localhost snap
# wait again

ssh -i ~/.ssh/id_ed25519_agent_snapshot -o IdentitiesOnly=yes localhost snap; echo "rc=$?"
# expect rc=78 (rate-limit denial), not rc=0
```

Confirm the denial was recorded:

```bash
cat "$HOME/Library/Application Support/agent-snapshot/state/last-rate-limit.json"
grep DENIED ~/Library/Logs/agent-snapshot/dispatch.log | tail -3
```

**Step 3 — recovery:** wait until the counted triggers age out of the sustain
window (default **3600 s** — check `retry_after` in `last-rate-limit.json`), or
wait at least that long. Then one more snap must succeed:

```bash
ssh -i ~/.ssh/id_ed25519_agent_snapshot -o IdentitiesOnly=yes localhost snap; echo "rc=$?"
# expect rc=0 after the window expires
```

To clear a stale denial artifact before the 24 h self-clear on the archive side
(not required on the writer, but harmless):

```bash
rm -f "$HOME/Library/Application Support/agent-snapshot/state/last-rate-limit.json"
```

Do not continue until you have seen **78** on a deliberate over-limit trigger
and **0** again after the window.

## Phase 2 — first snapshot

```bash
ssh -i ~/.ssh/id_ed25519_agent_snapshot -o IdentitiesOnly=yes localhost snap
```

## GATE 2 — prove the snapshot exists where it should

```bash
ssh <user@archive-host> 'ls -la <PRIMARY_VOLUME>/agent-snapshot/ | tail -5'
```

Expected: one `YYYY-MM-DD_HHMMSS` directory and a `latest` symlink. Spot-check
a few files inside it. (Reporting rule: never treat an empty or denied listing
as proof of anything — an error is "couldn't look", not "not there".)

## Phase 3 — confirm the schedule

```bash
launchctl list | grep agent-snapshot     # jobs present
tail -5 ~/Library/Logs/agent-snapshot/launchd-snap.log   # after first scheduled fire
```

The monthly log `~/Library/Logs/agent-snapshot/YYYY-MM.log` carries every run's
summary; `===== finished (rc=0) =====` is the success marker.

Confirm the writer's post-snapshot kick string includes the archive rate-limit
exemption (required when `mirror.sh` has the rate gate — deploy both together):

```bash
grep REPLICA_KICK "$HOME/Library/Application Support/agent-snapshot/conf/snapshot.conf"
# must contain AGENT_SNAPSHOT_KICK=1 (see archive-host/README.md)
```

If upgrading an existing conf, update `REPLICA_KICK` to match
`conf/snapshot.conf.example` before relying on immediate replica kicks.

## Phase 4 — archive host: replica + verify

Follow `archive-host/README.md`. Outline: install `engine.py` + `mirror.sh`
into `~/Library/AgentSnapshot/` on the archive host, set `SNAP_PRIMARY` /
`SNAP_REPLICA` if the volumes differ from the defaults, load the 5-minute
poll LaunchAgent and the daily deep-verify. On macOS archive hosts the
replica also runs through the sshd forced-command pattern, because launchd
there cannot open USB volumes either. Read `archive-host/SEMANTICS.md` and
keep `PRUNE_AGE_DAYS` above the writer's `SNAP_RETENTION`.

Bootstrap the replica key registry and confirm its weekly rotation job the
same way as on the writer (`bootstrap` / `status` / `launchctl` — see
`archive-host/README.md` for exact commands and paths).

**GATE 3:** after the first replica pass, the snapshot from Gate 2 exists on
the MIRROR volume too, and deep-verify reports the drives in sync.

## Phase 5 — monitor

Follow `monitor/MONITOR.md` on the archive host. When it is up you should see:
per-drive fill bars, last-snapshot age, "checked N min ago", and sync state.

## Final checklist — read it back to the user

- [ ] Probe rc=0 (transport + TCC + reachability proven)
- [ ] Writer key registry bootstrapped; `snapshot-key-rotate status --role writer` clean
- [ ] Weekly writer rotation job loaded (`com.agent-snapshot.key-rotate`)
- [ ] Rate limiting verified: probe unlimited; deliberate over-limit snap returned **78**; normal snap succeeded after window
- [ ] Writer `REPLICA_KICK` includes `AGENT_SNAPSHOT_KICK=1` (paired with archive `mirror.sh` rate gate)
- [ ] First snapshot verified on the primary DAS by listing it
- [ ] Replica key registry bootstrapped; weekly replica rotation job loaded (macOS archive hosts)
- [ ] Replica pass verified on the mirror DAS
- [ ] Schedules loaded (times the user chose)
- [ ] Monitor visible and fresh
- [ ] User knows: the printed key can only run `snap|vault|both|probe` —
      nothing on the source machine can delete backup history
- [ ] User knows where the logs live and what `finished (rc=0)` means
- [ ] User knows recurring key rotation is automated; the one-time install
      `authorized_keys` append was the last manual key line
