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

| Failure | Meaning | Fix |
|---|---|---|
| connection refused | Remote Login off | enable it |
| `T1/T2/T3 FAIL ... not permitted` | sshd lacks Full Disk Access | grant it, retry |
| `T4/T5 FAIL` | archive/vault host unreachable | fix ssh/network first |
| `refused (allowed: ...)` | authorized_keys line wrong | re-append the exact printed line |

Do not continue until the probe is clean.

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

## Phase 4 — archive host: replica + verify

Follow `archive-host/README.md`. Outline: install `engine.py` + `mirror.sh`
into `~/Library/AgentSnapshot/` on the archive host, set `SNAP_PRIMARY` /
`SNAP_REPLICA` if the volumes differ from the defaults, load the 5-minute
poll LaunchAgent and the daily deep-verify. On macOS archive hosts the
replica also runs through the sshd forced-command pattern, because launchd
there cannot open USB volumes either. Read `archive-host/SEMANTICS.md` and
keep `PRUNE_AGE_DAYS` above the writer's `SNAP_RETENTION`.

**GATE 3:** after the first replica pass, the snapshot from Gate 2 exists on
the MIRROR volume too, and deep-verify reports the drives in sync.

## Phase 5 — monitor

Follow `monitor/MONITOR.md` on the archive host. When it is up you should see:
per-drive fill bars, last-snapshot age, "checked N min ago", and sync state.

## Final checklist — read it back to the user

- [ ] Probe rc=0 (transport + TCC + reachability proven)
- [ ] First snapshot verified on the primary DAS by listing it
- [ ] Replica pass verified on the mirror DAS
- [ ] Schedules loaded (times the user chose)
- [ ] Monitor visible and fresh
- [ ] User knows: the printed key can only run `snap|vault|both|probe` —
      nothing on the source machine can delete backup history
- [ ] User knows where the logs live and what `finished (rc=0)` means
