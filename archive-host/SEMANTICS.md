# Replica semantics — what this engine does and does not guarantee

Scope: the **archive-host replica engine** (`archive-host/engine.py`), which copies dated
snapshots from a PRIMARY DAS volume to a MIRROR DAS volume on the same machine.
Every claim below was verified against the shipped source, and the engine's own suite
(430 assertions) exercises each behaviour.

Terminology: **source** = the machine being backed up. **primary** = the DAS volume the
writer creates snapshots on. **mirror** = the second DAS volume this engine copies to.

---

## (a) If a snapshot is deleted or corrupted on the PRIMARY, what happens to the mirror?

**Nothing is deleted from the mirror.** Deleting on the primary does NOT wipe the copy.
That guarantee rests on three independent mechanisms, not on retention alone:

**1. The engine never issues a delete to rsync.** `--delete`, `--delete-before`,
`--delete-during`, `--delete-after`, `--delete-excluded`, `--delete-delay`,
`--remove-source-files`, `--force` and `--inplace` are asserted ABSENT from every rsync
argv, at process start and again immediately before every invocation; a violation aborts
the run (exit 3) rather than proceeding. rsync is therefore structurally incapable of
propagating a deletion, whatever the primary looks like.

**2. A snapshot already on the mirror is never re-synced.** Work is selected as
"settled on the primary AND not already present on the mirror". Once a snapshot has been
verified and promoted, the engine never writes into it again. So deleting or truncating a
file *inside* an existing primary snapshot cannot reach through to the mirror's copy —
there is no code path that would touch it.

**3. Deletion from the mirror happens ONLY via an explicit, age-gated prune** that must
satisfy ALL of:
  - both volumes mounted; and
  - the primary currently holds at least 3 snapshots; and
  - the snapshot is absent from the primary; and
  - it is not the mirror's `latest` target; and
  - its timestamp is older than `PRUNE_AGE_DAYS` (default **100 days**); and
  - at most `MAX_PRUNES_PER_PASS` (default **2**) are removed per pass.

A snapshot missing from the primary and **younger** than 100 days is **retained** and
raises health rule **P9**: *"possible primary data loss - RETAINED, not pruned"*.
A wipe of the primary therefore produces an alarm, not an echo. The 3-snapshot
precondition governs deletion only — the P9 alarm is deliberately NOT gated on it,
because a wipe is precisely what leaves fewer than 3 snapshots behind.

### The rogue-agent case, stated precisely

An agent or process that deletes files on the **source** cannot remove them from the
archive: snapshots are immutable once promoted, so every prior snapshot on BOTH volumes
still contains the file. The next snapshot simply won't include it. Recovery is reading
it out of any earlier snapshot.

An agent that deletes **snapshot directories on the primary DAS** does not propagate that
to the mirror; the mirror retains them and alarms (P9).

### Limits — read these before relying on it

- **Not infinite.** A snapshot absent from the primary IS pruned once it passes the
  100-day threshold. Protection is bounded by `PRUNE_AGE_DAYS`, which is intentionally
  set above the writer's own retention so the mirror always outlives the primary.
- **The mirror is not protected from direct attack.** Anything with write access to the
  mirror volume can delete from it. This engine defends against *primary-side* loss
  propagating; it is not an access-control system, and it is not immutable/WORM storage.
- **It does not protect the primary.** The primary is the writer's target; this engine
  only reads from it.
- **Corruption is detected, not auto-repaired.** If a file inside an existing primary
  snapshot is damaged, the mirror keeps its good copy and deep-verify reports a mismatch
  (P5). It will not overwrite the mirror from a damaged primary, and it will not push the
  mirror's good copy back. Repair is a human decision.

---

## (b) Prune coordination between primary retention and the mirror

The writer enforces its own retention on the primary (in the reference deployment,
90 days). The mirror's `PRUNE_AGE_DAYS` default of **100 days** is deliberately larger.

The margin matters: pruning the mirror at or below the writer's retention would delete
copies while they are still inside the window where a vanished snapshot most likely means
data loss rather than expiry. Set the mirror's threshold **above** the writer's retention
plus a margin for clock skew, an offline source, and human reaction time.

Steady state is bounded and convergent: the mirror holds at most
`PRUNE_AGE_DAYS − writer_retention` days more history than the primary (10 days at the
defaults), never unbounded growth. Pruning is rate-limited to 2 snapshots per pass so no
single fault or clock error can mass-delete the mirror.

---

## (c) What deep-verify checks, and when

`deep-verify` is a separate mode, scheduled daily (03:15 in the reference deployment).
Per run it always targets the newest promoted snapshot, plus a **coverage-driven
rotation** of older ones: enough are selected each pass (`ceil(older / VERIFY_SWEEP_DAYS)`,
capped at `VERIFY_MAX_OLDER_PER_PASS`) that every promoted snapshot is content-checked at
least once within `VERIFY_SWEEP_DAYS`. This matters because coverage is a function of
backup **cadence**, not just retention: at 1 backup/day, 90 days of retention is 90
snapshots and a fixed one-per-pass rotation happens to sweep all of them every 90 days. At
4 backups/day, that same fixed rotation would need 360 days to reach every snapshot once —
three quarters of them would age out and be pruned **having never been content-verified at
all**. If the cost ceiling ever binds tightly enough that a full sweep would exceed
`VERIFY_SWEEP_DAYS`, the engine says so explicitly (an advisory note) rather than silently
verifying less than it claims to.

**Cost, so this doesn't surprise anyone deploying at higher cadence:** each older target is
a full two-sided listing walk plus sampled content hashing — roughly 2-3 minutes per
~150k-file snapshot over USB in the reference deployment. At the reference cadence (1
backup/day -> ~90 snapshots), a nightly pass is cheap. At 4 backups/day -> ~360 snapshots,
the ceiling (`VERIFY_MAX_OLDER_PER_PASS = 8`) makes a nightly pass take on the order of
30-70 minutes. Still fine for a once-daily job with nothing else contending, but no longer
negligible — budget for it, and raise `VERIFY_MAX_OLDER_PER_PASS` only with that cost in
mind.

Each targeted snapshot performs:

- a full listing comparison against the primary — file count, total bytes, and an md5 of
  the sorted `relpath\tsize` listing; and
- **content hashing of a sample** (200 files, seeded on stamp+date, files >64 MB skipped);
  and
- manifest backfill for snapshots that predate manifest support.

Where the primary's copy has already been pruned, the snapshot is verified against the
per-snapshot manifest stored at promote time, which records the sampled file hashes for
exactly this purpose. Any mismatch sets **P5** and emits a `verify_failed` event.

**Why sampling matters, honestly stated:** the per-copy verification proves the mirror
matches the primary *at copy time*. It cannot detect bit rot afterwards, nor a case where
the mirror's base copy was already wrong while the primary's inode was unchanged.
Scheduled content hashing is the only mechanism that catches that class, which is why it
is a scheduled job and not an optional extra. Health rule **P13** fires if deep-verify has
never completed, or its last success is more than 8 days old — an absent safety net is
reported as a problem, not as a neutral state.

---

## (d) Replica schedule

- **Poll:** every 300 s (`StartInterval`), with `RunAtLoad` true. Detection latency is
  therefore ≤5 minutes, and the schedule survives a reboot: on load the engine retries
  until the DAS volumes appear. An unmounted volume is a failure (exit 1, rule P1), never
  a success.
- **Post-write kick (optional):** the writer may invoke the entrypoint over ssh
  immediately after a successful snapshot, so replication begins in seconds rather than
  waiting for the next poll. The entrypoint must therefore behave correctly when invoked
  with **no arguments** — that is the contract with the writer, and breaking it fails
  silently, because the writer reports success either way.
- **Deep verify:** daily, separate LaunchAgent.
- **Concurrency:** a single `flock` held for the process lifetime. Overlapping passes exit
  2 without copying. The kernel releases the lock if the holder dies (including SIGKILL or
  power loss), so there is no stale-lock heuristic to go wrong.

A legacy calendar schedule (e.g. 03:00/13:00 twice-daily) is a valid alternative to
interval polling, but note that calendar-only scheduling with `RunAtLoad=false` leaves the
replica idle from a reboot until the next scheduled hour. Interval + RunAtLoad is
recommended for exactly that reason.

---

## Deployment shape

**DAS, not NAS.** Both volumes are directly attached to the archive host. The design
assumes local filesystem semantics — atomic same-filesystem rename for promotion, and
hardlink-based deduplication between snapshots. Neither survives a network filesystem
reliably, and the engine has not been validated on one.

**Best served on a remote system.** Running the archive host on a separate machine from
the source means a compromise or failure of the source does not reach the archive.

**Single-machine mode is first-class.** Source and archive host may be the same machine.
On macOS this is not merely supported but *required* to work a particular way: a LaunchAgent
invoking a shell directly cannot read removable volumes or protected folders under TCC, and
fails with `Operation not permitted`. Routing the job through ssh-to-localhost with a
dedicated key and a forced command executes it under `sshd`, which holds the necessary
grant. That mechanism is what makes same-machine operation reliable, and it is the same
mechanism used for the remote case.
