# Replica semantics — what this engine does and does not guarantee

Scope: the **archive-host replica engine** (`archive-host/engine.py`), which copies dated
snapshots from a PRIMARY DAS volume to a MIRROR DAS volume on the same machine.
Every claim below was verified against the shipped source, and the engine's own suite
(468 assertions) exercises each behaviour.

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

**When: monthly, straight after the early-morning copy.** A `mirror` pass that has just
promoted a snapshot whose stamp hour is in `DEEP_VERIFY_EARLY_HOURS` (03-06) runs the sweep
itself, still holding the lock, once the last successful sweep is at least
`DEEP_VERIFY_MIN_INTERVAL_HOURS` old (28 days). Copies that arrive meanwhile simply wait —
their passes bounce off the lock and heartbeat — and resume on the next pass, so the sweep
never races a copy and never needs its own timer. The busy timer is restarted when the sweep
begins, so P14 measures the sweep, not copy-plus-sweep back to back.

Why not a nightly job any more: on a large tree a copy can run for hours, and at several
backups a day the engine is busy almost continuously. A fixed nightly window then collides
with an in-flight copy nearly every night and the safety net silently stops (it did, for nine
days, in the reference deployment). Running it *inside* the pass that just finished the early
copy removes the collision by construction.

`deep-verify` is still available as an explicit mode. Within the month it is a logged no-op
(the interval guard); `SNAP_FORCE_DEEP_VERIFY=1` runs a sweep by hand regardless.

**Honest cost of monthly:** each run still targets the newest promoted snapshot plus the
rotation below, but at one run a month the rotation no longer sweeps every snapshot before it
is pruned. Monthly deep-verify is a **spot-check** of the archive, not exhaustive coverage. If
you need every snapshot content-checked within its lifetime, lower
`DEEP_VERIFY_MIN_INTERVAL_HOURS` and accept that the sweep will contend with copies.

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
never completed, or its last success is more than `DEEP_VERIFY_MAX_AGE_DAYS` (35) days old —
a monthly sweep plus slack. An absent safety net is reported as a problem, not as a neutral
state.

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
- **Deep verify:** monthly, inside the mirror pass that promotes the early-morning snapshot
  (see (c)). No separate LaunchAgent.
- **Handshake:** a ~60 s poll (`mirror.sh handshake` -> `handshake.py`) probes whether the
  writer is reachable and records it in `handshake.json`; see (f). It has its own rate-limit
  lane and deliberately takes no busy-lock, so a long copy never blinds it.
- **Concurrency:** a single `flock` held for the process lifetime. Overlapping passes exit
  2 without copying. The kernel releases the lock if the holder dies (including SIGKILL or
  power loss), so there is no stale-lock heuristic to go wrong.
- **Lock-held heartbeat:** a pass that finds the lock held does NOT exit silently. The
  entrypoint hands the busy case to `engine.py`, whose own flock refreshes `status.json`
  (`ts`, `mirror_running: true`) and computes the lock-held health subset (P1/P13/P14/P15)
  before exiting 2. Without this, a healthy multi-hour copy aged into a false stale-FAIL at
  minute 30, and those rules were starved for the whole copy.
- **Long-run caps:** P14 (a copy/sweep claiming to run longer than `SUPPRESS_CAP_SECONDS`)
  and P15 (a settled snapshot still uncopied after `PENDING_MAX_SECONDS`) are both **12 h**.
  Copies of large trees legitimately take ~6 h, and a monthly sweep can follow one.

A legacy calendar schedule (e.g. 03:00/13:00 twice-daily) is a valid alternative to
interval polling, but note that calendar-only scheduling with `RunAtLoad=false` leaves the
replica idle from a reboot until the next scheduled hour. Interval + RunAtLoad is
recommended for exactly that reason.

---

## (e) Latest success wins — and nothing becomes invisible

**The most recent backup is the most important one.** When a snapshot fails to copy, the
copy loop continues past it (one bad snapshot costs exactly that snapshot, never every later
one) and it raises **P4**. When a LATER snapshot then promotes healthily, that success
**supersedes** the earlier failure: the failed stamp leaves `pending`, P4/P15 clear, and the
board returns to green with no operator action.

Safeguards, so supersede can never hide a real fault:
- **Health-gated.** A promote only supersedes if its verified file count is at least
  `SUPERSEDE_HEALTH_FRACTION` (0.5) of the median of the last `SUPERSEDE_HEALTH_MANIFESTS` (7)
  manifests. A void or nearly-empty snapshot cannot clear anyone's alarm.
- **Never invisible.** The superseded stamp stays in STATUS as a `kind: "superseded"` row
  (its failure record keeps `superseded_by` / `superseded_at`), and a `superseded` event is
  logged. Rows older than 72 h are flagged `hidden` for display only; they stay in the data.
- **Opt back in.** An operator retry (`retry-request.json`, written by the monitor and
  consumed by the engine at the start of a pass) deletes the superseded record so the stamp
  re-enters `pending` that same pass. Consumes are counted in `retry_history` for the
  monitor's cooldown.
- **Patterns stay loud.** "P4 PATTERN" (3 distinct failed stamps within 7 days) and
  "P4 SYSTEMIC" (every pending stamp failing at once) are volume-level and can be neither
  superseded nor muted.

**Per-snapshot mute.** `muted.json` (written only by the monitor) writes a snapshot off on
purpose — a deliberately voided backup, or a corpse left by a writer run that died. A muted
stamp leaves `pending`, is never retried, is never a `--link-dest` base, and its per-stamp
problems move from `problems[]` to `muted_problems[]`, so `healthy` can return to true. Only
`P4/P9/P10/P11/P12/P15` are mutable, and a problem must name ONLY muted stamps — a
volume-level fault can never be muted. A mute lands on the next pass (the monitor does not
kick the engine for it). Unmuting restores the alarm immediately. **Per-line mutes**
(`muted-lines.json`) can silence any banner line and expire completely after 72 h.

**Mixed-use volumes.** Only `<volume>/snapshots` is cloned or watched. The old whole-volume
used-space / inode-count delta rules (P6/P7) were removed: on a volume that also holds other
data they are structurally meaningless. A manifest-ledger tripwire covers the one thing they
uniquely caught — a snapshot deleted from the mirror only.

---

## (f) On/off switch and the writer handshake

`handshake.py` probes the writer with a dedicated, forced-command-restricted key that can
only run the writer's read-only `probe-auth` mode, and records `reachable` / `last_check` in
`handshake.json`. When the writer is unreachable (travelling, asleep, off the network), the
engine **pauses**: no copies, a calm note, `system_enabled: false`, and the monitor shows
"off" — not a failure. A real problem always outranks "off".

If `handshake.json` is missing or older than `HANDSHAKE_STALE_SEC` (180 s), the engine
**fails open**: it runs normally and says so out loud ("the connectivity watchdog may be
down"). A backup system must never silently stop protecting data because its own watchdog
died.

A **manual override** (`engine.py enable` / `disable`, reachable remotely only through the
narrowly-scoped `control.sh` forced command) always wins over the handshake and persists
through reconnects, so a deliberate pause is never silently undone.

---

## (g) Self-healing fallbacks worth knowing about

- **Unreadable basis -> one baseless copy.** openrsync aborts the whole copy (rc 11) when an
  entry in the `--link-dest` basis changed type (for example a symlink replaced by a regular
  file); because base selection is deterministic, every retry would hit the same entry. The
  engine retries ONCE with no `--link-dest`. That stamp forgoes dedup; once it promotes it
  becomes the next base and dedup returns on the following copy.
- **Manifest-less bases are re-verified before use.** A promoted snapshot with no manifest
  (state predating manifests, or a lost state dir) is re-verified against the primary and its
  manifest backfilled before it may serve as a `--link-dest` base.
- **The writer's change sidecar is not consumed.** With `SNAP_CHANGE_SIDECAR=true` (off by
  default) the writer publishes `snapshots/.changes/<stamp>.json` after each incremental
  snapshot. The engine does not read it: a
  sidecar-driven fast path was built and rolled back, because `rsync -a --link-dest` already
  writes only changed files and the fast path added full-tree walks rather than removing them.
  Every copy takes the full, verified path.

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
