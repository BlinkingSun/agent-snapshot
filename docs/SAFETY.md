# SAFETY — the data-protection model, in depth

The prime directive of this system: **nothing that happens on the source
machine — human mistake, script bug, or rogue AI agent — can permanently
destroy backup history.** Everything below serves that.

## 1. History is immutable dated snapshots, not a mirror

Each snap run creates a brand-new directory `YYYY-MM-DD_HHMMSS/` on the
primary DAS. Unchanged files are **hardlinked** against the previous snapshot
(rsync `--link-dest`), so fifty snapshots of a stable tree cost barely more
than one, while every snapshot is a complete, browsable copy.

Consequences:

- **Deleting a file at the source deletes nothing on the archive.** The file
  simply stops appearing in *future* snapshots. Every snapshot taken while it
  existed still contains it, until age-based retention (default 90 days)
  expires that snapshot.
- The `--delete` flag in the rsync invocation operates **inside the brand-new
  dated directory being built** (it starts from the hardlink base). It never
  modifies previous snapshots. Snapshots are write-once by design.
- A rogue `rm -rf` of the entire source tree produces one thin, mostly-empty
  new snapshot — and 90 days of full history sitting untouched beside it.

## 2. The source machine cannot reach backup history destructively

The scheduled transport is a **dedicated SSH key locked with
`restrict,command="...snapshot-dispatch"`**. The dispatcher accepts exactly
four words: `snap`, `vault`, `both`, `probe`. Anything else — a shell, an
`rm`, an rsync crafted to overwrite history — is refused and logged.

So even an agent (or malware) that fully controls the source machine and
steals the backup key can only... trigger a backup, or a read-only probe.

**Hardening note (two-machine setups):** the snapshot rsync itself travels
over your normal ssh identity to the archive host. If you want the same
guarantee on that hop, give it a dedicated key too and restrict it on the
archive host with a forced command that only permits rsync into the snapshot
directory (e.g. `rrsync -wo <PRIMARY>/agent-snapshot`) — then no credential on
the source machine can delete archive data at all. Recommended for
agent-heavy machines; single-machine mode already has this property for the
scheduled path.

## 3. Deleting on the primary drive does not wipe the mirror

The mirror is **not a naive `--delete` mirror of the primary**. Three
independent mechanisms in the replica engine guarantee it — each verified in
source and exercised by the engine's 430-assertion suite (full statement:
[`archive-host/SEMANTICS.md`](../archive-host/SEMANTICS.md)):

1. **The engine never issues a delete to rsync.** Every `--delete*` variant,
   `--remove-source-files`, `--force` and `--inplace` are asserted absent from
   every rsync argv — at startup and again before each invocation — and a
   violation aborts the run. rsync is structurally incapable of propagating a
   deletion, whatever the primary looks like.
2. **A promoted snapshot is never re-synced.** Work is selected as "settled on
   the primary AND not yet on the mirror", so deleting or truncating files
   inside an existing primary snapshot has no code path to the mirror's copy.
3. **Mirror deletion happens only via an explicit, age-gated prune**: both
   volumes mounted, primary holding ≥3 snapshots, the snapshot absent from the
   primary, not the mirror's `latest`, **older than 100 days**
   (`PRUNE_AGE_DAYS`), and at most 2 removals per pass. Anything absent from
   the primary but younger than that is **retained and alarmed** (health rule
   P9: "possible primary data loss — RETAINED, not pruned"). A wipe of the
   primary produces an alarm, not an echo.

**The limits, stated just as plainly** (they are what make the guarantee
trustworthy):

- Protection is **bounded, not infinite**: a snapshot absent from the primary
  is pruned once it ages past `PRUNE_AGE_DAYS`. That threshold must stay above
  the writer's `SNAP_RETENTION` plus reaction margin (defaults: 100 vs 90).
- **The mirror is not WORM storage and not access control.** Anything with
  write access to the mirror volume can delete from it directly. The engine
  defends against *primary-side* loss propagating — keep the archive host
  itself boring and agent-free.
- **Corruption is detected, not auto-repaired — deliberately, not a missing
  feature.** A damaged file in a primary snapshot never overwrites the
  mirror's good copy; deep-verify raises P5 and a human decides the repair
  direction. This restraint is what makes the mirror trustworthy as a
  reference copy: an engine that "fixed" every mismatch by re-syncing would,
  on a genuinely damaged or contaminated primary, propagate that damage onto
  the mirror and destroy the one good copy that made diagnosis possible in
  the first place. Proven in practice: a false-positive P5 (Finder writing
  `.DS_Store` into a promoted snapshot) was diagnosed in hours specifically
  *because* the mirror had been left untouched to compare against.

## 4. Verified at every hop

- **Vault archives:** integrity-tested (`zstd -t`) *before* transfer — a
  truncated tar with valid bytes would otherwise hash-match and ship; then
  sha256-compared source-vs-destination *after* transfer. Only then is the
  local staging copy released.
- **Snapshots:** rsync exit codes are checked (vanished-file rc=24 is the one
  tolerated case, logged); the run is failed otherwise.
- **Drives:** deep-verify compares primary and mirror content so "the copy
  exists" is proven, not assumed.
- **Freshness:** the monitor shows last-snapshot age and last-check age —
  numbers that visibly move when the system is alive, unlike free-space
  percentages on a huge drive.

## 5. Failure is loud, absence is not success

- An unreachable target is a FAILED/SKIPPED result and a nonzero exit — never
  silently treated as done.
- Every run appends a summary to the monthly log; `finished (rc=0)` is the
  only success marker.
- Free-space floors abort the run before they'd wedge a drive.

## 6. What this does NOT protect against — be honest with yourself

- **Compromise of the archive host itself.** Anyone with a shell on the
  archive host can destroy both drives. Keep it remote, minimal, and boring;
  don't run agents on it.
- **Physical loss of the site** (fire, theft, surge taking both DAS drives).
  The optional vault leg on separate hardware helps; true off-site is on you.
- **Data that never made it into a snapshot** — files created and destroyed
  between runs. Tighten the schedule if that window matters.
- **Source-side completeness** is only as good as your excludes: an
  over-broad `EXCLUDES` entry silently thins every backup. Review
  `conf/snapshot.conf` after install, and check the run summaries' sizes
  against expectations.

## Recovery quick reference

```bash
# browse history (it's just directories)
ssh user@archive-host 'ls /Volumes/SnapArchive/agent-snapshot/'
# restore one file from the newest snapshot
scp 'user@archive-host:/Volumes/SnapArchive/agent-snapshot/latest/path/to/file' ./
# restore a whole tree as of a date
rsync -rlptD user@archive-host:/Volumes/SnapArchive/agent-snapshot/2026-08-20_120005/ ./restored/
# vault archive
zstd -d < 2026-08-20_000000.tar.zst | tar -xf -
```
