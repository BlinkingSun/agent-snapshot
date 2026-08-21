# Security Hardening Plan — Key Rotation + Snapshot-Spam Protection

**Status:** Ready for implementation. Produced 2026-08-21 via three parallel/sequential
Cursor agent passes (key-rotation design, anti-spam design, adversarial review) against
the live repo. Adversarial verdict: **GO-WITH-CHANGES** — the 12 mandatory changes below
are already folded into this plan, not left as a separate to-do list to reconcile later.

**For the implementing team:** this document is self-contained. The three raw agent
transcripts (full reasoning, alternatives considered, complete pseudocode) are archived
at the bottom under Appendix A if you want the unabridged version of any decision.

---

## 0. TL;DR

Two real gaps, both in how the forced-command SSH dispatchers (`bin/snapshot-dispatch`
on the source machine, `archive-host/mirror.sh` on the archive host) are secured:

1. **No key rotation.** Both dispatchers are guarded by a single static ed25519 key,
   generated once, never expiring. A leaked key is valid forever until a human notices.
2. **No spam protection.** The allowlist correctly blocks delete/shell access, but
   repeatedly triggering `snap`/`both` can force the writer's own free-space-floor logic
   (`prune_snap_to_fit()`) to delete real snapshot history early — an indirect but real
   data-loss path that never issues a delete command.

**Fixes, in the order to build them:**

1. Rate-limit both dispatchers first (closes the active abuse path today).
2. Add scheduled key rotation with an overlap window second (bounds future key leaks).
3. Ship them together tomorrow — they were designed to not conflict, and the adversarial
   pass confirmed the interaction is safe (see §4.1).

Estimated scope: one focused implementation day for a team, per the checklist in §5.

---

## 1. The Report: What's Actually Wrong

### 1.1 What already works (do not weaken this)

Both dispatchers use **forced-command SSH**: `authorized_keys` pins
`restrict,command="/bin/bash <dispatcher>"`, so the key's holder cannot choose what
runs — only `snap|vault|both|probe` (source) or `mirror|deep-verify` (archive). A stolen
key cannot delete history, open a shell, or run arbitrary commands. This containment is
solid and every design below preserves it exactly.

### 1.2 The gap: static, non-expiring, undifferentiated keys

Both keys are:
- Generated once, by the installer, and never rotated or expired.
- Shared identically by launchd, a human running it by hand, and any AI agent
  triggering it on demand — no distinction, no audit trail per caller.
- Valid until a human manually notices a leak and hand-edits `authorized_keys`.

For a key captured from a Time Machine backup, a disk image, or a compromised tool that
read `~/.ssh`, this is unbounded exposure — the exact failure mode key rotation exists
to bound.

### 1.3 The concrete abuse path (verified against the live code, twice independently)

`bin/snapshot`'s `backup_snap()`:

```bash
if [ "${freegb:-0}" -lt "$SNAP_MIN_FREE_GB" ]; then
  log "[snap] below floor — pruning oldest snapshots to make room"
  prune_snap_to_fit
  ...
```

`prune_snap_to_fit()` deletes **exactly one** oldest snapshot per invocation, whenever
free space is below the configured floor — no age check, no retention-policy check:

```bash
prune_snap_to_fit() {
  ...
  if [ "$count" -gt 1 ]; then rm -rf "$(echo "$list" | head -1)"; fi
}
```

**A holder of the source-side key — even though it cannot delete or run arbitrary
commands directly — can repeatedly trigger `snap` or `both`.** Each successful run near
the free-space floor can force one early, retention-bypassing deletion. This is
indirect, rate-limited to one deletion per completed run, but it is **real data loss**,
not mere denial-of-service. This is the exact "snapshot spamming" concern this plan
protects against.

**Corrected severity (per adversarial review, §4.2 below):** the original proposed
sustain limit (5 triggers/hour) under-stated this. At disk floor, sustained abuse at
that rate could delete up to 5 snapshots/hour, every hour — enough to erase an entire
~90-day/~90-snapshot primary history in under a day. **This plan uses the corrected,
tighter default (≤2/hour) throughout — see §3.3.**

The archive host has a structurally identical dispatcher (`mirror.sh`) guarding a
separate key; `deep-verify` in particular is expensive (~2–3 min per snapshot walk per
`SEMANTICS.md`), making repeated forced triggers a cheap availability attack against the
archive host and the monitor, even without any deletion risk on that side.

---

## 2. Fix 1 — Snapshot-Spam Flag-and-Deny (build this first)

### 2.1 Where enforcement lives

| Location | Enforce? | Why |
|---|---|---|
| `bin/snapshot-dispatch` | **Yes — primary chokepoint** | Every source-side trigger (scheduled or manual) passes through here before `bin/snapshot` runs. |
| `archive-host/mirror.sh` | **Yes — independent gate** | Separate machine, separate key, separate threat lane. Must not share state with the source. |
| `bin/snapshot` / `engine.py` | No (enforcement); yes (P16 observability on archive side) | Too late for enforcement — side effects already start. |

### 2.2 Thresholds (corrected per adversarial review)

**Source machine** (`snap`, `vault`, `both`; `probe` is exempt — read-only by contract):

| Parameter | Value | Meaning |
|---|---|---|
| `SNAP_RATE_BURST_COUNT` | **3** | Max accepted triggers in the burst window |
| `SNAP_RATE_BURST_WINDOW_SEC` | **600** (10 min) | Burst window |
| `SNAP_RATE_SUSTAIN_COUNT` | **2** ⚠️ *(corrected from the initial design's 5 — see §1.3)* | Max accepted triggers in the sustain window |
| `SNAP_RATE_SUSTAIN_WINDOW_SEC` | **3600** (60 min) | Sustain window |

Deny if **either** window's count is met or exceeded. This still allows a human to run
a backup, then retry once shortly after for testing (2 in a few minutes: fine), and
never comes close to the real scheduled cadence (as tight as one trigger per 4–6 hours
in the current deployment) — but now bounds worst-case forced deletion at disk floor to
**2/hour instead of 5/hour**, roughly halving the maximum possible history loss.
Document the "5/hour" number was the original design's proposal and this plan
deliberately tightens it; don't silently use 5 out of old habit if referencing draft
notes.

**Archive host** (forced-command path only — see kick exemption, §2.6):

| Mode | Count | Window | Why |
|---|---|---|---|
| `mirror` | **4** | 300s (5 min) | Reference poll interval is 300s (12 legitimate triggers/hour from launchd alone); this catches back-to-back spam without touching normal polling. |
| `deep-verify` | **2** | 86400s (24h) | Reference deployment runs this once daily; allows one retry, denies sustained multi-hour-burning spam. |

### 2.3 State tracking

Matches existing directory conventions exactly:

| Path | Purpose |
|---|---|
| `~/Library/Application Support/agent-snapshot/state/trigger-history.json` | Sliding-window timestamps (source) |
| `~/Library/Application Support/agent-snapshot/state/trigger-history.lock` | `flock` for the read-prune-check-append-write cycle |
| `~/Library/Application Support/agent-snapshot/state/last-rate-limit.json` | Last denial (audit/flag artifact) |
| `~/Library/AgentSnapshot/trigger-history.json` (+ `.lock`, `last-rate-limit.json`) | Same schema, archive host, matches `engine.py`'s existing `DEFAULT_STATE_DIR` |

Permissions: `0700` on the `state/` directory, `0600` on the JSON files, owned by the
install user. Directory creation via `mkdir -p` under `umask 077`.

Schema (one JSON object per lane, pruned to the max window on every check, capped at 64
entries as a safety bound):

```json
{
  "schema": 1,
  "lane": "source-forced",
  "entries": [{"ts": 1724210400, "mode": "snap", "client": "127.0.0.1 49152 22"}]
}
```

Archive lanes are separate: `archive-forced-mirror` and `archive-forced-deep-verify`.
The legitimate writer-kick path writes **no entry at all** (see §2.6).

### 2.4 Dispatcher logic

**`bin/snapshot-dispatch`** — insert before `exec bash "$BIN" "$MODE"` for
`snap|vault|both`:

```
1. Mode allowlist check (existing — unchanged)
2. If mode == probe: skip rate limit entirely (unchanged behavior)
3. Non-blocking check: is bin/snapshot already running (STAGE/.lock)?
     → if busy: exit 79, write NOTHING to trigger-history (see §4.4 for the
       fix to the TOCTOU race here)
4. Acquire trigger-history.lock (flock -x)
5. Prune entries older than max(window); count burst window; count sustain window
6. If either count >= its limit:
     → write last-rate-limit.json (ts, mode, reason, counts, client, retry_after)
     → log DENIED to dispatch.log
     → release lock, exit 78 (NEW — distinct from existing exit 77 "unknown mode")
     → do NOT exec bin/snapshot
7. Else: append this trigger, write history, release lock
8. exec bash "$BIN" "$MODE"           (unchanged)
```

**⚠️ Mandatory fix before this works (adversarial finding, §4.3):** `snapshot-dispatch`
today only sources `conf/snapshot.conf` for the `probe` mode — `snap|vault|both` do
**not** currently source it. The busy check needs `$STAGE` and the rate limit needs the
threshold variables, both of which live in the conf file. **Add conf sourcing for
`snap|vault|both` as part of this change**, not as an assumed pre-existing behavior.

**`archive-host/mirror.sh`** — same shape, plus the kick exemption:

```
1. Writer-kick exemption: if $AGENT_SNAPSHOT_KICK == "1": exec engine.py "$mode" immediately,
   no rate check, no history entry (see §2.6 for the trust model this relies on)
2. Forced-path detection: only enforce rate limiting when $SSH_CONNECTION is set
   (i.e., this really did arrive over the forced-command key, not a local/cron
   invocation) — document that Linux archive hosts (plain cron, no forced-command
   hop) are out of scope for this gate, same as they're already out of scope for
   key rotation
3. Non-blocking check: is engine.py already running (mirror.pid)? → exit 79, no entry
4. Mode-specific rate check against the thresholds in §2.2 (own lane per mode)
5. Deny → write last-rate-limit.json, exit 78
6. Else → append entry, exec python3 engine.py "$mode"
```

### 2.5 Exit codes

| Code | Meaning | Status |
|---|---|---|
| 0 | Success | Existing |
| 1 | Operational failure | Existing |
| 2 | Engine pass skipped, lock held | Existing (archive engine only) |
| **77** | Unrecognized mode | Existing |
| **78** | **Rate-limit denial (new)** | New, both dispatchers |
| **79** | **Already running — busy, not spam (new)** | New, both dispatchers |

### 2.6 The writer-kick exemption and its actual trust boundary

The writer's post-snapshot kick (`REPLICA_KICK` in `conf/snapshot.conf`) SSHs into the
archive host using the **normal `SNAP_SSH` identity**, not the replica forced-command
key — it bypasses the dispatcher's allowlist entirely by design (that's how the
kick reaches `mirror.sh` directly). The updated `REPLICA_KICK` string becomes:

```bash
REPLICA_KICK='AGENT_SNAPSHOT_KICK=1 nohup "$HOME/Library/AgentSnapshot/mirror.sh" >/dev/null 2>&1 &'
```

**State this precisely, not more strongly than it is (adversarial finding, §4.5):**
this exemption is **not bypassable by anyone holding only the replica forced-command
key** — they cannot set an env var on a shell they never reach. But anyone who
already has the normal `SNAP_SSH` identity (a materially different, already-privileged
credential) can also set `AGENT_SNAPSHOT_KICK=1` themselves and fully bypass the
archive rate limit. This is **not a new hole this change introduces** — `docs/SAFETY.md`
§2 already documents `SNAP_SSH` as unrestricted and recommends a follow-on hardening
(a dedicated `rrsync`-restricted key) for exactly this reason. Document the exemption
as: *"archive rate limits protect the replica forced-command key; the kick path is
trusted at the same level as `SNAP_SSH` already is."* Don't oversell it as closed.

**Ship the `mirror.sh` rate gate and the updated `REPLICA_KICK` string in the same
change** — deploying one without the other either breaks the kick (old string, new
`mirror.sh` requiring the flag) or leaves it uncovered (new string, old `mirror.sh`).
Existing deployments upgrading need an explicit note to update their conf.

### 2.7 Flag / monitor integration

**Source (no monitor today):** `last-rate-limit.json` + a loud `DENIED` line in
`dispatch.log` is sufficient for v1 — matches the existing "tail the monthly log"
habit. No new plumbing required.

**Archive (monitor exists):** add health rule **P16** to `engine.py`'s
`compute_health()`, same pattern as the existing P1–P15:

```python
self.problem("P16 forced-command trigger rate-limited (%s): %s at %s — "
             "possible abuse of replica key" % (mode, reason, iso))
```

Append a `rate_limited` event to `events.jsonl`. P16 clears when no new denial lands in
24h (or an operator deletes `last-rate-limit.json`) — document that as expected, not a
bug, so a 24h-old alarm after a stopped attack doesn't confuse anyone.

### 2.8 Known limitations (state these, don't bury them)

1. Key-only threat model. A local account with actual shell access can delete state
   files or run `bin/snapshot` directly — full host compromise is out of scope, same as
   the rest of this repo's threat model (`docs/SAFETY.md` §6).
2. Even at the corrected 2/hour, sustained abuse at disk floor still causes *some*
   accelerated loss — this bounds the worst case, it does not eliminate it.
3. `probe` remains unlimited by design (read-only, no prune path) — a minor CPU/network
   nuisance at worst.
4. Linux archive hosts (plain cron, no forced-command dispatcher) are outside this
   gate's coverage, consistent with them already being outside key-rotation's scope.

---

## 3. Fix 2 — Key Rotation (build this second)

### 3.1 Recommendation

**Primary (v1): scheduled rotation with an overlap window**, via a new unified
`bin/snapshot-key-rotate` script used on both the source machine (`--role writer`) and
the archive host (`--role replica`).

**Rejected as primary: porting a token-push ephemeral-token pattern.** That pattern
(push a per-job token, consumed and deleted before the real command runs) solves a
different layer of the problem. In a token-push dispatcher, SSH just gets you a shell,
and the job token is a second factor consumed inside it. Here, the **SSH key itself is the
capability** — authentication completes before `snapshot-dispatch`/`mirror.sh` ever
runs, so there is no "delete it before the real command starts" moment available.
Porting the pattern literally would add complexity without adding security.

**Optional v2, not needed for tomorrow: OpenSSH CA with short-lived certificates.**
For operators who want per-invocation validity rather than periodic rotation. Shares
the same dispatcher/install plumbing; only how credentials are minted changes. Ship as
an opt-in `--auth-mode certificate` profile later, not part of this pass.

### 3.2 Mechanism (v1)

New per-role directory:

```
~/.ssh/agent-snapshot/
  state.json        # active key id, previous key id, overlap deadline, role
  rotation.log
  keys/
    key-<timestamp>       (0600 private + .pub)
    key-<previous-timestamp>   (retained only during overlap)
```

A **stable symlink** (`~/.ssh/id_ed25519_agent_snapshot` for the writer,
`~/.ssh/id_ed25519_agentsnapshot_replica` for the replica) points at the currently
active key in the registry. **launchd plists keep referencing the stable symlink path
— they never change.** Rotation only ever updates the symlink target and the
`authorized_keys` lines.

`authorized_keys` comment format becomes `agent-snapshot:<key-id>` (writer) /
`agent-snapshot-replica:<key-id>` (replica) so rotate/finalize can match lines
precisely. During overlap, **two lines coexist** (old + new key, identical
`command=`, different comments).

`bin/snapshot-key-rotate` subcommands:

| Subcommand | Purpose |
|---|---|
| `bootstrap` | Migrate an existing flat key into the registry (upgrade path) |
| `status` | Print active/previous key ids, overlap window, pending actions |
| `rotate` | Generate new key, enter overlap, flip symlink, probe |
| `finalize` | Remove the previous key's `authorized_keys` line, securely delete its private key |
| `rotate-if-due` | What the scheduled launchd job actually calls — rotate if the active key is older than the configured interval; auto-finalize if overlap has expired and a probe against the *current* key succeeds |

**Default install never edits `authorized_keys` automatically** (same safety property
as `snapshot-install` today) — `rotate`/`finalize` print the exact line to
append/remove; `--apply-authorized-keys` is opt-in for operators who want full
automation, with a timestamped backup taken before every edit.

**Gate that matters (adversarial finding, §4.7 — pick this, not the alternative):**
do **not** flip the stable symlink to the new key until the new key's line is
confirmed present in `authorized_keys` (`grep -F` check). Flipping first and appending
second creates a real lockout window where the client tries the new key before the
server accepts it. This is stated as the "recommended" path in the underlying design
but contradicted by an earlier pseudocode draft that flips first — **use the
grep-gated order, not the draft pseudocode's naive order.**

### 3.3 Schedule and config

```bash
# conf/snapshot.conf.example additions
KEY_ROTATION_ENABLED=true
KEY_ROTATION_DAYS=90          # rotate when the active key is older than this
KEY_OVERLAP_HOURS=72          # how long the previous key stays valid after rotation
KEY_ROTATION_APPLY_AK=false   # default print-only; true only for operators who accept auto-edit
```

New launchd template (source): `launchd/com.agent-snapshot.key-rotate.plist.template`,
weekly (e.g. Sunday 04:00, before typical snap jobs), running `rotate-if-due --role writer`.
Parallel template for the archive host, `--role replica`.

### 3.4 Rotation guard must match the dispatch busy-check (adversarial finding, §4.6)

Use a **non-blocking probe of `STAGE/.lock`** to decide whether a snapshot is currently
running before starting a rotation — not `.pid` alone, which leaves a small window
where rotation could start mid-snapshot. This is the same lock Fix 1's busy-check
already uses; both features must agree on it.

### 3.5 Failure modes

| Scenario | Behavior |
|---|---|
| Rotation attempted mid-snapshot | Deferred (same lock-probe as above) |
| New `authorized_keys` line not yet appended (print-only mode) | Symlink not flipped; old key keeps working; `status` shows a pending-action note |
| Probe fails right after a symlink flip | Automatic rollback to the previous key; newly appended line removed if auto-apply was on; logged loudly |
| Archive host unreachable during a scheduled writer rotation | Irrelevant — writer rotation is entirely local to the source machine |
| First-ever install | `snapshot-install` creates the legacy key as always; first `bootstrap` brings it into the registry; the very first `rotate` after bootstrap is the first time overlap logic actually runs |
| Existing deployments upgrading | `bootstrap` migrates the flat key in place without forcing an immediate rotation |

### 3.6 Confirmed-safe interaction with Fix 1 (adversarial finding, §4.1)

During the 72-hour overlap window, two keys are simultaneously valid — but Fix 1's rate
limiter treats all forced-command triggers as **one shared lane** regardless of which
of the two valid keys was used. An attacker holding both keys during overlap cannot
double their quota by alternating between them; both land in the same
`trigger-history.json` and count against the same limits. **This must stay true if
caller-scoped key "slots" (§3.7) are ever added** — that would require the rate limiter
to gain per-key lanes, or overlap plus multiple slots would genuinely multiply quota.
Not needed for tomorrow; flag it as a hard coupling if that feature is ever revisited.

### 3.7 Explicitly out of scope for this pass

- **Caller-scoped keys** (separate key per launchd/manual/agent caller) — a good
  additive hardening, not required for v1, and would require the rate-limiter coupling
  noted in §3.6 if added later.
- **The source→archive rsync hop's key** (`SNAP_SSH` in `conf/snapshot.conf`) — already
  flagged in `docs/SAFETY.md` §2 as a recommended follow-on (a restricted `rrsync` key),
  and directly relevant to the kick-exemption trust boundary in §2.6, but a separate
  piece of work from rotating the two forced-command keys.
- **Linux archive hosts** — plain cron, no forced-command dispatcher; out of scope for
  both fixes in this pass.

---

## 4. Adversarial Review — Verdict and Findings

**Verdict: GO-WITH-CHANGES.** The combined plan is directionally correct — right
chokepoints, a verified real abuse path, and a rotation design that does not
accidentally undermine the rate limiter. It was **not ready to implement verbatim** in
its first draft; the corrections below are already folded into §§2–3 above, not left as
a separate pass to reconcile.

| # | Finding | Resolution (already applied above) |
|---|---|---|
| 1 | Two valid keys during overlap + one shared rate lane — could this double quota? | **Confirmed safe** — no quota doubling. Coupling noted for future caller-scoped keys (§3.6). |
| 2 | Does `vault` triggering cause the same kind of forced-deletion abuse as `snap`? | **Confirmed safe** — `prune_vault()` is age-based (`find -mtime +N`), idempotent under repeated triggers. Don't treat vault spam as a retention-bypass risk; it's a storage/DoS concern only. |
| 3 | Is the proposed sustain threshold (5/hour) actually safe? | **Real gap** — corrected to 2/hour (§2.2); 5/hour could erase ~90 days of history in under a day at disk floor. |
| 4 | Can the "busy, no quota consumed" exemption be exploited? | **Confirmed safe** against amplified deletion. A real (separate) TOCTOU race was found: two near-simultaneous dispatches can both pass the busy check before either acquires the lock, wasting two rate slots for one actual run. Fix: evaluate the rate-limit admission and the busy re-check under the same `flock`, not as two separate steps. |
| 5 | Does the writer-kick exemption create a bypass? | **Real but bounded** — bypassable only by holders of the pre-existing, already-privileged `SNAP_SSH` identity, not by the replica forced-command key alone. Documented precisely in §2.6; not oversold as closed. |
| 6 | Is same-day implementation of both fixes safe, and in what order? | **Needs a decision, not a blocker** — build Fix 1 (rate limiting) before Fix 2 (rotation); merge all `snapshot-install` changes in one pass; found and fixed a hidden dependency (dispatch doesn't currently source conf for the modes that need it — §2.4). |
| 7a | Does rotation mitigate the spam abuse path on its own? | No — cross-referenced explicitly in §1.3/§3.6 so this isn't assumed. |
| 7d | Changing concurrent-dispatch behavior from silent exit 0 to exit 79 | Correct for abuse detection, but changes launchd's view of job success — document in upgrade notes (§5). |
| 7g | Internal inconsistency in the rotation draft (flip-then-append vs. append-then-flip) | Resolved: append-then-flip, gated on a `grep` check (§3.2). |

---

## 5. Implementation Order and Checklist (tomorrow)

**Build order:** Fix 1 (rate limiting) before Fix 2 (rotation) — the active abuse path
matters more than the theoretical key-leak window, and Fix 2 depends on the same lock
discipline Fix 1 establishes.

1. **Shared scaffolding (one pass):** `state/` directory creation (0700) in
   `snapshot-install`; add the new conf variables (§2.2, §3.3) to
   `conf/snapshot.conf.example`; **add conf-sourcing to `snapshot-dispatch` for
   `snap|vault|both`** (currently only `probe` sources it — this is a real gap, not
   an assumption to skip).
2. **Fix 1 — rate limiting:**
   - Implement the shared bash rate-check functions (prune/count/deny/commit,
     atomic write-temp-then-rename).
   - Wire into `snapshot-dispatch`: busy check → rate check → exec, with the busy
     check and rate-limit admission evaluated under one lock (closes finding #4).
   - Wire the parallel gate into `mirror.sh`, including the `AGENT_SNAPSHOT_KICK=1`
     exemption — **ship the updated `REPLICA_KICK` string in the same change**, never
     separately (§2.6).
   - Add `last-rate-limit.json` writer on deny, both sides.
   - Add **P16** + `rate_limited` event kind to `engine.py`'s `compute_health()`.
   - Extend `archive-host/selftest.sh` per the test plan in §5.1 below.
3. **Fix 2 — key rotation:**
   - `bin/snapshot-key-lib.sh` (shared: `authorized_keys` line builder, path helpers,
     comment parsing) — both `snapshot-install` and `snapshot-key-rotate` use this one
     source of truth.
   - `bin/snapshot-key-rotate` — `bootstrap`, `status`, `probe` first (pure
     observability, safe to test against production immediately), then
     `rotate`/`finalize`/`rotate-if-due` (mutating).
   - `snapshot-install` integration: registry layout, stable symlink, new comment
     format, copy the rotate script.
   - New launchd templates (writer + replica) for the weekly `rotate-if-due` job.
   - Rotation's busy-guard uses the same `STAGE/.lock` non-blocking probe as Fix 1
     (closes finding #6/§3.4) — don't reimplement against `.pid` alone.
4. **Docs, last:** `docs/KEY-ROTATION.md` (operator runbook), updates to
   `docs/SAFETY.md` (credential lifetime section + the kick-exemption trust boundary
   language from §2.6, verbatim if possible), `AGENT-SETUP.md` (bootstrap/rotation
   awareness step), `archive-host/README.md` (replica key registry + rotation),
   `README.md` (one paragraph), upgrade notes for existing deployments (exit-79
   semantics change, required `REPLICA_KICK` update).

### 5.1 Testing checklist

**Rate limiting:**
- 3× `snap` within a few minutes → all succeed.
- 3rd `snap` within the sustain window at the corrected threshold → still succeeds;
  next one denied (exit 78, `dispatch.log` shows `DENIED`).
- `probe` × 10 → never rate-limited.
- Trigger while a snapshot is genuinely running → exit 79, no history entry consumed.
- After the oldest counted entry ages out of the window → allowed again.
- Unknown mode still exits 77, unchanged.
- Archive: forced `deep-verify` × 2 within 24h → OK, 3rd denied. Forced `mirror` × 4
  within 5 min → OK, 5th denied. `AGENT_SNAPSHOT_KICK=1` × 20 → always OK, no entries
  written. A legitimate kick immediately followed by a forced poll trigger → both OK.
- Deny on either side → `last-rate-limit.json` written; next archive health pass shows
  P16.

**Key rotation:**
- `bootstrap` on a fresh legacy install → registry created, symlink correct, no
  behavior change to existing scheduled jobs.
- `rotate` in print-only mode → prints the correct `authorized_keys` line; symlink
  does **not** flip until the line is actually present.
- `rotate --apply-authorized-keys` → line appended with backup taken first, symlink
  flips only after the grep-confirm, probe succeeds.
- Probe failure immediately after a flip → automatic rollback, appended line removed,
  loud log.
- `finalize` before the overlap window ends → warns / requires confirmation, doesn't
  silently proceed.
- `finalize` after the window → previous key's line removed (exact comment match),
  previous private key securely deleted.
- Rotation attempted while a snapshot is actively running → deferred, not run
  concurrently.

---

## 6. Open Decisions for the operator

Nothing here blocks starting tomorrow — these are calibration choices, not missing
designs:

1. **Sustain threshold exact value:** this plan uses the adversarially-corrected 2/hour.
   If that feels too tight once the team is testing against real usage patterns, the
   right move is to *raise it deliberately with the reasoning written down*, not to
   quietly revert to the original 5/hour — the whole point of the correction is that
   5/hour was checked against the actual deletion math and found wanting.
2. **`--apply-authorized-keys` default:** this plan keeps print-only as default (matches
   existing `snapshot-install` philosophy). If you want your own deployment to
   auto-apply (since you already run this system unattended), that's a one-line conf
   change once built — just confirm you want that for *your* install specifically, not
   as the shipped OSS default.
3. **SSH CA / v2 mode:** explicitly deferred, not designed against tomorrow's timeline.
   Worth a future pass if you want per-invocation credential validity rather than
   periodic rotation.
4. **The `SNAP_SSH` / kick-exemption trust boundary (§2.6):** already flagged in
   `docs/SAFETY.md` as a known follow-on (restricted `rrsync` key). Whether to fold that
   into the same implementation day or treat it as its own later pass is your call —
   it's a materially different piece of work (hardening the rsync hop, not the
   dispatcher).

---

## Appendix A — Full agent transcripts

Unabridged reasoning, alternatives considered, and complete pseudocode for anyone who
wants the full detail behind any decision above (kept in the repo as design
history):

- Key rotation design (Agent A, full): [`docs/design-history/2026-08-21-key-rotation-design.txt`](design-history/2026-08-21-key-rotation-design.txt)
- Anti-spam design (Agent B, full): [`docs/design-history/2026-08-21-antispam-design.txt`](design-history/2026-08-21-antispam-design.txt)
- Adversarial review (Agent C, full): [`docs/design-history/2026-08-21-adversarial-review.txt`](design-history/2026-08-21-adversarial-review.txt)
