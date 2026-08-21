# Key rotation — operator runbook

This document is for the two **forced-command SSH keys** that trigger backups on
the source machine (`snapshot-dispatch`) and replica work on the archive host
(`mirror.sh`). It does **not** cover the optional third credential — your normal
`SNAP_SSH` identity used for rsync to the archive — which is a separate
hardening track (`docs/SAFETY.md` §2).

Read this if you operate the system but did not read the design docs. Concrete
paths below assume the default install layout on macOS.

Throughout this doc, `$KR` means the rotation tool:

```bash
KR="$HOME/Library/Application Support/agent-snapshot/bin/snapshot-key-rotate"
```

On the archive host the same script lives under the same Application Support
path (or your install location).

---

## What rotation does — and what it does not

### Containment (already in place)

Each dispatch key is pinned in `~/.ssh/authorized_keys` with
`restrict,command="/bin/bash '<dispatcher>'"`. A stolen key cannot open a shell,
run `rm`, or override the dispatcher. On the writer it can only trigger
`snap|vault|both|probe|probe-auth`; on the replica, `mirror|deep-verify|probe-auth`.
That containment is solid and rotation does not change it.

### Why rotate anyway

Install generates one ed25519 key and, without rotation, it stays valid
**forever**. A key copied from a Time Machine backup, disk image, or compromised
tool remains a permanent capability until a human notices and revokes it.

**Rotation bounds how long a leaked key stays valid.** After a successful
rotation, the old private key is removed at finalize; until then, both keys work
during the overlap window (see below).

**Rotation is not a substitute for containment — both matter, for different
reasons:**

| Layer | Limits |
|---|---|
| Forced command + allowlist | What a key holder can *do* (trigger backups, not delete history) |
| Rotation + overlap + finalize | How long a stolen key remains *valid at all* |

Spam-driven retention bypass (repeated `snap` at disk floor) is addressed by
rate limiting, not by rotation alone. See `docs/SECURITY-HARDENING-PLAN.md` §1.3.

---

## Registry layout and the stable symlink

Rotation stores keys in a small registry instead of a single flat file:

```
~/.ssh/agent-snapshot/
  state.json          # active key id, previous key id, overlap deadline, role
  rotation.log        # append-only operator log
  .rotate.lockdir/    # PID lock — one mutating rotation at a time
  keys/
    key-20260821-054501       # private key (mode 0600)
    key-20260821-054501.pub
    key-20260523-054501       # previous key — retained only during overlap
    key-20260523-054501.pub
```

### Stable symlink (why it exists)

launchd plists and docs reference **one path forever**. Rotation never edits
those plists — it only moves the symlink target.

| Role | Stable path (clients use this) | Points at |
|---|---|---|
| Writer (source) | `~/.ssh/id_ed25519_agent_snapshot` | `~/.ssh/agent-snapshot/keys/<active-id>` |
| Replica (archive) | `~/.ssh/id_ed25519_agentsnapshot_replica` | same pattern |

**Why:** scheduled jobs, manual probes, and documentation all say
`ssh -i ~/.ssh/id_ed25519_agent_snapshot …`. Without the indirection, every
rotation would require re-rendering launchd plists and updating runbooks. The
symlink absorbs that churn; only the target path changes.

### `authorized_keys` comment format

Each registry key has a matching line in `~/.ssh/authorized_keys` with a
structured comment so finalize can remove **exactly** our line and nothing else:

- Writer: `agent-snapshot:<key-id>` (e.g. `agent-snapshot:key-20260821-054501`)
- Replica: `agent-snapshot-replica:<key-id>`

During overlap, **two lines coexist** — same `command=`, different comments and
different public keys.

Example writer line (path varies by user):

```
restrict,command="/bin/bash '/Users/you/Library/Application Support/agent-snapshot/bin/snapshot-dispatch'",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty ssh-ed25519 AAAA… agent-snapshot:key-20260821-054501
```

Replica forced command points at `~/Library/AgentSnapshot/mirror.sh`.

### Legacy bare comment (`agent-snapshot` without `:key-id`)

Pre-rotation installs often have a line whose comment is just `agent-snapshot`
(from `ssh-keygen -C "agent-snapshot"` at install time). That line uses the
**same public key** as the structured line but is invisible to finalize, which
only removes `agent-snapshot:<key-id>` comments.

**If the bare line survives finalize, the old key material stays valid forever**
— rotation would not actually bound exposure.

The tool removes a bare legacy line automatically, but **only when all of these
are true:**

1. The structured comment for the key being replaced already exists in
   `authorized_keys` (e.g. `agent-snapshot:key-20260821-054501`).
2. Exactly **one** line has the bare comment (`agent-snapshot` or
   `agent-snapshot-replica`).
3. That bare line's public key matches the structured line's key.

Otherwise the tool refuses or skips and prints instructions — it never guesses.
Cleanup runs on bootstrap (when structured line already present) and after a
successful rotate cutover.

If you see `refuse legacy authorized_keys cleanup — multiple lines with bare
comment`, remove duplicate bare lines manually, keeping only structured comments.

---

## Auth probe vs operational probe

Rotation cutover and pre-finalize checks use **`probe-auth`**, not the full
operational probe. Both modes exist on both dispatchers; they answer different
questions.

| Mode | Dispatcher | What it proves | Not checked | Engine lock |
|---|---|---|---|---|
| **`probe-auth`** | writer + replica | Localhost sshd accepted the key, ran the forced command, and the dispatcher exited cleanly for that mode | Archive host, DAS, TCC, rsync, conf contents, rate-limit history, engine lock | **No** |
| **`probe`** (writer) | `snapshot-dispatch` | Full health: conf, rsync, archive/vault reachability | — | May defer on busy |
| **`mirror`** (replica) | `mirror.sh` | Full replica pass via `engine.py` | — | **Yes** — fails if another mirror holds the lock |

**Why rotation gates on `probe-auth` only:** the old cutover used the full
operational probe. Archive offline, TCC/rsync failures, or a concurrent replica
mirror pass caused **false-negative probe failures** → automatic rollback → rotation
never completing while keys aged past policy. Auth-only cutover is intentionally
narrow: it proves the key line and forced-command path work **without** depending
on backup infrastructure — but it is **not** a pure “is this public key valid?”
oracle.

### What `probe-auth` still requires

The rotation tool runs the same SSH one-liner an operator would:

```bash
ssh -i "$STABLE_LINK" -o IdentitiesOnly=yes -o BatchMode=yes localhost probe-auth
```

That path still depends on local SSH plumbing:

| Layer | Writer | Replica |
|---|---|---|
| **Remote Login / sshd** | Must be running and accepting localhost connections | Same |
| **Host-key acceptance** | Default `StrictHostKeyChecking` applies — unknown or changed `localhost` host keys fail under `BatchMode=yes` even when the dispatch key is fine | Same |
| **Dispatcher startup** | `snapshot-dispatch` must load `snapshot-key-lib.sh` before the `probe-auth` case runs | `mirror.sh` handles `probe-auth` before loading the rate-limit library |
| **Forced-command pin** | The matching `authorized_keys` line must exist and point at the installed dispatch script | Same for `mirror.sh` |

`probe-auth` does **not** read `snapshot.conf`, touch the archive, acquire the
engine lock, or write rate-limit history. A passing `probe-auth` during rotation
means “this key can trigger the forced dispatcher locally,” not “backups are healthy.”

### When `probe-auth` fails — key problem vs local SSH problem

Use verbose SSH to see which layer failed:

```bash
ssh -v -i "$LINK" -o IdentitiesOnly=yes -o BatchMode=yes localhost probe-auth 2>&1 | tail -30
```

| Symptom in verbose output | Likely cause | Not a key/AK line problem? |
|---|---|---|
| `Connection refused` / `Connection reset` | Remote Login off, sshd down, or wrong port | Yes — fix sshd first |
| `Host key verification failed` / `No ED25519 host key is known` | Localhost host keys missing or changed | Yes — fix `~/.ssh/known_hosts` or host keys |
| `snapshot-dispatch: missing rate-limit library …` (writer) | Dispatch script or library missing/unreadable | Partially — install path, not AK comment |
| `Permission denied (publickey)` | No matching `authorized_keys` line, wrong key file, or symlink points at wrong private key | **No** — key/AK/symlink issue |
| Dispatcher prints `probe-auth: OK …` but SSH exits non-zero | Rare — treat as infrastructure; check `dispatch.log` / launchd | Maybe |

If `probe-auth` fails during rotate but a manual `ssh … probe-auth` succeeds
immediately after with no config change, suspect a transient sshd or host-key
glitch — check logs before re-running rotate.

Operator checks (health, not rotation):

```bash
# Writer — full operational health
ssh -i ~/.ssh/id_ed25519_agent_snapshot -o IdentitiesOnly=yes -o BatchMode=yes localhost probe

# Writer — auth only (same gate rotation uses)
ssh -i ~/.ssh/id_ed25519_agent_snapshot -o IdentitiesOnly=yes -o BatchMode=yes localhost probe-auth

# Replica — full mirror pass
ssh -i ~/.ssh/id_ed25519_agentsnapshot_replica -o IdentitiesOnly=yes -o BatchMode=yes localhost mirror

# Replica — auth only (same gate rotation uses)
ssh -i ~/.ssh/id_ed25519_agentsnapshot_replica -o IdentitiesOnly=yes -o BatchMode=yes localhost probe-auth
```

Or via the rotation tool (runs the **operational** probe, not `probe-auth`):

```bash
"$KR" probe --role writer
"$KR" probe --role replica
```

Successful `probe-auth` prints `probe-auth: OK role=writer|replica host=…` and
exits 0.

---

## Lifecycle: bootstrap → rotate → finalize

### 1. Bootstrap (upgrade path)

Existing installs have a flat key at the stable symlink path. **Bootstrap** moves
it into the registry without forcing an immediate rotation:

```bash
"$KR" bootstrap --role writer
# on the archive host:
"$KR" bootstrap --role replica
```

After bootstrap: registry exists, stable symlink points at the migrated key,
scheduled jobs behave as before. If `authorized_keys` still has a bare legacy
comment, bootstrap attempts safe removal when a structured line is already present
(see above).

**First install is unchanged:** `snapshot-install` still creates the flat key
and **prints** the one-time `authorized_keys` line for you to append manually.
That human gate is deliberate. Only **recurring** rotation is automated.

### 2. Rotate (enter overlap)

When the active key is older than `KEY_ROTATION_DAYS` (default 90), rotation:

1. Generates a new keypair under `keys/key-<timestamp>`
2. **Appends** the new line to `authorized_keys` (when auto-apply is on)
3. **Verifies** the new comment is present — only then flips the stable symlink
4. Runs **`probe-auth`** with the new key (auth-only gate — see above for scope)
5. Removes legacy bare comment line if safe (see above)
6. **Commits** overlap state (`active`, `previous`, `overlap_until`) — only after
   steps 4–5 succeed

```bash
"$KR" rotate --role writer
"$KR" rotate --role replica
```

On `probe-auth` failure the tool rolls back (restore symlink, remove new AK
line, **no state write**), verifies the restored config, and exits non-zero.

**Overlap window (`KEY_OVERLAP_HOURS`, default 72):** both old and new keys
accept SSH auth. This is intentional — in-flight snapshot runs, the 5-minute
replica poll, and any job still holding the old key material must never hit a
moment where **neither** key works. Overlap trades a few days of dual validity
for zero cutover downtime.

**Honest limit:** if the old key was stolen, it stays valid until finalize —
for the length of the overlap window, not just until symlink flip.

### 3. Finalize (remove previous key)

After overlap expires, finalize removes the **previous** key's `authorized_keys`
line (exact comment match only), securely deletes its private key, and clears
`previous` in `state.json`:

```bash
"$KR" finalize --role writer
"$KR" finalize --role replica
```

Finalize **refuses** unless the stable symlink basename equals `state.active`,
the active private key file exists, and the active AK line is present — before
and after removing the previous line. Running finalize before the overlap window
ends warns or refuses unless you pass `--force`.

### Scheduled path: `rotate-if-due`

The weekly launchd job calls:

```bash
snapshot-key-rotate rotate-if-due --role writer   # source machine
snapshot-key-rotate rotate-if-due --role replica  # archive host
```

Logic:

- If not bootstrapped → `bootstrap` only (no rotation on first run)
- If split-brain detected → **refuse** (see Recovery)
- If active key age ≥ `KEY_ROTATION_DAYS` → `rotate`
- Else if `previous` exists, overlap expired, and **`probe-auth`** on the active
  key succeeds → `finalize`
- Else → no-op (may log status)

Writer and replica rotation are **independent** — each host rotates its own
localhost forced-command key locally.

---

## Automation (default) and safety rails

By default, **`KEY_ROTATION_APPLY_AK=true`** in `conf/snapshot.conf` (writer) —
the weekly job edits `~/.ssh/authorized_keys` itself. You are not expected to
hand-append rotation lines on a schedule.

That is acceptable only because of non-negotiable safety rails:

1. **Timestamped backup before every AK edit** — `authorized_keys.bak-YYYYmmdd-HHMMSS`
   (mode 0600). Never rewrite the whole file from a template.
2. **Append → verify → flip symlink → probe-auth → commit state** — overlap state
   is written **only after** a successful auth probe. Flipping before AK verify
   or committing state before probe-auth both created real lockout windows (now
   fixed).
3. **Auth-probe-gated cutover with verified rollback** — after symlink flip,
   `probe-auth` must succeed. On failure: restore previous symlink, remove the
   just-added line (if auto-apply was on), **do not write state**, then verify
   restored AK line + symlink + auth probe. If verification fails → **CATASTROPHIC**
   (see Recovery).
4. **Split-brain detection** — if `state.active` ≠ basename of stable symlink,
   `rotate`, `finalize`, and `rotate-if-due` refuse with a **SPLIT-BRAIN**
   message. `status` lists it under pending actions. Authentication usually still
   works; the tool stopped to avoid making it worse.
5. **Rotation lock** — `rotate`, `finalize`, and `rotate-if-due` serialize on
   `~/.ssh/agent-snapshot/.rotate.lockdir`. The weekly job and a manual run
   cannot interleave.
6. **Exact-comment-only removal** — finalize matches `agent-snapshot:` /
   `agent-snapshot-replica:` comments only. Other forced-command jobs on the
   same machine are load-bearing and must never be touched.
7. **Refuse to rotate mid-run** — rotation checks the same busy lock as dispatch
   (`STAGE/.lock` flock on the writer; replica `mirror.pid` flock). If a snapshot
   or mirror pass is active, rotation defers (exit 79).

Set `KEY_ROTATION_APPLY_AK=false` if you want print-only rotation (the tool
prints the line; symlink does not flip until the line is actually present). That
reverts to manual append for each rotation — keys age on schedule but exposure
is not bounded until someone acts on the printed output.

**Install vs rotation:** `snapshot-install` never edits `authorized_keys` — the
one-time line remains a deliberate human step. Only recurring rotation is
automated.

### Config (writer)

In `~/Library/Application Support/agent-snapshot/conf/snapshot.conf`:

```bash
KEY_ROTATION_ENABLED=true
KEY_ROTATION_DAYS=90
KEY_OVERLAP_HOURS=72
KEY_ROTATION_APPLY_AK=true
```

Replica hosts use the same variable names when the rotation job is installed;
see your rendered `com.agent-snapshot-replica.key-rotate` LaunchAgent.

### Verify the schedule is actually running

Rotation only helps if it runs. Check:

```bash
# Writer (source machine)
launchctl print "gui/$(id -u)/com.agent-snapshot.key-rotate" | grep -E 'state|last exit|runs'
tail -30 ~/Library/Logs/agent-snapshot/launchd-key-rotate.log
tail -30 ~/.ssh/agent-snapshot/rotation.log

# Replica (archive host)
launchctl print "gui/$(id -u)/com.agent-snapshot-replica.key-rotate" | grep -E 'state|last exit|runs'
tail -30 ~/Library/Logs/agent-snapshot/launchd-replica-key-rotate.log
```

Reference schedule: **Sunday 05:45 local** (both templates), chosen to sit
after typical snapshot windows so the busy lock is usually clear.

```bash
"$KR" status --role writer
"$KR" status --role replica
```

Status shows active/previous key ids, key age, overlap deadline, symlink vs
state alignment, and pending actions (finalize due, SPLIT-BRAIN, print-only line
waiting for append, etc.).

### Rotation lock (concurrent runs)

If you run `rotate`, `finalize`, or `rotate-if-due` while another rotation
holds the lock:

```
snapshot-key-rotate: another rotation is in progress (lock ~/.ssh/agent-snapshot/.rotate.lockdir); retry later
```

Wait for the other run to finish (check `rotation.log` and launchd logs). Do not
delete `.rotate.lockdir` unless you have confirmed no rotation process is running
(stale lock after crash is rare — the lock uses PID semantics via the library).

---

## Commands reference

All subcommands take `--role writer|replica`.

| Subcommand | Purpose |
|---|---|
| `status` | Active/previous ids, overlap window, key age, symlink alignment, pending actions |
| `bootstrap` | Migrate legacy flat key into registry (upgrade) |
| `probe` | Run **operational** forced-command probe (`probe` on writer, `mirror` on replica) |
| `rotate` | Generate new key, overlap cutover gated on **`probe-auth`** |
| `finalize` | Remove previous key after overlap (never touches active line) |
| `rotate-if-due` | Scheduled entry point — bootstrap if needed, rotate/finalize when due |

Options: `--dry-run`, `--apply-authorized-keys`, `--no-apply-authorized-keys`,
`--force` (skip overlap guard on finalize; skip busy guard on rotate).

Script path (writer default install):

```
~/Library/Application Support/agent-snapshot/bin/snapshot-key-rotate
```

---

## Recovery (2am section)

Work on the **affected host** (writer rotation is local to the source machine;
replica rotation is local to the archive host). Set role-appropriate variables
once:

```bash
KR="$HOME/Library/Application Support/agent-snapshot/bin/snapshot-key-rotate"
# Writer:
LINK=~/.ssh/id_ed25519_agent_snapshot
# Replica:
# LINK=~/.ssh/id_ed25519_agentsnapshot_replica
```

**Before any manual fix:** read the log and status. They tell you which scenario
you are in.

```bash
tail -80 ~/.ssh/agent-snapshot/rotation.log
"$KR" status --role writer    # or --role replica
```

### 0. Stop making it worse

**Destructive if left disabled:** scheduled rotation will not run until re-enabled.

```bash
launchctl bootout "gui/$(id -u)/com.agent-snapshot.key-rotate" 2>/dev/null || true
launchctl bootout "gui/$(id -u)/com.agent-snapshot-replica.key-rotate" 2>/dev/null || true
```

Re-enable after recovery:

```bash
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/com.agent-snapshot.key-rotate.plist
# or replica plist on archive host
```

---

### 1. Auth probe failed during rotate — rollback succeeded

The tool prints:

```
snapshot-key-rotate: ROTATION FAILED — auth probe failed; rolled back to previous key
```

What happened: symlink restored, new AK line removed (if auto-apply), **no**
overlap state written. Post-rollback verification confirmed AK + symlink + auth.

Confirm you are healthy:

```bash
"$KR" status --role writer
ssh -i "$LINK" -o IdentitiesOnly=yes -o BatchMode=yes localhost probe-auth
```

No manual steps required unless status still shows problems. Investigate why
`probe-auth` failed (see **When `probe-auth` fails** above — distinguish sshd/host-key
issues from AK/symlink problems) before re-running rotate.

**Do not** blindly repoint the symlink at `state.previous` — after a successful
rollback, `state.active` and the symlink should already match the key that works.

---

### 2. CATASTROPHIC — rollback did not restore a working configuration

**This is the highest-severity rotation failure.** The tool prints:

```
snapshot-key-rotate: CATASTROPHIC — rollback did not restore a working configuration; manual intervention required (see ~/.ssh/agent-snapshot/rotation.log)
```

Meaning: cutover failed and rollback could not prove a working config (missing
AK line, symlink mismatch, or auth probe still failing). **Do not re-run rotate
or finalize** until you manually restore a known-good state.

Steps:

```bash
# 1. Find what rollback verification reported
grep -E 'ROLLBACK|CATASTROPHIC|VERIFY FAILED' ~/.ssh/agent-snapshot/rotation.log | tail -20

# 2. List AK backups (newest first) — pick one from BEFORE the failed rotation
ls -lt ~/.ssh/authorized_keys.bak-* | head -5

# 3. DESTRUCTIVE: replaces live authorized_keys — verify backup timestamp first
cp ~/.ssh/authorized_keys.bak-YYYYMMDD-HHMMSS ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# 4. Identify which key id the restored file expects
grep -E 'agent-snapshot(:|-replica:)' ~/.ssh/authorized_keys

# 5. Point stable symlink at that key's private file (use the active structured comment)
ACTIVE=key-YYYYMMDD-HHMMSS   # from grep, e.g. agent-snapshot:key-20260821-054501
ln -sfn "$HOME/.ssh/agent-snapshot/keys/$ACTIVE" "$LINK"

# 6. Verify auth before touching automation again
ssh -i "$LINK" -o IdentitiesOnly=yes -o BatchMode=yes localhost probe-auth

# 7. Reconcile state — status may still show stale overlap/previous
"$KR" status --role writer
```

If `state.json` disagrees with the working symlink + AK combo, either:

- Manually edit `state.json` so `active` matches the symlink basename, `previous`
  is `null`, `overlap_until` is `null`, **or**
- Restore a flat legacy key + AK from backup and run `"$KR" bootstrap --role writer`
  (destructive to registry layout — only if keys on disk and AK are consistent).

Re-enable launchd only after `probe-auth` succeeds and `status` shows no
SPLIT-BRAIN or missing AK lines.

---

### 3. SPLIT-BRAIN — `state.active` ≠ stable symlink

The tool prints (on rotate, finalize, or rotate-if-due):

```
snapshot-key-rotate: SPLIT-BRAIN — state.json active=key-OLD but stable symlink points at key-NEW; refusing to proceed (manual recovery required)
```

(`key-OLD` / `key-NEW` are placeholders — either side can be the symlink or
state value. **Read the actual ids in the message.**)

`status` includes pending actions like:

```
SPLIT-BRAIN: state active=key-OLD but symlink=key-NEW; rotate/finalize blocked;
```

**Reassuring part:** authentication is usually **still working**. Scheduled
backups keep running on whichever private key the symlink currently points at.
The tool refused precisely so finalize would not remove the only line matching
the symlink (the old C1 lockout scenario).

**Critical:** split-brain has **two opposite directions**. The fix for one
**actively harms** the other:

| Direction | Symlink | `state.active` | Wrong fix (makes it worse) | Correct fix moves… |
|---|---|---|---|---|
| **A — symlink ahead** | **NEW** key | **OLD** key | Repoint symlink to `state.active` (OLD) — **reverts a good cutover**, orphans the new AK line | **`state.json` forward** to match the symlink (do **not** move symlink backward) |
| **B — state ahead** | **OLD** key | **NEW** key | Editing `state.json` backward to match the symlink — leaves registry ahead of reality | **Symlink forward** to `state.active` |

Typical causes:

- **Direction A:** process killed after symlink flip but before state commit; or
  legacy bare-line cleanup failed after a successful auth probe (see §4).
- **Direction B:** legacy pre-fix rotation that wrote state before flipping the
  symlink; rare partial manual edits.

**Do not run finalize** while split-brain is reported. **Do not pick a recovery
path until you diagnose the direction** (below).

#### Step 1 — Diagnose direction (mandatory)

Run on the affected host with `$KR` and `$LINK` set (see top of Recovery):

```bash
STATE_ACTIVE="$(python3 -c "import json; print(json.load(open('$HOME/.ssh/agent-snapshot/state.json'))['active'])")"
LINK_ID="$(basename "$(readlink "$LINK")")"

echo "=== split-brain diagnosis ==="
echo "state.active=$STATE_ACTIVE"
echo "symlink basename=$LINK_ID"
ls -l "$LINK"
python3 -m json.tool ~/.ssh/agent-snapshot/state.json
grep -E 'agent-snapshot(:|-replica:)' ~/.ssh/authorized_keys

# Auth with CURRENT symlink — do not repoint yet
ssh -i "$LINK" -o IdentitiesOnly=yes -o BatchMode=yes localhost probe-auth
echo "probe-auth exit=$?"
```

Interpret the ids (do **not** skip this — both directions can pass `probe-auth`
with the current symlink):

```bash
# Key ids are key-YYYYMMDD-HHMMSS — newer id usually means the rotation target
python3 - "$STATE_ACTIVE" "$LINK_ID" <<'PY'
import sys
def stamp(k):
    parts = k.split("-", 1)
    return parts[1] if len(parts) == 2 else k
sa, li = sys.argv[1], sys.argv[2]
if sa == li:
    print("Ids match — not split-brain; re-run status")
elif stamp(li) > stamp(sa):
    print(f"DIRECTION A likely: symlink ({li}) is NEWER than state.active ({sa})")
    print("-> update state.json forward (Direction A); DO NOT repoint symlink to state.active")
elif stamp(sa) > stamp(li):
    print(f"DIRECTION B likely: state.active ({sa}) is NEWER than symlink ({li})")
    print("-> repoint symlink forward to state.active (Direction B)")
else:
    print("Ambiguous — decide from rotation.log (next block)")
PY
```

Also read `rotation.log` for `flipped symlink to` vs any state write:

```bash
grep -E 'flipped symlink|rotate: OK|legacy cleanup|SPLIT-BRAIN' ~/.ssh/agent-snapshot/rotation.log | tail -15
```

If the log shows `flipped symlink to key-NEW` but **no** `rotate: OK`, you are
almost certainly in **Direction A** (cutover succeeded; state never committed).

---

#### Direction A — symlink **NEW**, `state.active` **OLD** (symlink ahead)

**When:** `LINK_ID` ≠ `STATE_ACTIVE`, `probe-auth` succeeds with the **current**
symlink (no repoint), and the log shows flip without `rotate: OK`.

**What happened:** cutover effectively **succeeded** — symlink and new AK line
are live; only `state.json` is stale.

**WRONG recovery (do not do this):**

```bash
# DESTRUCTIVE — reverts a good cutover; orphans the new authorized_keys line
ln -sfn "$HOME/.ssh/agent-snapshot/keys/$STATE_ACTIVE" "$LINK"
```

That moves the symlink **backward** to the old key while the new structured AK
line remains — automation and reality diverge further.

**Correct recovery — advance `state.json` to match the symlink:**

```bash
# 1. Confirm auth on the current (new) key — still do not repoint
ssh -i "$LINK" -o IdentitiesOnly=yes -o BatchMode=yes localhost probe-auth

# 2. DESTRUCTIVE: updates state.json — verify LINK_ID is the intended new active key
python3 - "$LINK" <<'PY'
import json, datetime, sys
from pathlib import Path

link = Path(sys.argv[1]).resolve()
new_active = link.name
state_path = Path.home() / ".ssh/agent-snapshot/state.json"

with open(state_path) as fh:
    data = json.load(fh)
old_active = data["active"]
if new_active == old_active:
    raise SystemExit("symlink already matches state.active — not Direction A")

hours = int(data.get("overlap_hours", 72))
now = datetime.datetime.now().astimezone()
data["active"] = new_active
data["previous"] = old_active
data["overlap_until"] = (now + datetime.timedelta(hours=hours)).isoformat(timespec="seconds")
data["last_rotate_at"] = now.isoformat(timespec="seconds")

tmp = state_path.with_suffix(".json.tmp")
tmp.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
tmp.replace(state_path)
print(f"state updated: active={new_active} previous={old_active} overlap_until={data['overlap_until']}")
PY

# 3. Verify — SPLIT-BRAIN should clear
"$KR" status --role writer    # or --role replica
ssh -i "$LINK" -o IdentitiesOnly=yes -o BatchMode=yes localhost probe-auth
```

Re-enable launchd (§0). Finalize runs automatically after overlap expires.

Both structured AK lines (`agent-snapshot:<old>` and `agent-snapshot:<new>`) should
be present during overlap — that is expected until finalize.

---

#### Direction B — `state.active` **NEW**, symlink **OLD** (state ahead; legacy)

**When:** `state.active` names a **newer** key id than the symlink basename, and
the symlink still auth-probes only after you repoint it — typical of **pre-fix**
rotations that committed state before flipping the symlink.

**Correct recovery — repoint symlink forward to `state.active`:**

```bash
python3 -m json.tool ~/.ssh/agent-snapshot/state.json
ls -l "$LINK"
grep -E 'agent-snapshot(:|-replica:)' ~/.ssh/authorized_keys

# DESTRUCTIVE only if symlink is wrong — moves symlink FORWARD to state.active
ACTIVE="$(python3 -c "import json; print(json.load(open('$HOME/.ssh/agent-snapshot/state.json'))['active'])")"
ln -sfn "$HOME/.ssh/agent-snapshot/keys/$ACTIVE" "$LINK"

ssh -i "$LINK" -o IdentitiesOnly=yes -o BatchMode=yes localhost probe-auth
"$KR" status --role writer    # or --role replica
```

This moves the symlink **forward** to match registry state. Do **not** use this
when Direction A applies (symlink already on the new key and probing OK).

---

#### If neither direction fits — bad `state.active` or missing AK lines

If `state.active` does not auth but the current symlink target does **after**
you have confirmed direction (not a sshd/host-key false negative):

```bash
ssh -v -i "$LINK" -o IdentitiesOnly=yes -o BatchMode=yes localhost probe-auth 2>&1 | tail -20

# DESTRUCTIVE: restore AK from backup predating the bad state advance
ls -lt ~/.ssh/authorized_keys.bak-* | head
cp ~/.ssh/authorized_keys.bak-YYYYMMDD-HHMMSS ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

grep -E 'agent-snapshot(:|-replica:)' ~/.ssh/authorized_keys
WORKING=key-YYYYMMDD-HHMMSS
ln -sfn "$HOME/.ssh/agent-snapshot/keys/$WORKING" "$LINK"
ssh -i "$LINK" -o IdentitiesOnly=yes -o BatchMode=yes localhost probe-auth
```

Then set `state.json` so `active` equals `WORKING`, `previous` is `null`,
`overlap_until` is `null`, or re-bootstrap if the registry is untrustworthy.

**Never** use `PREV=$(… state.previous …)` blindly — after a bad finalize,
`previous` may be empty while the symlink still points at a removed key id.
Always grep `authorized_keys` and test `probe-auth`.

---

### 4. Legacy bare-line cleanup failed after cutover succeeded

The tool may print:

```
snapshot-key-rotate: legacy AK cleanup failed after cutover — manual cleanup may be required
```

**Meaning:** append, symlink flip, and **`probe-auth` all succeeded**. Rotation
**cutover worked** — the new key authenticates. The tool could not automatically
remove the pre-rotation bare comment line (`agent-snapshot` or
`agent-snapshot-replica` without `:key-id`), usually because:

- More than one bare comment line exists (`refuse legacy authorized_keys cleanup — multiple lines with bare comment '…'`), or
- `asnap_ak_remove` failed after the safety checks passed.

**Authentication is fine.** Scheduled backups keep running on the new symlink.
The remaining problem is exposure (old bare line may still authorize the **previous**
key material) and/or stale `state.json` depending on script version.

**Exit code:** **75** (`KR_EXIT_LEGACY_CLEANUP`) — rotation committed and
authentication verified; only the manual AK cleanup remains. This is
deliberately distinct from **1** (a genuine rotation failure), so automation and
operators can tell "succeeded, needs tidying" from "failed". Confirm with
`echo $?` immediately after the message.

#### If exit 75 (or status shows overlap, no SPLIT-BRAIN)

Overlap state was committed. Finish manually:

```bash
# 1. Stop scheduled rotation while editing AK (§0)
"$KR" status --role writer    # note active and previous key ids

# 2. Confirm auth — do not repoint symlink
ssh -i "$LINK" -o IdentitiesOnly=yes -o BatchMode=yes localhost probe-auth

# 3. Inspect bare vs structured lines
grep -E 'agent-snapshot(:|-replica:)?' ~/.ssh/authorized_keys

# 4. Backup before any edit
cp -p ~/.ssh/authorized_keys ~/.ssh/authorized_keys.manual-$(date +%Y%m%d-%H%M%S)
chmod 600 ~/.ssh/authorized_keys.manual-*

PREV="$(python3 -c "import json; print(json.load(open('$HOME/.ssh/agent-snapshot/state.json'))['previous'])")"
grep "$PREV" ~/.ssh/authorized_keys          # structured previous line — KEEP

# 5. List bare comment lines (exact last token — same rule as the rotation tool)
python3 - "$HOME/.ssh/authorized_keys" writer <<'PY'
import sys
path, role = sys.argv[1], sys.argv[2]
bare = "agent-snapshot-replica" if role == "replica" else "agent-snapshot"
for num, line in enumerate(open(path), 1):
    parts = line.strip().split()
    if parts and not line.lstrip().startswith("#") and parts[-1] == bare:
        print(f"line {num} BARE: {line.rstrip()}")
PY
# Replace "writer" with "replica" on the archive host

# 6. Verify bare line pubkey matches the PREVIOUS key (not the new active key)
python3 - "$PREV" <<'PY'
import sys
from pathlib import Path
prev = sys.argv[1]
pub = (Path.home() / f".ssh/agent-snapshot/keys/{prev}.pub").read_text().strip().split()
print(f"expected previous pubkey: {pub[0]} {pub[1]}")
PY
# Compare visually to the bare line's keytype + keydata fields before deleting

# 7. DESTRUCTIVE: remove only the verified bare line (exact comment match)
#    Use an editor, or re-run rotate's library path only if you understand asnap_ak_remove.
#    Never remove structured agent-snapshot:<key-id> lines.
#    Never remove a bare line whose command= differs from this role's forced command
#    if another job shares the same pubkey (see Legacy bare comment section above).

# 8. Verify
grep -E 'agent-snapshot(:|-replica:)' ~/.ssh/authorized_keys
ssh -i "$LINK" -o IdentitiesOnly=yes -o BatchMode=yes localhost probe-auth
"$KR" status --role writer
```

Re-enable launchd (§0). No symlink or `state.json` changes needed if status is clean.

#### If exit 1 and status shows SPLIT-BRAIN

State was **not** committed. Follow **Direction A** in §3 (update `state.json`
forward — **do not** repoint symlink backward), then perform the bare-line cleanup
steps above.

---

### 5. Stable symlink points at a deleted or missing key

```bash
ls -l "$LINK"
ls ~/.ssh/agent-snapshot/keys/
python3 -m json.tool ~/.ssh/agent-snapshot/state.json
"$KR" status --role writer
```

If the private key named in `state.json` still exists on disk:

```bash
ACTIVE="$(python3 -c "import json; print(json.load(open('$HOME/.ssh/agent-snapshot/state.json'))['active'])")"
ln -sfn "$HOME/.ssh/agent-snapshot/keys/$ACTIVE" "$LINK"
ssh -i "$LINK" -o IdentitiesOnly=yes -o BatchMode=yes localhost probe-auth
```

If `status` reports SPLIT-BRAIN, follow §3 after repointing.

If the private key file is gone, restore `keys/` from your own backup, or
restore `authorized_keys` from `.bak-*` and align symlink to a surviving key id.
There is no magic regeneration — you need a valid keypair or a backup.

---

### 6. `authorized_keys` was hand-edited wrongly

Never guess at line contents. Restore from the rotation tool's timestamped backup:

```bash
ls -lt ~/.ssh/authorized_keys.bak-* | head
# Pick the newest backup from BEFORE the bad edit

# DESTRUCTIVE: replaces live authorized_keys
cp ~/.ssh/authorized_keys.bak-20260821-054501 ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

"$KR" status --role writer
grep -E 'agent-snapshot(:|-replica:)' ~/.ssh/authorized_keys

# Align symlink with the structured comment in the restored file
ACTIVE=key-20260821-054501
ln -sfn "$HOME/.ssh/agent-snapshot/keys/$ACTIVE" "$LINK"

ssh -i "$LINK" -o IdentitiesOnly=yes -o BatchMode=yes localhost probe-auth
```

If no backup exists (file edited outside the tool), reconstruct from `status` +
the `.pub` under `~/.ssh/agent-snapshot/keys/`, or re-run rotate in print-only
mode (`KEY_ROTATION_APPLY_AK=false` or `--no-apply-authorized-keys`) and append
the printed line exactly — **append, never replace the whole file**.

Verify line count changed by exactly one when appending:

```bash
wc -l ~/.ssh/authorized_keys
```

---

### 7. Rotation ran during your maintenance window

Rotation **defers** when the dispatch busy lock is held (writer `STAGE/.lock`,
replica mirror flock). If you were restoring **files from backup history** (not
running snapshot), that does not hold the lock — rotation may still run.

If rotation changed `authorized_keys` or the symlink during maintenance:

1. Boot out the rotation LaunchAgent (§0)
2. Restore `authorized_keys` from the newest `.bak-*` predating the incident (§6)
3. Align symlink with the structured comment in that backup (§6)
4. Run `probe-auth`, then `status`
5. Re-bootstrap only if registry and `authorized_keys` are completely out of sync

If a snapshot **was** running and rotation proceeded anyway (you used `--force`),
treat as §1 or §2 depending on log messages.

---

### 8. Full manual recovery from `.bak-*` files only

When registry, symlink, and `authorized_keys` all disagree and logs are unhelpful:

```bash
# 1. Disable scheduled rotation (§0)

# 2. DESTRUCTIVE: restore authorized_keys to last known-good backup
cp ~/.ssh/authorized_keys.bak-YYYYMMDD-HHMMSS ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# 3. Identify which key id that backup expected
grep -E 'agent-snapshot(:|-replica:)' ~/.ssh/authorized_keys

# 4. Point stable symlink at matching private key
ACTIVE=key-YYYYMMDD-HHMMSS
ln -sfn "$HOME/.ssh/agent-snapshot/keys/$ACTIVE" "$LINK"

# 5. Verify auth
ssh -i "$LINK" -o IdentitiesOnly=yes -o BatchMode=yes localhost probe-auth

# 6. Reconcile registry
"$KR" status --role writer
# Worst case: move flat key aside, restore AK from bak, then:
# "$KR" bootstrap --role writer
```

After recovery, re-enable the LaunchAgent and watch one `rotate-if-due` cycle in
the logs before trusting automation again.

---

## Limits — stated plainly

- **Overlap means dual validity.** A stolen key works until finalize, up to
  `KEY_OVERLAP_HOURS` after rotation — not just until the symlink flips.
- **Rotation only helps if the schedule runs.** A configured but unloaded
  LaunchAgent buys nothing. Verify with `launchctl print` and `rotation.log`.
- **Full host compromise is out of scope.** Anyone with a shell on the machine
  can run `bin/snapshot` directly, delete registry state, or edit
  `authorized_keys` without using the dispatch key. Same threat model as
  `docs/SAFETY.md` §6.
- **Linux archive hosts** (plain cron, no forced-command hop) are outside this
  rotation design — consistent with them being outside the rate-limit gate.
- **`SNAP_SSH` is not rotated here.** Hardening the rsync hop is a separate
  follow-on (restricted `rrsync` key).

---

## Related docs

- `docs/SAFETY.md` — containment model and what stolen keys can still do
- `docs/SECURITY-HARDENING-PLAN.md` §3 — design rationale
- `docs/IMPLEMENTATION-BRIEF.md` §4 — automated rotation safety rails (binding)
- `archive-host/README.md` — replica forced-command install
