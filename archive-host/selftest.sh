#!/bin/bash
# engine/selftest.sh — real, self-asserting test suite for the SnapArchive replica engine.
#
# Everything runs on SYNTHETIC FIXTURES on the boot disk, driven entirely through the
# SNAP_PRIMARY / SNAP_REPLICA / SNAP_STATE_DIR / SNAP_LOG overrides.
# /Volumes/SnapArchive and /Volumes/SnapMirror are NEVER written to, never used as an rsync
# source or destination, and are checked for modification at the end of the run.
#
# Exit 0 iff every assertion passes.
#
#   bash engine/selftest.sh                              # full suite, ~60 s
#   SNAP_SELFTEST_DEEP_SAFETY=1 bash engine/selftest.sh   # + a full read-only find over both DAS
#                                                        #   volumes (many minutes over USB)

set -u

ENGDIR=$(cd -- "$(dirname -- "$0")" && pwd -P)
SCRATCH=${SNAP_SELFTEST_SCRATCH:-${TMPDIR:-/tmp}/agent-snapshot-selftest}
RUN="$SCRATCH/run.$$"

mkdir -p "$RUN" || exit 3
MARKER="$RUN/.start-marker"
: > "$MARKER"

# read-only baseline of the two live DAS volumes, so T20 can prove nothing was written to them.
# `df -k` is 0.004 s (CONTEXT.md); a full `find` over 236,735 inodes on USB takes many minutes, so
# that one is opt-in via SNAP_SELFTEST_DEEP_SAFETY=1.
das_fingerprint() {
    df -k /Volumes/SnapArchive /Volumes/SnapMirror 2>/dev/null | awk '{print $3, $6, $9}'
    ls -1 /Volumes/SnapArchive/snapshots /Volumes/SnapMirror/snapshots 2>/dev/null
    stat -f '%N %m %z %i' /Volumes/SnapArchive/snapshots /Volumes/SnapMirror/snapshots \
         /Volumes/SnapArchive/snapshots/* /Volumes/SnapMirror/snapshots/* 2>/dev/null
}
DAS_BEFORE=$(das_fingerprint)

# The engine is INSTALLED AND LIVE under launchd every 5 minutes, so it writes its own state into
# ~/Library/AgentSnapshot/ while this suite runs.  A blanket "nothing under ~/Library changed" check is
# therefore a coin flip.  What must be asserted instead: this subtask never touches the INSTALLED
# code, and nothing appears in the state dir that is not the live engine's own state.
INSTALLED_DIR="$HOME/Library/AgentSnapshot"
installed_fingerprint() {
    md5 -q "$INSTALLED_DIR/engine.py" 2>/dev/null
    md5 -q "$INSTALLED_DIR/mirror.sh" 2>/dev/null
}
INSTALLED_BEFORE=$(installed_fingerprint)
# every file name the live engine legitimately writes
LIVE_STATE="status.json|events.jsonl|persist.json|seen.json|detected.json|staging.json|pending.json|grandfathered.json|mirror.pid|manifests"

TOTAL=0
FAILED=0
CURTEST="(init)"

cleanup() { rm -rf "$RUN" 2>/dev/null; }
onsig() { cleanup; exit 130; }
trap cleanup EXIT
trap onsig INT TERM

ok()  { TOTAL=$((TOTAL+1)); printf '  PASS  %s\n' "$1"; }
bad() { TOTAL=$((TOTAL+1)); FAILED=$((FAILED+1)); printf '  FAIL  %s\n' "$1"; }
aeq() { if [ "$2" = "$3" ]; then ok "$1 [$3]"; else bad "$1  expected=<$2> got=<$3>"; fi; }
ane() { if [ "$2" != "$3" ]; then ok "$1 [$3]"; else bad "$1  expected NOT <$2>"; fi; }
ahas(){ case "$3" in *"$2"*) ok "$1";; *) bad "$1  <<$3>> does not contain <$2>";; esac; }
anot(){ case "$3" in *"$2"*) bad "$1  <<$3>> unexpectedly contains <$2>";; *) ok "$1";; esac; }
alt() { if [ "${3:-x}" -lt "$2" ] 2>/dev/null; then ok "$1 [$3 < $2]"; else bad "$1  expected < $2, got $3"; fi; }
head_() { printf '\n=== %s\n' "$1"; CURTEST="$1"; }

# ---------------------------------------------------------------- helper programs

cat > "$RUN/q.py" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
v = eval(sys.argv[2], {"d": d, "len": len, "sorted": sorted, "set": set, "str": str, "any": any})
if isinstance(v, bool):        print("true" if v else "false")
elif v is None:                print("null")
elif isinstance(v, (list, dict)): print(json.dumps(v))
else:                          print(v)
PYEOF

cat > "$RUN/ev.py" <<'PYEOF'
# ev.py <events.jsonl> [kind]  -> "kind:snapshot" per line, in file order
import json, sys, os
p = sys.argv[1]
want = sys.argv[2] if len(sys.argv) > 2 else None
if os.path.exists(p):
    for line in open(p):
        line = line.strip()
        if not line: continue
        r = json.loads(line)
        if want and r["event"] != want: continue
        print("%s:%s" % (r["event"], r["snapshot"]))
PYEOF

cat > "$RUN/fixture.py" <<'PYEOF'
#!/usr/bin/python3
# Synthetic snapshots hardlink farm.  Hygiene rules from FINDINGS-openrsync.md F5:
#   * NEVER write through a path that is hardlinked into an older snapshot (F3) -> always unlink first
#   * ALWAYS set mtimes deliberately, so the F2 window is only armed where a test means to arm it
import os, subprocess, sys

RSYNC = "/usr/bin/rsync"
T0 = 1750000000

def W(path, data, mtime):
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d)
    if os.path.lexists(path):
        os.unlink(path)                     # never write through a shared inode
    with open(path, "wb") as fh:
        fh.write(data)
    os.utime(path, (mtime, mtime))

def pdir(root):   return os.path.join(root, "primary", "snapshots")
def rdir(root):   return os.path.join(root, "replica", "snapshots")

def seed(root, stamp):
    P = os.path.join(pdir(root), stamp)
    os.makedirs(P)
    os.makedirs(rdir(root), exist_ok=True)
    for i in range(1, 13):
        sub = "a" if i <= 7 else "b"
        W(os.path.join(P, sub, "f%02d.txt" % i),
          (("f%02d:" % i) + str(i % 10) * (1024 * ((i * 431) % 5 + 1))).encode(), T0)
    W(os.path.join(P, "big.bin"), b"BIGPAYLOAD" * (256 * 1024 // 10), T0)
    W(os.path.join(P, "a", "hl1"), b"INTRA-SNAPSHOT HARDLINK PAYLOAD\n", T0)
    os.link(os.path.join(P, "a", "hl1"), os.path.join(P, "b", "hl2"))
    W(os.path.join(P, "a", "f2window.txt"), b"A" * 30 + b"\n", T0)
    # pathological but REAL filenames ("Redesign #1.step" exists in the live archive)
    W(os.path.join(P, "b", "Redesign #1.step"), b"STEP\n", T0)
    W(os.path.join(P, "b", u"naïve café.txt"), u"utf8 éè\n".encode("utf-8"), T0)
    W(os.path.join(P, "b", "-leading-dash.txt"), b"dash\n", T0)
    W(os.path.join(P, "b", "with space.txt"), b"space\n", T0)
    W(os.path.join(P, "b", "sub dir", "nested #2.txt"), b"nested\n", T0)
    os.makedirs(os.path.join(P, "b", "emptydir"))
    os.symlink("a/f01.txt", os.path.join(P, "s"))
    os.symlink("/nonexistent/target", os.path.join(P, "dangle"))

def snap(root, prev, new, f2window=False, change=True):
    P = pdir(root)
    os.makedirs(os.path.join(P, new))
    # the MacBook's writer spelling (dest-relative); the ENGINE is frozen on the absolute form
    # NOTE (subtask 02 CONTRACT PROBLEM C6): `-aH --link-dest` ABORTS openrsync (rc 16,
    # io_buffer_buf assertion) on any tree carrying an intra-source hardlink pair followed by
    # another regular file.  `-a --link-dest` does not, and still preserves a pre-existing pair
    # (both dest paths hardlink to the single base inode) - so the farm this builds is genuine.
    rc = subprocess.call([RSYNC, "-a", "--link-dest=../" + prev,
                          os.path.join(P, prev) + "/", os.path.join(P, new) + "/"])
    if rc != 0:
        sys.exit("fixture: rsync %s -> %s rc=%d" % (prev, new, rc))
    D = os.path.join(P, new)
    # DETERMINISTIC mtime and size per stamp.  The previous `hash(new)` was Python's RANDOMIZED
    # string hash, so two stamps could collide on mtime while their same-length payloads collided
    # on size - accidentally arming the FINDINGS F2 window in a test that did not mean to arm it,
    # nondeterministically.  That is precisely what FINDINGS-openrsync.md F5 warns about.
    hhmmss = int(new[-6:])
    t = T0 + 100000 * (hhmmss % 7 + 1)
    if change:
        W(os.path.join(D, "a", "f01.txt"),
          ("f01-CHANGED-IN-" + new + "\n").encode() + b"1" * (3000 + hhmmss % 97), t)
        W(os.path.join(D, "b", "added-" + new + ".txt"), ("added in " + new + "\n").encode(), t)
    if f2window:
        # THE F2 WINDOW: fresh inode on the primary, SAME size, SAME mtime, different bytes.
        src = os.path.join(P, prev, "a", "f2window.txt")
        st = os.stat(src)
        W(os.path.join(D, "a", "f2window.txt"), b"B" * 30 + b"\n", st.st_mtime)

def partial(root, prev, new):
    """Mimics a backup run that created its stamp dir and then died mid-write: a TRUNCATED tree,
    and `latest` is NOT repointed.  Verified 2026-08-19: mbp-backup does not clean this up."""
    P = pdir(root)
    D = os.path.join(P, new)
    os.makedirs(os.path.join(D, "a"))
    for i in (1, 2):
        W(os.path.join(D, "a", "f%02d.txt" % i), b"TRUNCATED PARTIAL\n", T0)

def newpair(root, stamp):
    """Create an intra-snapshot hardlink pair that is NEW in this snapshot (not present in the
    previous one).  This is the case 00 F8.3 ships -H for, and the case that makes openrsync abort
    under -aH --link-dest (subtask 02 CONTRACT PROBLEM C6)."""
    D = os.path.join(pdir(root), stamp)
    W(os.path.join(D, "a", "newpair1"), b"NEW INTRA PAIR PAYLOAD\n", T0)
    p2 = os.path.join(D, "b", "newpair2")
    if os.path.lexists(p2):
        os.unlink(p2)
    os.link(os.path.join(D, "a", "newpair1"), p2)

def latest(root, stamp):
    P = pdir(root)
    tmp = os.path.join(P, ".latest.tmp")
    if os.path.lexists(tmp): os.unlink(tmp)
    os.symlink(stamp, tmp)
    os.rename(tmp, os.path.join(P, "latest"))

def replica_only(root, stamp):
    """A promoted-looking replica stamp the primary does not have (prune / P9 fixtures)."""
    D = os.path.join(rdir(root), stamp)
    os.makedirs(os.path.join(D, "a"))
    W(os.path.join(D, "a", "old.txt"), ("old stamp " + stamp + "\n").encode(), T0)

cmd = sys.argv[1]
if   cmd == "seed":         seed(sys.argv[2], sys.argv[3])
elif cmd == "snap":         snap(sys.argv[2], sys.argv[3], sys.argv[4],
                                 f2window=("f2window" in sys.argv[5:]),
                                 change=("nochange" not in sys.argv[5:]))
elif cmd == "partial":      partial(sys.argv[2], sys.argv[3], sys.argv[4])
elif cmd == "latest":       latest(sys.argv[2], sys.argv[3])
elif cmd == "newpair":      newpair(sys.argv[2], sys.argv[3])
elif cmd == "replica_only": replica_only(sys.argv[2], sys.argv[3])
else: sys.exit("fixture: unknown cmd " + cmd)
PYEOF

# stamps: recent enough that P3 (newest primary stamp >= 2 calendar days old) does not fire
TODAY=$(date +%Y-%m-%d)
S1="${TODAY}_010000"; S2="${TODAY}_020000"; S3="${TODAY}_030000"
S4="${TODAY}_040000"; S5="${TODAY}_050000"; S6="${TODAY}_060000"; S7="${TODAY}_070000"
OLD_D()  { date -v-"$1"d +%Y-%m-%d; }

FIX() { /usr/bin/python3 "$RUN/fixture.py" "$@"; }
Q()   { /usr/bin/python3 "$RUN/q.py" "$SNAP_STATE_DIR/status.json" "$1" 2>/dev/null; }
EV()  { /usr/bin/python3 "$RUN/ev.py" "$SNAP_STATE_DIR/events.jsonl" "${1:-}" 2>/dev/null; }
LOGC(){ wc -l < "$SNAP_LOG" 2>/dev/null | tr -d ' '; }
LOGT(){ cat "$SNAP_LOG" 2>/dev/null; }

newroot() {
    ROOT="$RUN/$1"
    mkdir -p "$ROOT"
    export SNAP_PRIMARY="$ROOT/primary" SNAP_REPLICA="$ROOT/replica"
    export SNAP_STATE_DIR="$ROOT/state" SNAP_LOG="$ROOT/mirror.log"
    export SNAP_MIN_FREE_GB=0          # boot disk has <50 GB free; P8 is proven separately in T19
    unset SNAP_TEST_CRASH SNAP_TEST_BOGUS_LINKDEST SNAP_TEST_INJECT_FLAG \
          SNAP_SETTLE_OVERRIDE SNAP_VERIFY_SAMPLE SSH_ORIGINAL_COMMAND 2>/dev/null
    mkdir -p "$ROOT/state"
    R="$SNAP_REPLICA/snapshots"
    P="$SNAP_PRIMARY/snapshots"
}

ENG() { bash "$ENGDIR/mirror.sh" "$@" >"$ROOT/out.txt" 2>"$ROOT/err.txt"; RC=$?; }

# A cold start is `mirror` PLUS one `deep-verify`.  00 F5 P13 makes "deep-verify has never
# completed" a PROBLEM, so a mirror-only install is legitimately red until the content safety net
# has run once.  Subtask 05 must do the same at cutover.  P13's own lifecycle is tested in T30.
coldstart() {
    ENG mirror                       # rc is 1 here BY CONTRACT: P13, deep-verify has never run
    ENG deep-verify; RC=$RC
    aeq "cold start ok (mirror + deep-verify)" 0 "$RC"
}

# holds a REAL fcntl.flock on the lock file from another process, so the tests exercise the lock
# the engine actually takes rather than the pidfile contents it must ignore
cat > "$RUN/holdlock.py" <<'HLPY'
import fcntl, os, sys, time
lock, secs, mode, ready = sys.argv[1], float(sys.argv[2]), sys.argv[3], sys.argv[4]
fd = os.open(lock, os.O_CREAT | os.O_RDWR, 0o644)
fcntl.flock(fd, fcntl.LOCK_EX)
os.ftruncate(fd, 0)
if mode == "pid":                      # normal holder
    os.write(fd, ("%d\n" % os.getpid()).encode()); os.fsync(fd)
# mode == "empty" reproduces the BUG-1 window: flock taken, pid NOT yet written
open(ready, "w").write("held\n")
time.sleep(secs)
HLPY
holdlock() {   # holdlock <seconds> <pid|empty> -> exports HL_PID; blocks until the lock is held
    rm -f "$ROOT/.held"
    /usr/bin/python3 "$RUN/holdlock.py" "$SNAP_STATE_DIR/mirror.pid" "$1" "$2" "$ROOT/.held" &
    HL_PID=$!
    local i=0
    while [ ! -f "$ROOT/.held" ] && [ $i -lt 200 ]; do i=$((i+1)); done
    while [ ! -f "$ROOT/.held" ]; do i=$((i+1)); [ $i -gt 100000 ] && break; done
}

ino() { stat -f %i "$1" 2>/dev/null; }

# a standard 3-snapshot primary with an empty replica
build3() {
    FIX seed "$ROOT" "$S1"
    FIX snap "$ROOT" "$S1" "$S2"
    FIX snap "$ROOT" "$S2" "$S3" f2window
    FIX latest "$ROOT" "$S3"
}

########################################################################################
head_ "T00 env-override misuse -> exit 3, nothing touched"
newroot t00
unset SNAP_REPLICA
T0DIR="$ROOT/state"
ENG mirror
aeq "rc" 3 "$RC"
ahas "stderr explains the refusal" "partial SNAP_* redirection" "$(cat "$ROOT/err.txt")"
aeq "no status.json written" "0" "$(ls -1 "$T0DIR" 2>/dev/null | wc -l | tr -d ' ')"

########################################################################################
head_ "T01 cold start: 3 settled snapshots, empty replica"
newroot t01
build3
ENG mirror
aeq "mirror-only rc is 1: P13 says the content safety net has never run" 1 "$RC"
ahas "P13 raised before any deep-verify" "P13 deep-verify has NEVER completed" "$(Q 'd["problems"]')"
aeq "pass_kind (mirror pass)" mirror "$(Q 'd["pass_kind"]')"
ENG deep-verify
aeq "rc" 0 "$RC"
aeq "healthy" true "$(Q 'd["healthy"]')"
aeq "problems" "[]" "$(Q 'd["problems"]')"
aeq "schema" 1 "$(Q 'd["schema"]')"
aeq "pass_kind (deep-verify pass)" "deep-verify" "$(Q 'd["pass_kind"]')"
aeq "replica_snapshots" "[\"$S1\", \"$S2\", \"$S3\"]" "$(Q 'd["replica_snapshots"]')"
aeq "pending drained" "[]" "$(Q 'd["pending"]')"
aeq "latest_replica" "$S3" "$(Q 'd["latest_replica"]')"
aeq "replica latest symlink" "$S3" "$(readlink "$SNAP_REPLICA/snapshots/latest")"
aeq "manifests written" 3 "$(ls -1 "$SNAP_STATE_DIR/manifests"/*.json 2>/dev/null | wc -l | tr -d ' ')"
aeq "detected events" "detected:$S1
detected:$S2
detected:$S3" "$(EV detected)"
aeq "copied events" "copied:$S1
copied:$S2
copied:$S3" "$(EV copied)"
aeq "no copy_failed" "" "$(EV copy_failed)"
aeq "staging empty after promote" "[]" "$(Q 'd["incoming"]')"
# --- exact F4 top-level key set
aeq "status key set == 00 F4" "ok" "$(/usr/bin/python3 - "$SNAP_STATE_DIR/status.json" <<'PY'
import json,sys
want = ["schema","ts","pass_kind","engine_pid","primary_mounted","replica_mounted",
 "primary_total_kb","primary_used_kb","primary_free_kb","primary_iused",
 "replica_total_kb","replica_used_kb","replica_free_kb","replica_iused",
 "primary_snapshots","replica_snapshots","latest_primary","latest_replica",
 "pending","unsettled","incoming","last_copy","last_deep_verify","mirror_running",
 "mirror_running_seconds","healthy","problems","notes"]
got = set(json.load(open(sys.argv[1])).keys())
missing = set(want)-got; extra = got-set(want)
print("ok" if not missing and not extra else "missing=%s extra=%s" % (sorted(missing),sorted(extra)))
PY
)"
# --- hardlink dedup ACROSS replica snapshots (the whole point of the design)
aeq "dedup: b/f08.txt s1==s2 inode"  "$(ino "$R/$S1/b/f08.txt")" "$(ino "$R/$S2/b/f08.txt")"
aeq "dedup: b/f08.txt s2==s3 inode"  "$(ino "$R/$S2/b/f08.txt")" "$(ino "$R/$S3/b/f08.txt")"
aeq "dedup: big.bin s1==s3 inode"    "$(ino "$R/$S1/big.bin")"   "$(ino "$R/$S3/big.bin")"
ane "changed a/f01.txt s1 != s2"     "$(ino "$R/$S1/a/f01.txt")" "$(ino "$R/$S2/a/f01.txt")"
# --- intra-snapshot hardlink pair preserved (-H, decision D1)
aeq "intra pair a/hl1==b/hl2 in s3"  "$(ino "$R/$S3/a/hl1")"     "$(ino "$R/$S3/b/hl2")"
# --- pathological filenames survived
aeq "'Redesign #1.step' copied" "STEP" "$(cat "$R/$S3/b/Redesign #1.step" 2>/dev/null)"
aeq "utf-8 name copied" "1" "$(ls "$R/$S3/b/" | grep -c 'caf' | tr -d ' ')"
aeq "leading-dash name copied" "dash" "$(cat "$R/$S3/b/-leading-dash.txt" 2>/dev/null)"
aeq "name with space copied" "space" "$(cat "$R/$S3/b/with space.txt" 2>/dev/null)"
aeq "nested '#' name copied" "nested" "$(cat "$R/$S3/b/sub dir/nested #2.txt" 2>/dev/null)"
aeq "empty dir copied" "yes" "$([ -d "$R/$S3/b/emptydir" ] && echo yes || echo no)"
aeq "dangling symlink copied as symlink" "/nonexistent/target" "$(readlink "$R/$S3/dangle")"
# --- F8.5b audit repaired the F2 window: replica must hold the NEW bytes
aeq "F2 window: replica s3 has NEW bytes" "$(md5 -q "$SNAP_PRIMARY/snapshots/$S3/a/f2window.txt")" \
                                          "$(md5 -q "$R/$S3/a/f2window.txt")"
ane "F2 window: replica s3 != replica s2" "$(md5 -q "$R/$S2/a/f2window.txt")" \
                                          "$(md5 -q "$R/$S3/a/f2window.txt")"
ahas "audit repair visible in LOG" "violator(s) hardlinked to stale base bytes" "$(LOGT)"
ahas "audit counts recorded" "audit changed=" "$(LOGT)"
ahas "dedup assertion recorded" "dedup ok (shares inode(s) with base" "$(LOGT)"
ahas "F7 start line" "start pid=" "$(LOGT)"
ahas "F7 finished line" "finished rc=0" "$(LOGT)"
aeq "last_copy rc" 0 "$(Q 'd["last_copy"]["rc"]')"
aeq "last_copy snapshot" "$S3" "$(Q 'd["last_copy"]["snapshot"]')"
aeq "last_copy link_dest" "$S2" "$(Q 'd["last_copy"]["link_dest"]')"

########################################################################################
head_ "T02 incremental: only the new snapshot is copied"
FIX snap "$ROOT" "$S3" "$S4"
FIX latest "$ROOT" "$S4"
EVBEFORE=$(EV copy_started | wc -l | tr -d ' ')
ENG mirror
aeq "rc" 0 "$RC"
aeq "exactly one new rsync copy started" 1 \
    "$(( $(EV copy_started | wc -l | tr -d ' ') - EVBEFORE ))"
aeq "copied event for s4" "copied:$S4" "$(EV copied | tail -1)"
aeq "latest_replica" "$S4" "$(Q 'd["latest_replica"]')"
aeq "dedup: unchanged b/f08 s3==s4" "$(ino "$R/$S3/b/f08.txt")" "$(ino "$R/$S4/b/f08.txt")"
ane "changed a/f01 s3 != s4"        "$(ino "$R/$S3/a/f01.txt")" "$(ino "$R/$S4/a/f01.txt")"
aeq "healthy" true "$(Q 'd["healthy"]')"

########################################################################################
head_ "T03 no-op pass is fast and does not spam the LOG"
LINES_BEFORE=$(LOGC)
T_START=$(/usr/bin/python3 -c 'import time;print(int(time.time()*1000))')
ENG mirror
T_END=$(/usr/bin/python3 -c 'import time;print(int(time.time()*1000))')
aeq "rc" 0 "$RC"
aeq "no new LOG lines on a no-op pass" "$LINES_BEFORE" "$(LOGC)"
alt "no-op pass under 5000 ms" 5000 "$((T_END - T_START))"
ane "STATUS.ts still refreshed (heartbeat)" "" "$(Q 'd["ts"]')"

########################################################################################
head_ "T04 unsettled snapshot is NOT copied until latest advances"
FIX snap "$ROOT" "$S4" "$S5"        # created but latest still points at S4
ENG mirror
aeq "rc" 0 "$RC"
aeq "s5 not promoted" "no" "$([ -d "$R/$S5" ] && echo yes || echo no)"
aeq "s5 listed unsettled" "[\"$S5\"]" "$(Q 'd["unsettled"]')"
aeq "pending empty" "[]" "$(Q 'd["pending"]')"
ahas "note names the in-progress snapshot" "$S5" "$(Q 'd["notes"]')"
FIX latest "$ROOT" "$S5"
ENG mirror
aeq "rc after latest advances" 0 "$RC"
aeq "s5 promoted" "yes" "$([ -d "$R/$S5" ] && echo yes || echo no)"
aeq "latest_replica" "$S5" "$(Q 'd["latest_replica"]')"

########################################################################################
head_ "T05 CORPSE: partial stamp above latest is never copied, before OR after latest advances"
newroot t05
build3
coldstart
# a backup run creates its stamp dir and dies; `latest` is NOT repointed  (2026-08-19_145758)
FIX partial "$ROOT" "$S3" "$S6"
ENG mirror
aeq "rc while corpse is above latest" 0 "$RC"
aeq "corpse not copied (above latest)" "no" "$([ -d "$R/$S6" ] && echo yes || echo no)"
aeq "corpse recorded above_latest" "true" \
    "$(/usr/bin/python3 "$RUN/q.py" "$SNAP_STATE_DIR/seen.json" "\"$S6\" in d[\"above_latest\"]")"
# the next run SUCCEEDS and latest jumps PAST the corpse -- this is where the old rule failed
FIX snap "$ROOT" "$S3" "$S7"
FIX latest "$ROOT" "$S7"
ENG mirror
aeq "rc with corpse below latest" 1 "$RC"
aeq "corpse STILL not copied" "no" "$([ -d "$R/$S6" ] && echo yes || echo no)"
aeq "s7 was copied" "yes" "$([ -d "$R/$S7" ] && echo yes || echo no)"
ahas "P12 raised" "P12 CORPSE on primary: $S6" "$(Q 'd["problems"]')"
aeq "healthy false" false "$(Q 'd["healthy"]')"
ahas "orphan_partial event names the corpse" "orphan_partial:$S6" "$(EV orphan_partial)"
aeq "corpse never in was_latest" "false" \
    "$(/usr/bin/python3 "$RUN/q.py" "$SNAP_STATE_DIR/seen.json" "\"$S6\" in d[\"was_latest\"]")"

########################################################################################
head_ "T06 staging is WIPED before every rsync attempt (01 D2)"
newroot t06
build3
coldstart
FIX snap "$ROOT" "$S3" "$S4"
FIX latest "$ROOT" "$S4"
# plant exactly what a SIGKILL leaves behind: an orphan temp file that is not in the source list
mkdir -p "$R/.incoming/$S4/a"
printf 'PARTIAL GARBAGE' > "$R/.incoming/$S4/.big.bin.MeoYdgcSxa"
printf 'ORPHAN' > "$R/.incoming/$S4/a/leftover.junk"
ENG mirror
aeq "rc" 0 "$RC"
ahas "LOG records the wipe" "staging: wiping" "$(LOGT)"
aeq "orphan temp did not survive into the promoted stamp" "no" \
    "$([ -e "$R/$S4/.big.bin.MeoYdgcSxa" ] && echo yes || echo no)"
aeq "orphan junk did not survive" "no" "$([ -e "$R/$S4/a/leftover.junk" ] && echo yes || echo no)"
aeq "verification passed / promoted" "yes" "$([ -d "$R/$S4" ] && echo yes || echo no)"
aeq "healthy" true "$(Q 'd["healthy"]')"

########################################################################################
head_ "T07 crash between manifest and rename -> next pass converges"
newroot t07
build3
coldstart
FIX snap "$ROOT" "$S3" "$S4"
FIX latest "$ROOT" "$S4"
SNAP_TEST_CRASH=after_manifest ENG mirror
aeq "engine died at the crash point" 137 "$RC"
aeq "manifest exists" "yes" "$([ -f "$SNAP_STATE_DIR/manifests/$S4.json" ] && echo yes || echo no)"
aeq "stamp NOT promoted yet" "no" "$([ -d "$R/$S4" ] && echo yes || echo no)"
aeq "stamp is in staging" "yes" "$([ -d "$R/.incoming/$S4" ] && echo yes || echo no)"
aeq "lock file left behind by the kill" "yes" "$([ -f "$SNAP_STATE_DIR/mirror.pid" ] && echo yes || echo no)"
ENG mirror
aeq "next pass rc" 0 "$RC"
# BUG-1: the kernel released the flock when the SIGKILLed holder died, so the next pass simply
# takes it.  No stale-lock heuristic exists any more, and none is needed.
anot "no stale-lock heuristic was involved" "stale lock" "$(LOGT)"
anot "the pass was not skipped" "skip: already running" "$(LOGT)"
ahas "staging recovery path used" "re-verifying staging" "$(LOGT)"
aeq "stamp promoted" "yes" "$([ -d "$R/$S4" ] && echo yes || echo no)"
aeq "staging drained" "[]" "$(Q 'd["incoming"]')"
aeq "healthy" true "$(Q 'd["healthy"]')"
aeq "content correct after recovery" "$(md5 -q "$SNAP_PRIMARY/snapshots/$S4/a/f01.txt")" \
                                     "$(md5 -q "$R/$S4/a/f01.txt")"

########################################################################################
head_ "T08 crash between rename and event -> next pass converges"
newroot t08
build3
coldstart
FIX snap "$ROOT" "$S3" "$S4"
FIX latest "$ROOT" "$S4"
SNAP_TEST_CRASH=after_rename ENG mirror
aeq "engine died at the crash point" 137 "$RC"
aeq "stamp IS promoted (rename happened)" "yes" "$([ -d "$R/$S4" ] && echo yes || echo no)"
aeq "manifest exists (written first)" "yes" "$([ -f "$SNAP_STATE_DIR/manifests/$S4.json" ] && echo yes || echo no)"
aeq "copied event is the one thing missing" "" "$(EV copied | grep "$S4" || true)"
CS_BEFORE=$(EV copy_started | wc -l | tr -d ' ')
ENG mirror
aeq "next pass rc" 0 "$RC"
aeq "no re-copy attempted" "$CS_BEFORE" "$(EV copy_started | wc -l | tr -d ' ')"
aeq "healthy" true "$(Q 'd["healthy"]')"
aeq "latest_replica" "$S4" "$(Q 'd["latest_replica"]')"

########################################################################################
head_ "T09 dedup assertion fires when --link-dest silently does nothing (01 C3)"
newroot t09
build3
coldstart
FIX snap "$ROOT" "$S3" "$S4"
FIX latest "$ROOT" "$S4"
SNAP_TEST_BOGUS_LINKDEST=1 ENG mirror
aeq "rc" 1 "$RC"
aeq "stamp NOT promoted" "no" "$([ -d "$R/$S4" ] && echo yes || echo no)"
aeq "staging left for forensics" "yes" "$([ -d "$R/.incoming/$S4" ] && echo yes || echo no)"
ahas "P4 raised" "P4 snapshot $S4 failed to copy and is still missing" "$(Q 'd["problems"]')"
aeq "exactly one P4 line (no duplicate detail in the red banner)" 1 \
    "$(Q 'len([x for x in d["problems"] if x.startswith("P4")])')"
ahas "forensics hint is a note, not a second problem" "left in place for forensics" "$(Q 'd["notes"]')"
ahas "dedup assertion named" "dedup assertion FAILED" "$(Q 'd["problems"]')"
ahas "inode identity is THE assertion (C7)" "NO staged file shares an inode with the base" \
     "$(Q 'd["problems"]')"
ahas "nlink>1 is reported but did NOT gate promotion" \
     "which is exactly why that test alone is not the assertion" "$(Q 'd["problems"]')"
aeq "verify_failed event" "verify_failed:$S4" "$(EV verify_failed | tail -1)"
aeq "healthy false" false "$(Q 'd["healthy"]')"
# and it recovers on the next honest pass
ENG mirror
aeq "recovery rc" 0 "$RC"
aeq "stamp promoted on the retry" "yes" "$([ -d "$R/$S4" ] && echo yes || echo no)"
aeq "P4 superseded by the success" true "$(Q 'd["healthy"]')"

########################################################################################
head_ "T10 prune: 100-day boundary, P9 wipe alarm, 2-per-pass cap"
newroot t10
build3
coldstart
OLD1="$(OLD_D 101)_120000"; OLD2="$(OLD_D 102)_120000"; OLD3="$(OLD_D 103)_120000"
YOUNG="$(OLD_D 85)_120000"
for s in "$OLD1" "$OLD2" "$OLD3" "$YOUNG"; do
    FIX replica_only "$ROOT" "$s"
    printf '{"stamp":"%s","files":1,"bytes":1,"listing_md5":"x","verified":"x","link_dest":null}\n' \
        "$s" > "$SNAP_STATE_DIR/manifests/$s.json"
done
ENG mirror
aeq "rc (P9 present)" 1 "$RC"
aeq "oldest pruned"        "no"  "$([ -d "$R/$OLD3" ] && echo yes || echo no)"
aeq "2nd oldest pruned"    "no"  "$([ -d "$R/$OLD2" ] && echo yes || echo no)"
aeq "3rd is rate-limited"  "yes" "$([ -d "$R/$OLD1" ] && echo yes || echo no)"
aeq "85-day stamp RETAINED" "yes" "$([ -d "$R/$YOUNG" ] && echo yes || echo no)"
ahas "P9 wipe alarm on the young stamp" "P9 replica-only stamp $YOUNG" "$(Q 'd["problems"]')"
ahas "rate-limit note" "prune rate limit" "$(Q 'd["notes"]')"
aeq "pruned events" "pruned:$OLD3
pruned:$OLD2" "$(EV pruned)"
aeq "manifest moved to pruned/" "yes" \
    "$([ -f "$SNAP_STATE_DIR/manifests/pruned/$OLD3.json" ] && echo yes || echo no)"
ENG mirror
aeq "next pass drains the rest" "no" "$([ -d "$R/$OLD1" ] && echo yes || echo no)"
aeq "85-day stamp still retained" "yes" "$([ -d "$R/$YOUNG" ] && echo yes || echo no)"
aeq "rc still 1 (P9 latched)" 1 "$RC"

########################################################################################
head_ "T11 unmounted volume -> exit 1, never 0"
newroot t11
build3
coldstart
REPLICA_SUM_BEFORE=$(find "$SNAP_REPLICA" | sort | md5 -q)
export SNAP_PRIMARY="$ROOT/not-mounted"
ENG mirror
aeq "rc" 1 "$RC"
aeq "healthy" false "$(Q 'd["healthy"]')"
ahas "P1 raised" "P1 primary volume not mounted" "$(Q 'd["problems"]')"
aeq "primary_mounted" false "$(Q 'd["primary_mounted"]')"
ahas "F7 volume-missing line" "skip: volume missing (src=MISSING dst=ok)" "$(LOGT)"
aeq "zero writes to the replica fixture" "$REPLICA_SUM_BEFORE" "$(find "$SNAP_REPLICA" | sort | md5 -q)"
LINES_BEFORE=$(LOGC)
ENG mirror
aeq "volume-missing logged on TRANSITION only" "$LINES_BEFORE" "$(LOGC)"
export SNAP_PRIMARY="$ROOT/primary"
ENG mirror
aeq "recovers when the volume returns" 0 "$RC"
ahas "return transition logged" "volumes present again" "$(LOGT)"

########################################################################################
head_ "T12 BUG-1: the lock is fcntl.flock, and it is actually mutually exclusive"
newroot t12
build3
coldstart
TS_BEFORE=$(Q 'd["ts"]')
# (1) A LEFTOVER lock file that nobody flocks must NOT block the engine.  The file is never
# unlinked by design, so this is the NORMAL state after every pass; returning 2 here would wedge
# the engine permanently on its own leftovers.
aeq "lock file survives a completed pass (never unlinked)" "yes" \
    "$([ -f "$SNAP_STATE_DIR/mirror.pid" ] && echo yes || echo no)"
: > "$SNAP_STATE_DIR/mirror.pid"                       # zero-byte leftover
ENG mirror
aeq "zero-byte leftover, nobody holding: pass RUNS" 0 "$RC"
anot "no stale-lock reasoning anywhere" "stale lock" "$(LOGT)"
TS_BEFORE=$(Q 'd["ts"]')
sleep 1                                   # STATUS.ts has 1 s resolution
# (2) A zero-byte lock file that IS flocked -> the exact BUG-1 window (flock taken, pid not yet
# written).  Under the old pidfile scheme this is where a second engine stole the lock.
holdlock 6 empty
ENG mirror
aeq "flocked but EMPTY pid file: skipped" 2 "$RC"
ahas "F7 skip line present" "skip: already running pid=" "$(LOGT)"
aeq "heartbeat set mirror_running" true "$(Q 'd["mirror_running"]')"
ane "heartbeat refreshed ts" "$TS_BEFORE" "$(Q 'd["ts"]')"
aeq "status not clobbered (snapshots intact)" "[\"$S1\", \"$S2\", \"$S3\"]" "$(Q 'd["replica_snapshots"]')"
aeq "mirror_running_seconds is published" "true" "$(Q 'd["mirror_running_seconds"] >= 0')"
kill "$HL_PID" 2>/dev/null; wait "$HL_PID" 2>/dev/null
# (3) A normal holder with its pid written
holdlock 6 pid
ENG mirror
aeq "flocked with a pid: skipped" 2 "$RC"
ahas "skip line names the holder" "skip: already running pid=$HL_PID" "$(LOGT)"
kill "$HL_PID" 2>/dev/null; wait "$HL_PID" 2>/dev/null
ENG mirror
aeq "lock released when the holder exits" 0 "$RC"

########################################################################################
head_ "T29 BUG-1: N simultaneous passes, many rounds, exactly one copier per stamp"
newroot t29
FIX seed "$ROOT" "$S1"
FIX latest "$ROOT" "$S1"
coldstart
PARALLEL=5
PREV="$S1"; ROUND=0; TWO_PLUS=0; CONTENDED=0
for NEXT in "$S2" "$S3" "$S4" "$S5" "$S6" "$S7"; do
    ROUND=$((ROUND+1))
    FIX snap "$ROOT" "$PREV" "$NEXT"
    FIX latest "$ROOT" "$NEXT"
    BEFORE=$(grep -c "start pid=" "$SNAP_LOG" 2>/dev/null | tr -d ' ')
    RCS=""
    i=1
    while [ $i -le $PARALLEL ]; do
        ( bash "$ENGDIR/mirror.sh" mirror >/dev/null 2>&1; echo $? > "$ROOT/rc.$ROUND.$i" ) &
        i=$((i+1))
    done
    wait
    i=1
    while [ $i -le $PARALLEL ]; do RCS="$RCS $(cat "$ROOT/rc.$ROUND.$i")"; i=$((i+1)); done
    AFTER=$(grep -c "start pid=" "$SNAP_LOG" 2>/dev/null | tr -d ' ')
    [ "$((AFTER - BEFORE))" -gt 1 ] && TWO_PLUS=$((TWO_PLUS+1))
    case "$RCS" in *2*) CONTENDED=$((CONTENDED+1));; esac
    PREV="$NEXT"
done
aeq "never two copy passes for one stamp ($ROUND rounds x $PARALLEL simultaneous)" 0 "$TWO_PLUS"
aeq "contention really occurred (some pass exited 2)" "true" \
    "$([ "$CONTENDED" -gt 0 ] && echo true || echo false)"
aeq "no duplicate copy_started events" "" "$(EV copy_started | sort | uniq -d)"
aeq "no duplicate copied events" "" "$(EV copied | sort | uniq -d)"
aeq "zero copy failures" "" "$(EV copy_failed)"
aeq "zero verify failures" "" "$(EV verify_failed)"
aeq "every stamp promoted exactly once" 7 "$(ls -1d "$R"/2* | wc -l | tr -d ' ')"
aeq "staging drained" "[]" "$(Q 'd["incoming"]')"
ENG deep-verify
aeq "deep-verify clean after the storm" pass "$(Q 'd["last_deep_verify"]["result"]')"
aeq "healthy" true "$(Q 'd["healthy"]')"

########################################################################################
head_ "T13 legacy dispatch: any unrecognized command maps to mirror"
newroot t13
build3
coldstart
SSH_ORIGINAL_COMMAND="/Users/youruser/Library/AgentSnapshot/mirror.sh" ENG
aeq "legacy full-path rc" 0 "$RC"
aeq "pass_kind" mirror "$(Q 'd["pass_kind"]')"
SSH_ORIGINAL_COMMAND="rm -rf /; echo pwned" ENG
aeq "injection attempt rc" 0 "$RC"
aeq "injection mapped to mirror" mirror "$(Q 'd["pass_kind"]')"
aeq "shell injection did NOT execute" "" "$(grep -c pwned "$ROOT/out.txt" | grep -v '^0$' || true)"
SSH_ORIGINAL_COMMAND="deep-verify" ENG
aeq "deep-verify via SSH_ORIGINAL_COMMAND" "deep-verify" "$(Q 'd["pass_kind"]')"
ENG garbage-mode
aeq "unknown argv[1] maps to mirror" mirror "$(Q 'd["pass_kind"]')"
aeq "mirror.sh line count < 15 (00 F3)" "yes" \
    "$([ "$(wc -l < "$ENGDIR/mirror.sh" | tr -d ' ')" -lt 15 ] && echo yes || echo no)"
anot "mirror.sh never execs the ssh command" "eval" "$(cat "$ENGDIR/mirror.sh")"

########################################################################################
head_ "T14 deep-verify passes, then catches silent content corruption"
newroot t14
build3
coldstart
SNAP_VERIFY_SAMPLE=all ENG deep-verify
aeq "rc" 0 "$RC"
aeq "last_deep_verify.result" pass "$(Q 'd["last_deep_verify"]["result"]')"
ahas "newest stamp verified" "$S3" "$(Q 'd["last_deep_verify"]["snapshots"]')"
ahas "F7 start/finished logged for deep-verify" "finished rc=0" "$(LOGT)"
# same size, same name, different bytes: invisible to count/bytes/listing_md5
rm -f "$R/$S3/b/f08.txt"
/usr/bin/python3 -c 'import sys;open(sys.argv[1],"wb").write(b"Z"*int(sys.argv[2]))' \
    "$R/$S3/b/f08.txt" "$(stat -f %z "$SNAP_PRIMARY/snapshots/$S3/b/f08.txt")"
touch -r "$SNAP_PRIMARY/snapshots/$S3/b/f08.txt" "$R/$S3/b/f08.txt"
SNAP_VERIFY_SAMPLE=all ENG deep-verify
aeq "rc" 1 "$RC"
aeq "last_deep_verify.result" fail "$(Q 'd["last_deep_verify"]["result"]')"
ahas "P5 raised" "P5 last deep-verify FAILED" "$(Q 'd["problems"]')"
ahas "verify_failed event" "verify_failed:$S3" "$(EV verify_failed)"
ahas "the corrupt file is named" "b/f08.txt" "$(Q 'd["last_deep_verify"]["detail"]')"

########################################################################################
head_ "T15 forbidden rsync flags are asserted out of the argv"
newroot t15
build3
coldstart
REPLICA_BEFORE=$(ls -1 "$SNAP_REPLICA/snapshots" 2>/dev/null | wc -l | tr -d ' ')
SNAP_TEST_INJECT_FLAG=--delete ENG mirror
aeq "rc" 3 "$RC"
ahas "assertion fired" "FORBIDDEN rsync flag '--delete'" "$(cat "$ROOT/err.txt")"
aeq "the rejected run copied nothing new" "$REPLICA_BEFORE" \
    "$(ls -1 "$SNAP_REPLICA/snapshots" 2>/dev/null | wc -l | tr -d ' ')"
SNAP_TEST_INJECT_FLAG=--inplace ENG mirror
aeq "--inplace rc" 3 "$RC"
ahas "--inplace named" "FORBIDDEN rsync flag '--inplace'" "$(cat "$ROOT/err.txt")"
SNAP_TEST_INJECT_FLAG=--remove-source-files ENG mirror
aeq "--remove-source-files rc" 3 "$RC"
SNAP_TEST_INJECT_FLAG=--force ENG mirror
aeq "--force rc" 3 "$RC"
SNAP_TEST_INJECT_FLAG=-H ENG mirror
aeq "-H rc (D1 reversed: -H is now forbidden)" 3 "$RC"
ahas "-H named by the assertion" "FORBIDDEN rsync flag '-H'" "$(cat "$ROOT/err.txt")"
SNAP_TEST_INJECT_FLAG=-aH ENG mirror
aeq "short-flag bundle -aH rc" 3 "$RC"
ahas "bundle named" "FORBIDDEN rsync flag '-aH'" "$(cat "$ROOT/err.txt")"
SNAP_TEST_INJECT_FLAG=--hard-links ENG mirror
aeq "--hard-links rc" 3 "$RC"
aeq "no -H token inside either argv builder body" "0" \
    "$(sed -n '/^def build_copy_argv/,/^def run_rsync/p' "$ENGDIR/engine.py" \
       | grep -cE '"-[a-zA-Z]*H[a-zA-Z]*"|--hard-links' | tr -d ' ')"
aeq "forbidden flags appear ONLY in the FORBIDDEN_FLAG_PREFIXES definition" "0" \
    "$(grep -nE '"--(inplace|delete|del|force|remove-source-files)' "$ENGDIR/engine.py" \
       | grep -v FORBIDDEN_FLAG_PREFIXES | grep -vc ':[[:space:]]*#' | tr -d ' ')"
aeq "the REAL argv builders emit no forbidden flag" "clean" "$(/usr/bin/python3 - "$ENGDIR" <<'ARGVPY'
import sys, importlib.util
spec = importlib.util.spec_from_file_location("eng", sys.argv[1] + "/engine.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
argvs = [m.build_copy_argv("/s", "/d", "/b"), m.build_copy_argv("/s", "/d", None),
         m.build_repair_argv("/s", "/d", "/l")]
bad = [a for v in argvs for a in v
       if any(a.startswith(f) for f in ("--inplace", "--del", "--remove-source-files", "--force"))
       or a.startswith("--hard-links")
       or (a.startswith("-") and not a.startswith("--") and "H" in a[1:])]
print("clean" if not bad else "LEAKED %s" % bad)
ARGVPY
)"
ENG mirror
aeq "clean run still works" 0 "$RC"

########################################################################################
head_ "T16 dangling primary latest -> P2, nothing settles, no copy"
newroot t16
build3
coldstart
FIX snap "$ROOT" "$S3" "$S4"
( cd "$SNAP_PRIMARY/snapshots" && ln -sfn 1999-01-01_000000 latest )
CS_BEFORE=$(EV copy_started | wc -l | tr -d ' ')
ENG mirror
aeq "rc" 1 "$RC"
ahas "P2 raised" "P2 primary \`latest\` is dangling" "$(Q 'd["problems"]')"
aeq "nothing settled" "[]" "$(Q 'd["pending"]')"
aeq "no copy attempted" "$CS_BEFORE" "$(EV copy_started | wc -l | tr -d ' ')"
aeq "s4 not promoted" "no" "$([ -d "$R/$S4" ] && echo yes || echo no)"

########################################################################################
head_ "T17 primary mounted but empty; garbage in .incoming -> P10"
newroot t17
mkdir -p "$ROOT/primary/snapshots" "$ROOT/replica/snapshots"
ENG mirror
aeq "rc" 1 "$RC"
ahas "empty primary reported" "primary has no snapshots" "$(Q 'd["problems"]')"
ahas "P2 also raised" "P2 primary \`latest\` symlink is missing" "$(Q 'd["problems"]')"
aeq "healthy" false "$(Q 'd["healthy"]')"
mkdir -p "$ROOT/replica/snapshots/.incoming/GARBAGE-not-a-stamp/x"
/usr/bin/python3 - "$SNAP_STATE_DIR/staging.json" <<'PY'
import json,sys,time,datetime
p=sys.argv[1]
d=json.load(open(p)) if __import__("os").path.exists(p) else {}
old=datetime.datetime.now()-datetime.timedelta(hours=7)
d["GARBAGE-not-a-stamp"]=old.strftime("%Y-%m-%dT%H:%M:%S-0400")
json.dump(d,open(p,"w"))
PY
ENG mirror
ahas "P10 stuck staging" "P10 staging entry GARBAGE-not-a-stamp" "$(Q 'd["problems"]')"
ahas "garbage listed in incoming" "GARBAGE-not-a-stamp" "$(Q 'd["incoming"]')"
aeq "garbage never counted as a snapshot" "[]" "$(Q 'd["replica_snapshots"]')"

########################################################################################
head_ "T18 two stamps pending at once -> chained link-dest, ascending order"
newroot t18
FIX seed "$ROOT" "$S1"
FIX latest "$ROOT" "$S1"
coldstart
FIX snap "$ROOT" "$S1" "$S2"
FIX snap "$ROOT" "$S2" "$S3"
FIX latest "$ROOT" "$S3"
ENG mirror
aeq "rc" 0 "$RC"
aeq "both promoted, ascending" "copied:$S1
copied:$S2
copied:$S3" "$(EV copied)"
aeq "s3 chained off freshly promoted s2" "$S2" "$(Q 'd["last_copy"]["link_dest"]')"
aeq "dedup across the chain (b/f08)" "$(ino "$R/$S1/b/f08.txt")" "$(ino "$R/$S3/b/f08.txt")"
aeq "healthy" true "$(Q 'd["healthy"]')"

########################################################################################
head_ "T21 NEW intra-snapshot hardlink pair: plain -a + engine reconstruction (00 F8.3, D1 reversed)"
newroot t21
build3
coldstart
FIX snap "$ROOT" "$S3" "$S4"
FIX newpair "$ROOT" "$S4"
FIX latest "$ROOT" "$S4"
aeq "primary pair shares one inode" "$(ino "$P/$S4/a/newpair1")" "$(ino "$P/$S4/b/newpair2")"
ENG mirror
aeq "rc" 0 "$RC"
aeq "s4 promoted" "yes" "$([ -d "$R/$S4" ] && echo yes || echo no)"
aeq "replica pair shares ONE inode" "$(ino "$R/$S4/a/newpair1")" "$(ino "$R/$S4/b/newpair2")"
aeq "pair content correct" "$(md5 -q "$P/$S4/a/newpair1")" "$(md5 -q "$R/$S4/b/newpair2")"
anot "NO openrsync abort (D1 reversed, -H not shipped)" "ABORT" "$(LOGT)"
anot "NO retry / no second staging wipe for s4" "retrying" "$(LOGT)"
ahas "engine reconstructed the NEW pair itself" "intra-groups=2 relinked=1" "$(LOGT)"
aeq "NO amber note - reconstruction is routine, not an incident" "[]" "$(Q 'd["notes"]')"
aeq "healthy" true "$(Q 'd["healthy"]')"
aeq "rsync ran exactly ONCE for s4 (no retry)" 1 \
    "$(grep -c "copy $S4: rsync -a " "$SNAP_LOG" | tr -d ' ')"
anot "the log never claims -aH" "rsync -aH" "$(LOGT)"
# self-healing: break the pair on the replica, re-copy, engine must restore it
rm -rf "$R/$S4" "$SNAP_STATE_DIR/manifests/$S4.json"
ENG mirror
aeq "re-copy rc" 0 "$RC"
aeq "pair restored on re-copy" "$(ino "$R/$S4/a/newpair1")" "$(ino "$R/$S4/b/newpair2")"

########################################################################################
head_ "T22 events trim, LOG rotation, LEGACY_LOCK"
newroot t22
build3
coldstart
# F6: trim to the newest 1000 lines once the file passes 2000
/usr/bin/python3 - "$SNAP_STATE_DIR/events.jsonl" <<'TRIMPY'
import sys
p = sys.argv[1]
line = '{"ts":"x","event":"detected","snapshot":"pad","detail":"pad"}\n'
with open(p, "a") as fh:
    for _ in range(2100):
        fh.write(line)
TRIMPY
BEFORE=$(wc -l < "$SNAP_STATE_DIR/events.jsonl" | tr -d ' ')
ENG mirror
AFTER=$(wc -l < "$SNAP_STATE_DIR/events.jsonl" | tr -d ' ')
aeq "events file was over the 2000 trigger" "yes" "$([ "$BEFORE" -gt 2000 ] && echo yes || echo no)"
aeq "events trimmed to the newest 1000" 1000 "$AFTER"
aeq "trimmed file is still valid JSONL" "ok" "$(/usr/bin/python3 - "$SNAP_STATE_DIR/events.jsonl" <<'JPY'
import json,sys
for line in open(sys.argv[1]):
    if line.strip(): json.loads(line)
print("ok")
JPY
)"
# F7: rotate at 5 MB
/usr/bin/python3 -c 'import sys;open(sys.argv[1],"ab").write(b"x"*(5*1024*1024))' "$SNAP_LOG"
FIX snap "$ROOT" "$S3" "$S4"; FIX latest "$ROOT" "$S4"
ENG mirror
aeq "LOG rotated to .1" "yes" "$([ -f "$SNAP_LOG.1" ] && echo yes || echo no)"
aeq "new LOG is small again" "yes"     "$([ "$(stat -f %z "$SNAP_LOG")" -lt 5242880 ] && echo yes || echo no)"
# LEGACY_LOCK is honoured read-only and NEVER created
export SNAP_LEGACY_LOCK="$ROOT/legacy.pid"
ENG mirror
aeq "legacy lock is never created" "no" "$([ -f "$ROOT/legacy.pid" ] && echo yes || echo no)"
aeq "engine.py never writes the legacy lock" "0" \
    "$(grep -c 'legacy_lock' "$ENGDIR/engine.py" | tr -d ' ' >/dev/null; \
       grep -nE '_unlink\(self\.legacy_lock|open\(self\.legacy_lock, *.w' "$ENGDIR/engine.py" | wc -l | tr -d ' ')"
sleep 5 & LPID=$!
echo "$LPID" > "$ROOT/legacy.pid"
ENG mirror
aeq "live LEGACY_LOCK blocks the pass" 2 "$RC"
ahas "skip line names the legacy pid" "skip: already running pid=$LPID" "$(LOGT)"
kill "$LPID" 2>/dev/null; wait "$LPID" 2>/dev/null
ENG mirror
aeq "dead LEGACY_LOCK is stale, pass proceeds" 0 "$RC"
aeq "stale legacy lock is left in place, not deleted" "yes" \
    "$([ -f "$ROOT/legacy.pid" ] && echo yes || echo no)"
unset SNAP_LEGACY_LOCK

########################################################################################
head_ "T23 deep-verify falls back to the stored manifest once the primary copy is pruned"
newroot t23
FIX seed "$ROOT" "$S1"
FIX snap "$ROOT" "$S1" "$S2"
FIX latest "$ROOT" "$S2"          # exactly 2 promoted stamps => the rotating older target IS S1
coldstart
rm -rf "$P/$S1"                       # simulate the MacBook's 90-day retention removing it
SNAP_VERIFY_SAMPLE=all ENG deep-verify
aeq "rc" 1 "$RC"
ahas "P9 alarm (primary-only-loss guard) fires first" "P9 replica-only stamp $S1" "$(Q 'd["problems"]')"
aeq "deep-verify still passed" pass "$(Q 'd["last_deep_verify"]["result"]')"
# make the replica copy diverge from its manifest -> manifest comparison must catch it
echo "EXTRA FILE NOT IN THE MANIFEST" > "$R/$S1/a/rogue.txt"
SNAP_VERIFY_SAMPLE=all ENG deep-verify
aeq "deep-verify result" fail "$(Q 'd["last_deep_verify"]["result"]')"
ahas "mismatch is against the stored manifest" "listing mismatch vs stored manifest"      "$(Q 'd["last_deep_verify"]["detail"]')"
ahas "P5 raised" "P5 last deep-verify FAILED" "$(Q 'd["problems"]')"

########################################################################################
head_ "T24 grandfathered cutover stamps + the manifest-less recovery rule (00 F8 step 6)"
newroot t24
build3
# simulate cutover: the OLD whole-volume rsync already placed S1 and S2 on the replica, and by
# definition they have no manifests
mkdir -p "$R/$S1" "$R/$S2"
/usr/bin/rsync -a "$P/$S1/" "$R/$S1/"
/usr/bin/rsync -a --link-dest="$R/$S1" "$P/$S2/" "$R/$S2/"
( cd "$R" && ln -sfn "$S2" latest )
ENG mirror
ENG deep-verify                    # P13: the content safety net must have run at least once
aeq "rc" 0 "$RC"
aeq "grandfathered.json records the cutover stamps" "[\"$S1\", \"$S2\"]" \
    "$(/usr/bin/python3 "$RUN/q.py" "$SNAP_STATE_DIR/grandfathered.json" 'sorted(d)')"
aeq "s3 used the grandfathered stamp as base" "$S2" "$(Q 'd["last_copy"]["link_dest"]')"
anot "grandfathered base needed no re-verification" "re-verifying against primary" "$(LOGT)"
aeq "healthy" true "$(Q 'd["healthy"]')"
# a promoted stamp that is NOT grandfathered and has lost its manifest must be RE-VERIFIED
rm -f "$SNAP_STATE_DIR/manifests/$S3.json"
FIX snap "$ROOT" "$S3" "$S4"; FIX latest "$ROOT" "$S4"
ENG mirror
aeq "rc" 0 "$RC"
ahas "recovery rule fired" "recovery: promoted stamp $S3 has no manifest" "$(LOGT)"
ahas "manifest backfilled" "re-verified and manifest backfilled" "$(LOGT)"
aeq "manifest restored on disk" "yes" \
    "$([ -f "$SNAP_STATE_DIR/manifests/$S3.json" ] && echo yes || echo no)"
aeq "s4 used the re-verified stamp as base" "$S3" "$(Q 'd["last_copy"]["link_dest"]')"
# a manifest-less promoted stamp that FAILS re-verification must not serve as a base
rm -f "$SNAP_STATE_DIR/manifests/$S4.json"
echo "ROGUE FILE THE PRIMARY DOES NOT HAVE" > "$R/$S4/a/rogue.txt"
FIX snap "$ROOT" "$S4" "$S5"; FIX latest "$ROOT" "$S5"
ENG mirror
aeq "rc" 1 "$RC"
ahas "P4 on the unverifiable base" "does not match the primary" "$(Q 'd["problems"]')"
aeq "fell back to the older verified base" "$S3" "$(Q 'd["last_copy"]["link_dest"]')"
aeq "s5 still promoted correctly" "yes" "$([ -d "$R/$S5" ] && echo yes || echo no)"

########################################################################################
head_ "T25 primary WIPED down to one stamp -> P9 still fires (C8)"
newroot t25
build3
coldstart
aeq "replica holds all three" 3 "$(ls -1d "$R"/2* 2>/dev/null | wc -l | tr -d ' ')"
# the wipe: the primary loses two of its three stamps.  This is EXACTLY the state that used to
# silence P9, because the alarm lived behind prune()'s "primary has >=3 stamps" precondition.
rm -rf "$P/$S1" "$P/$S2"
FIX latest "$ROOT" "$S3"
ENG mirror
aeq "rc" 1 "$RC"
aeq "primary is down to ONE stamp" "[\"$S3\"]" "$(Q 'd["primary_snapshots"]')"
aeq "two P9 alarms, one per orphaned replica stamp" 2 \
    "$(Q 'len([x for x in d["problems"] if x.startswith("P9")])')"
ahas "P9 names the first orphan" "P9 replica-only stamp $S1" "$(Q 'd["problems"]')"
ahas "P9 names the second orphan" "P9 replica-only stamp $S2" "$(Q 'd["problems"]')"
aeq "healthy false" false "$(Q 'd["healthy"]')"
aeq "NOTHING was pruned - the replica still holds all three" 3 \
    "$(ls -1d "$R"/2* 2>/dev/null | wc -l | tr -d ' ')"
aeq "no pruned events" "" "$(EV pruned)"

########################################################################################
head_ "T26 pre-existing corpse + seen.json lost -> still caught (C9 bootstrap guard)"
newroot t26
build3
coldstart
# a MacBook run dies mid-write, leaving a truncated stamp above `latest`
FIX partial "$ROOT" "$S3" "$S6"
# ...and the engine's corpse memory is destroyed (disk repair, restore-from-backup, human rm)
rm -f "$SNAP_STATE_DIR/seen.json"
aeq "seen.json really is gone" "no" \
    "$([ -f "$SNAP_STATE_DIR/seen.json" ] && echo yes || echo no)"
ENG mirror
aeq "rc" 0 "$RC"
ahas "bootstrap reconciliation ran and named the stamp" \
     "bootstrapping corpse tracking (C9)" "$(LOGT)"
ahas "the pre-existing stamp above latest was recorded" "$S6" "$(LOGT)"
aeq "recorded in above_latest despite the wipe" "true" \
    "$(/usr/bin/python3 "$RUN/q.py" "$SNAP_STATE_DIR/seen.json" "\"$S6\" in d[\"above_latest\"]")"
aeq "corpse not copied" "no" "$([ -d "$R/$S6" ] && echo yes || echo no)"
# latest now advances past it - the moment the first-observation exception would have grandfathered it
FIX snap "$ROOT" "$S3" "$S7"
FIX latest "$ROOT" "$S7"
ENG mirror
aeq "rc" 1 "$RC"
aeq "corpse STILL not copied after latest advanced" "no" "$([ -d "$R/$S6" ] && echo yes || echo no)"
ahas "P12 fires" "P12 CORPSE on primary: $S6" "$(Q 'd["problems"]')"
aeq "the legitimate stamp copied normally" "yes" "$([ -d "$R/$S7" ] && echo yes || echo no)"

########################################################################################
head_ "T27 deep-verify content-checks a stamp whose primary copy is GONE (C12)"
newroot t27
FIX seed "$ROOT" "$S1"
FIX snap "$ROOT" "$S1" "$S2"
FIX latest "$ROOT" "$S2"          # 2 promoted stamps => the rotating older target IS S1
coldstart
aeq "manifest stores content samples" "true" \
    "$(/usr/bin/python3 "$RUN/q.py" "$SNAP_STATE_DIR/manifests/$S1.json" 'len(d["samples"]) > 0')"
SAMPLED=$(/usr/bin/python3 "$RUN/q.py" "$SNAP_STATE_DIR/manifests/$S1.json" 'len(d["samples"])')
rm -rf "$P/$S1"                   # the MacBook's 90-day retention removes the primary copy
SNAP_VERIFY_SAMPLE=all ENG deep-verify
aeq "deep-verify passes on the pruned-primary stamp" pass "$(Q 'd["last_deep_verify"]["result"]')"
ahas "it used the stored samples" "sampled" "$(Q 'd["last_deep_verify"]["detail"]')"
# same size, same mtime, different bytes: invisible to count/bytes/listing_md5, and there is no
# primary copy left to compare against.  Only the stored sample can catch this.
ORIG_SIZE=$(stat -f %z "$R/$S1/b/f08.txt")
rm -f "$R/$S1/b/f08.txt"
/usr/bin/python3 -c 'import sys;open(sys.argv[1],"wb").write(b"Z"*int(sys.argv[2]))' \
    "$R/$S1/b/f08.txt" "$ORIG_SIZE"
touch -r "$R/$S2/b/f08.txt" "$R/$S1/b/f08.txt"
aeq "corruption preserved the size (invisible to the listing check)" "$ORIG_SIZE" \
    "$(stat -f %z "$R/$S1/b/f08.txt")"
aeq "sample set was non-empty" "true" "$([ "$SAMPLED" -gt 0 ] && echo true || echo false)"
SNAP_VERIFY_SAMPLE=all ENG deep-verify
aeq "deep-verify result" fail "$(Q 'd["last_deep_verify"]["result"]')"
anot "NOT caught by the listing compare - it could not see this" "listing mismatch" \
     "$(Q 'd["last_deep_verify"]["detail"]')"
ahas "caught via the stored manifest sample" "vs stored manifest sample" \
     "$(Q 'd["last_deep_verify"]["detail"]')"
ahas "the corrupt file is named" "b/f08.txt" "$(Q 'd["last_deep_verify"]["detail"]')"
ahas "P5 raised" "P5 last deep-verify FAILED" "$(Q 'd["problems"]')"
# a pre-C12 manifest (no samples key) must still load, and be reported as listing-only
/usr/bin/python3 - "$SNAP_STATE_DIR/manifests/$S1.json" <<'OLDPY'
import json, sys
d = json.load(open(sys.argv[1])); d.pop("samples", None)
json.dump(d, open(sys.argv[1], "w"))
OLDPY
rm -f "$R/$S1/b/f08.txt"; cp "$R/$S2/b/f08.txt" "$R/$S1/b/f08.txt"
touch -r "$R/$S2/b/f08.txt" "$R/$S1/b/f08.txt"
SNAP_VERIFY_SAMPLE=all ENG deep-verify
aeq "pre-C12 manifest still loads" pass "$(Q 'd["last_deep_verify"]["result"]')"
ahas "and is honestly reported as listing-only" "LISTING ONLY" \
     "$(Q 'd["last_deep_verify"]["detail"]')"

########################################################################################
head_ "T28 G1: a real source file colliding with the relink temp name must never vanish"
newroot t28
build3
coldstart
FIX snap "$ROOT" "$S3" "$S4"
FIX newpair "$ROOT" "$S4"          # a/newpair1 + b/newpair2 share one inode, NEW in this snapshot
# A REAL source file whose name collides with the engine's internal relink temp suffix, on the
# NON-FIRST member of the group - the exact path the reconstruction builds its temp name from.
COLLIDE="b/newpair2.mbpa-relink-tmp"
printf 'REAL SOURCE FILE, NOT A TEMP\n' > "$P/$S4/$COLLIDE"
touch -t 202608190400 "$P/$S4/$COLLIDE"
FIX latest "$ROOT" "$S4"
PRIMARY_ENTRIES=$(find "$P/$S4" \! -type d | wc -l | tr -d ' ')
ENG mirror
PROMOTED=$([ -d "$R/$S4" ] && echo yes || echo no)
# THE INVARIANT: promote-with-the-file, or fail loudly.  Never promote a tree missing it.
aeq "no silent loss (promoted => the colliding file is present)" "ok" \
    "$([ "$PROMOTED" = "no" ] && echo ok || { [ -f "$R/$S4/$COLLIDE" ] && echo ok || echo "SILENTLY LOST"; })"
aeq "stamp promoted" "yes" "$PROMOTED"
aeq "colliding file preserved verbatim" "REAL SOURCE FILE, NOT A TEMP" "$(cat "$R/$S4/$COLLIDE" 2>/dev/null)"
aeq "manifest does not overstate completeness" "$PRIMARY_ENTRIES" \
    "$(/usr/bin/python3 "$RUN/q.py" "$SNAP_STATE_DIR/manifests/$S4.json" 'd["files"]' 2>/dev/null)"
aeq "replica entry count matches the primary" "$PRIMARY_ENTRIES" \
    "$(find "$R/$S4" \! -type d | wc -l | tr -d ' ')"
aeq "the hardlink group was still reconstructed" "$(ino "$R/$S4/a/newpair1")" "$(ino "$R/$S4/b/newpair2")"
ane "the collider is NOT part of that group" "$(ino "$R/$S4/a/newpair1")" "$(ino "$R/$S4/$COLLIDE")"
aeq "rc" 0 "$RC"
aeq "healthy" true "$(Q 'd["healthy"]')"

########################################################################################
head_ "T30 P13: an absent deep-verify safety net is a problem, not a neutral state (FG7)"
newroot t30
build3
ENG mirror
aeq "rc" 1 "$RC"
ahas "P13 fires when deep-verify has never run" "P13 deep-verify has NEVER completed" "$(Q 'd["problems"]')"
aeq "healthy false" false "$(Q 'd["healthy"]')"
aeq "last_deep_verify is still null" "null" "$(Q 'd["last_deep_verify"]')"
ENG deep-verify
aeq "rc after the first deep-verify" 0 "$RC"
anot "P13 cleared" "P13" "$(Q 'd["problems"]')"
aeq "healthy" true "$(Q 'd["healthy"]')"
# age the recorded success past the 8-day boundary
/usr/bin/python3 - "$SNAP_STATE_DIR/persist.json" <<'AGEPY'
import json, sys, datetime
p = sys.argv[1]; d = json.load(open(p))
d["last_deep_verify_ok_ts"] = (datetime.datetime.now() - datetime.timedelta(days=9)).strftime(
    "%Y-%m-%dT%H:%M:%S-0400")
json.dump(d, open(p, "w"))
AGEPY
ENG mirror
aeq "rc with a 9-day-old success" 1 "$RC"
ahas "P13 fires again on age" "P13 last successful deep-verify was" "$(Q 'd["problems"]')"
ENG deep-verify
aeq "a fresh deep-verify clears it" 0 "$RC"
# a FAILED deep-verify must not count as a success
OK_TS_BEFORE=$(/usr/bin/python3 "$RUN/q.py" "$SNAP_STATE_DIR/persist.json" 'd["last_deep_verify_ok_ts"]')
rm -f "$R/$S3/b/f08.txt"
printf 'CORRUPT-SAME-LENGTH-XXXXXXXX' > "$R/$S3/b/f08.txt"
SNAP_VERIFY_SAMPLE=all ENG deep-verify
aeq "failed deep-verify rc" 1 "$RC"
ahas "P5 raised" "P5 last deep-verify FAILED" "$(Q 'd["problems"]')"
aeq "the recorded SUCCESS timestamp was not advanced by a failure" "$OK_TS_BEFORE" \
    "$(/usr/bin/python3 "$RUN/q.py" "$SNAP_STATE_DIR/persist.json" 'd["last_deep_verify_ok_ts"]')"

########################################################################################
head_ "T31 P14 + FG6: a foreign lock holder can no longer pin the monitor at amber"
newroot t31
build3
coldstart
holdlock 8 pid
ENG mirror
aeq "rc" 2 "$RC"
aeq "mirror_running true" true "$(Q 'd["mirror_running"]')"
anot "P14 not yet: the copy has only just started" "P14" "$(Q 'd["problems"]')"
# backdate the busy marker past SUPPRESS_CAP (6 h)
/usr/bin/python3 - "$SNAP_STATE_DIR/persist.json" <<'BUSYPY'
import json, sys, datetime
p = sys.argv[1]; d = json.load(open(p))
d["busy_since"] = (datetime.datetime.now() - datetime.timedelta(hours=7)).strftime(
    "%Y-%m-%dT%H:%M:%S-0400")
json.dump(d, open(p, "w"))
BUSYPY
ENG mirror
aeq "still skipped" 2 "$RC"
ahas "P14 fires on the LOCK-HELD path (it cannot be starved)" \
     "P14 a copy has claimed to be running" "$(Q 'd["problems"]')"
aeq "healthy false -> the monitor can now reach FAIL" false "$(Q 'd["healthy"]')"
aeq "mirror_running_seconds exceeds the 6 h cap" "true" \
    "$(Q 'd["mirror_running_seconds"] > 21600')"
# mount rules are computed on the lock-held path too
SNAP_PRIMARY="$ROOT/gone" ENG mirror
aeq "still skipped" 2 "$RC"
ahas "P1 computed while the lock is held" "P1 primary volume not mounted" "$(Q 'd["problems"]')"
kill "$HL_PID" 2>/dev/null; wait "$HL_PID" 2>/dev/null
ENG mirror
aeq "rc once the holder exits" 0 "$RC"
anot "P14 cleared" "P14" "$(Q 'd["problems"]')"
aeq "mirror_running_seconds back to 0" 0 "$(Q 'd["mirror_running_seconds"]')"

########################################################################################
head_ "T32 FG2: seen.json loss is judged against corroborating state, and states its limit"
newroot t32
build3
coldstart
# --- partial loss: seen.json gone, but detected.json / manifests / persist.json survive
FIX partial "$ROOT" "$S3" "$S6"         # a corpse, created ABOVE latest
ENG mirror                              # observed once: recorded in detected.json
FIX snap "$ROOT" "$S3" "$S7"
FIX latest "$ROOT" "$S7"                # latest now advances PAST the corpse
rm -f "$SNAP_STATE_DIR/seen.json"       # the corpse memory is destroyed
ENG mirror
aeq "rc" 1 "$RC"
ahas "state loss detected, not mistaken for a first run" "seen.json was LOST, not absent" "$(LOGT)"
ahas "reconstructed from detected.json" "Reconstructed 1 suspicious stamp" "$(LOGT)"
ahas "note warns the operator" "was lost and rebuilt from" "$(Q 'd["notes"]')"
aeq "corpse NOT copied even though latest has passed it" "no" "$([ -d "$R/$S6" ] && echo yes || echo no)"
ahas "P12 still fires" "P12 CORPSE on primary: $S6" "$(Q 'd["problems"]')"
aeq "the legitimate stamp still copied" "yes" "$([ -d "$R/$S7" ] && echo yes || echo no)"
# --- total loss: the honest limit, stated rather than papered over
newroot t32b
build3
FIX partial "$ROOT" "$S3" "$S6"
FIX snap "$ROOT" "$S3" "$S7"
FIX latest "$ROOT" "$S7"                # corpse already below latest, engine has NEVER run
ENG mirror
ahas "bootstrap-from-nothing is announced, not hidden" \
     "corpse tracking is bootstrapping from NOTHING" "$(Q 'd["notes"]')"
ahas "and the limit is REAL: with no prior observation the corpse is treated as settled" \
     "copy_started:$S6" "$(EV copy_started)"
ahas "it appeared as a normal pending stamp" "$S6" "$(EV detected)"

########################################################################################
head_ "T33 P15: a replica that is falling behind is a PROBLEM, not a note"
newroot t33
build3
coldstart
# A stamp the engine can never copy: a NEW file rsync must actually READ, made unreadable.
# (chmod 000 on an UNCHANGED file proves nothing - --link-dest hardlinks it without reading.)
FIX snap "$ROOT" "$S3" "$S4"
printf 'SECRET\n' > "$P/$S4/b/unreadable.txt"
chmod 000 "$P/$S4/b/unreadable.txt"
FIX latest "$ROOT" "$S4"
ENG mirror
aeq "rc" 1 "$RC"
ahas "P4 names the failing stamp" "P4 snapshot $S4 failed to copy" "$(Q 'd["problems"]')"
aeq "s4 is settled and pending" "[\"$S4\"]" "$(Q 'd["pending"]')"
aeq "pending-since recorded for s4" "true" \
    "$(/usr/bin/python3 "$RUN/q.py" "$SNAP_STATE_DIR/pending.json" "\"$S4\" in d")"
anot "P15 does NOT fire while pending is young" "P15" "$(Q 'd["problems"]')"
ahas "short-lived pending stays a NOTE" "pending copy" "$(Q 'd["notes"]')"
# A newer, GOOD stamp arrives.  Under `continue` it copies straight past the bad one - which is
# exactly the supersede sequence 00 F5 P15 warns about, now reachable end-to-end rather than
# constructed: last_copy becomes a SUCCESS while stamp A is still missing from the replica.
FIX snap "$ROOT" "$S4" "$S5"
rm -f "$P/$S5/b/unreadable.txt"        # the offending file was gone by the next backup
FIX latest "$ROOT" "$S5"
ENG mirror
aeq "the good stamp copied past the bad one" "yes" "$([ -d "$R/$S5" ] && echo yes || echo no)"
aeq "only the bad stamp remains pending" "[\"$S4\"]" "$(Q 'd["pending"]')"
aeq "last_copy is now a SUCCESS (the supersede condition)" 0 "$(Q 'd["last_copy"]["rc"]')"
aeq "...for the later stamp" "$S5" "$(Q 'd["last_copy"]["snapshot"]')"
ahas "P4 is NOT buried by it - the ledger is per-stamp" "P4 snapshot $S4 failed to copy" \
     "$(Q 'd["problems"]')"
anot "still no P15 while young" "P15" "$(Q 'd["problems"]')"
# --- age the pending records past the 6 h threshold
/usr/bin/python3 - "$SNAP_STATE_DIR/pending.json" <<'AGEPY'
import json, sys, datetime
p = sys.argv[1]; d = json.load(open(p))
now = datetime.datetime.now()
for i, k in enumerate(sorted(d)):          # oldest stamp = longest pending, as in reality
    d[k] = (now - datetime.timedelta(hours=8 - i)).strftime("%Y-%m-%dT%H:%M:%S-0400")
json.dump(d, open(p, "w"))
AGEPY
ENG mirror
aeq "rc" 1 "$RC"
ahas "P15 fires on the oldest pending stamp" "P15 snapshot $S4 has been settled and awaiting copy" \
     "$(Q 'd["problems"]')"
ahas "P15 says what it means" "the replica is BEHIND and is not catching up" "$(Q 'd["problems"]')"
aeq "healthy false" false "$(Q 'd["healthy"]')"
ahas "P4 and P15 both name the stuck stamp" "P4 snapshot $S4" "$(Q 'd["problems"]')"
# --- P15 survives a lock-held pass too (it is computed on that path, so it cannot be starved)
holdlock 5 pid
ENG mirror
aeq "pass skipped (lock held)" 2 "$RC"
ahas "P15 STILL fires on the lock-held path" "P15 snapshot $S4" "$(Q 'd["problems"]')"
aeq "healthy false -> monitor reaches FAIL" false "$(Q 'd["healthy"]')"
kill "$HL_PID" 2>/dev/null; wait "$HL_PID" 2>/dev/null
# --- records are cleared once the stamps are finally copied
chmod 644 "$P/$S4/b/unreadable.txt"
ENG mirror
aeq "rc after the blockage is cleared" 0 "$RC"
aeq "the gap is filled in" 5 "$(ls -1d "$R"/2* | wc -l | tr -d ' ')"
aeq "the previously-skipped stamp is now promoted" "yes" "$([ -d "$R/$S4" ] && echo yes || echo no)"
aeq "pending drained" "[]" "$(Q 'd["pending"]')"
aeq "pending-since records cleared, none leaked" "{}" \
    "$(/usr/bin/python3 "$RUN/q.py" "$SNAP_STATE_DIR/pending.json" 'd')"
anot "P15 gone" "P15" "$(Q 'd["problems"]')"
aeq "healthy" true "$(Q 'd["healthy"]')"
# --- a CORPSE never leaks a pending record (it is unsettled, so it is never pending)
FIX partial "$ROOT" "$S5" "$S6"
ENG mirror                                     # observed ABOVE latest: unsettled, not pending
aeq "corpse above latest is not pending" "false" \
    "$(/usr/bin/python3 "$RUN/q.py" "$SNAP_STATE_DIR/pending.json" "\"$S6\" in d")"
FIX snap "$ROOT" "$S5" "$S7"
FIX latest "$ROOT" "$S7"                       # latest advances PAST the corpse
ENG mirror
ahas "P12 confirms it is a corpse" "P12 CORPSE on primary: $S6" "$(Q 'd["problems"]')"
aeq "corpse still never tracked as pending" "false" \
    "$(/usr/bin/python3 "$RUN/q.py" "$SNAP_STATE_DIR/pending.json" "\"$S6\" in d")"
aeq "no pending record leaked for any stamp" "{}" \
    "$(/usr/bin/python3 "$RUN/q.py" "$SNAP_STATE_DIR/pending.json" 'd')"
aeq "the legitimate stamp was copied" "yes" "$([ -d "$R/$S7" ] && echo yes || echo no)"

########################################################################################
head_ "T34 one bad snapshot costs ONE snapshot, not every later one (continue, not break)"
newroot t34
build3
coldstart
# A = permanently uncopyable; B and C are good and NEWER
FIX snap "$ROOT" "$S3" "$S4"
printf 'SECRET\n' > "$P/$S4/b/unreadable.txt"
chmod 000 "$P/$S4/b/unreadable.txt"
FIX snap "$ROOT" "$S4" "$S5"
rm -f "$P/$S5/b/unreadable.txt"        # gone by the next backup, so B and C are genuinely good
FIX snap "$ROOT" "$S5" "$S6"
FIX latest "$ROOT" "$S6"
ENG mirror
aeq "rc" 1 "$RC"
# --- the replica is NOT frozen
aeq "B was copied"  "yes" "$([ -d "$R/$S5" ] && echo yes || echo no)"
aeq "C was copied"  "yes" "$([ -d "$R/$S6" ] && echo yes || echo no)"
aeq "A was NOT copied" "no" "$([ -d "$R/$S4" ] && echo yes || echo no)"
aeq "replica advanced past the bad stamp" 5 "$(ls -1d "$R"/2* | wc -l | tr -d ' ')"
aeq "replica latest tracks the primary" "$S6" "$(Q 'd["latest_replica"]')"
aeq "only A remains pending" "[\"$S4\"]" "$(Q 'd["pending"]')"
# --- the skipped stamp stays LOUD
ahas "P4 names A" "P4 snapshot $S4 failed to copy and is still missing" "$(Q 'd["problems"]')"
aeq "healthy false" false "$(Q 'd["healthy"]')"
aeq "copy_failed event for A" "copy_failed:$S4" "$(EV copy_failed | tail -1)"
aeq "A is recorded in the per-stamp failure ledger" "true" \
    "$(/usr/bin/python3 "$RUN/q.py" "$SNAP_STATE_DIR/persist.json" "\"$S4\" in d[\"failed_copies\"]")"
aeq "a later SUCCESS did not bury the earlier failure" "$S6" "$(Q 'd["last_copy"]["snapshot"]')"
aeq "...and last_copy shows that success" 0 "$(Q 'd["last_copy"]["rc"]')"
# --- A never becomes a --link-dest base
anot "A is not a promoted stamp" "$S4" "$(Q 'd["replica_snapshots"]')"
aeq "B linked against the last GOOD promoted stamp, not A" "$S3" \
    "$(grep -o "copy $S5: rsync -a --link-dest=.*/$S3 " "$SNAP_LOG" >/dev/null && echo "$S3" || echo MISSING)"
aeq "C linked against B" "$S5" \
    "$(grep -o "copy $S6: rsync -a --link-dest=.*/$S5 " "$SNAP_LOG" >/dev/null && echo "$S5" || echo MISSING)"
aeq "dedup survived the gap (unchanged file shared with s3)" "$(ino "$R/$S3/b/f08.txt")" \
    "$(ino "$R/$S6/b/f08.txt")"
# --- P15 still fires for the stuck stamp
/usr/bin/python3 - "$SNAP_STATE_DIR/pending.json" <<'AGEPY'
import json, sys, datetime
p = sys.argv[1]; d = json.load(open(p))
old = (datetime.datetime.now() - datetime.timedelta(hours=7)).strftime("%Y-%m-%dT%H:%M:%S-0400")
for k in d: d[k] = old
json.dump(d, open(p, "w"))
AGEPY
ENG mirror
ahas "P15 fires for the stuck stamp" "P15 snapshot $S4 has been settled and awaiting copy" \
     "$(Q 'd["problems"]')"
ahas "P4 still on it too" "P4 snapshot $S4" "$(Q 'd["problems"]')"
anot "NOT the systemic escalation - only one stamp is failing" "SYSTEMIC" "$(Q 'd["problems"]')"
# --- and it self-heals when the blockage clears
chmod 644 "$P/$S4/b/unreadable.txt"
ENG mirror
aeq "rc" 0 "$RC"
aeq "A finally copied" "yes" "$([ -d "$R/$S4" ] && echo yes || echo no)"
aeq "ledger cleared" "{}" \
    "$(/usr/bin/python3 "$RUN/q.py" "$SNAP_STATE_DIR/persist.json" 'd["failed_copies"]')"
aeq "pending drained" "[]" "$(Q 'd["pending"]')"
aeq "healthy" true "$(Q 'd["healthy"]')"
aeq "all six promoted" 6 "$(ls -1d "$R"/2* | wc -l | tr -d ' ')"

########################################################################################
head_ "T35 EVERY pending stamp failing is a volume-level fault, and says so"
newroot t35
build3
coldstart
FIX snap "$ROOT" "$S3" "$S4"; printf 'x\n' > "$P/$S4/b/no1.txt"; chmod 000 "$P/$S4/b/no1.txt"
FIX snap "$ROOT" "$S4" "$S5"; printf 'y\n' > "$P/$S5/b/no2.txt"; chmod 000 "$P/$S5/b/no2.txt"
FIX latest "$ROOT" "$S5"
ENG mirror
aeq "rc" 1 "$RC"
aeq "nothing was promoted" 3 "$(ls -1d "$R"/2* | wc -l | tr -d ' ')"
ahas "SYSTEMIC escalation fires" "P4 SYSTEMIC: ALL 2 pending snapshots failed to copy" \
     "$(Q 'd["problems"]')"
ahas "it says what to look at" "volume-level fault, not one bad snapshot" "$(Q 'd["problems"]')"
ahas "both stamps are also named individually" "2 snapshots have failed to copy" "$(Q 'd["problems"]')"
aeq "healthy false" false "$(Q 'd["healthy"]')"
# one recovering is no longer systemic
chmod 644 "$P/$S4/b/no1.txt"
ENG mirror
aeq "rc" 1 "$RC"
aeq "the recovered stamp promoted" "yes" "$([ -d "$R/$S4" ] && echo yes || echo no)"
anot "no longer systemic" "SYSTEMIC" "$(Q 'd["problems"]')"
ahas "still P4 on the remaining one" "P4 snapshot $S5 failed to copy" "$(Q 'd["problems"]')"
chmod 644 "$P/$S5/b/no2.txt"
ENG mirror
aeq "full recovery" 0 "$RC"
aeq "healthy" true "$(Q 'd["healthy"]')"

########################################################################################
head_ "T19 P8 free-space floor fires"
newroot t19
build3
SNAP_MIN_FREE_GB=99999999 ENG mirror
aeq "rc" 1 "$RC"
ahas "P8 raised" "P8 primary volume has only" "$(Q 'd["problems"]')"

########################################################################################
head_ "T20 no writes outside the sandbox"
aeq "the INSTALLED engine.py / mirror.sh are byte-identical (never touched)" \
    "$INSTALLED_BEFORE" "$(installed_fingerprint)"
OUTSIDE=$(find "$HOME/Library/SnapshotMonitor" "$HOME/.ssh" "$HOME/Library/LaunchAgents" \
               -newer "$MARKER" 2>/dev/null | head -5)
aeq "nothing written under ~/.ssh or ~/Library/LaunchAgents" "" "$OUTSIDE"
# the live engine may write its own state; nothing ELSE may appear there
STRAY=$(find "$INSTALLED_DIR" -newer "$MARKER" 2>/dev/null \
        | sed "s|^$INSTALLED_DIR/*||" | grep -vE "^($LIVE_STATE)(/|$)" | grep -v '^$' | head -5)
aeq "no stray files in the live state dir (only the engine's own state)" "" "$STRAY"
aeq "DAS volumes unchanged (df + snapshot dir stat)" "$DAS_BEFORE" "$(das_fingerprint)"
if [ "${SNAP_SELFTEST_DEEP_SAFETY:-0}" = "1" ]; then
    VOLS=$(find /Volumes/SnapArchive /Volumes/SnapMirror -newer "$MARKER" 2>/dev/null | head -5)
    aeq "full find: nothing newer than the marker on either DAS volume" "" "$VOLS"
else
    printf '  note  full DAS find skipped (set SNAP_SELFTEST_DEEP_SAFETY=1; takes many minutes over USB)\n'
fi
# NOTE: monitor/ and specs/ are owned by other subtasks that are running concurrently, so a
# whole-project check false-fails on their edits.  Scoped to the paths THIS subtask must never
# write: the shared fixtures/labs, the plan, and the recon/baseline material.
PROJ=$(find "$ENGDIR/../tests" "$ENGDIR/../baseline-20260819" "$ENGDIR/../PLAN.md" \
            "$ENGDIR/../CONTEXT.md" "$ENGDIR/../FINDINGS-openrsync.md" \
            -newer "$MARKER" 2>/dev/null | head -5)
aeq "no off-limits project files modified by the run" "" "$PROJ"

########################################################################################
printf '\n========================================\n'
printf 'engine selftest: %d assertions, %d failed\n' "$TOTAL" "$FAILED"
if [ "$FAILED" -eq 0 ]; then
    printf 'RESULT: PASS\n'
    exit 0
fi
printf 'RESULT: FAIL\n'
exit 1
