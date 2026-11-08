#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
SnapArchive replica engine  (subtask 02)

Implements specs/00-frozen-interfaces.md F3-F9 for /usr/bin/python3 3.9.6, stdlib only.

Design rules that are NOT negotiable (each is here because it was empirically proven, see
tests/01-RESULTS.md and FINDINGS-openrsync.md):

  * rc==0 from /usr/bin/rsync is the ONLY rc that may be read as "rsync worked", and even then the
    engine verifies the result itself.  openrsync has NO rc=24: "file vanished during transfer"
    (benign) and TCC "Operation not permitted" (catastrophic - the job read nothing) BOTH return
    rc 23.  Nothing but stderr distinguishes them and stderr is for humans, not control flow.
  * Staging is WIPED (rm -rf) and re-created immediately before EVERY rsync attempt.  Never rsync
    into a staging dir you did not just create: a SIGKILL leaves an orphan `.<name>.<10 alnum>`
    temp behind, which fails verification forever and can never be transferred away because the
    engine (correctly) never passes --delete*.  (01 D2)
  * -H is shipped.  Without it an intra-snapshot hardlink pair that is NEW in this snapshot is
    split into two inodes on the replica and the split then propagates forward through every later
    --link-dest.  Cost measured at 150k files: +8 MB RSS, no wall-time change.  (01 D1)
  * --link-dest is spelled ABSOLUTE, exactly once, so two code paths cannot drift.  (00 F8.3 / 01 C5)
  * --inplace / --delete* / --remove-source-files / --force are asserted absent from every argv.
    An in-place write through a shared inode rewrites that file in EVERY snapshot.  (FINDINGS F3)
  * The primary's own hardlink structure is ground truth for "did this file change".  rsync's quick
    check is size+mtime, so a content change that preserves both is silently hardlinked to STALE
    bytes.  The changed-set inode audit (F8.5b) closes that window.  (FINDINGS F2 / 01 E1b)
"""

import datetime
import errno
import fcntl
import hashlib
import json
import math
import os
import random
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

# --------------------------------------------------------------------------- frozen constants

SCHEMA = 1
SNAPDIR = "snapshots"
STAGING_DIRNAME = ".incoming"
LATEST = "latest"

STAMP_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{6}$")
# Unanchored twin of STAMP_RE, for pulling every stamp a problem string mentions (mute matching).
STAMP_FIND_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{6}")
STAMP_FMT = "%Y-%m-%d_%H%M%S"

RSYNC = "/usr/bin/rsync"

# 00 F8.5 / 01 C2: ONE shared constant.  Used by the rsync invocation, the step-5 verify walk,
# the step-5b inode audit walks and the F9 deep-verify walk.  A bare name matches AT ANY DEPTH
# (01 E8), so the walk filter tests every path component, not just the tree root.
# ONE shared constant: used by the rsync argv, the verify walk, the inode audit AND
# deep-verify. If these ever diverge, a path rsync was told to skip still gets counted by
# verification and the snapshot fails forever (00 F8 C2).
#
# .DS_Store added 2026-08-21 after a REAL production false alarm. Finder writes .DS_Store
# into any directory it browses, including snapshot dirs on the mounted DAS. Snapshots are
# immutable once promoted, so the mirror's copy never gains them -- the primary drifts and
# deep-verify reports "listing mismatch: files 166994/166955", healthy=false, monitor RED,
# on an archive with ZERO missing data (all 39 differing paths were .DS_Store; nothing was
# absent from the mirror). The writer already excludes .DS_Store, so these never originate
# from the backup source and excluding them here loses nothing real. A monitor that goes
# red because someone opened a Finder window is a monitor people learn to ignore.
#
# 2026-08-25: that same false alarm reappeared via a THIRD path -- self.incoming, the
# .incoming/ staging-dir listing that drives P10 (stuck staging). A Finder browse of
# .incoming (to clean up a real stale entry) left a .DS_Store there, which does not match
# any pending stamp and is never cleared by wipe_staging(), so it aged into its own P10 six
# hours later. EXCLUDES was already applied to the rsync argv and both verify walks but not
# to this listing -- see excluded() at both `self.incoming = ...` assignments.
EXCLUDES = (".Spotlight-V100", ".Trashes", ".fseventsd", ".TemporaryItems", ".DS_Store")

# 00 F8.3 / 02 hard constraints.  Prefix match: "--del" also catches --delete-before/--delete-excluded
# /--del, "--force" also catches --force-delete.
FORBIDDEN_FLAG_PREFIXES = ("--inplace", "--del", "--remove-source-files", "--force")

VERIFY_SWEEP_DAYS = 90        # every promoted snapshot must be content-verified at least once
                              # within this many days -- keep it <= the writer's retention, or
                              # snapshots age out unverified.  See deep_verify().
VERIFY_MAX_OLDER_PER_PASS = 8 # cost ceiling: each older target is a full two-sided walk plus
                              # sampled hashing (~2-3 min on a 146k-file snapshot over USB).
PRUNE_AGE_DAYS = 100          # 00 F8: 90-day writer retention + 10 days of margin.  Do not lower.
MAX_PRUNES_PER_PASS = 2       # 00 F8: a mass rm -rf is never one bug away.
MIN_FREE_GB_DEFAULT = 50      # 00 F5 P8 / HANDOFF 4.8
# P6/P7 (whole-volume used-KB / inode delta) were DELETED 2026-08-26 (PLAN A4, owner R4+R5):
# the drives are declared mixed-use, so a whole-volume statvfs comparison is structurally
# meaningless in BOTH directions -- nothing may ever compare primary vs replica volume totals
# again. Replica correctness is proven per snapshot (copy verify, P9, P4, deep-verify) and the
# manifest-ledger tripwire (check_manifest_ledger) covers the one case only P6/P7 caught:
# deletion of a promoted replica-only snapshot outside the engine.
SUPERSEDE_HEALTH_FRACTION = 0.5   # M1: a promote supersedes older failures only if its verified
SUPERSEDE_HEALTH_MANIFESTS = 7    # file count is >= FRACTION * median(files of the last ~this
                                  # many manifests). A tiny/void promote must never quietly bury
                                  # a real failure (the 2026-08-25_180005 10-file pattern).
PATTERN_FAIL_WINDOW_DAYS = 7  # M1 escalation: N distinct failed stamps within this window ...
PATTERN_FAIL_MIN = 3          # ... where N >= this fires "P4 PATTERN" (counts superseded too)
MUTED_ROW_HIDE_HOURS = 72     # A2/M8: rows older than this ship with "hidden": true (UI drops
                              # them; suppression and endpoint validation use the FULL list)
LINE_MUTE_EXPIRY_HOURS = 72   # A2: a line mute expires COMPLETELY at 72 h -- the note returns
RETRY_HISTORY_WINDOW_SEC = 86400  # M8: retry_count counts consumes within the last 24 h
STALE_STAGING_HOURS = 6       # 00 F5 P10
# 2026-10-23 (the owner): copies now legitimately take ~6 h (656k files), and a monthly deep-verify
# runs inside a mirror pass right after a copy, so both 6 h caps were raised to 12 h. Previous
# values (21600) are in engine.py.pre-monthly-verify-20261023-224401.
SUPPRESS_CAP_SECONDS = 43200  # 00 F5 P14 / F10: 12 h. A copy/verify running longer than this is stuck.
PENDING_MAX_SECONDS = 43200   # 00 F5 P15: 12 h. A settled stamp still uncopied after this means the
                              # replica is FALLING BEHIND, which is a problem and never just a note.
# MONTHLY DEEP-VERIFY (2026-10-23, the owner: "run this once per month ... after the early morning
# backup and continue regular backups after it is finished"). The launchd verify windows were
# retired; instead a MIRROR pass that just promoted an early-morning stamp (hour in
# DEEP_VERIFY_EARLY_HOURS) runs deep_verify() itself, still holding the lock, once the last
# successful sweep is >= DEEP_VERIFY_MIN_INTERVAL_HOURS old. Copies queued meanwhile simply wait
# (passes bounce + heartbeat) and resume on the next pass. Was: 8 days / 20 h, 3 daily windows.
DEEP_VERIFY_MAX_AGE_DAYS = 35  # 00 F5 P13 -- a monthly sweep plus a few days of slack
DEEP_VERIFY_MIN_INTERVAL_HOURS = 28 * 24.0  # monthly guard; see deep_verify()
DEEP_VERIFY_EARLY_HOURS = (3, 4, 5, 6)  # stamp hours that count as "the early morning backup"
RATE_LIMIT_MAX_AGE_SEC = 86400  # 00 F5 P16: mirror.sh denial artifact self-clears after 24 h
ORPHAN_FAIL_HOURS = 48        # 00 F5 P11
ORPHAN_WARN_HOURS = 24        # 00 F5 notes
HANDSHAKE_STALE_SEC = 180     # on/off switch: 3x the handshake's own ~60s poll interval. Older
                              # than this and the watchdog itself may be down -- fail OPEN (assume
                              # reachable, run normally, note it) rather than silently pausing.
PRIMARY_STALE_DAYS = 2        # 00 F5 P3 (calendar days)
DEEP_SAMPLE_FILES = 200       # 00 F9
DEEP_SAMPLE_MAX_BYTES = 64 * 1024 * 1024
# C12 (authorised by the orchestrator 2026-08-19): the manifest also stores a bounded, deterministic
# per-file md5 sample of the VERIFIED tree, so a stamp whose primary copy has since been pruned can
# still be CONTENT-verified by deep-verify instead of listing-verified only.  Bounds keep the
# promote-time cost trivial: at most 200 files, no single file over 4 MB, 64 MB of reads total.
MANIFEST_SAMPLE_FILES = 200
MANIFEST_SAMPLE_MAX_FILE_BYTES = 4 * 1024 * 1024
MANIFEST_SAMPLE_MAX_TOTAL_BYTES = 64 * 1024 * 1024
EVENTS_TRIM_AT = 2000         # 00 F6
EVENTS_TRIM_TO = 1000
LOG_ROTATE_BYTES = 5 * 1024 * 1024   # 00 F7

STATUS_KEYS = (
    "schema", "ts", "pass_kind", "engine_pid", "primary_mounted", "replica_mounted",
    "primary_total_kb", "primary_used_kb", "primary_free_kb", "primary_iused",
    "replica_total_kb", "replica_used_kb", "replica_free_kb", "replica_iused",
    "primary_snapshots", "replica_snapshots", "latest_primary", "latest_replica",
    "pending", "unsettled", "incoming", "last_copy", "last_deep_verify",
    "mirror_running", "mirror_running_seconds", "healthy", "problems", "notes",
    "system_enabled", "enabled_source", "handshake_reachable", "handshake_last_change",
    "control_override", "incomplete_uploads", "dedup_failures", "force_settle_candidates",
    "muted", "muted_problems", "muted_lines",
)

# Problem codes a per-snapshot MUTE is allowed to silence.  Strictly per-stamp faults only:
# muting one snapshot must never be able to hide a VOLUME-level fault that merely happens to
# name that stamp in passing.  P1/P2/P3/P5/P8/P13/P14/P16, "P4 SYSTEMIC", "P4 PATTERN" and the
# manifest-ledger tripwire ("promoted snapshot ... is MISSING from the replica") are therefore
# absent by design and can never be muted by this mechanism.  "P4 SYSTEMIC" and "P4 PATTERN"
# share the mutable "P4" prefix, so problem_is_muted() excludes BOTH explicitly -- if you add
# another volume-class escalation under a mutable prefix, carve it out there too.
MUTABLE_CODES = ("P4", "P9", "P10", "P11", "P12", "P15")

DEFAULT_PRIMARY = "/Volumes/SnapArchive"
DEFAULT_REPLICA = "/Volumes/SnapMirror"
DEFAULT_STATE_DIR = os.path.expanduser("~/Library/AgentSnapshot")
DEFAULT_LOG = os.path.expanduser("~/Library/Logs/agent-snapshot.log")
DEFAULT_LEGACY_LOCK = os.path.expanduser("~/Library/Application Support/AgentSnapshot/mirror.pid")

ENV_PATH_KEYS = ("SNAP_PRIMARY", "SNAP_REPLICA", "SNAP_STATE_DIR", "SNAP_LOG")


class ConfigError(Exception):
    """Fatal before a status could be written -> exit 3."""


class CopyFailure(Exception):
    """A copy attempt was rejected.  rc is the value recorded in last_copy['rc']."""

    def __init__(self, rc, detail):
        Exception.__init__(self, detail)
        self.rc = rc
        self.detail = detail


# --------------------------------------------------------------------------- small helpers

def iso_now():
    """00 F4: `date +%Y-%m-%dT%H:%M:%S%z` format, local time."""
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def log_clock():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def parse_ts(ts):
    """Parse an F4 'date +%Y-%m-%dT%H:%M:%S%z'-style timestamp. Returns an aware datetime, or
    None if ts is missing/malformed. Same tolerant parser as monitor.py's parse_ts -- duplicated,
    not imported, matching the existing decoupling between the two components."""
    if not isinstance(ts, str) or not ts:
        return None
    try:
        return datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S%z")
    except ValueError:
        pass
    try:
        alt = ts.replace("Z", "+0000")
        if len(alt) >= 6 and alt[-3] == ":":
            alt = alt[:-3] + alt[-2:]
        return datetime.datetime.strptime(alt, "%Y-%m-%dT%H:%M:%S%z")
    except (ValueError, IndexError):
        return None


def stamp_dt(stamp):
    return datetime.datetime.strptime(stamp, STAMP_FMT)


def stamp_age_hours(stamp, now=None):
    now = now or datetime.datetime.now()
    return (now - stamp_dt(stamp)).total_seconds() / 3600.0


def stamp_age_days(stamp, now=None):
    return stamp_age_hours(stamp, now) / 24.0


def excluded(name):
    return name in EXCLUDES


def write_atomic(path, data, binary=False):
    """tmp + fsync + os.replace, in the destination directory."""
    d = os.path.dirname(path) or "."
    if not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        with os.fdopen(fd, "wb" if binary else "w") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_json(path, default=None):
    try:
        with open(path, "r") as fh:
            return json.load(fh)
    except (IOError, OSError, ValueError):
        return default


def read_json_strict(path, default):
    """(value, corrupt) -- like read_json but DISTINGUISHES absence from corruption (S11).

    `corrupt` is True only when the file EXISTS but cannot be read/parsed as JSON of the
    default's type. read_json's silent-default behaviour is right for bookkeeping files the
    engine itself rewrites every pass, and exactly wrong for operator-decision files
    (muted.json, retry-request.json): one truncated write there and every recorded decision
    silently ceases to exist. Callers must surface corrupt=True as a problem/note."""
    try:
        with open(path, "r") as fh:
            raw = fh.read()
    except (IOError, OSError):
        if os.path.exists(path):
            return default, True        # exists but unreadable: as loud as unparseable
        return default, False
    try:
        val = json.loads(raw)
    except ValueError:
        return default, True
    if not isinstance(val, type(default)):
        return default, True            # e.g. muted.json holding a list/null/string
    return val, False


def write_json(path, obj):
    write_atomic(path, json.dumps(obj, indent=1, sort_keys=True) + "\n")


def pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError as exc:
        return exc.errno == errno.EPERM


def rmtree(path):
    """rm -rf without a shell.  Proven safe against a --link-dest base (01 E12): unlinking a
    hardlink is not writing through it."""
    shutil.rmtree(path, ignore_errors=False)


# --------------------------------------------------------------------------- tree walking

def walk_tree(root):
    """Yield (relpath, kind, size, target, st) for everything under `root`.

    kind: 'd' dir, 'f' regular file, 'l' symlink, 'o' other.
    Symlinks are NEVER followed (os.walk misclassifies a symlink-to-directory as a directory,
    which is why this does not use os.walk).  EXCLUDES are dropped at any depth (01 E8).
    """
    stack = [("", root)]
    while stack:
        rel, path = stack.pop()
        with os.scandir(path) as it:
            entries = sorted(it, key=lambda e: e.name)
        for ent in entries:
            if excluded(ent.name):
                continue
            erel = ent.name if not rel else rel + "/" + ent.name
            st = ent.stat(follow_symlinks=False)
            m = st.st_mode
            if stat.S_ISLNK(m):
                yield (erel, "l", 0, os.readlink(ent.path), st)
            elif stat.S_ISDIR(m):
                yield (erel, "d", 0, None, st)
                stack.append((erel, ent.path))
            elif stat.S_ISREG(m):
                yield (erel, "f", st.st_size, None, st)
            else:
                yield (erel, "o", 0, None, st)


def listing_line(rel, kind, size, target, st):
    """00 F8.5 listing element.  Regular files contribute `relpath\\tsize`; symlinks contribute
    their target instead of a size (02: "symlinks compared by (relpath, readlink target)") and
    directories are included so that a missing EMPTY directory cannot slip past verification."""
    if kind == "f":
        return rel + "\t" + str(size)
    if kind == "l":
        return rel + "\t@" + target
    if kind == "d":
        return rel + "/\td"
    return rel + "\t?" + oct(stat.S_IFMT(st.st_mode))


def summarize_tree(root, want_inodes=False, dedup_base=None):
    """One walk -> everything F8.5 / F8.5b / F8.5c need.

    files   count of non-directory entries
    bytes   sum of regular-file sizes
    listing_md5  md5 over the sorted listing
    nlink_gt1    count of regular files with st_nlink > 1
    linked_to_base  True as soon as one regular file shares an inode with dedup_base/<same rel>
                    (short-circuits; this is the real proof that --link-dest did something)
    inodes  {relpath: st_ino} for regular files, when want_inodes
    paths   set of EVERY relpath in the tree (any kind), when want_inodes.  Used by the
            intra-group reconstruction to allocate a temp name that cannot collide with a real
            source file (G1).
    """
    lines = []
    nfiles = 0
    nbytes = 0
    nlink_gt1 = 0
    inodes = {} if want_inodes else None
    paths = set() if want_inodes else None
    # SAMPLE POOL (2026-08-26).  Collected here for FREE -- rel/kind/size are already in hand
    # on this walk.  promote() used to call sample_hashes(), which re-walked the whole staging
    # tree (~481k lstats, ~14 min on the USB DAS) purely to rebuild this list and then discard
    # all but 200 entries.  Handing the pool forward removes that entire walk.  It is also
    # STRICTLY more correct: this pool comes from the same walk that produced the verified
    # listing_md5, so there is no TOCTOU window between "verified" and "sampled".
    sample_pool = []
    linked = False
    for rel, kind, size, target, st in walk_tree(root):
        lines.append(listing_line(rel, kind, size, target, st))
        if want_inodes:
            paths.add(rel)
        if kind != "d":
            nfiles += 1
        if kind == "f":
            nbytes += size
            if size <= MANIFEST_SAMPLE_MAX_FILE_BYTES:
                sample_pool.append(rel)
            if want_inodes:
                inodes[rel] = st.st_ino
            if st.st_nlink > 1:
                nlink_gt1 += 1
                if dedup_base is not None and not linked:
                    try:
                        if os.stat(os.path.join(dedup_base, rel),
                                   follow_symlinks=False).st_ino == st.st_ino:
                            linked = True
                    except OSError:
                        pass
    lines.sort()
    h = hashlib.md5()
    for ln in lines:
        h.update(ln.encode("utf-8", "surrogateescape"))
        h.update(b"\n")
    return {
        "files": nfiles,
        "bytes": nbytes,
        "listing_md5": h.hexdigest(),
        "nlink_gt1": nlink_gt1,
        "linked_to_base": linked,
        "inodes": inodes,
        "paths": paths,
        "sample_pool": sample_pool,
    }


RELINK_TMP_SUFFIX = ".mbpa-relink-tmp"


def relink_tmp_path(staging, rel, source_paths):
    """Allocate a staging temp path for the intra-snapshot hardlink reconstruction whose relpath
    does NOT exist in the source snapshot (G1).

    The original spelling was `tmp = path + SUFFIX; if lexists(tmp): unlink(tmp)`.  If a snapshot
    legitimately contained a file named `<member>.mbpa-relink-tmp`, that unlink DELETED a real file
    that came from the primary - after step 5's verify had already passed, and before the manifest
    was written from the post-mutation summary.  The snapshot was then promoted, healthy, with a
    manifest certifying a file count that was one short.  Measured, not hypothesised.

    So: never unlink here.  Allocate around any collision, and fail loudly if we cannot."""
    for n in range(64):
        cand_rel = rel + RELINK_TMP_SUFFIX + ("" if n == 0 else "-%d" % n)
        if cand_rel in source_paths:
            continue                      # a genuine source file lives at this path
        path = os.path.join(staging, cand_rel)
        if os.path.lexists(path):
            continue                      # not in the source listing, but occupied: leave it alone
        return path
    raise CopyFailure(
        -1, "could not allocate a collision-free reconstruction temp name for %r "
            "(64 candidates all taken); refusing to unlink anything" % rel)


def inode_map(root):
    """{relpath: st_ino} for regular files only."""
    out = {}
    for rel, kind, _size, _t, st in walk_tree(root):
        if kind == "f":
            out[rel] = st.st_ino
    return out


def sample_hashes(root, stamp, pool=None):
    """Deterministic bounded content fingerprint of a tree that has JUST been verified (C12).
    Seeded on the stamp alone so the same paths are re-checked on every later deep-verify.

    `pool`, when given, is the eligible-relpath list already collected by summarize_tree's
    walk of this same tree -- passing it skips a redundant full traversal.  Omit it (None)
    and the tree is walked, which is what the deep-verify/backfill callers still do because
    they have no adjacent summarize_tree of that tree."""
    if pool is not None:
        # Pool handed in by summarize_tree's walk (see its `sample_pool`).  Same predicate,
        # same tree, no second traversal.  sorted() because the caller's list is in walk
        # order and the RNG below is seeded to be reproducible over a STABLE ordering.
        eligible = sorted(pool)
    else:
        eligible = sorted(rel for rel, kind, size, _t, _st in walk_tree(root)
                          if kind == "f" and size <= MANIFEST_SAMPLE_MAX_FILE_BYTES)
    if not eligible:
        return {}
    if len(eligible) <= MANIFEST_SAMPLE_FILES:
        pick = eligible
    else:
        pick = sorted(random.Random("mbpa-manifest|" + stamp).sample(
            eligible, MANIFEST_SAMPLE_FILES))
    out = {}
    total = 0
    for rel in pick:
        path = os.path.join(root, rel)
        try:
            size = os.stat(path, follow_symlinks=False).st_size
        except OSError:
            continue
        if out and total + size > MANIFEST_SAMPLE_MAX_TOTAL_BYTES:
            break
        try:
            out[rel] = file_md5(path)
        except (IOError, OSError):
            continue
        total += size
    return out


def file_md5(path):
    h = hashlib.md5()
    with open(path, "rb") as fh:
        while True:
            b = fh.read(1 << 20)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


# --------------------------------------------------------------------------- rsync argv

def assert_no_forbidden(argv):
    """00 F8.3 / 02: assert the built argv contains none of the poison flags, every time.

    `-H` is in this set as of the 2026-08-19 D1 reversal: it aborts openrsync (rc 16, io_buffer_buf
    assertion) on exactly the trees it exists to protect, so it can never deliver its benefit.  The
    check covers the bare flag, any short-flag bundle containing it (`-aH`, `-Ha`), and the long
    spelling."""
    for a in argv:
        for bad in FORBIDDEN_FLAG_PREFIXES:
            if a == bad or a.startswith(bad):
                raise ConfigError(
                    "FORBIDDEN rsync flag %r in argv (%s); refusing to run rsync" % (a, bad))
        if a.startswith("--hard-links"):
            raise ConfigError(
                "FORBIDDEN rsync flag %r in argv (--hard-links / -H aborts openrsync under "
                "--link-dest, 00 F8.3); refusing to run rsync" % a)
        if a.startswith("-") and not a.startswith("--") and "H" in a[1:]:
            raise ConfigError(
                "FORBIDDEN rsync flag %r in argv (-H aborts openrsync under --link-dest, "
                "00 F8.3); refusing to run rsync" % a)
    return argv


def build_copy_argv(src_dir, dst_dir, link_dest, inject=None):
    """00 F8.3 — the one canonical spelling.  link_dest is ABSOLUTE or None.  `../<base>` must not
    appear anywhere in this engine (01 C5: both forms work, one spelling means no drift).

    PLAIN `-a`.  `-H` is FORBIDDEN (00 F8.3 as amended 2026-08-19; D1 reversed).  Intra-snapshot
    hardlink groups are reconstructed by the engine from the primary's inode map instead - see
    verify_and_audit()."""
    argv = [RSYNC, "-a"]
    if link_dest:
        argv.append("--link-dest=" + link_dest)
    for x in EXCLUDES:
        argv.extend(["--exclude", x])
    if inject:
        argv.append(inject)
    argv.append(src_dir.rstrip("/") + "/")
    argv.append(dst_dir.rstrip("/") + "/")
    return assert_no_forbidden(argv)


def build_repair_argv(src_dir, dst_dir, list_path, inject=None):
    """00 F8.5b repair.  -0 / NUL-delimited list per 01 R3: the newline-delimited form breaks on a
    filename containing a newline (rc 23, mangled path).  Repairs go through rsync's default
    temp-file+rename, NEVER --inplace."""
    argv = [RSYNC, "-a", "-c", "-0", "--files-from=" + list_path]
    for x in EXCLUDES:
        argv.extend(["--exclude", x])
    if inject:
        argv.append(inject)
    argv.append(src_dir.rstrip("/") + "/")
    argv.append(dst_dir.rstrip("/") + "/")
    return assert_no_forbidden(argv)


# ---------------------------------------------------------------------------
# C6 DEFENSIVE GUARD.  RESOLVED 2026-08-19: -H is no longer shipped (00 F8.3, D1 reversed), so this
# abort is no longer an expected path.  The detector stays because a future openrsync could abort
# for another reason, and catching an abort by name beats reporting a bare rc.  If it ever fires,
# something UNEXPECTED happened: the copy fails, P4 latches, and the note says so.  It does NOT
# retry and it is NOT routine.
#
# The defect, for the record (subtask 02 C6, reproduced by the orchestrator 5/5).
# `/usr/bin/rsync -aH --link-dest=<abs> <src>/ <dst>/` — the ENGINE's exact frozen invocation —
# ABORTS openrsync with
#     Assertion failed: (*bufpos + valsz <= buflen), function io_buffer_buf, file io.c, line 859
#     rsync(<pid>): error: unexpected end of file            -> rc 16, partial dest left behind
# whenever the SOURCE tree contains an intra-source hardlink group with another regular file after
# it in the file list.  Deterministic (5/5).  `-a --link-dest` on the identical tree: rc 0.
# `-aH` WITHOUT `--link-dest` on the identical tree: rc 0.  So it is specifically the combination
# that 00 F8.3 freezes.  01's D1 evidence is real but its fixtures happen to place the pair last,
# which is the non-crashing layout, and the live archive has zero intra pairs today - so the bug is
# invisible until the exact day -H was bought as insurance for.
# Intra-snapshot hardlink groups are now rebuilt by the engine from the primary's inode map (see
# verify_and_audit) - the PRIMARY mechanism, not a fallback, and strictly stronger than -H because
# it also repairs a group an earlier pass left split.


def is_openrsync_abort(rc, err):
    return rc != 0 and "Assertion failed" in err and "io_buffer_buf" in err


def run_rsync(argv):
    """Own process group (01 R2) so an engine-initiated abort can signal the group and can never
    shoot down an unrelated rsync."""
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         start_new_session=True)
    out, err = p.communicate()
    return p.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


# --------------------------------------------------------------------------- engine

class Engine(object):

    def __init__(self, mode):
        self.mode = mode
        self.pid = os.getpid()
        self.started = iso_now()

        env = os.environ
        overridden = [k for k in ENV_PATH_KEYS if env.get(k)]
        if overridden and len(overridden) != len(ENV_PATH_KEYS):
            raise ConfigError(
                "partial SNAP_* redirection (%s set, %s missing): refusing to run so a "
                "half-redirected test can never reach the live volumes" %
                (",".join(sorted(overridden)),
                 ",".join(k for k in ENV_PATH_KEYS if k not in overridden)))
        self.test_mode = bool(overridden)

        self.primary = env.get("SNAP_PRIMARY") or DEFAULT_PRIMARY
        self.replica = env.get("SNAP_REPLICA") or DEFAULT_REPLICA
        self.state_dir = env.get("SNAP_STATE_DIR") or DEFAULT_STATE_DIR
        self.log_path = env.get("SNAP_LOG") or DEFAULT_LOG

        self.primary_snapdir = os.path.join(self.primary, SNAPDIR)
        self.replica_snapdir = os.path.join(self.replica, SNAPDIR)
        self.staging_root = os.path.join(self.replica_snapdir, STAGING_DIRNAME)

        self.status_path = os.path.join(self.state_dir, "status.json")
        self.events_path = os.path.join(self.state_dir, "events.jsonl")
        self.manifest_dir = os.path.join(self.state_dir, "manifests")
        self.pruned_manifest_dir = os.path.join(self.manifest_dir, "pruned")
        self.lock_path = os.path.join(self.state_dir, "mirror.pid")
        self.seen_path = os.path.join(self.state_dir, "seen.json")
        self.detected_path = os.path.join(self.state_dir, "detected.json")
        self.persist_path = os.path.join(self.state_dir, "persist.json")
        self.staging_meta_path = os.path.join(self.state_dir, "staging.json")
        self.pending_path = os.path.join(self.state_dir, "pending.json")
        self.grandfathered_path = os.path.join(self.state_dir, "grandfathered.json")
        self.rate_limit_path = os.path.join(self.state_dir, "last-rate-limit.json")

        if self.test_mode:
            self.legacy_lock = env.get("SNAP_LEGACY_LOCK") or \
                os.path.join(self.state_dir, "legacy-mirror.pid")
        else:
            self.legacy_lock = DEFAULT_LEGACY_LOCK

        # -------- test-only knobs.  All of them except SNAP_VERIFY_SAMPLE are inert unless the
        # four SNAP_* path overrides are set, so none of them can alter a production pass.
        self.verify_sample_all = env.get("SNAP_VERIFY_SAMPLE") == "all"
        if self.test_mode:
            self.min_free_gb = float(env.get("SNAP_MIN_FREE_GB") or MIN_FREE_GB_DEFAULT)
            self.settle_override = set(
                s for s in (env.get("SNAP_SETTLE_OVERRIDE") or "").split(",") if s)
            self.inject_flag = env.get("SNAP_TEST_INJECT_FLAG") or None
            self.crash_at = env.get("SNAP_TEST_CRASH") or None
            self.bogus_link_dest = env.get("SNAP_TEST_BOGUS_LINKDEST") == "1"
        else:
            self.min_free_gb = MIN_FREE_GB_DEFAULT
            self.settle_override = set()
            self.inject_flag = None
            self.crash_at = None
            self.bogus_link_dest = False

        self.holds_lock = False
        self._lock_fd = None            # flock fd; must stay open for the process lifetime
        self.log_opened = False
        self.copy_logged_start = False
        self.pass_rc_for_log = 0

        self.problems = []
        self.notes = []
        self.events_buffered = 0
        self.copies_attempted = 0
        self.copies_failed = 0

        # populated by probe()
        self.primary_mounted = False
        self.replica_mounted = False
        self.stat_primary = self._zero_stat()
        self.stat_replica = self._zero_stat()
        self.primary_snapshots = []
        self.replica_snapshots = []
        self.latest_primary = None
        self.latest_replica = None
        self.latest_primary_dangling = False
        self.incoming = []
        self.pending = []
        self.unsettled = []
        self.corpses = []
        self.incomplete = []
        self.orphan_partial = None
        self.mirror_running = False
        # PER-PHASE TIMING (2026-08-26). Purely observational -- nothing reads this but the log
        # line at the end of a copy. Added because two successive "this will be faster" changes
        # were predicted from a COST MODEL and both missed: the model priced every full-tree walk
        # at its cold-cache rate, but the staging tree is hot in the buffer cache the moment rsync
        # finishes writing it, so the walks are NOT equally expensive. Stop inferring, measure.
        self.phase_times = {}

        self.persist = read_json(self.persist_path, {}) or {}
        self.seen = read_json(self.seen_path, {}) or {}
        self.detected = read_json(self.detected_path, {}) or {}
        self.staging_meta = read_json(self.staging_meta_path, {}) or {}
        self.pending_since = read_json(self.pending_path, {}) or {}
        self.grandfathered = read_json(self.grandfathered_path, None)

        # on/off switch (single writer each): handshake.json <- handshake.py only;
        # control-override.json <- this engine's own "enable"/"disable" mode only.
        self.handshake_path = os.path.join(self.state_dir, "handshake.json")
        self.control_path = os.path.join(self.state_dir, "control-override.json")
        self.incomplete_path = os.path.join(self.state_dir, "incomplete.json")
        self.skip_dedup_path = os.path.join(self.state_dir, "skip-dedup.json")
        self.force_settle_path = os.path.join(self.state_dir, "force-settle.json")
        # Retry opt-back-in for SUPERSEDED failures (A3): same add-by-monitor/consume-by-engine
        # pattern as skip-dedup/force-settle. Deliberately NOT read here: consume_retry_requests()
        # re-reads it at the consume point (F10), which shrinks the monitor-write clobber window
        # from a whole pass to microseconds.
        self.retry_request_path = os.path.join(self.state_dir, "retry-request.json")
        self.handshake = read_json(self.handshake_path, {}) or {}
        self.control_override = read_json(self.control_path, {}) or {}
        self.incomplete_marks = read_json(self.incomplete_path, {}) or {}
        # Single writer: monitor.py's POST /api/control/skip-dedup ONLY (a human click or an
        # agent's API call) -- never engine.py itself. Consumed (removed) here on first
        # successful use of each entry; see verify_and_audit()'s 5c dedup assertion.
        self.skip_dedup = read_json(self.skip_dedup_path, {}) or {}
        # Single writer: monitor.py's POST /api/control/force-settle ONLY. Forces classify() to
        # treat an UNSETTLED stamp as settled -- a bigger override than skip-dedup, gated on the
        # was_latest safety invariant in classify() itself (see there for why that makes this
        # safe even if marked carelessly: a stamp that was never was_latest is refused, not
        # silently accepted, because that's corpse-tracking's own proof the writer actually
        # finished it at some point, as opposed to it possibly still being mid-upload right now).
        self.force_settle = read_json(self.force_settle_path, {}) or {}
        # Single writer: monitor.py's POST /api/control/mute + /unmute ONLY. UNLIKE skip-dedup and
        # force-settle this is NEVER consumed on use -- that is exactly what makes it PERMANENT.
        # A muted stamp (a) is never retried (it leaves self.pending), and (b) has its per-stamp
        # problems moved out of problems[] into muted_problems[], so `healthy` stops being pinned
        # false by a snapshot the operator has deliberately written off. It stays fully visible in
        # status.muted / status.muted_problems -- muted is "acknowledged", never "hidden".
        # Removing a stamp from this file (POST /unmute) restores every one of those behaviours.
        self.muted_path = os.path.join(self.state_dir, "muted.json")
        # S11: an operator-decision file that EXISTS but cannot be parsed must never silently
        # become {} -- check_state_file_integrity() turns the flag into a problem on every pass.
        self.muted, self.muted_parse_error = read_json_strict(self.muted_path, {})
        self.muted_stamps = []
        # A1/F15: stamps whose failure record was closed as superseded. classify() populates it
        # on a full pass; it MUST also exist (empty) on the lock-held heartbeat path, where
        # classify() never runs -- status rows never derive from it (M9: they derive from
        # persist["failed_copies"] inside muted_records()).
        self.superseded_stamps = []
        self.muted_problems = []
        # LINE mutes: the per-snapshot mute above can only silence per-stamp problems, so it
        # cannot touch a note or a stamp-less problem (P16, P13, the space-delta notes...). This
        # covers everything else, keyed by the line's SHAPE rather than its exact text -- see
        # line_key(). Single writer: monitor.py POST /api/control/mute-line + /unmute-line.
        self.muted_lines_path = os.path.join(self.state_dir, "muted-lines.json")
        self.muted_lines, self.muted_lines_parse_error = \
            read_json_strict(self.muted_lines_path, {})    # S11: same class as muted.json
        self.muted_line_hits = []
        self.enabled = True
        self.enabled_source = "handshake"

        self.last_copy = self.persist.get("last_copy")
        self.last_deep_verify = self.persist.get("last_deep_verify")

    @staticmethod
    def _zero_stat():
        return {"total_kb": 0, "used_kb": 0, "free_kb": 0, "iused": 0}

    # ---------------------------------------------------------------- logging / events

    def log(self, line):
        """00 F7.  Additional human-readable lines are allowed; the four frozen shapes never change."""
        try:
            d = os.path.dirname(self.log_path)
            if d and not os.path.isdir(d):
                os.makedirs(d, exist_ok=True)
            try:
                if os.path.getsize(self.log_path) >= LOG_ROTATE_BYTES:
                    os.replace(self.log_path, self.log_path + ".1")
            except OSError:
                pass
            with open(self.log_path, "a") as fh:
                fh.write("%s  %s\n" % (log_clock(), line))
        except (IOError, OSError):
            pass

    def event(self, kind, snapshot, detail):
        """00 F6 append-only JSONL."""
        rec = {"ts": iso_now(), "event": kind, "snapshot": snapshot, "detail": detail}
        try:
            d = os.path.dirname(self.events_path)
            if d and not os.path.isdir(d):
                os.makedirs(d, exist_ok=True)
            with open(self.events_path, "a") as fh:
                fh.write(json.dumps(rec) + "\n")
            self.events_buffered += 1
        except (IOError, OSError):
            pass

    def trim_events(self):
        try:
            if not os.path.exists(self.events_path):
                return
            with open(self.events_path, "r") as fh:
                lines = fh.readlines()
            if len(lines) > EVENTS_TRIM_AT:
                write_atomic(self.events_path, "".join(lines[-EVENTS_TRIM_TO:]))
        except (IOError, OSError):
            pass

    def crashpoint(self, name):
        """TEST ONLY (gated on the SNAP_* redirection).  Simulates a SIGKILL at an exact spot so the
        crash windows in 00 F8 step 6 can be tested deterministically."""
        if self.crash_at and self.crash_at == name:
            self.log("TEST crash point %s (pid=%d)" % (name, self.pid))
            os._exit(137)

    # ---------------------------------------------------------------- lock (00 F3)

    def acquire_lock(self):
        """00 F3 as amended (BUG-1, subtask 04 + orchestrator).  Returns (True, None) on success,
        (False, <diagnostic pid>) when another process holds the lock.

        `fcntl.flock(LOCK_EX|LOCK_NB)` held for the lifetime of the process.  The previous scheme
        (`os.open(O_CREAT|O_EXCL)` then write the pid) had a window between the two syscalls where
        the file existed but was ZERO BYTES; a concurrent pass read it, found nothing parseable,
        declared it stale, DELETED it and took the lock - so the lock was not mutually exclusive at
        all.  flock is atomic, has no create-then-write window, and the KERNEL releases it when the
        holder dies (SIGKILL, panic, power loss included), which deletes the entire stale-lock
        heuristic this code used to need.  The pid in the file is DIAGNOSTIC ONLY and never decides
        whether the lock is held."""
        os.makedirs(self.state_dir, exist_ok=True)

        # LEGACY_LOCK: advisory only.  Checked, NEVER created, NEVER flocked, NEVER unlinked.
        legacy = self._check_legacy_lock()
        if legacy is not None:
            return False, legacy

        try:
            fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o644)
        except OSError as exc:
            raise ConfigError("cannot open lock %s: %s" % (self.lock_path, exc))
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (IOError, OSError) as exc:
            if exc.errno not in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
                os.close(fd)
                raise
            holder = self._read_lock_pid(fd)          # diagnostic only
            os.close(fd)
            return False, holder
        # We own it.  The fd MUST stay open for the process lifetime - closing it drops the lock.
        self._lock_fd = fd
        self.holds_lock = True
        try:
            os.ftruncate(fd, 0)
            os.write(fd, ("%d\n" % self.pid).encode())
            os.fsync(fd)
        except OSError:
            pass                                       # the pid is diagnostic; the flock is the lock
        return True, None

    @staticmethod
    def _read_lock_pid(fd):
        """DIAGNOSTIC ONLY.  Never used to decide whether the lock is held."""
        try:
            raw = os.pread(fd, 64, 0).decode("utf-8", "replace").strip()
            return int(raw.split()[0])
        except (OSError, ValueError, IndexError, UnicodeDecodeError):
            return -1

    def _check_legacy_lock(self):
        """LEGACY_LOCK is the OLD mirror.sh's pidfile.  We honour a LIVE pid in it so a hand-run
        legacy script is not raced, but we never create it, never flock it and never remove it."""
        try:
            with open(self.legacy_lock, "r") as fh:
                raw = fh.read().strip()
        except (IOError, OSError):
            return None
        try:
            pid = int(raw.split()[0])
        except (ValueError, IndexError):
            return None
        if pid != self.pid and pid_alive(pid):
            return pid
        return None

    def release_lock(self):
        """Drops the flock and closes the fd.  NEVER unlinks: the lock file is a stable inode that
        other processes flock, and unlinking it would let two engines lock two different inodes."""
        if self.holds_lock and self._lock_fd is not None:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            except (IOError, OSError):
                pass
            try:
                os.close(self._lock_fd)
            except OSError:
                pass
        self._lock_fd = None
        self.holds_lock = False

    def busy_seconds(self):
        """Seconds since ANYTHING first claimed to be copying: either this engine starting a copy,
        or the first pass that observed the lock held by someone else.  Drives F4's
        mirror_running_seconds and F5 P14, and is what stops a foreign live lock holder from
        pinning the monitor at amber forever (FG6)."""
        since = self.persist.get("busy_since")
        if not since:
            return 0
        try:
            t = time.mktime(time.strptime(since[:19], "%Y-%m-%dT%H:%M:%S"))
        except ValueError:
            return 0
        return max(0, int(time.time() - t))

    def mark_busy(self):
        if not self.persist.get("busy_since"):
            self.persist["busy_since"] = iso_now()
            write_json(self.persist_path, self.persist)

    def clear_busy(self):
        if self.persist.get("busy_since"):
            del self.persist["busy_since"]
            write_json(self.persist_path, self.persist)

    def heartbeat_status(self, held_pid):
        """00 F3 + FG6.  A lock-held pass still refreshes STATUS `ts` / `mirror_running` so a long
        healthy copy never ages into a false stale-FAIL — but it ALSO computes the mount and
        stuck-copy rules.  Without that, a foreign live pid in the lock file starved every health
        computation and pinned the monitor at amber forever: compute_health() never ran, so not
        even P10 or P14 could fire.  A rule must never be starved by the condition it detects."""
        self.mark_busy()
        self.probe(write_state=False)
        self.mirror_running = True
        self.lock_held_health(held_pid)
        # lock_held_health() can raise P10, which IS mutable -- so this path must honour mutes too,
        # or a muted stamp's stuck staging would still pin the banner red for the whole copy.
        self.apply_mutes()
        cur = read_json(self.status_path)
        if isinstance(cur, dict) and cur.get("schema") == SCHEMA:
            # preserve the last completed pass's view of the trees; the holder owns those fields
            cur["ts"] = iso_now()
            cur["mirror_running"] = True
            cur["mirror_running_seconds"] = self.busy_seconds()
            cur["primary_mounted"] = self.primary_mounted
            cur["replica_mounted"] = self.replica_mounted
            for side, st in (("primary", self.stat_primary), ("replica", self.stat_replica)):
                for k in ("total_kb", "used_kb", "free_kb", "iused"):
                    cur["%s_%s" % (side, k)] = st[k]
            cur["problems"] = list(self.problems)
            cur["notes"] = list(self.notes)
            cur["healthy"] = not self.problems
            cur["muted"] = self.muted_records()
            cur["muted_problems"] = list(self.muted_problems)
            cur["muted_lines"] = self.muted_line_records()
            try:
                write_atomic(self.status_path,
                             json.dumps(cur, indent=1, sort_keys=True) + "\n")
                return True
            except (IOError, OSError):
                return False
        # no usable STATUS yet: publish a complete one rather than leaving the monitor blind
        try:
            self.write_status(True)
            return True
        except (IOError, OSError):
            return False

    def lock_held_health(self, held_pid):
        """The subset of F5 that must be computable while another process holds the lock."""
        if not self.primary_mounted:
            self.problem("P1 primary volume not mounted (%s missing)" % self.primary_snapdir)
        if not self.replica_mounted:
            self.problem("P1 replica volume not mounted (%s missing)" % self.replica_snapdir)
        self.check_stuck_copy()
        self.check_deep_verify_age()
        self.check_pending_age()
        self.check_state_file_integrity()   # S11: corrupt operator state is loud here too
        self.note("a copy is in progress (lock held by pid=%s)" % held_pid)

    def update_pending_tracker(self):
        """00 F5 P15 bookkeeping.  The keys of pending.json are EXACTLY the current settled-and-
        pending set, so a record cannot leak: a stamp that gets copied, pruned, reclassified as a
        CORPSE, or removed from the primary simply stops being a key on the next pass.  Existing
        timestamps are preserved so the clock measures how long the replica has been behind, not
        how long since the last pass."""
        if not (self.primary_mounted and self.replica_mounted):
            return          # cannot tell "not pending" from "cannot see the volumes"
        now = iso_now()
        fresh = {}
        for s in self.pending:
            fresh[s] = self.pending_since.get(s) or now
        if fresh != self.pending_since:
            self.pending_since = fresh
            write_json(self.pending_path, fresh)

    def check_pending_age(self):
        """00 F5 P15.  Reads pending.json rather than self.pending, so the rule is computable on the
        lock-held path too and cannot be starved.  Short-lived pending stays a note: the point is
        PERSISTENCE, not presence."""
        worst, worst_age = None, 0.0
        for s in sorted(self.pending_since or {}):     # stamp order == chronological order
            since = self.pending_since[s]
            try:
                t = time.mktime(time.strptime(str(since)[:19], "%Y-%m-%dT%H:%M:%S"))
            except (ValueError, TypeError):
                continue
            age = time.time() - t
            # strict >, over a stamp-sorted walk: ties resolve to the OLDEST STAMP, so the banner
            # names the same snapshot on every pass instead of flapping between equals
            if age > worst_age:
                worst, worst_age = s, age
        if worst is not None and worst_age > PENDING_MAX_SECONDS:
            extra = ""
            if len(self.pending_since) > 1:
                extra = " (%d stamp(s) pending in total)" % len(self.pending_since)
            self.problem("P15 snapshot %s has been settled and awaiting copy for %.1f h (> %d h): "
                         "the replica is BEHIND and is not catching up%s"
                         % (worst, worst_age / 3600.0, PENDING_MAX_SECONDS // 3600, extra))

    def _read_rate_limit_artifact(self):
        """Read mirror.sh's last-rate-limit.json.  Missing/empty/truncated/malformed -> None."""
        try:
            if not os.path.isfile(self.rate_limit_path):
                return None
            if os.path.getsize(self.rate_limit_path) == 0:
                return None
            with open(self.rate_limit_path, "r") as fh:
                raw = fh.read()
        except (IOError, OSError) as exc:
            self.log("last-rate-limit.json unreadable: %s" % exc)
            return None
        if not raw.strip():
            return None
        try:
            data = json.loads(raw)
        except ValueError as exc:
            self.log("last-rate-limit.json unreadable: %s" % exc)
            return None
        if not isinstance(data, dict):
            self.log("last-rate-limit.json unreadable: not an object")
            return None
        try:
            ts = int(data["ts"])
        except (KeyError, TypeError, ValueError):
            self.log("last-rate-limit.json unreadable: missing or invalid ts")
            return None
        mode = data.get("mode")
        reason = data.get("reason")
        if mode not in ("mirror", "deep-verify") or reason not in ("burst", "sustain"):
            self.log("last-rate-limit.json unreadable: missing or invalid mode/reason")
            return None
        iso = data.get("iso")
        if not iso:
            try:
                iso = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts))
            except (ValueError, OSError):
                iso = str(ts)
        return {"ts": ts, "iso": str(iso), "mode": mode, "reason": reason,
                "count": data.get("count"), "limit": data.get("limit"),
                "window_sec": data.get("window_sec"),
                "client": data.get("client") or ""}

    def check_rate_limit_denial(self):
        """00 F5 P16.  mirror.sh writes last-rate-limit.json on exit 78; the engine surfaces it on
        the next pass.  Denials older than 24 h self-clear; corrupt artifacts are ignored."""
        denial = self._read_rate_limit_artifact()
        if denial is None:
            return
        age = time.time() - denial["ts"]
        if age < 0 or age > RATE_LIMIT_MAX_AGE_SEC:
            return
        self.problem("P16 forced-command trigger rate-limited (%s): %s at %s — "
                     "possible abuse of the replica forced-command key"
                     % (denial["mode"], denial["reason"], denial["iso"]))
        if self.persist.get("last_rate_limit_event_ts") != denial["ts"]:
            detail = ("mode=%s reason=%s count=%s limit=%s window_sec=%s client=%s"
                      % (denial["mode"], denial["reason"], denial.get("count"),
                         denial.get("limit"), denial.get("window_sec"), denial["client"]))
            self.event("rate_limited", None, detail)
            self.persist["last_rate_limit_event_ts"] = denial["ts"]
            write_json(self.persist_path, self.persist)

    def check_stuck_copy(self):
        """00 F5 P14."""
        secs = self.busy_seconds()
        if secs > SUPPRESS_CAP_SECONDS:
            self.problem("P14 a copy has claimed to be running for %.1f h (> %d h): stuck copy, or "
                         "a foreign process is holding %s"
                         % (secs / 3600.0, SUPPRESS_CAP_SECONDS // 3600, self.lock_path))

    def check_deep_verify_age(self):
        """00 F5 P13.  An absent safety net is a problem, not a neutral state."""
        ok_ts = self.persist.get("last_deep_verify_ok_ts")
        if not ok_ts:
            self.problem("P13 deep-verify has NEVER completed successfully: F9 sampled content "
                         "hashing is the only cover for bit rot and for F9's documented residual, "
                         "so until it runs once nothing is checking replica CONTENT")
            return
        try:
            t = time.mktime(time.strptime(ok_ts[:19], "%Y-%m-%dT%H:%M:%S"))
        except ValueError:
            return
        age_days = (time.time() - t) / 86400.0
        if age_days > DEEP_VERIFY_MAX_AGE_DAYS:
            self.problem("P13 last successful deep-verify was %.1f days ago (> %d): the content "
                         "safety net has stopped running" % (age_days, DEEP_VERIFY_MAX_AGE_DAYS))

    def check_clock_skew(self, prev_ts):
        """FG5, engine half.  The monitor clamps stale_seconds at 0 (F10); the engine can also SEE
        the cause - a STATUS timestamp in the future means the clock moved backwards, which is
        itself evidence something is wrong."""
        if not prev_ts:
            return
        try:
            t = time.mktime(time.strptime(prev_ts[:19], "%Y-%m-%dT%H:%M:%S"))
        except ValueError:
            return
        skew = t - time.time()
        if skew > 60:
            self.note("previous status.json timestamp is %.0f s in the FUTURE (%s): the system "
                      "clock moved backwards, or another writer has a bad clock" % (skew, prev_ts))

    # ---------------------------------------------------------------- probe

    def statvfs_of(self, path):
        try:
            v = os.statvfs(path)
        except OSError:
            return self._zero_stat()
        frs = v.f_frsize or v.f_bsize
        return {
            "total_kb": int(v.f_blocks * frs // 1024),
            "used_kb": int((v.f_blocks - v.f_bfree) * frs // 1024),
            "free_kb": int(v.f_bavail * frs // 1024),
            "iused": int(v.f_files - v.f_ffree),
        }

    def list_snapshots(self, snapdir):
        out = []
        try:
            with os.scandir(snapdir) as it:
                for ent in it:
                    if not STAMP_RE.match(ent.name):
                        continue
                    try:
                        st = ent.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISDIR(st.st_mode):
                        out.append(ent.name)
        except OSError:
            return []
        out.sort()
        return out

    @staticmethod
    def read_latest(snapdir):
        p = os.path.join(snapdir, LATEST)
        try:
            t = os.readlink(p)
        except OSError:
            return None
        return os.path.basename(t.rstrip("/")) or None

    def refresh_volume_stats(self):
        """Re-sample statvfs for BOTH volumes immediately before compute_health().

        WHY THIS EXISTS (real incident, 2026-08-20 first scheduled noon run):
        probe() samples df once at the START of a pass. A real incremental copy took
        675.9s, and the status written at the END of that pass still carried the
        START-of-pass figures -- a POST-copy primary compared against a PRE-copy
        replica. P6/P7 duly fired: "used-space delta 2,756,924 KB", "inode delta
        45,031", healthy=false, monitor RED, on a copy that had in fact succeeded
        (rc=0, 166,955 files verified). The replica's iused had not moved at all in
        that status, which is impossible for a volume that had just gained a
        166,916-file snapshot -- that impossibility is what exposed it.
        Re-probing here costs ~0.004s (statvfs, measured) and turns a guaranteed
        daily false alarm after every successful backup into a correct reading.
        A backup monitor that cries wolf once per day trains its owner to ignore it,
        which is worse than having no monitor at all.

        2026-08-26: P6/P7 themselves were deleted (PLAN A4 -- mixed-use drives), but this
        re-probe STAYS: the status volume fields and P8 free-space must still describe the
        post-copy world, not the pre-copy one.
        """
        if self.primary_mounted:
            self.stat_primary = self.statvfs_of(self.primary)
        if self.replica_mounted:
            self.stat_replica = self.statvfs_of(self.replica)

    def probe(self, write_state=True):
        self.primary_mounted = os.path.isdir(self.primary_snapdir)
        self.replica_mounted = os.path.isdir(self.replica_snapdir)

        if self.primary_mounted:
            self.stat_primary = self.statvfs_of(self.primary)
            self.primary_snapshots = self.list_snapshots(self.primary_snapdir)
            self.latest_primary = self.read_latest(self.primary_snapdir)
            if self.latest_primary is not None:
                self.latest_primary_dangling = not os.path.isdir(
                    os.path.join(self.primary_snapdir, self.latest_primary))
        if self.replica_mounted:
            self.stat_replica = self.statvfs_of(self.replica)
            self.replica_snapshots = self.list_snapshots(self.replica_snapdir)
            self.latest_replica = self.read_latest(self.replica_snapdir)
            try:
                self.incoming = sorted(n for n in os.listdir(self.staging_root) if not excluded(n))
            except OSError:
                self.incoming = []

        # first-ever pass: whatever is already on the replica is a grandfathered cutover stamp
        # (00 F8 "Grandfathering"), so the manifest-less recovery rule does not fire on it.
        if self.grandfathered is None:
            self.grandfathered = list(self.replica_snapshots) if self.replica_mounted else []
            if write_state:      # never write STATE_DIR from a pass that does not hold the lock
                write_json(self.grandfathered_path, self.grandfathered)

    # ---------------------------------------------------------------- corpse tracking (00 F8)

    def update_seen(self):
        was = set(self.seen.get("was_latest") or [])
        above = set(self.seen.get("above_latest") or [])
        known = set(self.seen.get("known") or [])

        cur = self.latest_primary if not self.latest_primary_dangling else None

        # C9 BOOTSTRAP RECONCILIATION.  seen.json absent or empty means either the very first pass
        # after install, or that the file was lost/restored.  Either way the first-observation
        # exception (00 F8) would otherwise grandfather EVERY existing stamp as settled, including a
        # corpse the writer left behind before this engine ever ran.  So: seed above_latest from
        # the CURRENT primary listing FIRST, before anything is treated as known.  The loop below
        # already does exactly that; this block makes it a named, logged, tested behaviour rather
        # than an emergent one, and records when the bootstrap happened for forensics.
        bootstrap = not (was or above or known)
        if bootstrap and self.primary_mounted:
            pre = [x for x in self.primary_snapshots if cur and x > cur]
            self.log("seen.json absent/empty: bootstrapping corpse tracking (C9). latest=%s, "
                     "%d primary stamp(s) above latest recorded as above_latest%s"
                     % (cur or "NONE", len(pre), (": " + ", ".join(pre)) if pre else ""))
            self.persist["seen_bootstrapped"] = iso_now()
            write_json(self.persist_path, self.persist)

            # FG2.  Do NOT decide "first run" from seen.json alone.  Corroborating state tells us
            # whether this engine has run before, and if it has, seen.json was LOST rather than
            # never written - which means the first-observation exception must not be trusted.
            corroborating = []
            if self.persist.get("last_copy") or self.persist.get("last_deep_verify") \
                    or self.persist.get("seen_bootstrapped_prior"):
                corroborating.append("persist.json")
            if self.detected.get("detected"):
                corroborating.append("detected.json")
            if os.path.isdir(self.manifest_dir) and \
                    any(n.endswith(".json") for n in os.listdir(self.manifest_dir)):
                corroborating.append("manifests/")
            if self.grandfathered:
                corroborating.append("grandfathered.json")

            if corroborating:
                # PARTIAL state loss.  Re-derive the suspicious set from detected.json: a stamp we
                # positively OBSERVED before, that now sits below latest and was never promoted, is
                # a stamp we declined to copy at the time - i.e. it was above latest then.  In
                # steady state that set is empty, because everything settled is copied within a
                # pass.  Anything in it is a corpse or a stamp whose copy has been failing (which
                # already has P4 latched), so refusing to copy it is the conservative direction and
                # it is LOUD, not silent.
                promoted = set(self.replica_snapshots)
                seen_before = set(self.detected.get("detected") or [])
                recovered = sorted(x for x in self.primary_snapshots
                                   if cur and x < cur and x in seen_before and x not in promoted)
                above |= set(recovered)
                self.log("FG2: seen.json was LOST, not absent - corroborating state present (%s). "
                         "Reconstructed %d suspicious stamp(s) from detected.json%s"
                         % (", ".join(corroborating), len(recovered),
                            (": " + ", ".join(recovered)) if recovered else ""))
                self.note("corpse-tracking state (seen.json) was lost and rebuilt from %s; "
                          "%d stamp(s) reconstructed as suspicious - verify before deleting anything"
                          % ("/".join(corroborating), len(recovered)))
            else:
                # BOOTSTRAP FROM NOTHING.  Honest limit, stated rather than papered over: a corpse
                # that `latest` has ALREADY advanced past is indistinguishable from an ordinary old
                # snapshot, because `latest` is the writer's only completion signal and it no
                # longer points anywhere useful.  Prior observation is the only discriminator and
                # by definition we have none.
                self.note("corpse tracking is bootstrapping from NOTHING (no seen.json and no "
                          "corroborating state): a truncated snapshot that `latest` has already "
                          "passed cannot be distinguished from a legitimate old one on this pass")
            self.persist["seen_bootstrapped_prior"] = True
            write_json(self.persist_path, self.persist)

        if cur:
            was.add(cur)
        for s in self.primary_snapshots:
            if cur and s > cur:
                # Observed strictly above the then-current latest.  A stamp FIRST seen already at or
                # below latest never enters this set, which is exactly 00 F8's first-observation
                # exception (engine was down across one or more backups -> treat as settled).
                above.add(s)
            known.add(s)

        # garbage-collect stamps that exist on neither volume (only when we can see the primary,
        # so an unmounted volume can never erase corpse evidence)
        if self.primary_mounted and self.replica_mounted:
            live = set(self.primary_snapshots) | set(self.replica_snapshots)
            was &= live
            above &= live
            known &= live

        self.seen = {"was_latest": sorted(was), "above_latest": sorted(above),
                     "known": sorted(known),
                     "bootstrapped": self.seen.get("bootstrapped") or
                                     (iso_now() if bootstrap else None)}
        write_json(self.seen_path, self.seen)

    def is_corpse(self, s):
        """00 F8 CORPSE(S) == S in above_latest AND S not in was_latest AND S < current latest."""
        cur = self.latest_primary if not self.latest_primary_dangling else None
        if not cur:
            return False
        return (s in set(self.seen.get("above_latest") or [])
                and s not in set(self.seen.get("was_latest") or [])
                and s < cur)

    # ---------------------------------------------------------------- classification

    def classify(self):
        self.corpses = []
        self.unsettled = []
        self.pending = []
        self.incomplete = []
        self.refused_force_settle = []
        self.muted_stamps = []
        self.superseded_stamps = []
        if not self.primary_mounted:
            return
        cur = self.latest_primary if not self.latest_primary_dangling else None
        promoted = set(self.replica_snapshots)
        marked_incomplete = set(self.incomplete_marks)
        was_latest = set(self.seen.get("was_latest") or [])
        for s in self.primary_snapshots:
            if s in marked_incomplete:
                # On/off switch: handshake.py positively marked this stamp incomplete (connection
                # to the writer was lost mid-write and the dir stopped growing). Invisible to
                # pending/corpses/orphan_partial by design -- "incomplete is not a failure."
                self.incomplete.append(s)
                continue
            if s in self.settle_override:
                settled = True
            elif s in self.force_settle and s in was_latest:
                # Operator override (monitor.py POST /api/control/force-settle): this stamp WAS
                # observed as primary's own `latest` at some point -- was_latest is corpse-
                # tracking's own proof of a genuinely COMPLETED upload, so this can never be used
                # to bypass protection against a stamp that might still be mid-write right now.
                # Needed when something ELSE (e.g. a primary-side restore) moves `latest`
                # backward past a stamp that had already legitimately finished.
                settled = True
            elif s in self.force_settle:
                # Marked, but NOT was_latest -- refuse rather than silently no-op (00 F5's own
                # standard: an unclear non-action is worse than a loud one). Most likely this
                # names a stamp that is genuinely still being written; forcing it would be exactly
                # the corpse-protection failure this whole check exists to prevent.
                self.refused_force_settle.append(s)
                settled = False
            elif cur is None:
                settled = False          # broken/missing latest => nothing settles (00 F8) + P2
            elif s > cur:
                settled = False
            elif self.is_corpse(s):
                settled = False
                self.corpses.append(s)
            else:
                settled = True
            if not settled:
                self.unsettled.append(s)
            elif s not in promoted:
                if s in self.muted:
                    # Operator wrote this snapshot off (monitor.py POST /api/control/mute). It
                    # leaves `pending` so the copy loop stops spending a full multi-minute attempt
                    # on it every StartInterval, and so P15 stops counting it as "the replica is
                    # BEHIND and is not catching up". It is NOT forgotten: it stays fully visible
                    # in the status.muted ledger until the stamp leaves both volumes, and unmuting
                    # puts it straight back into `pending`. (The muted branch deliberately wins
                    # over the superseded one below, so Unmute keeps working as documented.)
                    self.muted_stamps.append(s)
                elif self._is_superseded(s):
                    # A1/R1: a later healthy promote closed this stamp's failure record as
                    # superseded -- "the most recent backup is the most important one". It leaves
                    # `pending` (never retried automatically again; the operator can opt back in
                    # via POST /api/control/retry -> consume_retry_requests()), and its record
                    # survives in persist["failed_copies"] as history and in status as a
                    # kind="superseded" row.
                    self.superseded_stamps.append(s)
                else:
                    self.pending.append(s)
        self.pending.sort()
        self.unsettled.sort()
        self.incomplete.sort()
        self.muted_stamps.sort()
        self.superseded_stamps.sort()

        # orphan partial: newest primary stamp is not the latest target (00 F5 P11).
        # A marked-incomplete newest stamp is excluded here too -- otherwise it dodges P12 only to
        # trip a different problem/note 24-48h later, which still breaks "no warning necessary."
        if self.primary_snapshots and cur and self.primary_snapshots[-1] != cur \
                and self.primary_snapshots[-1] not in marked_incomplete:
            self.orphan_partial = self.primary_snapshots[-1]

    def emit_detected(self):
        """00 F6: `detected` fires once per stamp."""
        seen = set(self.detected.get("detected") or [])
        orphaned = set(self.detected.get("orphan_partial") or [])
        changed = False
        for s in self.primary_snapshots:
            if s not in seen:
                self.event("detected", s, "new snapshot on primary")
                seen.add(s)
                changed = True
        for s in self.corpses:
            if s not in orphaned:
                self.event("orphan_partial", s,
                           "CORPSE: seen above latest, never was latest, latest has advanced "
                           "past it - a writer backup run died mid-write; never copied (P12)")
                orphaned.add(s)
                changed = True
        if self.orphan_partial and self.orphan_partial not in orphaned:
            if stamp_age_hours(self.orphan_partial) >= ORPHAN_WARN_HOURS:
                self.event("orphan_partial", self.orphan_partial,
                           "newest primary stamp is not the latest target")
                orphaned.add(self.orphan_partial)
                changed = True
        if changed:
            live = set(self.primary_snapshots) | set(self.replica_snapshots)
            if self.primary_mounted and self.replica_mounted:
                seen &= live
                orphaned &= live
            self.detected = {"detected": sorted(seen), "orphan_partial": sorted(orphaned)}
            write_json(self.detected_path, self.detected)

    # ---------------------------------------------------------------- manifests

    def manifest_path(self, s):
        return os.path.join(self.manifest_dir, s + ".json")

    def read_manifest(self, s):
        return read_json(self.manifest_path(s))

    def write_manifest(self, s, summary, link_dest, samples=None):
        """00 F8 step 6a + C12.  `samples` is {relpath: md5} over a tree that has just been proven
        equal to the primary; it is what lets deep-verify content-check the stamp after the primary
        copy is pruned.  Manifests written before C12 simply lack the key and still load."""
        write_json(self.manifest_path(s), {
            "stamp": s,
            "files": summary["files"],
            "bytes": summary["bytes"],
            "listing_md5": summary["listing_md5"],
            "verified": iso_now(),
            "link_dest": link_dest,
            "samples": samples if samples is not None else {},
        })

    # ---------------------------------------------------------------- base selection (00 F8.1)

    def choose_base(self, s):
        """Greatest promoted replica stamp that is ALSO still present on the primary and older
        than S.  A STAGING dir is never eligible.  A promoted stamp with no manifest and no
        grandfather record must be re-verified before it may serve as a base (00 F8 step 6
        RECOVERY RULE)."""
        primary_set = set(self.primary_snapshots)
        gf = set(self.grandfathered or [])
        for cand in sorted(self.replica_snapshots, reverse=True):
            if cand >= s or cand not in primary_set:
                continue
            if cand in self.muted:
                # A snapshot the operator VOIDED is not a trustworthy dedup reference. Real case
                # (2026-08-26): 2026-08-25_180005 was captured mid-restore and holds 10 files, but
                # being the newest promoted stamp it was picked as the base for a 37 GB copy. No
                # staged file could possibly share an inode with a 10-file tree, so the 5c dedup
                # assertion fired and the copy failed -- and would have failed on every retry,
                # because base selection is deterministic. Skipping muted stamps falls through to
                # the last GOOD snapshot (here 2026-08-25_120003, 474922 files), which both fixes
                # the failure and restores real dedup. Voided as a restore point == voided as a
                # reference point; the two must not diverge.
                self.log("base: skipping %s (muted/voided) as a --link-dest candidate" % cand)
                continue
            if self.read_manifest(cand) is None and cand not in gf:
                if not self.reverify_promoted(cand):
                    continue
            return cand
        return None

    def reverify_promoted(self, s):
        """00 F8 step 6 recovery rule.  Returns True if the stamp is now proven equal to the
        primary copy (and a manifest has been backfilled)."""
        rpath = os.path.join(self.replica_snapdir, s)
        ppath = os.path.join(self.primary_snapdir, s)
        self.log("recovery: promoted stamp %s has no manifest; re-verifying against primary" % s)
        if not os.path.isdir(ppath):
            self.problem("P4 promoted replica stamp %s has no manifest and the primary copy is "
                         "gone: cannot be verified, refusing to use it as a --link-dest base" % s)
            return False
        try:
            a = summarize_tree(ppath)
            b = summarize_tree(rpath)
        except OSError as exc:
            self.problem("P4 re-verification of %s failed: %s" % (s, exc))
            return False
        if (a["files"], a["bytes"], a["listing_md5"]) != (b["files"], b["bytes"], b["listing_md5"]):
            self.event("verify_failed", s, "re-verification of manifest-less promoted stamp failed")
            self.problem("P4 promoted replica stamp %s does not match the primary "
                         "(files %d/%d bytes %d/%d)" % (s, a["files"], b["files"],
                                                        a["bytes"], b["bytes"]))
            return False
        # the tree was just proven equal to the primary, so content samples recorded now are
        # trustworthy (C12 backfill rule)
        self.write_manifest(s, b, None, sample_hashes(rpath, s))
        self.log("recovery: %s re-verified and manifest backfilled" % s)
        return True

    # ---------------------------------------------------------------- copy (00 F8 steps 1-7)

    def staging_path(self, s):
        return os.path.join(self.staging_root, s)

    def wipe_staging(self, s):
        """00 F8 step 2b (01 D2).  WIPE-THEN-CREATE, immediately before EVERY rsync attempt.
        NEVER rsync into a staging dir you did not just create."""
        p = self.staging_path(s)
        if os.path.exists(p) or os.path.islink(p):
            self.log("staging: wiping %s before rsync (00 F8 2b / 01 D2)" % p)
            rmtree(p)
        os.makedirs(p, exist_ok=False)
        self.staging_meta[s] = iso_now()
        write_json(self.staging_meta_path, self.staging_meta)
        return p

    def forget_staging(self, s):
        if s in self.staging_meta:
            del self.staging_meta[s]
            write_json(self.staging_meta_path, self.staging_meta)

    def record_copy_failure(self, s, rc, detail):
        """PER-STAMP failure ledger.  `last_copy` is a single record, so once the copy loop
        CONTINUES past a failure a later success would overwrite it and P4 would clear while the
        failed snapshot was still missing from the replica.  P4 is therefore keyed to the stamp:
        "not yet superseded by a success" means a success OF THAT STAMP."""
        fails = dict(self.persist.get("failed_copies") or {})
        fails[s] = {"ts": iso_now(), "rc": rc, "detail": (detail or "")[:600]}
        self.persist["failed_copies"] = fails
        write_json(self.persist_path, self.persist)

    def clear_copy_failure(self, s):
        fails = dict(self.persist.get("failed_copies") or {})
        if s in fails:
            del fails[s]
            self.persist["failed_copies"] = fails
            write_json(self.persist_path, self.persist)

    # ------------------------------------------------- supersede-on-success (A1/R1 + M1 gate)

    def _is_superseded(self, s):
        """True iff the stamp's failure record is closed as superseded. getattr-safe: the
        status-row builders run on the lock-held path and under tests whose Fakes skip
        __init__ (F15/F23)."""
        rec = ((getattr(self, "persist", None) or {}).get("failed_copies") or {}).get(s)
        return bool(isinstance(rec, dict) and rec.get("superseded_by"))

    def _superseded_set(self):
        """Every stamp whose failure record carries superseded_by -- derived ONLY from
        persist["failed_copies"], never classify state, so it is identical on both status
        writers (M9/F15)."""
        out = set()
        fails = (getattr(self, "persist", None) or {}).get("failed_copies") or {}
        for k, v in fails.items():
            if isinstance(v, dict) and v.get("superseded_by"):
                out.add(k)
        return out

    def _manifest_files_median(self, exclude=None):
        """Median of the `files` counts over the last ~SUPERSEDE_HEALTH_MANIFESTS per-stamp
        manifests in manifests/ (top level only: prune() moves a pruned stamp's manifest into
        manifests/pruned/, and that subdirectory name never matches the <stamp>.json filter).
        `exclude` drops the stamp being judged, so a tiny promote cannot drag its own baseline
        down. Returns None when no usable manifest exists (no baseline)."""
        try:
            names = os.listdir(self.manifest_dir)
        except OSError:
            return None
        stamps = sorted(n[:-5] for n in names
                        if n.endswith(".json") and STAMP_RE.match(n[:-5]))
        vals = []
        for s in reversed(stamps):          # newest first
            if exclude is not None and s == exclude:
                continue
            man = self.read_manifest(s)
            files = man.get("files") if isinstance(man, dict) else None
            if isinstance(files, (int, float)) and not isinstance(files, bool):
                vals.append(float(files))
            if len(vals) >= SUPERSEDE_HEALTH_MANIFESTS:
                break
        if not vals:
            return None
        vals.sort()
        mid = len(vals) // 2
        if len(vals) % 2:
            return vals[mid]
        return (vals[mid - 1] + vals[mid]) / 2.0

    def supersede_health_ok(self, files, exclude=None):
        """M1 health gate: a promote may supersede older failures ONLY if its verified file
        count is >= SUPERSEDE_HEALTH_FRACTION * median(recent manifest file counts). The
        2026-08-25_180005 pattern is real: a 10-file snapshot captured mid-restore PROMOTED
        CLEANLY (verify proves staging==primary, not staging==good) -- such a void promote
        must never quietly bury a real failure. No baseline (first promotes) => gate passes;
        an unreadable/missing files count => gate FAILS (conservative: keep the failure loud)."""
        if not isinstance(files, (int, float)) or isinstance(files, bool):
            return False
        med = self._manifest_files_median(exclude=exclude)
        if med is None:
            return True
        return files >= SUPERSEDE_HEALTH_FRACTION * med

    def purge_pending(self, s):
        """F1(b): a stamp that just became superseded must leave BOTH self.pending and
        pending.json immediately. Otherwise update_pending_tracker() re-writes its key at the
        end of this very pass and check_pending_age() -- which reads pending.json and runs on
        every heartbeat -- keeps firing P15 for a stamp that will never be retried."""
        if s in (getattr(self, "pending", None) or []):
            self.pending.remove(s)
        if s in (getattr(self, "pending_since", None) or {}):
            del self.pending_since[s]
            write_json(self.pending_path, self.pending_since)

    def supersede_older_failures(self, s):
        """A1/R1 hook, called from pass_body at the single point that covers BOTH promote
        paths (normal copy and try_recover_staging -- copy_stamp() returns True for both):
        after stamp S promotes, close every older open failure record as superseded, so the
        banner clears on the next success with no operator action.

        Health-gated (M1): judged on S's own just-written manifest. F16: mutates self.persist
        in memory (record_copy_failure idiom) and never re-reads persist.json from disk, so a
        concurrent heartbeat cannot resurrect stale state through this path."""
        fails = dict(self.persist.get("failed_copies") or {})
        older = [f for f in sorted(fails)
                 if f < s and not (isinstance(fails.get(f), dict)
                                   and fails[f].get("superseded_by"))]
        if not older:
            return
        man = self.read_manifest(s)
        files = man.get("files") if isinstance(man, dict) else None
        if not self.supersede_health_ok(files, exclude=s):
            self.log("supersede: promote of %s (files=%s) fails the health gate (< %d%% of the "
                     "recent manifest median); older failure(s) %s stay open"
                     % (s, files, int(SUPERSEDE_HEALTH_FRACTION * 100), ", ".join(older)))
            return
        now = iso_now()
        for f in older:
            rec = fails.get(f)
            rec = dict(rec) if isinstance(rec, dict) else {}
            rec["superseded_by"] = s
            rec["superseded_at"] = now
            fails[f] = rec
        self.persist["failed_copies"] = fails
        write_json(self.persist_path, self.persist)
        for f in older:
            self.log("supersede: failed copy of %s superseded by successful copy of %s" % (f, s))
            self.event("superseded", f,
                       "failed copy superseded by successful copy of %s; kept as history, "
                       "no longer retried (POST /api/control/retry to opt back in)" % s)
            self.purge_pending(f)

    def consume_retry_requests(self):
        """A3/F10 consume point: pass start, AFTER probe(), BEFORE classify(), gated on both
        volumes mounted. Re-reads retry-request.json HERE (never the __init__ snapshot) and
        rewrites it, shrinking the monitor-add/engine-consume clobber window to microseconds --
        retry-request.json follows the same monitor-adds/engine-consumes contract as
        skip-dedup.json and force-settle.json.

        Semantics (F10): a request naming a stamp whose failure record is superseded -> delete
        the record entirely (classify() runs right after this, so the stamp re-enters pending
        naturally THIS pass); anything else -> drop the request and log it; never an error.
        M8: every honoured consume appends iso_now() to persist["retry_history"][stamp]
        (trimmed to RETRY_HISTORY_WINDOW_SEC) -- that survives the record's deletion and any
        later re-failure, and is what feeds the status row's retry_count that the monitor's
        >=3-in-24h cooldown validates against."""
        if not (self.primary_mounted and self.replica_mounted):
            return
        reqs, corrupt = read_json_strict(self.retry_request_path, {})
        if corrupt:
            # S11: an explicit operator request that cannot be read must be loud, never a
            # silent {}. Absence stays silent (read_json_strict distinguishes the two).
            self.note("retry-request.json exists but cannot be parsed -- no retry request can "
                      "be honoured until it is fixed or removed (%s)" % self.retry_request_path)
            return
        if not reqs:
            return
        fails = dict(self.persist.get("failed_copies") or {})
        history = dict(self.persist.get("retry_history") or {})
        persist_dirty = False
        for s in sorted(reqs):
            rec = fails.get(s)
            if isinstance(rec, dict) and rec.get("superseded_by"):
                del fails[s]
                times = [t for t in (history.get(s) or []) if isinstance(t, str)]
                times.append(iso_now())
                cutoff = time.time() - RETRY_HISTORY_WINDOW_SEC
                kept = []
                for t in times:
                    dt = parse_ts(t)
                    if dt is None or dt.timestamp() >= cutoff:
                        kept.append(t)      # unparseable entries are kept: they can only make
                                            # the retry cooldown STRICTER, never looser
                history[s] = kept
                persist_dirty = True
                self.log("retry: consumed operator request for superseded stamp %s -- failure "
                         "record dropped, it re-enters pending this pass (consume %d in 24 h)"
                         % (s, len(kept)))
                self.event("retry_consumed", s,
                           "operator retry request consumed; superseded failure record removed "
                           "so the stamp re-enters pending")
            else:
                self.log("retry: request for %s ignored (no superseded failure record for it); "
                         "request removed" % s)
        if persist_dirty:
            self.persist["failed_copies"] = fails
            self.persist["retry_history"] = history
            write_json(self.persist_path, self.persist)
        write_json(self.retry_request_path, {})

    def consume_skip_dedup(self, s):
        """Called once a stamp that used the skip-dedup override has actually PROMOTED (never
        speculatively) -- one-time use, same shape as engine.py's other single-writer state
        files. Shared by copy_stamp()'s normal path and try_recover_staging()'s crash-recovery
        path so this lives in exactly one place."""
        if s not in self.skip_dedup:
            return
        mark = self.skip_dedup.pop(s)
        write_json(self.skip_dedup_path, self.skip_dedup)
        self.event("dedup_skipped", s, "promoted without a shared inode against the base, by "
                                       "operator override (reason: %s)"
                                       % (mark.get("reason") or "none given"))

    def consume_force_settle(self, s):
        """Same one-time-use shape as consume_skip_dedup(), for the force-settle override."""
        if s not in self.force_settle:
            return
        mark = self.force_settle.pop(s)
        write_json(self.force_settle_path, self.force_settle)
        self.event("force_settled", s, "promoted despite primary `latest` not currently "
                                       "pointing at or past it, by operator override "
                                       "(reason: %s)" % (mark.get("reason") or "none given"))

    def gc_copy_failures(self):
        """Failure-ledger GC + the F1(c) supersede backstop. Never runs while a volume is
        unmounted (an unreadable disk must not look like a pruned snapshot).

        Keep-rule (F5):
          - an OPEN failure stays while the stamp is on the primary, missing from the replica,
            and not muted. A muted stamp is a CLOSED failure the operator accepted: dropping
            its record is what stops P4 re-deriving it every pass; the decision survives in
            muted.json, and unmuting puts the stamp straight back into pending so a real
            failure re-derives from scratch. (Muted wins over superseded, here and in
            classify(), so Unmute keeps working.)
          - a SUPERSEDED record is history ("just in case") and stays while the stamp exists
            on EITHER volume; it is dropped only once the stamp is gone from both.

        F1(c) backstop, idempotent: a SIGKILL can land between promote()'s os.rename and
        pass_body's supersede write. Any un-superseded failure with a NEWER promoted stamp on
        the replica is marked superseded here -- which also applies R1 retroactively at
        install (failed_copies is {} today, so no latent effect) and makes the pass_body hook
        a latency optimization. The backstop honours the same M1 health gate as the hook:
        only a promoted stamp whose manifest passes supersede_health_ok() counts, and the
        NEWEST such stamp is recorded as the superseder."""
        if not (self.primary_mounted and self.replica_mounted):
            return
        fails = dict(self.persist.get("failed_copies") or {})
        changed = False

        gate_cache = {}

        def _healthy_promote(cand):
            if cand not in gate_cache:
                man = self.read_manifest(cand)
                files = man.get("files") if isinstance(man, dict) else None
                gate_cache[cand] = self.supersede_health_ok(files, exclude=cand)
            return gate_cache[cand]

        for f in sorted(fails):
            rec = fails.get(f)
            if isinstance(rec, dict) and rec.get("superseded_by"):
                continue
            if f in self.muted:
                continue        # muted wins; the keep-rule below drops the record as before
            sup = None
            for cand in sorted(self.replica_snapshots, reverse=True):
                if cand <= f:
                    break
                if _healthy_promote(cand):
                    sup = cand
                    break
            if sup:
                rec = dict(rec) if isinstance(rec, dict) else {}
                rec["superseded_by"] = sup
                rec["superseded_at"] = iso_now()
                fails[f] = rec
                changed = True
                self.log("supersede backstop: failed copy of %s superseded by promoted %s"
                         % (f, sup))
                self.purge_pending(f)

        live = set(self.primary_snapshots) - set(self.replica_snapshots)
        either = set(self.primary_snapshots) | set(self.replica_snapshots)
        keep = {}
        for k, v in fails.items():
            if isinstance(v, dict) and v.get("superseded_by"):
                if k in either:
                    keep[k] = v
            elif k in live and k not in self.muted:
                keep[k] = v
        if changed or keep != (self.persist.get("failed_copies") or {}):
            self.persist["failed_copies"] = keep
            write_json(self.persist_path, self.persist)

    def record_attempt(self, s, started, rc, files, nbytes, link_dest, detail):
        self.last_copy = {"snapshot": s, "started": started, "finished": iso_now(), "rc": rc,
                          "files": files, "bytes": nbytes, "link_dest": link_dest,
                          "detail": detail}
        self.persist["last_copy"] = self.last_copy
        write_json(self.persist_path, self.persist)

    def tmark(self, name, t0):
        """Accumulate elapsed seconds under `name`. Observational only -- never raises, never
        affects control flow, and a failure here must never cost a copy."""
        try:
            self.phase_times[name] = self.phase_times.get(name, 0.0) + (time.time() - t0)
        except Exception:
            pass

    def phase_line(self):
        """'rsync=1200.4s src_walk=830.1s ...' ordered slowest-first, plus the share of the
        measured total each phase accounts for. Empty string if nothing was recorded."""
        try:
            if not self.phase_times:
                return ""
            tot = sum(self.phase_times.values()) or 1.0
            parts = sorted(self.phase_times.items(), key=lambda kv: kv[1], reverse=True)
            return " ".join("%s=%.1fs/%.0f%%" % (k, v, 100.0 * v / tot) for k, v in parts)
        except Exception:
            return ""

    def copy_stamp(self, s):
        """Returns True on promote.  Raises nothing; records problems/events itself."""
        started = iso_now()
        src = os.path.join(self.primary_snapdir, s)
        base = self.choose_base(s)
        link_dest = os.path.join(self.replica_snapdir, base) if base else None
        if link_dest and not os.path.isdir(link_dest):
            # 01 C3: a --link-dest that does not exist returns rc 0 and silently produces a full,
            # un-deduplicated copy.  Pre-check here; 5c closes the TOCTOU remainder.
            self.log("base %s vanished before rsync; falling back to a full copy" % base)
            base, link_dest = None, None
        if link_dest and self.bogus_link_dest:
            link_dest += "-SNAP-TEST-BOGUS"          # test knob, gated on SNAP_* redirection

        staging = None
        summary = None
        baseless_retry = False     # 2026-09-05: at most ONE basis-unreadable fallback per stamp
        try:
            staging = self.staging_path(s)
            if self.try_recover_staging(s, base, link_dest, started):
                return True

            staging = self.wipe_staging(s)
            argv = build_copy_argv(src, staging, link_dest, self.inject_flag)
            self.event("copy_started", s, "link_dest=%s" % (base or "none"))
            self.log("copy %s: rsync -a%s (%d file(s) on primary side pending)" %
                     (s, " --link-dest=" + link_dest if link_dest else " (full copy, no base)",
                      len(self.pending)))
            t0 = time.time()
            self.phase_times = {}          # per-copy, so the line describes THIS copy only
            _tp = time.time()
            rc, _out, err = run_rsync(argv)
            self.tmark("rsync", _tp)
            self.crashpoint("after_rsync")
            if is_openrsync_abort(rc, err):
                # DEFENSIVE ONLY.  With -H gone this must not happen; if it does, an openrsync
                # internal assertion fired and the engine is NOT going to reason about the
                # half-written staging dir.  Fail loudly, no retry.
                self.log("copy %s: UNEXPECTED openrsync internal ABORT (rc=%d). -H is not shipped, "
                         "so this is NOT the known C6 defect. Treating as a hard failure."
                         % (s, rc))
                self.note("UNEXPECTED openrsync internal abort while copying %s (rc=%d) - "
                          "investigate; this should not happen now that -H is not shipped"
                          % (s, rc))
            # BASIS-UNREADABLE FALLBACK (2026-09-05).  openrsync can fail rc=11 reading the
            # --link-dest BASIS rather than the source.  Trigger: the basis entry is a SYMLINK and
            # the source entry is a REGULAR FILE -- a symlink->file change between snapshots, which
            # is a routine developer action.  Types differ so it cannot hardlink, it falls through
            # to copy_file using the basis as the read side, and its openat(O_NOFOLLOW) on a symlink
            # returns ELOOP on BSD.  The message reads "Too many levels of symbolic links" but there
            # is NO loop and nothing is corrupt -- O_NOFOLLOW simply refuses a symlink.  openrsync
            # never checks the basis entry is a regular file first (GNU rsync does).  The whole copy
            # aborts, and because base selection is deterministic EVERY retry hits the same entry:
            # observed 7 consecutive failures 05:29-12:15 on 2026-09-05_043549, replica stuck 7.2 h.
            # Fall back to ONE baseless copy.  Self-healing: once this stamp promotes it becomes the
            # next base and holds the regular file, so dedup returns on the following copy.  Cost is
            # this stamp's dedup only.  DO NOT "fix" this by muting the base to skip it -- every
            # candidate back to the symlink's creation carries it, and falling back that far is what
            # produced the 451,391-violator repair storm on 2026-08-26.
            # `base` MUST go None alongside link_dest, or verify_and_audit's 5c dedup assertion
            # would fail a tree that legitimately shares no inode with any base.
            if (rc == 11 and link_dest and not baseless_retry
                    and link_dest.rstrip("/") in (err or "")):
                baseless_retry = True
                for line in [l for l in err.splitlines() if l.strip()][:3]:
                    self.log("  rsync: " + line.strip())
                self.log("copy %s: rsync rc=11 while reading the basis %s -- retrying ONCE with no "
                         "--link-dest (this stamp forgoes dedup; later copies regain it)"
                         % (s, base))
                self.event("baseless_retry", s,
                           "rc=11 against basis %s; retrying without link_dest" % (base or "none"))
                link_dest = None
                base = None
                staging = self.wipe_staging(s)   # 00 F8 2b: wipe-then-create before EVERY rsync
                argv = build_copy_argv(src, staging, None, self.inject_flag)
                _tp = time.time()
                rc, _out, err = run_rsync(argv)
                self.tmark("rsync_baseless", _tp)
                self.crashpoint("after_rsync")
            if rc != 0:
                # openrsync has NO rc=24 (00 F8 step 4 / 01 E6): a vanished file and a TCC denial
                # are the SAME code.  No rc but 0 may be treated as benign.
                for line in [l for l in err.splitlines() if l.strip()][:5]:
                    self.log("  rsync: " + line.strip())
                raise CopyFailure(rc, "rsync rc=%d: %s" % (rc, (err.strip().splitlines() or [""])[0][:200]))

            summary, detail = self.verify_and_audit(s, src, staging, base, link_dest)
            self.promote(s, staging, summary, link_dest, base)
            dt = time.time() - t0
            self.record_attempt(s, started, 0, summary["files"], summary["bytes"], base, detail)
            self.log("copy %s: OK %d file(s) %d byte(s) in %.1fs; %s" %
                     (s, summary["files"], summary["bytes"], dt, detail))
            # Per-phase breakdown, log-only (2026-08-26). `unattributed` is wall time inside the
            # copy that no timer covered -- if it is large, the instrumentation is missing a phase.
            _pl = self.phase_line()
            if _pl:
                _acct = sum(self.phase_times.values())
                self.log("copy %s: phases %s unattributed=%.1fs (%.1f%% of %.1fs total)"
                         % (s, _pl, max(0.0, dt - _acct),
                            100.0 * max(0.0, dt - _acct) / (dt or 1.0), dt))
            self.event("copied", s, "files=%d bytes=%d link_dest=%s; %s" %
                       (summary["files"], summary["bytes"], base or "none", detail))
            self.consume_skip_dedup(s)
            self.consume_force_settle(s)
            self.clear_copy_failure(s)
            return True
        except CopyFailure as cf:
            files = summary["files"] if summary else 0
            nbytes = summary["bytes"] if summary else 0
            self.record_attempt(s, started, cf.rc, files, nbytes, base, cf.detail)
            kind = "copy_failed" if cf.rc > 0 else "verify_failed"
            self.event(kind, s, cf.detail)
            # the P4 problem line itself is derived from last_copy in compute_health(); adding it
            # here too would duplicate the whole detail string in the monitor's red banner
            self.note("staging for %s left in place for forensics" % s)
            self.record_copy_failure(s, cf.rc, cf.detail)
            if self.pass_rc_for_log == 0:
                self.pass_rc_for_log = cf.rc
            self.log("copy %s: FAILED %s" % (s, cf.detail))
            return False
        except OSError as exc:
            self.record_attempt(s, started, -1, 0, 0, base, "os error: %s" % exc)
            self.event("copy_failed", s, "os error: %s" % exc)
            self.record_copy_failure(s, -1, "os error: %s" % exc)
            if self.pass_rc_for_log == 0:
                self.pass_rc_for_log = -1
            return False

    def try_recover_staging(self, s, base, link_dest, started):
        """00 F8 step 6 crash window "after 6a, before 6b": the manifest exists but the stamp is
        still in STAGING.  Re-verify the staging tree in full and promote it; anything less than a
        complete match falls through to the normal wipe+rsync path.  This never rsyncs into an
        inherited staging dir, so 00 F8 2b is not violated."""
        staging = self.staging_path(s)
        man = self.read_manifest(s)
        if man is None or not os.path.isdir(staging):
            return False
        src = os.path.join(self.primary_snapdir, s)
        if not os.path.isdir(src):
            return False
        self.log("recovery: manifest for %s exists and staging survives; re-verifying staging" % s)
        try:
            summary, detail = self.verify_and_audit(s, src, staging, base, link_dest)
        except CopyFailure as cf:
            self.log("recovery: staging for %s did not verify (%s); rebuilding from scratch"
                     % (s, cf.detail))
            return False
        except OSError as exc:
            self.log("recovery: staging for %s unreadable (%s); rebuilding" % (s, exc))
            return False
        self.promote(s, staging, summary, link_dest, base)
        self.consume_skip_dedup(s)
        self.consume_force_settle(s)
        self.clear_copy_failure(s)
        self.record_attempt(s, started, 0, summary["files"], summary["bytes"], base,
                            "recovered from staging; " + detail)
        self.event("copied", s, "recovered pre-verified staging; files=%d bytes=%d; %s"
                   % (summary["files"], summary["bytes"], detail))
        self.log("copy %s: OK (recovered from verified staging) %d file(s)"
                 % (s, summary["files"]))
        return True

    def verify_and_audit(self, s, src, staging, base, link_dest):
        """00 F8 steps 5, 5b, 5c.  Raises CopyFailure with rc=-1 for any engine-side rejection
        (rsync itself returned 0, so -1 is used to make "the attempt failed" unambiguous in
        last_copy.rc and therefore in P4)."""
        _tp = time.time()
        psum = summarize_tree(src, want_inodes=True)
        self.tmark("walk_primary_src", _tp)          # COLD: primary volume, ~2.5 ms/entry probed
        replica_base = os.path.join(self.replica_snapdir, base) if base else None
        _tp = time.time()
        ssum = summarize_tree(staging, dedup_base=replica_base)
        self.tmark("walk_staging", _tp)              # WARM: rsync just wrote this tree

        if (psum["files"], psum["bytes"], psum["listing_md5"]) != \
           (ssum["files"], ssum["bytes"], ssum["listing_md5"]):
            raise CopyFailure(-1, "verify mismatch: files %d/%d bytes %d/%d listing_md5 %s/%s" % (
                psum["files"], ssum["files"], psum["bytes"], ssum["bytes"],
                psum["listing_md5"][:8], ssum["listing_md5"][:8]))

        detail_bits = []

        # =====================================================================================
        # STAGING-MUTATION INVARIANT (G2).  Step 5 above has just proven the staged tree equals
        # the primary.  EVERY mutation of staging from here on MUST be followed by recomputing
        # `ssum` and re-asserting (files, bytes, listing_md5) against `psum` - because the manifest
        # written at promote time is built from `ssum`, so an unverified mutation gets recorded as
        # if it were correct.  That is silent data loss with a certificate attached.
        # There are exactly TWO such mutations in this engine, and no others:
        #     1. the F8.5b `-c --files-from` repair pass   (re-verified below)
        #     2. the intra-snapshot hardlink reconstruction (re-verified below)
        # Audited 2026-08-19 across every write call in the file: `wipe_staging` runs BEFORE the
        # rsync (not after this point), `promote`'s os.rename moves the tree without altering its
        # contents, and every other write targets STATE_DIR, the LOG, the `latest` symlink, or the
        # prune path.  IF YOU ADD A THIRD MUTATION, RE-VERIFY IT HERE TOO.
        # =====================================================================================

        # ---- 5b changed-set inode audit
        repaired = 0
        if base is not None:
            pbase = os.path.join(self.primary_snapdir, base)
            _tp = time.time()
            base_inodes = inode_map(pbase)
            self.tmark("walk_primary_base", _tp)     # COLD: the prime suspect for the real cost
            changed = [rel for rel, ino in psum["inodes"].items()
                       if rel in base_inodes and base_inodes[rel] != ino]
            _tp = time.time()
            violators = []
            for rel in changed:
                try:
                    a = os.stat(os.path.join(staging, rel), follow_symlinks=False).st_ino
                    b = os.stat(os.path.join(replica_base, rel), follow_symlinks=False).st_ino
                except OSError:
                    continue
                if a == b:
                    violators.append(rel)
            self.tmark("audit_changed_stats", _tp)    # 2 stats per CHANGED file (normally tiny)
            if violators:
                violators.sort()
                _tp = time.time()
                repaired = self.repair_violators(s, src, staging, violators)
                self.tmark("repair_violators", _tp)
                still = []
                for rel in violators:
                    try:
                        a = os.stat(os.path.join(staging, rel), follow_symlinks=False).st_ino
                        b = os.stat(os.path.join(replica_base, rel), follow_symlinks=False).st_ino
                    except OSError:
                        continue
                    if a == b:
                        still.append(rel)
                # 01 R4: a fresh-inode-but-IDENTICAL-content file legitimately stays "violating"
                # (it is hardlinked to byte-correct bytes).  Only a real content difference fails.
                bad = []
                for rel in still:
                    try:
                        if file_md5(os.path.join(src, rel)) != file_md5(os.path.join(staging, rel)):
                            bad.append(rel)
                    except (IOError, OSError) as exc:
                        bad.append("%s (%s)" % (rel, exc))
                if bad:
                    raise CopyFailure(-1, "inode audit: %d file(s) still hold stale bytes after "
                                          "repair, first: %s" % (len(bad), bad[0]))
                # re-verify the listing after a repair pass touched the tree
                _tp = time.time()
                ssum = summarize_tree(staging, dedup_base=replica_base)
                self.tmark("reverify_after_repair", _tp)
                if (psum["files"], psum["bytes"], psum["listing_md5"]) != \
                   (ssum["files"], ssum["bytes"], ssum["listing_md5"]):
                    raise CopyFailure(-1, "verify mismatch after inode-audit repair")
            detail_bits.append("audit changed=%d violators=%d repaired=%d"
                               % (len(changed), len(violators), repaired))
        else:
            detail_bits.append("audit skipped (no base)")

        # ---- INTRA-SNAPSHOT HARDLINK GROUPS.  THIS IS THE PRIMARY MECHANISM (00 F8.3 as amended
        # 2026-08-19: `-H` IS NOT SHIPPED; the engine reconstructs the groups itself).
        # The primary's inode map is ground truth: two relpaths inside S sharing one inode are
        # provably the same bytes and MUST share one inode on the replica, or the split propagates
        # forward through every later --link-dest as cumulative, permanent inode/space waste.
        # Strictly stronger than -H: it also SELF-HEALS a group an earlier pass (or an earlier
        # engine, or a -H-less copy) left split, which -H only does when rsync elects to relink.
        # A group still split after reconstruction is a hard verify failure (post-condition below).
        groups = {}
        for rel, ino in psum["inodes"].items():
            groups.setdefault(ino, []).append(rel)
        groups = dict((k, sorted(v)) for k, v in groups.items() if len(v) > 1)
        relinked = 0
        for _ino, rels in sorted(groups.items()):
            keep = os.path.join(staging, rels[0])
            try:
                kino = os.stat(keep, follow_symlinks=False).st_ino
            except OSError as exc:
                raise CopyFailure(-1, "intra-snapshot hardlink audit: %s missing in staging (%s)"
                                  % (rels[0], exc))
            for rel in rels[1:]:
                path = os.path.join(staging, rel)
                try:
                    if os.stat(path, follow_symlinks=False).st_ino == kino:
                        continue
                except OSError as exc:
                    raise CopyFailure(-1, "intra-snapshot hardlink audit: %s missing in staging "
                                      "(%s)" % (rel, exc))
                # G1: the temp relpath is proven absent from the SOURCE listing, so this can
                # never destroy a real file that came from the primary.
                tmp = relink_tmp_path(staging, rel, psum["paths"])
                try:
                    os.link(keep, tmp)
                    os.replace(tmp, path)      # unlink-then-rename: never writes through an inode
                    relinked += 1
                except OSError as exc:
                    try:
                        if os.path.lexists(tmp):
                            os.unlink(tmp)     # only ever the link we just made, never source data
                    except OSError:
                        pass
                    raise CopyFailure(-1, "intra-snapshot hardlink repair failed for %s: %s"
                                      % (rel, exc))
        for _ino, rels in sorted(groups.items()):     # post-condition, always checked
            inos = set()
            for rel in rels:
                try:
                    inos.add(os.stat(os.path.join(staging, rel), follow_symlinks=False).st_ino)
                except OSError:
                    inos.add(None)
            if len(inos) != 1:
                raise CopyFailure(-1, "intra-snapshot hardlink group %s is still split in staging "
                                      "(%d distinct inodes)" % (rels[0], len(inos)))
        if groups:
            detail_bits.append("intra-groups=%d relinked=%d" % (len(groups), relinked))
        if relinked:
            # NO notes[] entry: reconstructing intra-snapshot groups is now the engine's NORMAL
            # mechanism (00 F8.3, -H not shipped), so it must not turn the monitor amber every time
            # an `npm i` lands a hardlink farm on the Desktop.  It is recorded in the LOG and in
            # last_copy.detail.  notes[] is reserved for things that are NOT routine.
            self.log("audit %s: reconstructed %d intra-snapshot hardlink(s) from the primary's "
                     "inode map" % (s, relinked))
            # relinking changes nlink and can move a path off the base inode, so the 5c evidence
            # below must be recomputed rather than reused from before the repair
            _tp = time.time()
            ssum = summarize_tree(staging, dedup_base=replica_base)
            self.tmark("reverify_after_relink", _tp)
            # STAGING-MUTATION INVARIANT (G2): staging was just mutated, so the listing is
            # re-asserted before `ssum` is allowed to become the manifest.  Sibling of the
            # "verify mismatch after inode-audit repair" check above.
            if (psum["files"], psum["bytes"], psum["listing_md5"]) != \
               (ssum["files"], ssum["bytes"], ssum["listing_md5"]):
                raise CopyFailure(-1, "verify mismatch after intra-snapshot hardlink "
                                      "reconstruction: files %d/%d bytes %d/%d listing_md5 %s/%s"
                                  % (psum["files"], ssum["files"], psum["bytes"], ssum["bytes"],
                                     psum["listing_md5"][:8], ssum["listing_md5"][:8]))

        # ---- 5c DEDUP ASSERTION (00 F8.5c as amended by C7).  A --link-dest pointing nowhere
        # returns rc 0 and produces a byte-perfect but completely UN-deduplicated copy that nothing
        # in step 5 can see.  THE ASSERTION IS INODE IDENTITY AGAINST THE REPLICA BASE:
        # at least one staged file must share an inode with its counterpart in the base.
        # `st_nlink > 1` is DIAGNOSTIC ONLY and never gates promotion - it is defeatable, and was
        # measured being defeated: once the engine reconstructs intra-snapshot hardlink groups, one
        # such group inside a wholly un-deduplicated snapshot supplies nlink>1 by itself.
        if link_dest is not None:
            if not ssum["linked_to_base"]:
                mark = self.skip_dedup.get(s)
                if mark is not None:
                    # Operator override (monitor.py POST /api/control/skip-dedup), NOT a routine
                    # exception -- this deliberately does not touch step 5's content verification
                    # (file count/bytes/listing_md5 above), which still applies in full. Only the
                    # "at least one shared inode" heuristic is exempted, and only for a stamp a
                    # human or agent explicitly marked. Consumed (one-time) by the caller once
                    # promotion actually succeeds -- see copy_stamp().
                    self.log("copy %s: dedup assertion SKIPPED by operator override (%s)"
                             % (s, mark.get("reason") or "no reason given"))
                    detail_bits.append(
                        "dedup assertion SKIPPED by operator override (reason: %s) - staged tree "
                        "has %d file(s) with nlink>1; content verify (step 5) still passed in full"
                        % (mark.get("reason") or "none given", ssum["nlink_gt1"]))
                else:
                    raise CopyFailure(
                        -1, "dedup assertion FAILED: link_dest=%s was in effect but NO staged file "
                            "shares an inode with the base - the link-dest silently did nothing "
                            "(00 F8.5c / 01 C3). For the record the staged tree does have %d file(s) "
                            "with nlink>1, which is exactly why that test alone is not the assertion "
                            "(C7)." % (link_dest, ssum["nlink_gt1"]))
            else:
                detail_bits.append("dedup ok (shares inode(s) with base; nlink>1: %d)"
                                   % ssum["nlink_gt1"])
        if repaired:
            self.note("inode audit repaired %d stale-hardlink file(s) in %s (FINDINGS F2 window)"
                      % (repaired, s))
        return ssum, "; ".join(detail_bits)

    def repair_violators(self, s, src, staging, violators):
        """00 F8.5b repair pass, 01 R3 spelling (NUL-delimited list)."""
        fd, list_path = tempfile.mkstemp(prefix="filesfrom-", dir=self.state_dir)
        try:
            with os.fdopen(fd, "wb") as fh:
                for rel in violators:
                    fh.write(rel.encode("utf-8", "surrogateescape") + b"\0")
            argv = build_repair_argv(src, staging, list_path, self.inject_flag)
            self.log("audit %s: %d violator(s) hardlinked to stale base bytes; running "
                     "targeted `rsync -a -c -0 --files-from`" % (s, len(violators)))
            rc, _out, err = run_rsync(argv)
            if rc != 0:
                raise CopyFailure(rc, "inode-audit repair rsync rc=%d: %s"
                                  % (rc, (err.strip().splitlines() or [""])[0][:200]))
            return len(violators)
        finally:
            try:
                os.unlink(list_path)
            except OSError:
                pass

    def promote(self, s, staging, summary, link_dest, base):
        """00 F8 step 6: manifest, THEN rename, THEN event.  The ordering is load-bearing."""
        # C12: fingerprint the VERIFIED staging tree before it is published.  This is the only
        # moment the engine can honestly record "these bytes equalled the primary".
        # `summary` is the FINAL staging summary from verify_and_audit -- recomputed after every
        # G2 mutation -- so its sample_pool describes exactly the tree that was just verified.
        _tp = time.time()
        samples = sample_hashes(staging, s, pool=summary.get("sample_pool"))
        self.tmark("sample_hashes", _tp)   # now pool-fed: 200 md5s, no walk. Was walk + 200 md5s.
        _tp = time.time()
        self.write_manifest(s, summary, base, samples)   # 6a
        self.tmark("write_manifest", _tp)
        self.crashpoint("after_manifest")
        os.rename(staging, os.path.join(self.replica_snapdir, s))   # 6b atomic, same filesystem
        self.crashpoint("after_rename")
        self.forget_staging(s)
        if s not in self.replica_snapshots:
            self.replica_snapshots.append(s)
            self.replica_snapshots.sort()

    # ---------------------------------------------------------------- latest reconcile (00 F8.7)

    def reconcile_latest(self):
        if not self.replica_mounted or not self.replica_snapshots:
            return
        promoted = set(self.replica_snapshots)
        want = None
        if self.latest_primary and not self.latest_primary_dangling \
                and self.latest_primary in promoted:
            want = self.latest_primary
        else:
            want = self.replica_snapshots[-1]
        if want == self.latest_replica and \
                os.path.isdir(os.path.join(self.replica_snapdir, want)):
            return
        tmp = os.path.join(self.replica_snapdir, ".latest.tmp-%d" % self.pid)
        try:
            if os.path.islink(tmp) or os.path.exists(tmp):
                os.unlink(tmp)
            os.symlink(want, tmp)
            os.rename(tmp, os.path.join(self.replica_snapdir, LATEST))
            self.latest_replica = want
            self.log("latest: replica latest -> %s" % want)
        except OSError as exc:
            self.problem("P4 could not update replica latest -> %s: %s" % (want, exc))
            try:
                os.unlink(tmp)
            except OSError:
                pass

    # ---------------------------------------------------------------- prune (00 F8)

    def check_wipe_alarm(self):
        """00 F5 P9.  Deliberately NOT inside prune(): prune is gated on the primary having >=3
        stamps, and a primary WIPE is exactly the case that leaves fewer than three.  Gating the
        alarm behind the prune preconditions would silence it in the only scenario it exists for."""
        if not (self.primary_mounted and self.replica_mounted):
            return
        primary_set = set(self.primary_snapshots)
        for s in self.replica_snapshots:
            if s in primary_set:
                continue
            age = stamp_age_days(s)
            if age <= PRUNE_AGE_DAYS:
                self.problem("P9 replica-only stamp %s (%.1f days old, < %d) is missing from the "
                             "primary: possible primary data loss - RETAINED, not pruned"
                             % (s, age, PRUNE_AGE_DAYS))

    def prune(self):
        if not (self.primary_mounted and self.replica_mounted):
            return
        if len(self.primary_snapshots) < 3:
            return
        primary_set = set(self.primary_snapshots)
        cands = []
        for s in self.replica_snapshots:
            if s in primary_set or s == self.latest_replica:
                continue
            if stamp_age_days(s) > PRUNE_AGE_DAYS:
                cands.append(s)
        if not cands:
            return
        cands.sort()
        doing = cands[:MAX_PRUNES_PER_PASS]
        if len(cands) > MAX_PRUNES_PER_PASS:
            self.note("prune rate limit: %d stamp(s) eligible, pruning the %d oldest this pass"
                      % (len(cands), MAX_PRUNES_PER_PASS))
        for s in doing:
            path = os.path.join(self.replica_snapdir, s)
            try:
                rmtree(path)
            except OSError as exc:
                self.problem("P4 prune of %s failed: %s" % (s, exc))
                continue
            man = self.manifest_path(s)
            if os.path.exists(man):
                os.makedirs(self.pruned_manifest_dir, exist_ok=True)
                try:
                    os.replace(man, os.path.join(self.pruned_manifest_dir, s + ".json"))
                except OSError:
                    pass
            if s in self.replica_snapshots:
                self.replica_snapshots.remove(s)
            self.log("pruned %s (older than %d days, absent from primary)" % (s, PRUNE_AGE_DAYS))
            self.event("pruned", s, "age > %d days and absent from primary" % PRUNE_AGE_DAYS)

    # ---------------------------------------------------------------- deep verify (00 F9)
    # (The primary-side attribution walker lived here until 2026-08-26: it existed ONLY to
    #  feed the P6/P7 whole-volume delta comparison and was deleted with it -- PLAN A4/F13.
    #  Its 1-2 full primary walks per pass go with it.)

    def monthly_verify_due(self, promoted_now):
        """True when this mirror pass just promoted an early-morning stamp AND the last
        successful sweep is at least DEEP_VERIFY_MIN_INTERVAL_HOURS old (or never ran).
        Pure decision helper -- never raises, never writes."""
        try:
            early = [s for s in promoted_now
                     if len(s) >= 13 and s[11:13].isdigit()
                     and int(s[11:13]) in DEEP_VERIFY_EARLY_HOURS]
            if not early:
                return False
            ok_ts = self.persist.get("last_deep_verify_ok_ts")
            if not ok_ts:
                return True
            t = time.mktime(time.strptime(ok_ts[:19], "%Y-%m-%dT%H:%M:%S"))
            return (time.time() - t) / 3600.0 >= DEEP_VERIFY_MIN_INTERVAL_HOURS
        except Exception:
            return False

    def deep_verify(self):
        # RETRY-WINDOW GUARD (2026-08-26).  The nightly deep-verify used to be a single
        # 03:15 shot that shares mirror.pid with the mirror lane, so one collision with an
        # in-flight copy (exit 79) silently lost the ENTIRE night -- no retry, no event, no
        # log line, and P13 stays quiet for 8 days.  That happened on 2026-08-26.
        # The launchd job now has extra windows (03:15 / 07:15 / 15:15); this guard is what
        # makes them retries rather than repeats, since a sweep is several full tree walks
        # per target and must not run again just because the first window succeeded.
        ok_ts = self.persist.get("last_deep_verify_ok_ts")
        # SNAP_FORCE_DEEP_VERIFY=1 lets an operator run a sweep by hand before the month is up.
        if ok_ts and os.environ.get("SNAP_FORCE_DEEP_VERIFY") != "1":
            try:
                t = time.mktime(time.strptime(ok_ts[:19], "%Y-%m-%dT%H:%M:%S"))
            except ValueError:
                t = None
            if t is not None:
                age_h = (time.time() - t) / 3600.0
                if age_h < DEEP_VERIFY_MIN_INTERVAL_HOURS:
                    self.log("deep-verify: skipped, last successful sweep was %.1f h ago "
                             "(< %.0f h retry-window guard)"
                             % (age_h, DEEP_VERIFY_MIN_INTERVAL_HOURS))
                    return
        if not self.replica_mounted:
            self.record_deep("fail", [], "replica not mounted")
            return
        promoted = list(self.replica_snapshots)
        if not promoted:
            # P13 deliberately does NOT clear here: verifying nothing is not evidence that the
            # content safety net works.  record_deep only stamps last_deep_verify_ok_ts when at
            # least one snapshot was actually checked.
            self.record_deep("pass", [], "no promoted snapshots to verify")
            return
        targets = [promoted[-1]]
        older = promoted[:-1]
        if older:
            # COVERAGE-DRIVEN ROTATION.  Verifying ONE older snapshot per day is only
            # adequate while the archive holds about as many snapshots as the retention
            # window has days.  When the writer's cadence rises, a fixed count silently
            # guts the safety net:
            #
            #   1 backup/day  -> 90 snapshots, full sweep 90d  == 90d lifetime -> 100% ever verified
            #   4 backups/day -> 360 snapshots, full sweep 360d >> 90d lifetime ->  25% ever verified
            #
            # i.e. three quarters of snapshots would be pruned having NEVER had their
            # content checked, and sampled content hashing is the only thing that detects
            # bit rot or a mirror copy that was already wrong.  So scale the rotation to
            # finish a full sweep within the retention window instead of fixing it at one.
            per_pass = max(1, int(math.ceil(len(older) / float(VERIFY_SWEEP_DAYS))))
            want = per_pass
            per_pass = min(per_pass, VERIFY_MAX_OLDER_PER_PASS, len(older))
            if want > VERIFY_MAX_OLDER_PER_PASS:
                # The cost ceiling is binding, so a full sweep will take longer than
                # VERIFY_SWEEP_DAYS and some snapshots WILL age out unverified. Say so:
                # a safety net that quietly shrinks is worse than one that reports it.
                self.note("deep-verify coverage degraded: %d older snapshot(s) would need "
                          "checking per pass to sweep all %d within %d days, but the cost "
                          "ceiling allows %d -- full sweep now ~%.0f days, so some snapshots "
                          "may be pruned unverified. Raise VERIFY_MAX_OLDER_PER_PASS or "
                          "shorten retention."
                          % (want, len(older), VERIFY_SWEEP_DAYS, VERIFY_MAX_OLDER_PER_PASS,
                             len(older) / float(VERIFY_MAX_OLDER_PER_PASS)))
            doy = datetime.date.today().timetuple().tm_yday
            start = (doy * per_pass) % len(older)
            for k in range(per_pass):
                cand = older[(start + k) % len(older)]
                if cand not in targets:
                    targets.append(cand)
        details = []
        ok = True
        for s in targets:
            good, detail = self.deep_verify_one(s)
            details.append("%s: %s" % (s, detail))
            if not good:
                ok = False
                self.event("verify_failed", s, "deep-verify: " + detail)
        self.record_deep("pass" if ok else "fail", targets, "; ".join(details))

    def deep_verify_one(self, s):
        rpath = os.path.join(self.replica_snapdir, s)
        ppath = os.path.join(self.primary_snapdir, s)
        have_primary = self.primary_mounted and os.path.isdir(ppath)
        try:
            rsum = summarize_tree(rpath)
        except OSError as exc:
            return False, "replica tree unreadable: %s" % exc
        man = self.read_manifest(s)

        if have_primary:
            try:
                psum = summarize_tree(ppath)
            except OSError as exc:
                return False, "primary tree unreadable: %s" % exc
            if (psum["files"], psum["bytes"], psum["listing_md5"]) != \
               (rsum["files"], rsum["bytes"], rsum["listing_md5"]):
                return False, ("listing mismatch vs primary: files %d/%d bytes %d/%d"
                               % (psum["files"], rsum["files"], psum["bytes"], rsum["bytes"]))
        elif man:
            if (man.get("files"), man.get("bytes"), man.get("listing_md5")) != \
               (rsum["files"], rsum["bytes"], rsum["listing_md5"]):
                return False, ("listing mismatch vs stored manifest: files %s/%d bytes %s/%d"
                               % (man.get("files"), rsum["files"], man.get("bytes"), rsum["bytes"]))
        else:
            return False, "primary copy pruned and no manifest to verify against"

        sampled = 0
        if have_primary:
            files = [rel for rel, kind, size, _t, _st in walk_tree(rpath)
                     if kind == "f" and size <= DEEP_SAMPLE_MAX_BYTES]
            files.sort()
            if self.verify_sample_all:
                pick = files
            else:
                rnd = random.Random(s + "|" + datetime.date.today().isoformat())
                pick = files if len(files) <= DEEP_SAMPLE_FILES \
                    else rnd.sample(files, DEEP_SAMPLE_FILES)
            for rel in pick:
                try:
                    if file_md5(os.path.join(ppath, rel)) != file_md5(os.path.join(rpath, rel)):
                        return False, "content md5 mismatch on %s" % rel
                except (IOError, OSError) as exc:
                    return False, "content read failed on %s: %s" % (rel, exc)
                sampled += 1
        else:
            # C12: the primary copy is gone (pruned at 90 days by the writer).  The stored manifest
            # sample is the ONLY thing that can still catch replica-side bit rot here - the listing
            # comparison above cannot see a same-size content change.
            stored = (man or {}).get("samples") or {}
            for rel in sorted(stored):
                try:
                    got = file_md5(os.path.join(rpath, rel))
                except (IOError, OSError) as exc:
                    return False, "stored-sample file unreadable: %s (%s)" % (rel, exc)
                if got != stored[rel]:
                    return False, ("content md5 mismatch vs stored manifest sample on %s "
                                   "(replica-side corruption: the listing still matches)" % rel)
                sampled += 1
            if not stored:
                self.note("stamp %s can only be listing-verified: its primary copy is pruned and "
                          "its manifest predates stored content samples" % s)
                return True, ("ok (%d file(s), LISTING ONLY - primary copy pruned and the manifest "
                              "has no stored content samples)" % rsum["files"])

        # Backfill.  Samples are only trustworthy when recorded against a tree just proven equal to
        # the primary, so backfilling is gated on have_primary: recording a pruned stamp's current
        # replica bytes would enshrine whatever rot is already there as the reference.
        if have_primary and (man is None or "samples" not in man):
            self.write_manifest(s, rsum, (man or {}).get("link_dest"), sample_hashes(rpath, s))
            return True, "ok (%d file(s), %d sampled, manifest %s)" % (
                rsum["files"], sampled,
                "backfilled" if man is None else "samples backfilled (C12)")
        return True, "ok (%d file(s), %d sampled)" % (rsum["files"], sampled)

    def record_deep(self, result, snapshots, detail):
        self.last_deep_verify = {"ts": iso_now(), "snapshots": list(snapshots),
                                 "result": result, "detail": detail[:800]}
        self.persist["last_deep_verify"] = self.last_deep_verify
        if result == "pass" and snapshots:
            self.persist["last_deep_verify_ok_ts"] = self.last_deep_verify["ts"]
        write_json(self.persist_path, self.persist)
        self.log("deep-verify %s: %s" % (result, detail[:400]))

    # ---------------------------------------------------------------- health (00 F5)

    def problem(self, text):
        if text not in self.problems:
            self.problems.append(text)

    def note(self, text):
        if text not in self.notes:
            self.notes.append(text)

    def compute_enabled(self):
        """On/off switch.  A manual override (written only by this engine's own "enable"/
        "disable" mode, never by handshake.py) always wins and persists through automatic
        handshake changes -- a deliberate pause must never be silently undone by a reconnect.
        Absent an override, follow handshake.json (written only by handshake.py).  If that state
        is missing or older than HANDSHAKE_STALE_SEC, FAIL OPEN: assume reachable and run
        normally, but say so loudly.  A backup system must never silently stop protecting data
        because its own connectivity watchdog died -- "an absent safety net is a problem, not a
        neutral state" (00 F5 P13's own rationale, applied here to the switch itself)."""
        override = self.control_override.get("override")
        if override in ("on", "off"):
            self.enabled_source = "manual"
            return override == "on"
        last_check = parse_ts(self.handshake.get("last_check"))
        if last_check is None or (time.time() - last_check.timestamp()) > HANDSHAKE_STALE_SEC:
            self.note("handshake state is missing or stale (last_check=%s) -- assuming reachable "
                      "and running normally; the connectivity watchdog may be down"
                      % (self.handshake.get("last_check") or "never"))
            self.enabled_source = "handshake-stale-failopen"
            return True
        self.enabled_source = "handshake"
        return bool(self.handshake.get("reachable", True))

    def check_state_file_integrity(self):
        """S11: an operator-decision state file that EXISTS but cannot be parsed must be loud.
        read_json's silent {} default would otherwise erase every recorded decision at once
        (one truncated muted.json and every mute ceases to exist, with no row left to miss);
        the corrupt retry-request.json case is raised at its consume point instead, because
        only the re-read there sees the file's current bytes."""
        if getattr(self, "muted_parse_error", False):
            self.problem("muted.json exists but cannot be parsed: every per-snapshot mute is "
                         "suspended until the file is fixed or removed (%s)" % self.muted_path)
        if getattr(self, "muted_lines_parse_error", False):
            self.problem("muted-lines.json exists but cannot be parsed: every line mute is "
                         "suspended until the file is fixed or removed (%s)"
                         % self.muted_lines_path)

    def check_failure_pattern(self):
        """M1 escalation: quiet individual supersedes must still ADD UP to an alarm. Counts
        DISTINCT stamps whose failure record -- INCLUDING superseded ones, that is the whole
        point -- is younger than PATTERN_FAIL_WINDOW_DAYS; at PATTERN_FAIL_MIN the operator
        learns even though each individual failure was quietly closed by a later success.
        "P4 PATTERN" shares P4's mutable prefix, so problem_is_muted() excludes it explicitly,
        exactly like "P4 SYSTEMIC"; supersede never touches it (it is derived, not stored)."""
        fails = self.persist.get("failed_copies") or {}
        recent = set()
        for k, v in fails.items():
            dt = parse_ts(v.get("ts")) if isinstance(v, dict) else None
            if dt is not None:
                age_days = (time.time() - dt.timestamp()) / 86400.0
            else:
                try:
                    age_days = stamp_age_days(k)   # record ts unusable: date the stamp itself
                except ValueError:
                    continue
            if age_days <= PATTERN_FAIL_WINDOW_DAYS:
                recent.add(k)
        if len(recent) >= PATTERN_FAIL_MIN:
            self.problem("P4 PATTERN: %d distinct stamps failed to copy within %d days (%s) - "
                         "each may have been superseded by a later success, but this many in a "
                         "week is a recurring fault, not noise; check the log before trusting "
                         "the green board"
                         % (len(recent), PATTERN_FAIL_WINDOW_DAYS, ", ".join(sorted(recent))))

    def check_manifest_ledger(self):
        """M6 tripwire -- the one irreplaceable thing the deleted P6/P7 volume-delta used to
        cover: deletion of a promoted snapshot OUT FROM UNDER the engine (e.g. an rm on the
        DAS of a replica-only stamp whose primary copy is long pruned -- nothing else would
        ever notice). Every top-level manifests/<stamp>.json is a standing promise "this stamp
        was promoted and lives on the replica"; prune() moves a pruned stamp's manifest into
        manifests/pruned/, so a top-level manifest whose replica dir is GONE means the dir was
        deleted outside the engine. Volume-class: the problem's code word ("promoted") is not
        in MUTABLE_CODES so a per-snapshot mute can never silence it, and supersede cannot
        touch it. Runs only while the replica is mounted -- an unmounted volume must never
        read as a deletion. Set-difference on listings already in hand; zero extra I/O beyond
        one listdir of the local manifests/ dir."""
        if not self.replica_mounted:
            return
        try:
            names = os.listdir(self.manifest_dir)
        except OSError:
            return
        replica = set(self.replica_snapshots)
        staged = set(getattr(self, "incoming", None) or [])
        primary = set(self.primary_snapshots)
        for n in sorted(names):
            if not n.endswith(".json") or not STAMP_RE.match(n[:-5]):
                continue
            s = n[:-5]
            if s in replica:
                continue
            if s in staged:
                continue    # promote crash window (manifest written, rename pending):
                            # try_recover_staging() owns this case, not the tripwire
            if self.primary_mounted and s not in primary \
                    and stamp_age_days(s) > PRUNE_AGE_DAYS:
                # Consistent with a COMPLETED prune whose manifest move failed (prune() logs
                # that OSError): finish the bookkeeping move instead of false-alarming forever.
                # Bookkeeping-only -- no snapshot data is touched.
                try:
                    os.makedirs(self.pruned_manifest_dir, exist_ok=True)
                    os.replace(self.manifest_path(s),
                               os.path.join(self.pruned_manifest_dir, s + ".json"))
                    self.log("manifest ledger: moved stale manifest for pruned %s to pruned/" % s)
                    continue
                except OSError:
                    pass
            self.problem("promoted snapshot %s is MISSING from the replica "
                         "(deleted outside the engine)" % s)

    def _newer_healthy_promote_exists(self, s):
        """F2's alternative guard for the defensive last-copy P4 fallback, health-gated per
        M1: True iff a promoted replica stamp newer than `s` exists whose manifest passes the
        supersede health gate (a void newer promote must not quiet the fallback)."""
        for cand in sorted(getattr(self, "replica_snapshots", None) or [], reverse=True):
            if cand <= s:
                return False
            man = self.read_manifest(cand)
            files = man.get("files") if isinstance(man, dict) else None
            if self.supersede_health_ok(files, exclude=cand):
                return True
        return False

    def compute_health(self):
        self.check_state_file_integrity()
        if not self.enabled:
            # On/off switch: paused. Only checks that matter regardless of pause state run --
            # everything about "is copying keeping up" (P4/P10/P14/P15) is suppressed,
            # since falling behind is the deliberate, expected state while paused, not a fault.
            self.note("backup system is PAUSED (%s) -- new snapshots will not be copied until "
                      "re-enabled" % self.enabled_source)
            if not self.primary_mounted:
                self.problem("P1 primary volume not mounted (%s missing)" % self.primary_snapdir)
            if not self.replica_mounted:
                self.problem("P1 replica volume not mounted (%s missing)" % self.replica_snapdir)
            min_kb = self.min_free_gb * 1024 * 1024
            for label, mounted, st in (("primary", self.primary_mounted, self.stat_primary),
                                       ("replica", self.replica_mounted, self.stat_replica)):
                if mounted and st["free_kb"] < min_kb:
                    self.problem("P8 %s volume has only %.1f GB free (< %.0f GB)"
                                 % (label, st["free_kb"] / 1048576.0, self.min_free_gb))
            self.check_wipe_alarm()   # P9 -- arguably MORE important while paused: verify isn't running either
            self.check_manifest_ledger()   # M6 -- same reasoning as P9: deletion detection never pauses
            return
        # P1
        if not self.primary_mounted:
            self.problem("P1 primary volume not mounted (%s missing)" % self.primary_snapdir)
        if not self.replica_mounted:
            self.problem("P1 replica volume not mounted (%s missing)" % self.replica_snapdir)

        if self.primary_mounted:
            # P2
            if self.latest_primary is None:
                self.problem("P2 primary `latest` symlink is missing (%s)"
                             % os.path.join(self.primary_snapdir, LATEST))
            elif self.latest_primary_dangling:
                self.problem("P2 primary `latest` is dangling -> %s" % self.latest_primary)
            # P3 / empty primary
            if not self.primary_snapshots:
                self.problem("primary has no snapshots (%s is empty)" % self.primary_snapdir)
            else:
                newest = self.primary_snapshots[-1]
                age_cal = (datetime.date.today() - stamp_dt(newest).date()).days
                if age_cal >= PRIMARY_STALE_DAYS:
                    self.problem("P3 newest primary snapshot %s is %d calendar day(s) old"
                                 % (newest, age_cal))
        # P4 : PER-STAMP, because the copy loop continues past a failure and a later success of a
        # DIFFERENT stamp must never bury an earlier one -- except by the sanctioned A1 route:
        # a record closed as superseded_by a later HEALTH-GATED success is history, not an open
        # failure, so P4 derives only from the still-open records.
        self.gc_copy_failures()
        all_fails = self.persist.get("failed_copies") or {}
        fails = dict((k, v) for k, v in all_fails.items()
                     if not (isinstance(v, dict) and v.get("superseded_by")))
        if fails:
            stamps = sorted(fails)
            oldest = fails[stamps[0]]
            if len(stamps) == 1:
                self.problem("P4 snapshot %s failed to copy and is still missing from the replica: "
                             "rc=%s %s" % (stamps[0], oldest.get("rc"), oldest.get("detail") or ""))
            else:
                self.problem("P4 %d snapshots have failed to copy and are still missing from the "
                             "replica (%s); oldest %s: rc=%s %s"
                             % (len(stamps), ", ".join(stamps), stamps[0], oldest.get("rc"),
                                oldest.get("detail") or ""))
        elif self.last_copy and self.last_copy.get("rc") != 0:
            # defensive: a failed attempt with no OPEN ledger entry (state predating the ledger).
            # F2 guard: after the gc backstop supersedes the record, this fallback must not
            # resurrect the same failure -- skip when last_copy's stamp is superseded, or when a
            # newer health-gated promote exists (the ledger-less equivalent of superseded).
            lc_stamp = self.last_copy.get("snapshot")
            if not (lc_stamp and (self._is_superseded(lc_stamp)
                                  or self._newer_healthy_promote_exists(lc_stamp))):
                self.problem("P4 most recent copy attempt (%s) did not succeed: rc=%s %s"
                             % (self.last_copy.get("snapshot"), self.last_copy.get("rc"),
                                self.last_copy.get("detail") or ""))
        # SYSTEMIC escalation: every stamp we tried this pass failed.  One bad snapshot is one bad
        # file; ALL of them failing is a volume-level fault (TCC, unmounted mid-pass, full disk,
        # permissions) and must not read as N independent per-stamp notes.  Requires >=2 attempts:
        # with a single pending stamp "all failed" and "one failed" are the same observation.
        if self.copies_attempted >= 2 and self.copies_failed == self.copies_attempted:
            self.problem("P4 SYSTEMIC: ALL %d pending snapshots failed to copy in this pass. This "
                         "is a volume-level fault, not one bad snapshot - check TCC/permissions, "
                         "that both volumes are still mounted, and free space before looking at "
                         "any individual stamp" % self.copies_attempted)
        # P4 PATTERN (M1): counted over ALL failure records including superseded ones, so quiet
        # per-stamp supersedes cannot hide a recurring fault.
        self.check_failure_pattern()
        # P5
        if self.last_deep_verify and self.last_deep_verify.get("result") == "fail":
            self.problem("P5 last deep-verify FAILED: %s" % (self.last_deep_verify.get("detail")))
        # P6/P7 (whole-volume used-KB / inode-delta comparison) DELETED 2026-08-26 -- PLAN A4,
        # owner requirement R5, both directions: the drives are mixed-use, so nothing may ever
        # compare primary vs replica volume totals again. Per-snapshot proof (copy verify, P9,
        # P4, deep-verify) plus check_manifest_ledger() below cover what P6/P7 actually caught.
        # P8
        min_kb = self.min_free_gb * 1024 * 1024
        for label, mounted, st in (("primary", self.primary_mounted, self.stat_primary),
                                   ("replica", self.replica_mounted, self.stat_replica)):
            if mounted and st["free_kb"] < min_kb:
                self.problem("P8 %s volume has only %.1f GB free (< %.0f GB)"
                             % (label, st["free_kb"] / 1048576.0, self.min_free_gb))
        # P13 / P14 / P15 / P16
        self.check_deep_verify_age()
        self.check_stuck_copy()
        self.check_pending_age()
        self.check_rate_limit_denial()
        # P9
        self.check_wipe_alarm()
        # manifest-ledger tripwire (M6)
        self.check_manifest_ledger()
        # P10
        now = time.time()
        for name in self.incoming:
            p = os.path.join(self.staging_root, name)
            created = self.staging_meta.get(name)
            if created:
                try:
                    t = time.mktime(time.strptime(created[:19], "%Y-%m-%dT%H:%M:%S"))
                except ValueError:
                    t = now
            else:
                try:
                    t = os.stat(p).st_ctime
                except OSError:
                    t = now
            hours = (now - t) / 3600.0
            if hours > STALE_STAGING_HOURS and not self.mirror_running:
                self.problem("P10 staging entry %s has been present for %.1f h with no copy "
                             "running (stuck staging)" % (name, hours))
        # P11 / orphan notes
        if self.orphan_partial:
            hours = stamp_age_hours(self.orphan_partial)
            if hours > ORPHAN_FAIL_HOURS:
                self.problem("P11 orphan partial snapshot %s on the primary is %.1f h old "
                             "(newest stamp is not the `latest` target)"
                             % (self.orphan_partial, hours))
            elif hours >= ORPHAN_WARN_HOURS:
                self.note("orphan partial %s on the primary is %.1f h old"
                          % (self.orphan_partial, hours))
        # P12
        for s in self.corpses:
            self.problem("P12 CORPSE on primary: %s was seen above `latest`, never was `latest`, "
                         "and `latest` has advanced past it. A writer backup run died mid-write "
                         "and left a truncated snapshot dir. NEVER copied." % s)
        # notes
        if self.pending:
            self.note("%d snapshot(s) pending copy: %s"
                      % (len(self.pending), ", ".join(self.pending[:5])))
        if self.mirror_running:
            self.note("a copy is in progress")
        if self.unsettled:
            newest_unsettled = self.unsettled[-1]
            if newest_unsettled not in self.corpses and \
                    stamp_age_hours(newest_unsettled) < ORPHAN_WARN_HOURS:
                self.note("snapshot %s is unsettled (in progress on the writer)"
                          % newest_unsettled)
        if self.refused_force_settle:
            # Loud, not silent (00 F5's own standard): a force-settle mark that did nothing with
            # no explanation is exactly the confusing dead-end this note exists to prevent.
            self.note("force-settle REFUSED for %s: not proven to be a completed upload "
                      "(never observed as primary `latest` -- may genuinely still be mid-write); "
                      "remove the mark or wait for it to become was_latest legitimately"
                      % ", ".join(self.refused_force_settle))
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft != resource.RLIM_INFINITY and soft < 1024:
            # 01 C4: RECORD, never abort.  openrsync completed a 150k-file -aH --link-dest pass at
            # ulimit -n 256, so aborting here would refuse a copy that would have succeeded.
            self.note("open-file soft limit is only %d (ENTRYPOINT raises it to 65535)" % soft)

        # LAST, after every P-rule has run: an operator MUTE is applied to the finished problem
        # set, never to the rules that build it. Keeping it terminal means a muted stamp cannot
        # change how any check evaluates -- only whether its verdict is allowed to alarm.
        self.gc_mutes()
        self.apply_mutes()

    # ---------------------------------------------------------------- operator mutes (permanent)

    def problem_is_muted(self, text):
        """True iff `text` is a per-stamp problem that names ONLY suppressed stamps, where
        suppressed = muted by the operator OR superseded by a later healthy success (F4: a
        superseded stamp's leftovers -- its forensic staging aging into P10, above all -- must
        not re-alarm; the staging dir itself is NEVER deleted for this, it stays for forensics
        at the bounded cost of one failed copy and dies at the stamp's normal prune/gc).

        Three guards, each of which exists to stop suppression from hiding something it
        should not:
          1. the code must be in MUTABLE_CODES -- volume-level faults (P1/P8/P13/P14/P16, the
             manifest-ledger tripwire...) are never mutable, no matter which stamp they happen
             to mention;
          2. "P4 SYSTEMIC" and "P4 PATTERN" are excluded explicitly -- both are P4 by prefix
             but report a VOLUME-level / systemic fault (TCC, unmounted mid-pass, full disk,
             a week of repeated failures), which is exactly the class of problem per-snapshot
             suppression must never be able to silence;
          3. the problem must name at least one stamp and EVERY stamp it names must be
             suppressed -- so the multi-stamp "P4 N snapshots have failed" line stays loud
             while even one of the snapshots it names is still live.
        """
        if not text:
            return False
        code = text.split(None, 1)[0]
        if code not in MUTABLE_CODES:
            return False
        if text.startswith("P4 SYSTEMIC") or text.startswith("P4 PATTERN"):
            return False
        stamps = set(STAMP_FIND_RE.findall(text))
        if not stamps:
            return False
        return stamps.issubset(set(self.muted) | self._superseded_set())

    def gc_mutes(self):
        """Drop mute records for snapshots that exist on NEITHER volume.

        Answers "will this row ever go away?": yes, on its own. A mute is permanent for as long
        as the snapshot exists, but once the stamp has been pruned from both sides there is
        nothing left to mute, and keeping the row would leave a ledger entry that outlives its
        subject forever. Same shape and the same guard as gc_copy_failures(): never run while a
        volume is unmounted, or an unreadable disk would look like a pruned snapshot and silently
        discard a live operator decision."""
        if not (self.primary_mounted and self.replica_mounted):
            return
        if not self.muted:
            return
        live = set(self.primary_snapshots) | set(self.replica_snapshots)
        keep = dict((k, v) for k, v in self.muted.items() if k in live)
        if keep != self.muted:
            gone = sorted(set(self.muted) - set(keep))
            self.muted = keep
            write_json(self.muted_path, keep)
            self.log("mute: cleared for pruned snapshot(s) %s - no longer on either volume"
                     % ", ".join(gone))

    def muted_records(self):
        """The muted set PLUS superseded failure records as one UI-ready list. Superseded rows
        ride inside the same "muted" status list with kind="superseded" (A2) so STATUS_KEYS is
        unchanged; every row carries kind so the UI can switch its button on it.

        M9/F15: superseded rows derive ONLY from persist["failed_copies"] -- classify() never
        runs on the lock-held heartbeat path, so classify state must never feed a status row.
        Defensive about every input: a hand-edited entry that is not a dict still yields a
        usable record, and everything is read via getattr so this is safe on the lock-held
        path and under test Fakes that skip __init__.

        M8/A2 (the 72-hour dropdown): every row is EMITTED; a row whose timestamp is older
        than MUTED_ROW_HIDE_HOURS is FLAGGED "hidden": true rather than dropped, so the UI can
        drop it while /api/control/retry and /unmute keep validating against the full list --
        the only recovery path for a superseded stamp must not die at 3 days. A missing or
        malformed timestamp leaves the row VISIBLE (S11/F7: visibility-safe)."""
        primary = set(getattr(self, "primary_snapshots", None) or [])
        replica = set(getattr(self, "replica_snapshots", None) or [])
        now = time.time()

        def hidden(ts_str):
            dt = parse_ts(ts_str)
            if dt is None:
                return False
            return (now - dt.timestamp()) > MUTED_ROW_HIDE_HOURS * 3600.0

        muted = getattr(self, "muted", None) or {}
        out = []
        for s in sorted(muted):
            rec = muted.get(s)
            rec = rec if isinstance(rec, dict) else {}
            out.append({
                "stamp": s,
                "kind": "muted",
                "muted_at": rec.get("muted_at"),
                "reason": rec.get("reason"),
                "hidden": hidden(rec.get("muted_at")),
                "on_primary": s in primary,
                "on_replica": s in replica,
            })
        fails = (getattr(self, "persist", None) or {}).get("failed_copies") or {}
        history = (getattr(self, "persist", None) or {}).get("retry_history") or {}

        def recent_retries(s):
            n = 0
            for t in (history.get(s) or []):
                dt = parse_ts(t) if isinstance(t, str) else None
                # unparseable entries count: they can only make the cooldown stricter
                if dt is None or (now - dt.timestamp()) <= RETRY_HISTORY_WINDOW_SEC:
                    n += 1
            return n

        for s in sorted(fails):
            rec = fails.get(s)
            if not (isinstance(rec, dict) and rec.get("superseded_by")):
                continue
            if s in muted:
                continue    # muted wins (F5): one row per stamp, and the mute ledger owns it
            out.append({
                "stamp": s,
                "kind": "superseded",
                "superseded_at": rec.get("superseded_at"),
                "superseded_by": rec.get("superseded_by"),
                "failed_at": rec.get("ts"),          # monitor's <30-min retry cooldown (M8)
                "retry_count": recent_retries(s),    # monitor's 3-in-24h retry cooldown (M8)
                "reason": "failed; superseded by %s" % rec.get("superseded_by"),
                "hidden": hidden(rec.get("superseded_at")),
                "on_primary": s in primary,
                "on_replica": s in replica,
            })
        return out

    @staticmethod
    def line_key(text):
        """Identity of a message's SHAPE, not its exact text.

        Every varying part of these messages is numeric -- byte counts, hour counts, and
        snapshot stamps (2026-08-25_180005 -> #-#-#_#). Collapsing digit runs means muting
        "P15 snapshot X has been ... awaiting copy for 9.2 h" also mutes it at 12.7 h on the
        next pass, which is the whole point: the operator is silencing a RECURRING message,
        not one reading of it. Without this, a line mute would expire the moment a counter
        ticked.
        """
        s = re.sub(r"[0-9]+", "#", str(text or ""))
        return re.sub(r"\s+", " ", s).strip()

    def _active_line_mutes(self):
        """The subset of muted_lines that is still in force. A line mute EXPIRES COMPLETELY at
        LINE_MUTE_EXPIRY_HOURS (A2): an eternal invisible silence is the one thing worse than
        a nagging banner, so after 72 h the note/problem returns if it is still true. F7
        malformed-timestamp policy: a record whose muted_at is missing or unparseable counts
        as EXPIRED here (loud-safe: stop silencing) while its ROW stays visible in
        muted_line_records() (visibility-safe). monitor.py, the file's writer, garbage-collects
        parseably-expired entries on its next mute-line/unmute-line POST."""
        out = {}
        now = time.time()
        for k, rec in (getattr(self, "muted_lines", None) or {}).items():
            rec_d = rec if isinstance(rec, dict) else {}
            dt = parse_ts(rec_d.get("muted_at"))
            if dt is None:
                continue
            if (now - dt.timestamp()) > LINE_MUTE_EXPIRY_HOURS * 3600.0:
                continue
            out[k] = rec
        return out

    def apply_mutes(self):
        """Partition problems[]/notes[] into (still alarming, muted) -- the point of the feature.

        `healthy` is computed as `not self.problems` in both build_status() and heartbeat_status(),
        so moving a problem out of that list is precisely what lets display_state leave "fail";
        removing a note is what lets it leave "warn". Nothing is deleted: muted_problems[] ships
        in STATUS so the monitor can keep showing what was silenced, and the reason/timestamp live
        in muted.json / muted-lines.json / persist's failed_copies records.

        Three independent mechanisms, applied in order:
          1. per-SNAPSHOT suppression -- per-stamp problems only, guarded by MUTABLE_CODES.
             The suppression set is muted ∪ superseded (F4): a stamp closed by a later healthy
             success must not re-alarm through its leftovers (P10 forensic staging above all),
             exactly as a muted one must not. Suppression persists past the 72 h row-hide.
          2. per-LINE mute -- anything at all, matched on line_key(). This is the one that can
             silence a note or a stamp-less problem, and it is deliberately unrestricted: the
             owner asked to be able to quiet ANY banner. It stays honest because every muted
             line is listed back in STATUS with its reason, unmuting restores it instantly,
             and the mute self-expires at 72 h (_active_line_mutes).
        """
        self.muted_problems = []
        self.muted_line_hits = []
        suppressed = set(self.muted) | self._superseded_set()
        active_lines = self._active_line_mutes()
        if not suppressed and not active_lines:
            return

        kept = []
        for text in self.problems:
            if suppressed and self.problem_is_muted(text):
                self.muted_problems.append(text)
            elif active_lines and self.line_key(text) in active_lines:
                self.muted_problems.append(text)
                self.muted_line_hits.append(self.line_key(text))
            else:
                kept.append(text)
        self.problems = kept

        # NOTES too, or a mute only half-works. A note naming a muted stamp (e.g. "snapshot X is
        # unsettled (in progress on the writer)") keeps display_state at "warn" forever, which
        # for a deliberately voided snapshot is the same permanent-banner trap in amber. Notes are
        # informational by construction -- every volume-level alarm is a problem[], never a note --
        # so dropping the ones that describe ONLY suppressed stamps cannot hide a fault. The muted
        # ledger still shows the stamp, so nothing becomes invisible.
        surviving = []
        for text in self.notes:
            stamps = set(STAMP_FIND_RE.findall(text or ""))
            if suppressed and stamps and stamps.issubset(suppressed):
                continue
            if active_lines and self.line_key(text) in active_lines:
                self.muted_line_hits.append(self.line_key(text))
                continue
            surviving.append(text)
        self.notes = surviving

    def muted_line_records(self):
        """Line mutes as UI-ready records, with a live flag for the ones matching something
        now. M8 shape parity with muted_records(): a row whose muted_at parses and is older
        than MUTED_ROW_HIDE_HOURS ships "hidden": true (such a mute has also EXPIRED --
        _active_line_mutes() ignores it -- and the monitor GCs the entry on its next
        mute-line write); a missing/malformed muted_at leaves the row VISIBLE (F7: the row
        display is visibility-safe even though the mute itself is treated as expired)."""
        hits = set(self.muted_line_hits)
        now = time.time()
        out = []
        for k in sorted(self.muted_lines):
            rec = self.muted_lines.get(k)
            rec = rec if isinstance(rec, dict) else {}
            dt = parse_ts(rec.get("muted_at"))
            hidden = (dt is not None) and \
                (now - dt.timestamp()) > MUTED_ROW_HIDE_HOURS * 3600.0
            out.append({
                "key": k,
                "sample": rec.get("sample"),      # the text as it read when muted
                "muted_at": rec.get("muted_at"),
                "reason": rec.get("reason"),
                "active": k in hits,              # is it silencing something on THIS pass?
                "hidden": hidden,
            })
        return out

    # ---------------------------------------------------------------- status (00 F4)

    def build_status(self, mirror_running):
        st = {
            "schema": SCHEMA,
            "ts": iso_now(),
            "pass_kind": self.mode,
            "engine_pid": self.pid,
            "primary_mounted": self.primary_mounted,
            "replica_mounted": self.replica_mounted,
            "primary_total_kb": self.stat_primary["total_kb"],
            "primary_used_kb": self.stat_primary["used_kb"],
            "primary_free_kb": self.stat_primary["free_kb"],
            "primary_iused": self.stat_primary["iused"],
            "replica_total_kb": self.stat_replica["total_kb"],
            "replica_used_kb": self.stat_replica["used_kb"],
            "replica_free_kb": self.stat_replica["free_kb"],
            "replica_iused": self.stat_replica["iused"],
            "primary_snapshots": list(self.primary_snapshots),
            "replica_snapshots": list(self.replica_snapshots),
            "latest_primary": self.latest_primary,
            "latest_replica": self.latest_replica,
            "pending": list(self.pending),
            "unsettled": list(self.unsettled),
            "incoming": list(self.incoming),
            "last_copy": self.last_copy,
            "last_deep_verify": self.last_deep_verify,
            "mirror_running": bool(mirror_running),
            "mirror_running_seconds": self.busy_seconds() if mirror_running else 0,
            "healthy": not self.problems,
            "problems": list(self.problems),
            "notes": list(self.notes),
            "system_enabled": bool(self.enabled),
            "enabled_source": self.enabled_source,
            "handshake_reachable": self.handshake.get("reachable"),
            "handshake_last_change": self.handshake.get("last_change"),
            "control_override": self.control_override.get("override"),
            "incomplete_uploads": list(self.incomplete),
            # F3: a superseded record is excluded -- its stamp is never retried, so offering
            # "Skip dedup check" for it would write a skip-dedup.json entry that
            # consume_skip_dedup() never consumes.
            "dedup_failures": sorted(
                s for s, f in (self.persist.get("failed_copies") or {}).items()
                if "dedup assertion FAILED" in (f.get("detail") or "")
                and not f.get("superseded_by")),
            # A muted snapshot is offered NO action but Unmute: continuing to advertise "Force
            # resume" for a stamp the operator has explicitly voided is exactly the confusing
            # dead-end the mute is meant to end.
            "force_settle_candidates": sorted(
                s for s in self.unsettled
                if s in (self.seen.get("was_latest") or []) and s not in self.muted),
            # Full records, not bare stamps: the UI shows WHY and WHEN each snapshot was written
            # off, so a mute can be reviewed months later instead of being an unexplained silence.
            "muted": self.muted_records(),
            "muted_problems": list(self.muted_problems),
            "muted_lines": self.muted_line_records(),
        }
        assert set(st.keys()) == set(STATUS_KEYS), "STATUS key set drifted from 00 F4"
        return st

    def write_status(self, mirror_running):
        st = self.build_status(mirror_running)
        write_atomic(self.status_path, json.dumps(st, indent=1, sort_keys=True) + "\n")
        return st

    # ---------------------------------------------------------------- volume-missing transition

    def log_mount_transition(self):
        """00 F7: logged on state transition (missing<->present), not every 5 minutes."""
        cur = "%s/%s" % ("ok" if self.primary_mounted else "MISSING",
                         "ok" if self.replica_mounted else "MISSING")
        prev = self.persist.get("mount_state")
        if cur != prev:
            if not (self.primary_mounted and self.replica_mounted):
                self.log("skip: volume missing (src=%s dst=%s)"
                         % ("ok" if self.primary_mounted else "MISSING",
                            "ok" if self.replica_mounted else "MISSING"))
            elif prev is not None:
                self.log("volumes present again (src=ok dst=ok)")
            self.persist["mount_state"] = cur
            write_json(self.persist_path, self.persist)

    # ---------------------------------------------------------------- the pass

    def run(self):
        ok, held_pid = self.acquire_lock()
        if not ok:
            self.heartbeat_status(held_pid)
            self.log("skip: already running pid=%d" % held_pid)
            return 2
        self.clear_busy()          # we hold the lock: nothing else can be copying
        prev = read_json(self.status_path)
        self.check_clock_skew(prev.get("ts") if isinstance(prev, dict) else None)
        try:
            try:
                self.pass_body()
            except ConfigError:
                raise
            except Exception as exc:          # never die without a status
                self.problem("internal engine error: %s: %s" % (type(exc).__name__, exc))
                self.event("error", None, "%s: %s" % (type(exc).__name__, exc))
                self.log("internal error: %s: %s" % (type(exc).__name__, exc))
        finally:
            self.clear_busy()
            self.release_lock()
        self.write_status(False)
        self.trim_events()
        if self.copy_logged_start:
            self.log("finished rc=%d" % self.pass_rc_for_log)
        return 0 if not self.problems else 1

    def pass_body(self):
        self.probe()
        self.log_mount_transition()
        self.update_seen()
        # A3/F10 consume point: AFTER probe (volumes known), BEFORE classify (a consumed retry
        # deletes the superseded failure record, so THIS pass's classify already re-derives the
        # stamp into pending). Gated on both volumes mounted inside the method.
        self.consume_retry_requests()
        self.classify()
        self.emit_detected()

        # On/off switch: computed AFTER probe/classify/emit_detected (never before) so
        # corpse-tracking's seen.json bookkeeping and status.json both stay fully accurate
        # regardless of enabled state -- "off doesn't turn off the display," and 00 F8's own
        # corpse-tracking rationale depends on continuous per-pass observation.
        self.enabled = self.compute_enabled()

        if not (self.primary_mounted and self.replica_mounted):
            # An unmounted volume is exit 1, NEVER 0 (00 F3 / HANDOFF 4.2).  No copies, no prune.
            self.compute_health()
            return

        if not self.enabled:
            # Paused: skip copy/prune/deep-verify, but keep status.json honest and fresh so
            # staleness never false-fires during a pause (mirrors mirror_running's own
            # staleness-suppression rationale in 00 F10).
            self.refresh_volume_stats()
            self.compute_health()
            return

        if self.mode == "deep-verify" or self.pending:
            self.log("start pid=%d" % self.pid)
            self.copy_logged_start = True

        promoted_now = []    # stamps promoted by THIS pass (drives the monthly deep-verify)
        if self.pending:
            # 00 F3/F10: publish an in-flight STATUS before a copy that can run for >30 minutes,
            # so the monitor shows WARN "copy in progress" instead of ageing into a false FAIL.
            # Health is computed for this snapshot too, so a latched P4 cannot look green mid-copy;
            # the accumulators are then reset for the authoritative end-of-pass computation.
            self.mirror_running = True
            self.mark_busy()
            pre_problems, pre_notes = list(self.problems), list(self.notes)
            self.compute_health()
            self.note("copy in progress: %s" % ", ".join(self.pending[:5]))
            self.write_status(True)
            # restore, do NOT clear: anything raised before the copy phase (a corpse-tracking
            # bootstrap warning, a clock-skew note) must survive into the authoritative
            # end-of-pass computation.  Clearing them silently dropped real warnings.
            self.problems, self.notes = pre_problems, pre_notes
            # CONTINUE, NOT BREAK (orchestrator decision 2026-08-19).  With `break`, ONE
            # permanently-uncopyable snapshot cost every subsequent backup and the loss compounded
            # forever - measured: an unreadable file in stamp 4 froze the replica at stamp 3 with
            # stamps 4 and 5 both pending, indefinitely.  With `continue`, one bad snapshot costs
            # exactly that snapshot while every newer one keeps replicating.  For an archive whose
            # purpose is redundancy of RECENT work, a one-snapshot gap beats an unbounded one.
            # Safe because choose_base() only ever selects from PROMOTED replica stamps, so a
            # skipped stamp can never become a --link-dest base; dedup degrades (the next stamp
            # links against an older base), correctness does not.  The skipped stamp stays in
            # self.pending, so it keeps its pending.json record and P15 makes it permanently
            # visible, while the per-stamp failure ledger keeps P4 on it.
            self.copies_attempted = 0
            self.copies_failed = 0
            for s in list(self.pending):
                self.copies_attempted += 1
                if self.copy_stamp(s):
                    self.pending.remove(s)
                    promoted_now.append(s)
                    # A1/F1(a): the ONE point that covers both promote paths (normal copy and
                    # try_recover_staging both return True through copy_stamp). Health-gated
                    # inside; purges superseded stamps from pending/pending.json (F1(b)) --
                    # safe because this loop walks list(self.pending) ASCENDING, so every
                    # f < s was already attempted before s promoted.
                    self.supersede_older_failures(s)
                else:
                    self.copies_failed += 1
                    continue
            self.mirror_running = False

        self.reconcile_latest()
        self.prune()

        if self.mode == "deep-verify":
            self.deep_verify()
        elif self.mode == "mirror" and self.monthly_verify_due(promoted_now):
            # Monthly sweep right after the early-morning copy, still holding the lock, so
            # regular copies wait and resume on the next pass. The busy timer is restarted so
            # P14 measures the verify itself, not copy+verify back to back.
            self.log("deep-verify: monthly run after early-morning copy of %s"
                     % ", ".join(promoted_now))
            self.clear_busy()
            self.mark_busy()
            self.mirror_running = True
            # Same in-flight STATUS idiom as the copy phase above: compute, publish, restore.
            pre_problems, pre_notes = list(self.problems), list(self.notes)
            self.compute_health()
            self.note("monthly deep-verify in progress (backups resume when it finishes)")
            self.write_status(True)
            self.problems, self.notes = pre_problems, pre_notes
            self.deep_verify()
            self.mirror_running = False

        try:
            self.incoming = sorted(n for n in os.listdir(self.staging_root) if not excluded(n))
        except OSError:
            self.incoming = []
        self.update_pending_tracker()     # post-copy: anything promoted has left the set
        self.refresh_volume_stats()       # MUST precede compute_health -- see below
        self.compute_health()
        if self.problems and self.pass_rc_for_log == 0 and self.copy_logged_start:
            self.pass_rc_for_log = 1


# --------------------------------------------------------------------------- entry point

def selfcheck_argv_builder():
    """02: assert at startup that the built argv contains no forbidden flag.  This runs the REAL
    builder, so the assertion is proven to cover the code path that actually launches rsync."""
    inject = None
    if all(os.environ.get(k) for k in ENV_PATH_KEYS):
        inject = os.environ.get("SNAP_TEST_INJECT_FLAG") or None
    build_copy_argv("/nonexistent/src", "/nonexistent/dst", "/nonexistent/base", inject)
    build_repair_argv("/nonexistent/src", "/nonexistent/dst", "/nonexistent/list", inject)


def main(argv):
    mode = argv[1] if len(argv) > 1 else "mirror"
    if mode in ("enable", "disable"):
        # On/off switch, manual path: a dedicated forced-command key invokes this mode directly
        # (see specs) -- writes control-override.json only, touches nothing else, no lock needed.
        state_dir = os.environ.get("SNAP_STATE_DIR") or DEFAULT_STATE_DIR
        path = os.path.join(state_dir, "control-override.json")
        try:
            write_json(path, {"override": "on" if mode == "enable" else "off",
                               "changed_at": iso_now(), "changed_by": "manual"})
        except (IOError, OSError) as exc:
            sys.stderr.write("engine: FATAL: cannot write %s: %s\n" % (path, exc))
            return 3
        return 0
    if mode not in ("mirror", "deep-verify"):
        mode = "mirror"
    try:
        selfcheck_argv_builder()
        eng = Engine(mode)
    except ConfigError as exc:
        sys.stderr.write("engine: FATAL: %s\n" % exc)
        return 3
    except Exception as exc:
        sys.stderr.write("engine: FATAL: %s: %s\n" % (type(exc).__name__, exc))
        return 3
    try:
        return eng.run()
    except ConfigError as exc:
        sys.stderr.write("engine: FATAL: %s\n" % exc)
        eng.release_lock()
        return 3


if __name__ == "__main__":
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    sys.exit(main(sys.argv))
