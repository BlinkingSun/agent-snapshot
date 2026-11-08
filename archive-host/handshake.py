#!/usr/bin/env python3
"""
SnapArchive on/off switch: archive-host connectivity handshake.

Invoked by launchd every ~60s (com.agent-snapshot-replica.handshake, StartInterval). Each run:
  1. Probes whether the writer is reachable, via a dedicated forced-command-restricted key that
     can invoke ONLY the writer's existing `probe-auth` mode on snapshot-dispatch (read-only,
     side-effect-free -- confirmed by reading its source before wiring this up).
  2. Debounces: requires DEBOUNCE_FAILS consecutive failed probes before flipping reachable=false,
     so one dropped packet doesn't pause the whole system.
  3. On the transition to unreachable, samples any settled-but-not-yet-observed unsettled primary
     stamp (read from the archive host's own fresh status.json -- reusing engine.py's classification
     rather than re-implementing settle/corpse logic here) and watches it across one more poll;
     if its total size and newest mtime are BOTH unchanged, marks it incomplete in
     incomplete.json and appends a `marked_incomplete` event. If it's still growing, keeps
     watching rather than marking prematurely.
  4. Always writes handshake.json (reachable/last_check every run; last_change/consecutive_fail
     only when relevant). This is the ONLY writer of handshake.json and incomplete.json.

Single-writer discipline (00 F1/F8 spirit, applied to the new files): this script NEVER touches
control-override.json (engine.py's own enable/disable mode owns that exclusively -- composing
manual override vs. automatic handshake state is engine.py's job, so a deliberate pause is never
silently undone by a reconnect) and NEVER writes under PRIMARY (the frozen "the archive host NEVER writes to
PRIMARY. Ever." rule applies to every archive-host component, not just engine.py).

stdlib only, matching engine.py/monitor.py. Env overrides mirror engine.py's SNAP_* convention so
this can be exercised against a synthetic fixture the same way engine.py's tests are.
"""

import datetime
import json
import os
import subprocess
import sys
import tempfile
import time

DEFAULT_PRIMARY = "/Volumes/SnapArchive"
DEFAULT_STATE_DIR = os.path.expanduser("~/Library/AgentSnapshot")
DEFAULT_WRITER_HOST = "youruser@writer-host"  # the writer host's ssh target
DEFAULT_WRITER_KEY = os.path.expanduser("~/.ssh/id_ed25519_agentsnapshot_probe")

PRIMARY = os.environ.get("SNAP_PRIMARY") or DEFAULT_PRIMARY
STATE_DIR = os.environ.get("SNAP_STATE_DIR") or DEFAULT_STATE_DIR
WRITER_HOST = os.environ.get("SNAP_WRITER_HOST") or DEFAULT_WRITER_HOST
WRITER_KEY = os.environ.get("SNAP_WRITER_KEY") or DEFAULT_WRITER_KEY
SNAPDIR = "snapshots"

HANDSHAKE_PATH = os.path.join(STATE_DIR, "handshake.json")
INCOMPLETE_PATH = os.path.join(STATE_DIR, "incomplete.json")
STATUS_PATH = os.path.join(STATE_DIR, "status.json")
EVENTS_PATH = os.path.join(STATE_DIR, "events.jsonl")

DEBOUNCE_FAILS = 2          # consecutive failed probes before flipping reachable=false
PROBE_TIMEOUT_SEC = 8


def iso_now():
    """Same format as engine.py's iso_now(): date +%Y-%m-%dT%H:%M:%S%z, local time."""
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def log(msg):
    sys.stderr.write("[handshake] %s\n" % msg)


def read_json(path, default=None):
    try:
        with open(path, "r") as fh:
            return json.load(fh)
    except (IOError, OSError, ValueError):
        return default


def write_atomic(path, data):
    """tmp + fsync + os.replace -- same discipline as engine.py's write_atomic, duplicated
    locally rather than imported (matching the existing decoupling between components)."""
    d = os.path.dirname(path) or "."
    if not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        with os.fdopen(fd, "w") as fh:
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


def write_json(path, obj):
    write_atomic(path, json.dumps(obj, indent=1, sort_keys=True) + "\n")


def append_event(kind, snapshot, detail):
    """Same shape as engine.py's event(): {"ts","event","snapshot","detail"}, plain append.
    engine.py's own next pass (every 5 min regardless) sweeps this into its normal
    trim_events() pass -- no need to duplicate the 2000/1000-line rotation here."""
    rec = {"ts": iso_now(), "event": kind, "snapshot": snapshot, "detail": detail}
    try:
        d = os.path.dirname(EVENTS_PATH)
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)
        with open(EVENTS_PATH, "a") as fh:
            fh.write(json.dumps(rec) + "\n")
    except (IOError, OSError) as exc:
        log("could not append event: %s" % exc)


def probe_mbp():
    """Read-only liveness check. Uses a key whose authorized_keys forced-command on the
    The writer's dispatcher hardcodes `probe-auth` regardless of what is sent (see credential notes) -- it
    cannot invoke `snap`/`vault`/`both` (real backup runs) no matter what this process passes."""
    try:
        r = subprocess.run(
            ["ssh", "-i", WRITER_KEY, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
             "-o", "StrictHostKeyChecking=yes",
             "-o", "ConnectTimeout=%d" % PROBE_TIMEOUT_SEC,
             "-o", "PreferredAuthentications=publickey",
             WRITER_HOST, "probe-auth"],
            capture_output=True, text=True, timeout=PROBE_TIMEOUT_SEC + 3,
        )
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError) as exc:
        log("probe failed: %s" % exc)
        return False


def sample_stamp(name):
    """Recursive (size, newest-mtime) sample of a primary stamp dir. Only ever called around a
    disconnection event (rare), so an O(files) walk is an acceptable cost -- NOT called on every
    routine poll. A directory's own mtime alone is too fragile a signal (it only changes when an
    entry is added/removed directly inside it, not for writes deeper in the tree, so a transfer
    still landing bytes in a nested subdir could look falsely idle) -- this walks everything."""
    root = os.path.join(PRIMARY, SNAPDIR, name)
    total_size = 0
    newest_mtime = 0.0
    try:
        for dirpath, _dirnames, filenames in os.walk(root):
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                total_size += st.st_size
                if st.st_mtime > newest_mtime:
                    newest_mtime = st.st_mtime
    except OSError as exc:
        log("could not sample %s: %s" % (name, exc))
        return None
    return {"size": total_size, "mtime": newest_mtime}


def main():
    handshake = read_json(HANDSHAKE_PATH, {}) or {}
    incomplete = read_json(INCOMPLETE_PATH, {}) or {}
    status = read_json(STATUS_PATH, {}) or {}

    was_reachable = handshake.get("reachable", True)
    consecutive_fail = handshake.get("consecutive_fail", 0)
    watch = handshake.get("_watch", {})  # scratch state, not part of the public schema

    ok = probe_mbp()
    now = iso_now()

    if ok:
        consecutive_fail = 0
        reachable = True
    else:
        consecutive_fail += 1
        reachable = (consecutive_fail < DEBOUNCE_FAILS) and was_reachable

    became_unreachable = was_reachable and not reachable

    if reachable:
        # Reconnected (or never dropped): nothing left to watch. If a watched stamp never got
        # marked before reconnecting, the NEXT disconnection starts a fresh assessment rather
        # than trusting a stale in-flight sample.
        watch = {}
    else:
        unsettled = list(status.get("unsettled") or [])
        already_marked = set(incomplete)
        candidates = [s for s in unsettled if s not in already_marked]

        if became_unreachable:
            for s in candidates:
                sample = sample_stamp(s)
                if sample is not None:
                    watch[s] = sample
            log("became unreachable; watching %d unsettled stamp(s): %s"
                % (len(watch), ", ".join(sorted(watch)) or "(none)"))
        else:
            for s in list(watch):
                if s not in candidates:
                    # promoted, corpsed, or otherwise no longer unsettled since we started
                    # watching -- something else already resolved it, stop watching.
                    del watch[s]
                    continue
                prev = watch[s]
                cur = sample_stamp(s)
                if cur is None:
                    continue
                if cur["size"] == prev["size"] and cur["mtime"] == prev["mtime"]:
                    incomplete[s] = {"marked_at": now,
                                      "reason": "connection to the writer lost mid-upload"}
                    write_json(INCOMPLETE_PATH, incomplete)
                    append_event("marked_incomplete", s,
                                 "connection to the writer lost mid-upload; stamp stopped growing "
                                 "(size=%d bytes, newest mtime unchanged) -- excluded from "
                                 "copy, never faulted for lacking a mirror" % cur["size"])
                    log("marked incomplete: %s" % s)
                    del watch[s]
                else:
                    watch[s] = cur   # still moving -- keep watching, don't mark prematurely

    out = {
        "reachable": reachable,
        "last_check": now,
        "consecutive_fail": consecutive_fail,
        "_watch": watch,
    }
    if reachable != was_reachable:
        out["last_change"] = now
    else:
        out["last_change"] = handshake.get("last_change")
    write_json(HANDSHAKE_PATH, out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
