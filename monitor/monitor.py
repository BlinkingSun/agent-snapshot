#!/usr/bin/env python3
"""
Snapshot Monitor web backend.

Serves a small single-page status UI + JSON API for the SnapArchive backup
engine, reading ONLY:
    STATUS  = STATE_DIR/status.json   (F4, written atomically by the engine)
    EVENTS  = STATE_DIR/events.jsonl  (F6, append-only, written by the engine)
    LOG     = SNAP_LOG (informational only; not currently exposed via the API)

This process NEVER touches /Volumes. That is the whole point: it is a plain
foreground/launchd process with no Full Disk Access, so it must derive every
number it shows from files under ~/Library that the (TCC-privileged) engine
already wrote. Grep this file for "/Volumes" — it must never appear.

stdlib only. Must run under /usr/bin/python3 (3.9.6). No pip, no flask.

Env overrides (F1/F10), all four independent of each other here (unlike the
engine's all-or-nothing SNAP_* rule -- the monitor is read-only and each
override is safe standalone):
    SNAP_STATE_DIR   directory containing status.json + events.jsonl
                      (default: /Users/youruser/Library/AgentSnapshot)
    SNAP_LOG         path to the mirror log (default: F1 LOG path)
    SNAP_PORT        port to bind (default: 7788)

Bind address is ALWAYS 127.0.0.1 -- not overridable, per F1 MONITOR_URL.
"""

import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# ---------------------------------------------------------------------------
# F1 paths, with test-only env redirection.
# ---------------------------------------------------------------------------

DEFAULT_STATE_DIR = "/Users/youruser/Library/AgentSnapshot"
DEFAULT_LOG = "/Users/youruser/Library/Logs/agent-snapshot.log"

STATE_DIR = os.environ.get("SNAP_STATE_DIR", DEFAULT_STATE_DIR)
STATUS_PATH = os.path.join(STATE_DIR, "status.json")
EVENTS_PATH = os.path.join(STATE_DIR, "events.jsonl")
# On/off switch, skip-dedup control action (2026-08-25): the ONE write path this process has.
# Single writer of this specific file (engine.py never writes it, only consumes/deletes entries
# it acts on) -- see engine.py's consume_skip_dedup() and 00 F8.5c.
SKIP_DEDUP_PATH = os.path.join(STATE_DIR, "skip-dedup.json")
# Single writer of this file too -- see engine.py's consume_force_settle() and classify()'s
# was_latest safety check (added 2026-08-26). A bigger override than skip-dedup: it can make an
# UNSETTLED stamp eligible for copying at all, not just bypass the dedup heuristic. engine.py
# refuses it (loudly, in notes[]) unless the stamp was previously observed as primary's own
# `latest` -- this endpoint does not weaken that; it only lets an operator name a candidate.
FORCE_SETTLE_PATH = os.path.join(STATE_DIR, "force-settle.json")
# Permanent per-snapshot mute. Written ONLY here (POST /api/control/mute and /unmute); engine.py
# reads it and never writes it, which is what keeps the "single writer per state file" rule intact.
MUTED_PATH = os.path.join(STATE_DIR, "muted.json")
# Per-LINE mutes (any banner line, not just per-snapshot ones). Written ONLY here.
MUTED_LINES_PATH = os.path.join(STATE_DIR, "muted-lines.json")
# Retry opt-back-in for SUPERSEDED failures (A3): monitor-adds / engine-consumes, same contract
# as skip-dedup.json and force-settle.json. This process only ever ADDS entries; engine.py's
# consume_retry_requests() re-reads and rewrites the file at the start of its next pass. If a
# pass is already running when we kick, the kick bounces off the engine's lock and the request
# is simply consumed at the next scheduled pass (<= ~5 min) -- that is fine, not an error.
RETRY_REQUEST_PATH = os.path.join(STATE_DIR, "retry-request.json")
# M8 retry cooldowns -- a UI button must never be able to trip the P16 forced-command rate
# alarm, and each consumed retry burns a long (potentially 40-70 min) USB copy attempt:
RETRY_MIN_FAILURE_AGE_SEC = 1800   # 409 while the failure is younger than 30 min
RETRY_MAX_PER_DAY = 3              # 409 once the engine has consumed 3 retries in 24 h
# A2: a line mute expires completely at 72 h (engine side: _active_line_mutes()). This process
# is muted-lines.json's single writer, so IT garbage-collects expired entries on any
# mute-line/unmute-line POST.
LINE_MUTE_EXPIRY_SECONDS = 72 * 3600


def _line_key(text):
    """MUST match engine.py's Engine.line_key() exactly -- the engine is the authority, this is
    only so the UI can pre-check. Collapses digit runs so a mute survives changing counters."""
    s = re.sub(r"[0-9]+", "#", str(text or ""))
    return re.sub(r"\s+", " ", s).strip()
STAMP_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{6}$")
MIRROR_KEY = os.path.expanduser("~/.ssh/id_ed25519_agentsnapshot_replica")
LOG_PATH = os.environ.get("SNAP_LOG", DEFAULT_LOG)

try:
    PORT = int(os.environ.get("SNAP_PORT", "7788"))
except ValueError:
    PORT = 7788

BIND_ADDR = "127.0.0.1"

# F4 top-level keys, used only to build a well-shaped placeholder response
# when STATUS is missing/unparseable so the UI never has to special-case
# "undefined" fields. Field names copied verbatim from specs/00 F4 -- do not
# rename or add engine-namespace fields here.
F4_DEFAULTS = {
    "schema": None,
    "ts": None,
    "pass_kind": None,
    "engine_pid": None,
    "primary_mounted": False,
    "replica_mounted": False,
    "primary_total_kb": None,
    "primary_used_kb": None,
    "primary_free_kb": None,
    "primary_iused": None,
    "replica_total_kb": None,
    "replica_used_kb": None,
    "replica_free_kb": None,
    "replica_iused": None,
    "primary_snapshots": [],
    "replica_snapshots": [],
    "latest_primary": None,
    "latest_replica": None,
    "pending": [],
    "unsettled": [],
    "incoming": [],
    "last_copy": None,
    "last_deep_verify": None,
    "mirror_running": False,
    "mirror_running_seconds": None,
    "healthy": False,
    "problems": [],
    "notes": [],
    "system_enabled": True,
    "enabled_source": None,
    "handshake_reachable": None,
    "handshake_last_change": None,
    "control_override": None,
    "incomplete_uploads": [],
    "dedup_failures": [],
    "force_settle_candidates": [],
}

# F10 post-second-audit constant: staleness suppression while mirror_running
# is capped at 6 hours. Beyond this, a claimed-in-flight copy no longer
# suppresses staleness and display_state may reach fail (FG6: an engine that
# leaves a foreign live pid in the lock file must not stay amber forever).
SUPPRESS_CAP = 43200  # 12 h (2026-10-23, matches engine SUPPRESS_CAP_SECONDS; was 21600)


def _log(msg):
    """One-line diagnostic to stderr -- never a traceback. launchd (later,
    subtask 05) redirects stderr to StandardErrorPath; in dev SNAP_LOG isn't
    used for this (it's the engine's log), so this goes wherever the caller
    redirected our stderr (selftest.sh points it at /dev/null)."""
    try:
        sys.stderr.write("[monitor] %s\n" % msg)
        sys.stderr.flush()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# STATUS / EVENTS readers -- must never raise out of the request handler.
# ---------------------------------------------------------------------------

def read_status_raw():
    """Returns (dict_or_None, error_code_or_None).
    error_code in (None, "missing", "unparseable")."""
    try:
        with open(STATUS_PATH, "r", encoding="utf-8") as f:
            raw = f.read()
    except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
        return None, "missing"
    except OSError as e:
        _log("status read OSError: %s" % e)
        return None, "missing"

    try:
        data = json.loads(raw)
    except (ValueError, TypeError) as e:
        _log("status parse error: %s" % e)
        return None, "unparseable"

    if not isinstance(data, dict):
        return None, "unparseable"

    return data, None


def parse_ts(ts):
    """Parse an F4 'date +%Y-%m-%dT%H:%M:%S%z'-style timestamp. Returns an
    aware datetime, or None if ts is missing/malformed."""
    if not isinstance(ts, str) or not ts:
        return None
    try:
        return datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S%z")
    except ValueError:
        pass
    # Tolerate a bare 'Z' suffix or a colon in the offset, just in case.
    try:
        alt = ts.replace("Z", "+0000")
        if len(alt) >= 6 and alt[-3] == ":":
            alt = alt[:-3] + alt[-2:]
        return datetime.datetime.strptime(alt, "%Y-%m-%dT%H:%M:%S%z")
    except (ValueError, IndexError):
        return None


def build_status_response():
    """Returns a JSON-ready dict: STATUS contents (or well-shaped
    placeholder) + stale_seconds + display_state, per F10 exactly (second-
    audit version -- specs/00 F10, current as of the P13/P14/SUPPRESS_CAP
    revision)."""
    data, err = read_status_raw()

    if err is not None or data is None:
        out = dict(F4_DEFAULTS)
        out["stale_seconds"] = None
        out["display_state"] = "fail"
        out["monitor_error"] = "status.json " + err
        out["monitor_notes"] = []
        return out

    dt = parse_ts(data.get("ts"))
    if dt is None:
        # Parsed JSON but no usable timestamp -- can't prove freshness.
        # Corrupt-in-effect: never crash, never green.
        out = dict(F4_DEFAULTS)
        out.update({k: data.get(k, F4_DEFAULTS[k]) for k in F4_DEFAULTS})
        out["stale_seconds"] = None
        out["display_state"] = "fail"
        out["monitor_error"] = "status.json unparseable (bad ts)"
        out["monitor_notes"] = []
        return out

    now = datetime.datetime.now(dt.tzinfo)
    raw_stale_seconds = (now - dt).total_seconds()

    # F10: "stale_seconds = now - STATUS.ts, CLAMPED AT 0 FROM BELOW. A
    # negative value ... must NEVER read as maximally fresh ... Treat any
    # negative value as 0 AND raise a note, because a future timestamp is
    # itself evidence something is wrong." (FG5: a bad/skewed ts drove this
    # to -172798 and the old unclamped code reported ok forever.)
    monitor_notes = []
    if raw_stale_seconds < 0:
        stale_seconds = 0.0
        monitor_notes.append(
            "status timestamp is %.0fs in the future (clock skew or a bad write) -- "
            "treating as 0s stale, not fresh" % (-raw_stale_seconds)
        )
    else:
        stale_seconds = raw_stale_seconds

    healthy = data.get("healthy") is True
    notes = data.get("notes") or []
    mirror_running = data.get("mirror_running") is True

    # mirror_running_seconds: new F4 field. Older/partial STATUS may omit it
    # or send null -- per F10 "handle it ... without crashing". Absent means
    # no signal either way, so we don't treat it as having exceeded the cap
    # (that would regress a genuinely-in-flight copy on a not-yet-upgraded
    # engine build back to the old unbounded-vs-nothing behavior); it's
    # simply not counted toward the cap until the engine reports it.
    mrs = data.get("mirror_running_seconds")
    if not isinstance(mrs, (int, float)) or isinstance(mrs, bool):
        mrs = 0
    # SUPPRESS_CAP escape hatch, repaired 2026-08-26.  mirror_running_seconds is written
    # ONCE, at copy start, as busy_seconds() immediately after mark_busy() -- i.e. ~0 --
    # and the engine writes STATUS again only at copy END.  So during a copy `mrs` is
    # frozen near zero and `mrs > SUPPRESS_CAP` could never become true: a copy that DIED
    # mid-flight left mirror_running=true forever, permanently suppressing fail_stale, and
    # the board sat amber instead of red while nothing was being backed up at all.
    # stale_seconds is the one quantity that DOES keep growing in that state (STATUS stops
    # being rewritten), so use whichever is larger.  Normal operation is unaffected: a
    # healthy copy is well under SUPPRESS_CAP (12 h), even on large trees.
    # Same correction as the banner's elapsed timer: mirror_running_seconds advances only when a
    # pass reaches engine.py (copy start, then each lock-held heartbeat), and stale_seconds is
    # time since that same write -- so true elapsed is the SUM, and either alone under-reports.
    # This is what makes the 12 h escape hatch reachable again: previously mrs sat frozen near 0
    # for the whole copy, so a copy that DIED mid-flight left mirror_running=true suppressing
    # fail_stale forever -- amber, never red, while nothing was being backed up.
    over_suppress_cap = mirror_running and ((mrs + stale_seconds) > SUPPRESS_CAP)

    # F10 display_state (LATEST-SUCCESS-WINS revision, 2026-08-26):
    #   fail IF healthy==false OR STATUS missing OR
    #        (stale_seconds>1800 AND (mirror_running==false OR mirror_running_seconds>SUPPRESS_CAP))
    #   warn IF monitor_notes nonempty OR (stale_seconds>900 AND mirror_running==false)
    #   else ok
    #
    # Two former warn triggers were REMOVED here, because they fired during
    # provably healthy operation and were the dominant source of "tons of
    # warnings":
    #   * mirror_running==true -- a copy in flight is the system DOING ITS JOB.
    #     Copies run several times a day, so this painted the board amber for a
    #     large fraction of every day. In-flight is now shown as the activity
    #     row + glyph only, never as a colour.
    #   * notes nonempty -- notes[] are informational BY CONSTRUCTION; the engine
    #     contract is that every volume-level alarm is a problem[], never a note
    #     (engine.py, muted-notes section). They still render as banner text, but
    #     they no longer drive colour. Worse, the UI's own NOTE_NOISE filter
    #     stripped most of that text, so a note produced a warning with no stated
    #     reason on screen.
    # monitor_notes (the future-ts / clock-skew signal) IS kept as warn: that is
    # the monitor telling you it cannot trust its own input, which is rare and
    # genuinely worth a colour.
    #
    # Real faults are unaffected: healthy is `not problems`, so anything the
    # engine raises as a problem[] still goes straight to fail/red.
    fail_stale = stale_seconds > 1800 and (not mirror_running or over_suppress_cap)
    # On/off switch: a real problem always wins over a calm "off" pill (never mask an active
    # alarm behind "paused"); "off" outranks routine warn-notes so a paused system is never
    # silently indistinguishable from "ok".
    if (not healthy) or fail_stale:
        display_state = "fail"
    elif not data.get("system_enabled", True):
        display_state = "off"
    elif monitor_notes or (stale_seconds > 900 and not mirror_running):
        display_state = "warn"
    else:
        display_state = "ok"

    out = dict(data)
    out["stale_seconds"] = stale_seconds
    out["display_state"] = display_state
    out["monitor_notes"] = monitor_notes
    return out


def read_events(n):
    try:
        n = int(n)
    except (TypeError, ValueError):
        n = 50
    n = max(1, min(n, 500))

    try:
        with open(EVENTS_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
        return []
    except OSError as e:
        _log("events read OSError: %s" % e)
        return []

    events = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            # Trailing partial line (engine mid-append) or other corruption
            # -- skip it, never 500.
            continue
        if isinstance(obj, dict):
            events.append(obj)

    events.reverse()  # file is append-order (oldest..newest) -> newest-first
    return events[:n]


# ---------------------------------------------------------------------------
# HTML UI (inline CSS/JS, no external assets)
# ---------------------------------------------------------------------------

INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Snapshot Monitor</title>
<style>
  :root {
    --bg:      #0a0a0a;
    --card:    #131313;
    --border:  #232323;
    --text:    #e6e6e6;
    --dim:     #8a8a8a;
    --faint:   #555;
    --green:   #2ea043;
    --green-dim: #1c3a22;
    --amber:   #d29922;
    --amber-dim: #3a2f10;
    --red:     #c0392b;
    --red-dim: #3a1414;
    --gray:      #9a9a9a;
    --gray-dim:  #2a2a2a;
    --pill-fg: #0a0a0a;
  }
  * { box-sizing: border-box; }
  html, body { overflow: hidden; }        /* no scrollbars on the primary view */
  html, body {
    margin: 0; padding: 0;
    background: transparent;          /* the .app supplies a blurred vibrancy backdrop */
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", Helvetica, Arial, sans-serif;
    font-size: 13px;
    -webkit-font-smoothing: antialiased;
  }
  /* CONTENT-SIZED. `min-height: 100vh` used to stretch this to the window and
     `overflow: hidden` clipped the absolutely-positioned #activity panel; both are
     gone so the page reports its true height and the app matches the window to it.
     Page scrollbars are still suppressed by `html, body { overflow: hidden }`. */
  #app { display: flex; flex-direction: column; position: relative; }

  /* COLLAPSED BY DEFAULT: exactly one line, ellipsised. The monitor must stay
     small when something is wrong -- a long problems[] list used to push the
     whole panel open unprompted. Click the banner to expand it. */
  #banner {
    display: none;
    padding: 7px 11px;
    font-weight: 600;
    font-size: 11px;
    line-height: 1.45;
    cursor: pointer;
    user-select: none;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  /* EXPANDED: full text. A long problems[] list (P1..P14 in a bad case) must
     stay legible in the window rather than pushing the drives/timeline
     off-screen or overflowing horizontally -- cap the height and let IT
     scroll, not the page. */
  #banner.open {
    white-space: pre-wrap;
    word-break: break-word;
    text-overflow: clip;
    max-height: 40vh;
    overflow-y: auto;
  }
  #banner.fail { display: block; background: var(--red); color: #fff; }
  #banner.warn { display: block; background: var(--amber); color: #1a1300; }
  /* WORKING. Added 2026-08-26: removing "a copy is running" from the warn trigger stopped the
     board going amber several hours a day, but it also left the page with NO way to say a
     backup is in progress -- "no warning" and "I can see it working" are different things, and
     the owner asked for the second. This is a CALM, POSITIVE state: the green of the OK pill on
     a dim ground, deliberately nothing like the amber warn or the red fail. It shows only while
     something is genuinely in flight; when idle the banner is empty as before. */
  #banner.ok { display: block; background: var(--gray-dim); color: var(--green); }
  #banner.unreachable { display: block; background: var(--red); color: #fff; }
  #banner.off  { display: block; background: var(--gray-dim); color: var(--gray); }

  /* One row per dedup-blocked stamp, shown only while #banner is fail AND expanded -- a skip
     action makes sense only once you can see WHICH problem line it applies to. */
  #dedup-actions { display: none; border-bottom: 1px solid var(--border); }
  #dedup-actions.open { display: block; }
  .dedup-row {
    display: flex; align-items: center; gap: 8px;
    padding: 7px 11px; font-size: 10.5px; color: var(--dim);
    border-top: 1px solid var(--border);
  }
  .dedup-row:first-child { border-top: none; }
  .dedup-row .stamp { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: var(--text); flex: 1 1 auto; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .skip-btn {
    flex: 0 0 auto;
    background: var(--card); color: var(--text); border: 1px solid var(--border);
    border-radius: 5px; padding: 3px 9px; font-size: 10px; font-weight: 600;
    cursor: pointer;
  }
  .skip-btn:hover { border-color: var(--dim); }
  .skip-btn:disabled { opacity: 0.5; cursor: default; }

  /* force-settle: a bigger override than skip-dedup (can make an unsettled stamp eligible at
     all, not just bypass one heuristic) -- amber-tinted so it visually reads as more consequential,
     not a plain gray button identical to the smaller dedup-skip action. */
  #force-settle-actions { display: none; border-bottom: 1px solid var(--border); }
  #force-settle-actions.open { display: block; }
  .force-settle-btn {
    flex: 0 0 auto;
    background: var(--amber-dim); color: var(--amber); border: 1px solid var(--amber);
    border-radius: 5px; padding: 3px 9px; font-size: 10px; font-weight: 600;
    cursor: pointer;
  }
  .force-settle-btn:hover { opacity: 0.85; }
  .force-settle-btn:disabled { opacity: 0.5; cursor: default; }

  /* mute: the most consequential of the three, because it is the only PERMANENT one -- it stops
     the snapshot being retried at all and takes its problem line out of the alarm set until it is
     explicitly unmuted. Red-tinted to read as heavier than the amber force-settle. */
  #mute-actions { display: none; border-bottom: 1px solid var(--border); }
  #mute-actions.open { display: block; }
  .mute-btn {
    flex: 0 0 auto;
    background: var(--red-dim); color: var(--red); border: 1px solid var(--red);
    border-radius: 5px; padding: 3px 9px; font-size: 10px; font-weight: 600;
    cursor: pointer;
  }
  .mute-btn:hover { opacity: 0.85; }
  .mute-btn:disabled { opacity: 0.5; cursor: default; }

  /* The muted ledger. Originally ALWAYS visible, on the reasoning that an invisible silenced
     snapshot is how a monitor starts lying. Changed 2026-08-26 at the owner's explicit request:
     a suppressed stamp from a day or two ago sitting permanently on the board is precisely the
     "obscure warning" he does not want to look at. It is now INSIDE the click-to-expand
     disclosure (same gate as #dedup-actions and #mute-actions), so it is one click away rather
     than always on screen. It does NOT become invisible: whenever rows exist the banner always
     carries a calm one-line handle saying how many, so the disclosure is discoverable and the
     old "quietly lying" failure mode is still avoided. */
  #muted-list { display: none; border-bottom: 1px solid var(--border); }
  #muted-list.show.open { display: block; }
  .muted-row {
    display: flex; align-items: baseline; gap: 8px;
    padding: 6px 11px; font-size: 10px; color: var(--dim);
    border-top: 1px solid var(--border);
  }
  .muted-row:first-child { border-top: none; }
  .muted-row .stamp {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    color: var(--dim); flex: 0 0 auto;
  }
  .muted-row .why { flex: 1 1 auto; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .muted-row .gap { color: var(--amber); flex: 0 0 auto; }
  .unmute-btn {
    flex: 0 0 auto;
    background: transparent; color: var(--dim); border: 1px solid var(--border);
    border-radius: 5px; padding: 2px 7px; font-size: 9.5px; font-weight: 600;
    cursor: pointer;
  }
  .unmute-btn:hover { color: var(--text); border-color: var(--dim); }
  .unmute-btn:disabled { opacity: 0.5; cursor: default; }

  /* A hairline scrim keeps text legible over a bright wallpaper without
     hiding it -- the vibrancy blur does most of the work. */
  /* True transparency: no panel background at all. Text legibility over an
     arbitrary wallpaper comes from a shadow on the glyphs, not from covering
     the wallpaper up. */
  #app::before {
    content: ""; position: absolute; inset: 0;
    background: rgba(0,0,0,0.12);
    pointer-events: none; z-index: -1;
  }
  body, body * {
    text-shadow: 0 1px 2px rgba(0,0,0,0.95), 0 0 6px rgba(0,0,0,0.75);
  }
  .pill, .pill * { text-shadow: none; }
  /* Banners and the action/muted rows paint their OWN solid background, so the glyph shadow
     above buys no legibility there -- it only smears the text. The shadow exists for text
     sitting directly over the wallpaper; these elements never are. */
  #banner, #banner *,
  #mute-actions, #mute-actions *,
  #muted-list, #muted-list *,
  #dedup-actions, #dedup-actions *,
  #force-settle-actions, #force-settle-actions * { text-shadow: none; }
  header {
    /* The WKWebView fills the window INCLUDING under the titlebar, so the first
       ~22px are behind the traffic-light buttons. Pad down to clear them. */
    padding: 23px 11px 5px 11px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    border-bottom: 1px solid var(--border);
    cursor: pointer;              /* click the header to toggle Recent activity */
    user-select: none;
  }
  header h1 {
    font-size: 12.5px;
    margin: 0;
    font-weight: 600;
    letter-spacing: 0.2px;
  }
  .pill {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 3px 10px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.4px;
    text-transform: uppercase;
    user-select: none;
  }
  /* The pill is the DISCLOSURE control (2026-08-26): click it to expand muted rows and the
     override actions. It only advertises itself when there is actually something behind it --
     `has-details` is set by render(). Muting must leave the board silent, so the affordance is
     a cursor and a faint ring on hover, never a notice. */
  .pill.has-details { cursor: pointer; }
  .pill.has-details:hover { box-shadow: 0 0 0 1px var(--border) inset; }
  .pill .dot { width: 7px; height: 7px; border-radius: 50%; background: currentColor; }
  .pill.ok   { background: var(--green-dim); color: var(--green); }
  .pill.warn { background: var(--amber-dim); color: var(--amber); }
  .pill.fail { background: var(--red-dim);   color: var(--red); }
  .pill.off  { background: var(--gray-dim);  color: var(--gray); }

  main { padding: 7px 11px 8px 11px; }

  .section-title { display: none; }              /* compact layout drops section headers */

  #status-line { font-size: 11px; color: var(--dim); line-height: 1.35; }
  #status-line strong { color: var(--text); font-weight: 600; }
  /* #inflight REMOVED 2026-08-26. It was a second, AMBER "copying <stamp>..." line pinned under
     the drives. Once the banner started reporting live activity in green it became pure
     duplication -- and amber reads as "worry" for what is simply the system working. Activity
     is now reported in exactly ONE place, the banner, in the calm colour. */

  .kv { display: flex; gap: 8px; align-items: baseline; margin-bottom: 3px; }
  .kv .k {
    flex: 0 0 34px; font-size: 9.5px; text-transform: uppercase;
    letter-spacing: 0.6px; color: var(--faint);
  }
  .kv .v { font-size: 11.5px; color: var(--text); white-space: nowrap; }
  .kv .v .ago { color: var(--dim); font-weight: 400; }

  .drive { display: flex; align-items: center; gap: 7px; margin-top: 6px; }
  .dname { flex: 0 0 46px; font-size: 10.5px; font-weight: 600; color: var(--text); }
  .dstate { flex: 0 0 auto; font-size: 9.5px; color: var(--dim); white-space: nowrap; min-width: 46px; text-align: right; }
  .bar-track {
    flex: 1 1 auto; height: 7px; border-radius: 4px;
    background: rgba(255,255,255,0.13);
    overflow: hidden; display: block;
  }
  .bar-fill {
    display: block; height: 100%; border-radius: 4px;
    background: var(--green);
    /* A true-proportion bar at ~0.1% renders as an EMPTY track, which is the
       "looks dead" problem in graphical form. Any nonzero usage gets a visible
       sliver so a healthy, barely-filled drive never reads as broken. */
    min-width: 4px;
    transition: width .35s ease;
  }
  .drive.bad .bar-fill { background: var(--red); min-width: 100%; }
  .drive.bad .dname, .drive.bad .dstate { color: #ffb4a8; }
  .bar-fill.warn { background: var(--amber); }
  .bar-fill.full { background: var(--red); }

  #checked-line { margin-top: 6px; font-size: 10px; color: var(--faint); }

  /* Recent activity: hidden until the pointer is over the window. */
  /* IN FLOW, not an overlay. As a translucent absolutely-positioned dropdown it
     covered the status lines and both bled through each other; and because it
     contributed no height, opening it could not grow the window. In flow it adds
     real height, so clicking for more info makes the panel bigger -- which is the
     whole contract here. The title and pill stay above it either way, which was
     the point of the original top:47px anchor. */
  #activity {
    display: none;
    border-top: 1px solid var(--border);
    padding: 8px 11px 10px 11px;
    overflow: hidden;                      /* never scrolls */
  }
  /* CLICK, NOT HOVER. The old trigger was `body.hovering` (set by the app's native
     tracking area) plus an `#app:hover` fallback. A missed mouse-exit left the
     dropdown stuck open over the content with no way to dismiss it, so the panel
     is now toggled explicitly by clicking the header. */
  body.activity-open #activity { display: block; }
  .act-foot { display: none; }
  .act-title {
    font-size: 9.5px; text-transform: uppercase; letter-spacing: 0.6px;
    color: var(--faint); margin-bottom: 5px;
  }
  .drive-card.unmounted .mount-state { color: #ffb4a8; font-weight: 600; }

  .timeline { display: flex; flex-direction: column; gap: 2px; }
  /* Narrow-panel rows: ONE line each, time -> kind -> stamp, clipped not wrapped.
     The panel is only ~340px wide, so the old card grid overflowed horizontally. */
  .ev-row {
    display: flex;
    gap: 6px;
    align-items: baseline;
    padding: 2px 0;
    font-size: 10.5px;
    white-space: nowrap;
    overflow: hidden;
  }
  .ev-row.copy_failed, .ev-row.verify_failed, .ev-row.error { color: #ffb4a8; }
  .ev-row.pruned { opacity: 0.55; }
  .ev-time { color: var(--faint); font-size: 10px; flex: 0 0 auto; }
  .ev-kind {
    font-weight: 700; text-transform: uppercase; font-size: 9px;
    color: var(--dim); flex: 0 0 auto; letter-spacing: 0.3px;
  }
  .ev-row.copied .ev-kind   { color: var(--green); }
  .ev-row.detected .ev-kind { color: var(--dim); }
  .ev-row.copy_failed .ev-kind, .ev-row.verify_failed .ev-kind, .ev-row.error .ev-kind { color: #ffb4a8; }
  .ev-snap {
    color: var(--text); font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 10px; overflow: hidden; text-overflow: ellipsis; min-width: 0;
  }
  .ev-detail { display: none; }          /* detail is noise in a 340px strip */
  .empty { color: var(--faint); font-size: 11.5px; padding: 8px 2px; }

  footer {
    padding: 8px 14px 12px 14px;
    font-size: 10px;
    color: var(--faint);
    text-align: center;
  }
</style>
</head>
<body>
<div id="app">
  <header>
    <h1>Snapshot Monitor</h1>
    <span id="pill" class="pill ok"><span class="dot"></span><span id="pill-text">...</span></span>
  </header>
  <!-- BELOW the header on purpose: the header pads down to clear the traffic-light
       buttons, so a banner placed above it renders underneath them. This also keeps
       the title and the OK/WARN/FAIL pill visible whatever the banner is doing. -->
  <div id="banner"></div>
  <div id="dedup-actions"></div>
  <div id="force-settle-actions"></div>
  <div id="mute-actions"></div>
  <div id="muted-list"></div>
  <main>
    <div class="kv"><span class="k">last</span><span class="v" id="last-line">&mdash;</span></div>
    <div class="kv"><span class="k">next</span><span class="v" id="next-line">&mdash;</span></div>
    <div class="drive" id="card-primary">
      <span class="dname">primary</span>
      <span class="bar-track"><span class="bar-fill" id="primary-bar" style="width:0%"></span></span>
      <span class="dstate" id="primary-mount">&mdash;</span>
    </div>
    <div class="drive" id="card-replica">
      <span class="dname">replica</span>
      <span class="bar-track"><span class="bar-fill" id="replica-bar" style="width:0%"></span></span>
      <span class="dstate" id="replica-mount">&mdash;</span>
    </div>
    <div id="checked-line">&mdash;</div>
  </main>

  <div id="activity">
    <div class="act-title">Recent activity</div>
    <div class="timeline" id="timeline"><div class="empty">loading&hellip;</div></div>
    <div class="act-foot">127.0.0.1:7788</div>
  </div>

</div>

<script id="bootstrap" type="application/json">__BOOTSTRAP_JSON__</script>
<script>
(function () {
  "use strict";
  var ORIG_TITLE = "Snapshot Monitor";
  var unreachable = false;
  var lastStatus = null;

  function fmtKB(kb) {
    if (kb === null || kb === undefined) return "\u2014";
    var b = kb * 1024;
    var tb = b / 1099511627776;
    if (tb >= 1) return tb.toFixed(2) + " TB";
    var gb = b / 1073741824;
    return gb.toFixed(1) + " GB";
  }

  function fmtAge(sec) {
    if (sec === null || sec === undefined || isNaN(sec)) return "unknown age";
    sec = Math.max(0, sec);
    if (sec < 60) return Math.round(sec) + "s old";
    var m = sec / 60;
    if (m < 60) return Math.round(m) + " min old";
    var h = m / 60;
    if (h < 48) return h.toFixed(1) + " h old";
    return (h / 24).toFixed(1) + " days old";
  }

  /* " \u2014 15 min" for a live activity line, or "" when the elapsed time is unknown or still
     under a minute (a bare "0 min" reads as broken). Suffix form so the caller can append it
     unconditionally. */
  function fmtElapsedSuffix(sec) {
    if (sec === null || sec === undefined || isNaN(sec)) return "";
    sec = Math.max(0, sec);
    if (sec < 60) return "";
    var m = Math.round(sec / 60);
    if (m < 60) return " \u2014 " + m + " min";
    var h = Math.floor(m / 60), r = m % 60;
    return " \u2014 " + h + " h " + (r < 10 ? "0" + r : r) + " min";
  }

  function fmtClock(iso) {
    if (!iso) return "\u2014";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    return d.toLocaleString();
  }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function setPill(state, label) {
    var pill = document.getElementById("pill");
    pill.className = "pill " + state;
    document.getElementById("pill-text").textContent = label;
  }

  // Expanded/collapsed is USER state, so it must survive the 10 s re-render --
  // renderBanner reassigns className wholesale and would otherwise snap the
  // banner shut under the pointer every poll.
  var bannerOpen = false;

  function renderBanner(state, lines) {
    var b = document.getElementById("banner");
    var open = bannerOpen ? " open" : "";
    if (state === "fail" && lines && lines.length) {
      b.className = "fail" + open;
      b.textContent = "\u26a0 " + lines.join("\\n\u26a0 ");
    } else if (state === "warn" && lines && lines.length) {
      b.className = "warn" + open;
      b.textContent = lines.join("\\n");
    } else if (state === "unreachable") {
      b.className = "unreachable" + open;
      b.textContent = "\u26a0 monitor backend unreachable \u2014 retrying\u2026";
    } else if (state === "off" && lines && lines.length) {
      b.className = "off" + open;
      b.textContent = lines.join("\\n");
    } else if (state === "ok" && lines && lines.length) {
      b.className = "ok" + open;
      b.textContent = lines.join("\\n");
    } else {
      b.className = "";
      b.textContent = "";
      // NOTE: bannerOpen is deliberately NOT reset here any more (2026-08-26). An empty banner
      // no longer means "nothing to disclose" -- the muted ledger opens from the PILL and lives
      // behind the same flag, so resetting here closed it again on every poll. render() owns
      // that decision now, via hasDisclosure.
    }
  }

  // The writer's snapshot schedule, verified directly from the writer's LaunchAgent
  // on 2026-08-21: StartCalendarInterval = 12:00, 18:00, 00:15, 04:00 (four per day).
  // 00:15 is offset deliberately -- a separate archive job holds the writer's lock at
  // 00:00, and whichever started second would silently bounce.
  //
  // KEEP THIS IN SYNC WITH THE WRITER. It is display-only (nothing schedules off it),
  // but a stale slot list makes NEXT lie, and NEXT exists precisely so a not-yet-due
  // backup is never mistaken for a missed one.
  var WRITER_SLOTS = [[12, 0], [18, 0], [0, 15], [4, 0]];

  function nextRunInfo() {
    var now = new Date();
    var best = null;
    // Check today's and tomorrow's occurrence of every slot; take the soonest future one.
    for (var d = 0; d <= 1; d++) {
      for (var i = 0; i < WRITER_SLOTS.length; i++) {
        var h = WRITER_SLOTS[i][0], m = WRITER_SLOTS[i][1];
        var t = new Date(now.getFullYear(), now.getMonth(), now.getDate() + d, h, m, 0);
        if (t.getTime() > now.getTime() && (best === null || t.getTime() < best.getTime())) {
          best = t;
        }
      }
    }
    if (best === null) return { label: "\u2014", secs: 0 };
    var hh = best.getHours() % 12 || 12;
    var ap = best.getHours() < 12 ? "AM" : "PM";
    var mm = best.getMinutes() < 10 ? "0" + best.getMinutes() : "" + best.getMinutes();
    var today = best.getDate() === now.getDate();
    return { label: (today ? "today " : "tomorrow ") + hh + ":" + mm + " " + ap,
             secs: (best.getTime() - now.getTime()) / 1000 };
  }

  function stampAgeSeconds(stamp) {
    if (!stamp) return null;
    var m = /^(\\d{4})-(\\d{2})-(\\d{2})_(\\d{2})(\\d{2})(\\d{2})$/.exec(stamp);
    if (!m) return null;
    var t = new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]).getTime();
    return Math.max(0, (Date.now() - t) / 1000);
  }

  function fmtStamp(stamp) {
    var m = /^(\\d{4})-(\\d{2})-(\\d{2})_(\\d{2})(\\d{2})(\\d{2})$/.exec(stamp || "");
    if (!m) return null;
    var d = new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
    var hh = d.getHours() % 12 || 12;
    var ap = d.getHours() < 12 ? "AM" : "PM";
    var mo = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"][d.getMonth()];
    return mo + " " + d.getDate() + ", " + hh + ":" + m[5] + " " + ap;
  }

  function renderDrive(prefix, mounted, freeKb, usedKb, totalKb) {
    var card = document.getElementById("card-" + prefix);
    var mountEl = document.getElementById(prefix + "-mount");
    var barEl = document.getElementById(prefix + "-bar");
    if (!mounted) {
      card.classList.add("bad");
      mountEl.textContent = "OFFLINE";
      if (barEl) { barEl.style.width = "100%"; }
      return;
    }
    card.classList.remove("bad");
    var pct = (totalKb ? Math.min(100, Math.max(0, (usedKb / totalKb) * 100)) : 0);
    if (barEl) {
      barEl.style.width = pct.toFixed(2) + "%";
      barEl.classList.toggle("warn", pct >= 75 && pct < 90);
      barEl.classList.toggle("full", pct >= 90);
    }
    // Title carries the exact figures for a hover/right-click read without
    // spending any of the 146px on them.
    if (card) card.title = fmtGBexact(usedKb) + " used of " + fmtGBexact(totalKb)
                           + "  (" + pct.toFixed(2) + "%)";
    mountEl.textContent = "mounted";
  }

  function fmtGBexact(kb) {
    if (kb === null || kb === undefined) return "\u2014";
    var gb = kb / 1048576;
    return gb >= 1024 ? (gb / 1024).toFixed(2) + " TB" : gb.toFixed(2) + " GB";
  }

  function render(d) {
    lastStatus = d;
    var state = d.display_state || "fail";

    setPill(state, state.toUpperCase());
    document.title = (state === "fail" ? "\u26a0 " : "") + ORIG_TITLE;

    var monitorNotes = (d.monitor_notes && d.monitor_notes.length) ? d.monitor_notes : [];

    // Plain-English lines, built from the STATUS DATA rather than the engine's diagnostic prose.
    var plain = humanNotes(d);
    var shownLines = [];

    if (state === "fail") {
      var flines = (d.problems && d.problems.length) ? d.problems.slice() : [];
      if (!flines.length && d.monitor_error) flines.push(d.monitor_error);
      // Deliberately NOT concat(plain): in a fail state the progress lines contradict the
      // failure ("1 backup waiting to be copied" printed directly under "failed to copy").
      // When something has failed, the failure IS the message.
      flines = flines.concat(monitorNotes);
      shownLines = flines.length ? flines : ["Something is wrong \u2014 no detail available"];
      renderBanner("fail", shownLines);
    } else if (state === "warn") {
      shownLines = plain.concat(monitorNotes);
      if (!shownLines.length) {
        // humanNotes() already emits a progress sentence whenever a copy is running, pending or
        // being written. So an EMPTY result here means nothing is in flight -- printing
        // "Working..." then would be a plain lie, and it stayed on screen for hours.
        var busy = d.mirror_running || (d.pending || []).length || (d.unsettled || []).length;
        shownLines = [busy ? "Working\u2026" : "Up to date \u2014 nothing waiting to copy"];
      }
      renderBanner("warn", shownLines);
    } else if (state === "off") {
      shownLines = plain.concat(monitorNotes);
      if (!shownLines.length) shownLines = ["Paused \u2014 waiting for the writer to reconnect"];
      renderBanner("off", shownLines);
    } else {
      // OK is not the same as "nothing to say". humanNotes() emits a progress sentence ONLY
      // when something is actually in flight (copy running / writer writing / stamps queued),
      // so this cannot print a reassuring lie while idle -- an empty result still clears the
      // banner exactly as before. What it fixes: before 2026-08-26 the ok branch discarded
      // `plain` outright, so once a running copy stopped forcing the board amber there was
      // NOTHING on screen saying a backup was in progress.
      shownLines = plain.concat(monitorNotes);
      // NO "N suppressed snapshot" handle here (removed 2026-08-26 at the owner's request):
      // "after I mute a message, I want to see nothing in the monitor." Muting must mean
      // silence, not a smaller notice about the silence. The ledger stays reachable because
      // the PILL is now the disclosure control -- see the #pill click handler.
      renderBanner("ok", shownLines);
    }
    // Collapse only when there is genuinely NOTHING behind the disclosure. renderBanner used to
    // reset bannerOpen itself whenever the banner had no text, which would now snap the muted
    // ledger shut on the next 10 s poll -- the banner is empty in exactly the case the pill
    // exists to open. Decide it here instead, where the full status is in hand.
    var hasDisclosure = shownLines.length || suppressedCount(d) ||
                        (d.dedup_failures || []).length || (d.force_settle_candidates || []).length;
    if (!hasDisclosure) bannerOpen = false;
    document.getElementById("pill").classList.toggle("has-details", !!hasDisclosure);

    renderDedupActions(state === "fail" ? (d.dedup_failures || []) : []);
    document.getElementById("dedup-actions").classList.toggle("open", bannerOpen);
    // The muted ledger now lives behind the same disclosure as the action rows (2026-08-26).
    document.getElementById("muted-list").classList.toggle("open", bannerOpen);
    // Independent of display_state: a stamp can be unsettled-but-eligible without that alone
    // being a "fail" (being unsettled is only ever a note by itself), so this isn't gated on
    // state === "fail" the way the dedup row is.
    renderForceSettleActions(d.force_settle_candidates || []);
    document.getElementById("force-settle-actions").classList.toggle("open", bannerOpen);

    // Mute is offered against the LIVE problem set only, so a button can never appear for a
    // problem that has already resolved on its own.
    renderMuteActions(shownLines);
    document.getElementById("mute-actions").classList.toggle("open", bannerOpen);
    // ...but the ledger of what IS muted is unconditional -- see #muted-list in the CSS.
    renderMutedList(d.muted || [], d.muted_lines || []);

    renderDrive("primary", d.primary_mounted, d.primary_free_kb, d.primary_used_kb, d.primary_total_kb);
    renderDrive("replica", d.replica_mounted, d.replica_free_kb, d.replica_used_kb, d.replica_total_kb);

    var lc = d.last_copy;
    var stamp = d.latest_replica || d.latest_primary;
    var snapAge = stampAgeSeconds(stamp);
    var pretty = fmtStamp(stamp);

    document.getElementById("last-line").innerHTML =
      pretty ? esc(pretty) + " <span class='ago'>\u00b7 " + esc(fmtAge(snapAge)).replace(/ old$/, " ago") + "</span>"
             : "\u2014";

    var nx = nextRunInfo();
    document.getElementById("next-line").innerHTML =
      esc(nx.label) + " <span class='ago'>\u00b7 in " + esc(fmtAge(nx.secs)).replace(/ old$/, "") + "</span>";

    // replica state: in sync when it holds everything the primary does
    var pend = (d.pending || []).length;
    var rEl = document.getElementById("replica-mount");
    var rCard = document.getElementById("card-replica");
    if (!d.replica_mounted) { rEl.textContent = "OFFLINE"; rCard.classList.add("bad"); }
    else if (pend) { rEl.textContent = pend + " pending"; rCard.classList.remove("bad"); }
    else { rEl.textContent = "in sync"; rCard.classList.remove("bad"); }

    document.getElementById("checked-line").textContent =
      "checked " + fmtAge(d.stale_seconds).replace(/ old$/, " ago");

    // (an amber #inflight "copying <stamp>..." line used to render here; removed 2026-08-26 --
    //  the banner is now the single place in-flight work is reported, and it reports it green)
  }

  function renderUnreachable() {
    setPill("fail", "UNREACHABLE");
    renderBanner("unreachable", []);
    document.title = "\u26a0 " + ORIG_TITLE;
  }

  function renderEvents(events) {
    var tl = document.getElementById("timeline");
    if (!events || !events.length) {
      tl.innerHTML = '<div class="empty">no events yet</div>';
      return;
    }
    var rows = [];
    for (var i = 0; i < events.length; i++) {
      var e = events[i];
      var kind = e.event || "?";
      rows.push(
        '<div class="ev-row ' + esc(kind) + '">' +
          '<span class="ev-kind">' + esc(kind) + '</span>' +
          '<span class="ev-snap">' + esc(e.snapshot || "\u2014") + '</span>' +
          '<span class="ev-time">' + esc(fmtClock(e.ts)) + '</span>' +
          (e.detail ? '<span class="ev-detail">' + esc(e.detail) + '</span>' : '') +
        '</div>'
      );
    }
    tl.innerHTML = rows.join("");
  }

  function fetchStatus() {
    fetch("/api/status", { cache: "no-store" })
      .then(function (r) { if (!r.ok) throw new Error("http " + r.status); return r.json(); })
      .then(function (d) {
        unreachable = false;
        render(d);
      })
      .catch(function () {
        unreachable = true;
        renderUnreachable();
      });
  }

  function fetchEvents() {
    fetch("/api/events?n=4", { cache: "no-store" })
      .then(function (r) { if (!r.ok) throw new Error("http " + r.status); return r.json(); })
      .then(function (d) { renderEvents(d); })
      .catch(function () {
        // Leave the last-known timeline in place; the status banner already
        // communicates "unreachable" -- don't blank the timeline too.
      });
  }

  // Server-side bootstrap: the HTML response embeds the CURRENT /api/status
  // and /api/events payloads verbatim in the JSON-typed script tag above,
  // computed at request time from the same STATE_DIR reads the API
  // uses. This makes the very first paint correct (no "loading..." flash,
  // and the raw HTML -- even with no JS execution, e.g. `curl` -- already
  // contains problem/notes text verbatim) without duplicating any display
  // logic: it's rendered through the exact same render()/renderEvents()
  // functions the periodic fetches use.
  var bootEl = document.getElementById("bootstrap");
  if (bootEl && bootEl.textContent) {
    try {
      var boot = JSON.parse(bootEl.textContent);
      if (boot && boot.status) render(boot.status);
      if (boot && boot.events) renderEvents(boot.events);
    } catch (e) { /* fall through to the live fetch below */ }
  }

  // ---- content-sized window ----
  // Report the real rendered height to the native shell, which resizes the window
  // to match. #activity is position:absolute so it contributes nothing to #app's
  // height -- measure its bottom explicitly or the window will not grow to reveal it.
  function reportHeight() {
    try {
      var mh = window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.resize;
      if (!mh) return;                       // plain browser: nothing to tell
      var app = document.getElementById("app");
      if (!app) return;
      var h = app.getBoundingClientRect().height;
      if (document.body.classList.contains("activity-open")) {
        var act = document.getElementById("activity");
        if (act) h = Math.max(h, act.getBoundingClientRect().bottom);
      }
      mh.postMessage(Math.ceil(h) + 1);      // +1 absorbs sub-pixel rounding
    } catch (e) { /* never let sizing break the page */ }
  }
  // Coalesce bursts (a render can fire several times in a tick).
  var heightTimer = null;
  function scheduleHeight() {
    if (heightTimer) clearTimeout(heightTimer);
    heightTimer = setTimeout(reportHeight, 30);
  }

  // ---- click-to-reveal (replaces the old hover behaviour) ----
  var bannerEl = document.getElementById("banner");
  bannerEl.addEventListener("click", function () {
    if (!bannerEl.className) return;          // ok state: nothing to expand
    setDisclosure(!bannerOpen);
  });

  // The PILL is the disclosure control (2026-08-26). The owner's rule: once something is muted
  // the board shows NOTHING about it -- so the old "N suppressed snapshot" handle line is gone,
  // and the expanded view is reached by clicking the status pill in the top right instead.
  var pillEl = document.getElementById("pill");
  pillEl.addEventListener("click", function () {
    if (!pillEl.classList.contains("has-details")) return;   // nothing behind it -> inert
    setDisclosure(!bannerOpen);
  });

  // Single place that opens/closes every disclosed section, so the pill and the banner can never
  // disagree about what is expanded.
  function setDisclosure(open) {
    bannerOpen = open;
    bannerEl.classList.toggle("open", bannerOpen);
    ["dedup-actions", "force-settle-actions", "muted-list", "mute-actions"].forEach(function (id) {
      var el = document.getElementById(id);
      if (el) el.classList.toggle("open", bannerOpen);
    });
    scheduleHeight();
  }

  // ---- skip-dedup control action (2026-08-25): a human click or an agent's own POST to the
  // same endpoint both land here from the caller's side; this is only the UI half. ----
  function renderDedupActions(stamps) {
    var el = document.getElementById("dedup-actions");
    if (!stamps || !stamps.length) { el.innerHTML = ""; return; }
    el.innerHTML = stamps.map(function (s) {
      return '<div class="dedup-row"><span class="stamp">' + esc(s) + '</span>' +
             '<button class="skip-btn" data-stamp="' + esc(s) + '">Skip dedup check</button></div>';
    }).join("");
    el.querySelectorAll(".skip-btn").forEach(function (btn) {
      btn.addEventListener("click", function (ev) {
        ev.stopPropagation();   // must not also trigger the banner's own collapse/expand
        skipDedup(btn.dataset.stamp, btn);
      });
    });
  }

  // reason/okLabel are optional and default to the original values, so the two pre-existing
  // callers (skip-dedup, force-settle) are byte-for-byte unchanged in behaviour.
  function postControl(endpoint, stamp, btn, idleLabel, reason, okLabel) {
    btn.disabled = true;
    btn.textContent = "Queuing…";
    fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ stamp: stamp, reason: reason || "requested via monitor UI" }),
    }).then(function (r) {
      return r.json().then(function (d) { return { ok: r.ok, body: d }; });
    }).then(function (res) {
      if (!res.ok) {
        btn.disabled = false;
        btn.textContent = idleLabel;
        alert("Could not act on " + stamp + ": " + (res.body && res.body.error || "unknown error"));
        return;
      }
      btn.textContent = okLabel || "Queued — re-running…";
      fetchStatus();   // re-fetch now rather than waiting for the next 10s poll
    }).catch(function () {
      btn.disabled = false;
      btn.textContent = idleLabel;
      alert("Could not reach the monitor backend for " + stamp);
    });
  }

  function skipDedup(stamp, btn) {
    postControl("/api/control/skip-dedup", stamp, btn, "Skip dedup check");
  }

  function forceSettle(stamp, btn) {
    postControl("/api/control/force-settle", stamp, btn, "Force resume");
  }

  // ---------------------------------------------------------------- plain-English status
  //
  // The engine's notes[] are written for whoever is debugging the engine: they quote inode
  // counts, KB deltas and attribution arithmetic. That is the right content for the LOG and
  // exactly the wrong content for a person asking "is my backup OK?". So the banner is built
  // from the STATUS DATA instead, and the diagnostic notes that merely narrate the same thing
  // are dropped rather than translated -- one clear sentence beats three technical ones.
  // Anything unrecognised still falls through verbatim: a note this build has never seen must
  // never be silently swallowed.

  // Notes that are pure internal accounting. They describe HOW the engine measured something,
  // not anything the owner can act on, and the same facts are already in the log.
  // (The three volume-delta patterns that used to lead this list died with the engine's
  // P6/P7 deletion -- PLAN A4/F13: the engine can no longer emit them.)
  var NOTE_NOISE = [
    /^open-file soft limit is only /,
    /^prune rate limit: /,
    /^inode audit repaired /,
    /^deep-verify coverage degraded: /,
    // these three are replaced wholesale by the single progress sentence below
    /^a copy is in progress/,
    /^copy in progress: /,
    /^snapshot .* is unsettled \\(in progress on the writer\\)/,
    /^[0-9]+ snapshot\\(s\\) pending copy: /
  ];

  // Plain rewrites for notes that DO matter to the owner.
  var NOTE_REWRITE = [
    [/^backup system is PAUSED/, "Paused — waiting for the writer to come back on the network"],
    [/^handshake state is missing or stale/, "Can't tell if the writer is reachable right now"],
    [/^force-settle REFUSED for ([0-9_-]+)/, "Can't resume $1 yet — it isn't confirmed finished"],
    [/^orphan partial ([0-9_-]+) on the primary is ([0-9.]+) h old/,
     "An unfinished backup ($1) has been sitting for $2 hours"],
    [/^staging for ([0-9_-]+) left in place for forensics/,
     "Kept the partial copy of $1 so it can be examined"],
    [/^stamp ([0-9_-]+) can only be listing-verified/,
     "$1 can only be checked by file list — the original is pruned"],
    [/^corpse tracking is bootstrapping from NOTHING/,
     "Still learning which backups are complete — first run"],
    [/^corpse-tracking state \\(seen\\.json\\) was lost/,
     "Rebuilt its record of which backups are complete"],
    [/^previous status\\.json timestamp is .* in the FUTURE/,
     "The clock moved backwards — timestamps may be off"],
    [/^UNEXPECTED openrsync internal abort while copying ([0-9_-]+)/,
     "The copy of $1 aborted unexpectedly"]
  ];

  /* How many suppressed rows the ledger would actually SHOW. Mirrors renderMutedList's own
     filter: rows past MUTED_ROW_HIDE_HOURS arrive flagged hidden:true and are dropped from
     display (suppression itself persists, and the control endpoints still validate against the
     full list). Counting hidden rows here would advertise a disclosure that renders empty. */
  function suppressedCount(d) {
    var n = 0;
    (d.muted || []).forEach(function (m) { if (m && !m.hidden) n++; });
    (d.muted_lines || []).forEach(function (m) { if (m && !m.hidden) n++; });
    return n;
  }

  function humanNotes(d) {
    var out = [];
    var mutedStamps = {};
    (d.muted || []).forEach(function (m) { if (m && m.stamp) mutedStamps[m.stamp] = 1; });

    // ONE sentence for "work is happening", built from data rather than parsed from prose.
    // Deliberately NO size on these sentences (M7): the only per-pass number available here
    // was the whole-volume used-KB subtraction, and with the drives declared mixed-use that
    // difference measures the owner's other files, not the copy -- it lied. A truthful
    // per-copy figure does not exist in STATUS while the copy is still running.
    var writing = (d.unsettled || []).filter(function (s) { return !mutedStamps[s]; });
    var pending = (d.pending || []).filter(function (s) { return !mutedStamps[s]; });

    if (d.mirror_running) {
      // Elapsed = mirror_running_seconds + stale_seconds, and it has to be the SUM.
      // Corrected 2026-08-26 after observing a live copy: neither field alone is right.
      //   * mirror_running_seconds is the engine's own busy timer, but it only advances when a
      //     pass actually reaches engine.py -- i.e. at copy start (written as ~0) and then on
      //     each lock-held HEARTBEAT. Between heartbeats it is stale.
      //   * stale_seconds is (now - ts), and ts is rewritten by that same heartbeat -- so it
      //     measures time since the LAST heartbeat, not since the copy began.
      // Because ts and mirror_running_seconds are written in the SAME status write, the sum is
      // exact: "elapsed as of the last heartbeat" + "time since that heartbeat". Verified live
      // against a copy that started 18:23:29 -- 1335 + 312 = 1647s = the true 27.5 min, where
      // stale_seconds alone would have under-reported it as 5 min.
      var mrs = d.mirror_running_seconds;
      if (typeof mrs !== "number" || isNaN(mrs) || mrs < 0) mrs = 0;
      var st = (typeof d.stale_seconds === "number" && !isNaN(d.stale_seconds)) ? Math.max(0, d.stale_seconds) : 0;
      var cStamp = (d.incoming && d.incoming.length ? d.incoming[0] : (pending.length ? pending[0] : null));
      out.push("Copying " + (cStamp ? cStamp + " " : "") + "to the backup drive"
               + fmtElapsedSuffix(mrs + st));
    } else if (writing.length) {
      out.push("Writer is writing " + writing[0]
               + fmtElapsedSuffix(stampAgeSeconds(writing[0])));
    } else if (pending.length) {
      out.push(pending.length === 1
        ? "1 backup waiting to be copied"
        : pending.length + " backups waiting to be copied");
    }

    (d.notes || []).forEach(function (n) {
      if (!n) return;
      for (var i = 0; i < NOTE_NOISE.length; i++) {
        if (NOTE_NOISE[i].test(n)) return;
      }
      for (var j = 0; j < NOTE_REWRITE.length; j++) {
        if (NOTE_REWRITE[j][0].test(n)) {
          out.push(n.replace(NOTE_REWRITE[j][0], NOTE_REWRITE[j][1]));
          return;
        }
      }
      out.push(n);   // unrecognised -> verbatim, never swallowed
    });
    return out;
  }

  // Stamps this build is willing to offer a Mute button for: those named by a problem line whose
  // code is per-stamp mutable. Mirrors engine.py's MUTABLE_CODES exactly -- the engine re-checks
  // and is the real authority, so a drift here can only ever offer a button that does nothing,
  // never mute something the engine considers unmutable.
  var MUTABLE_CODES = ["P4", "P9", "P10", "P11", "P12", "P15"];
  var STAMP_IN_TEXT = /[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{6}/g;

  function mutableStampsFrom(problems) {
    var seen = {}, out = [];
    (problems || []).forEach(function (text) {
      if (!text) return;
      var code = String(text).split(/\\s+/)[0];
      if (MUTABLE_CODES.indexOf(code) === -1) return;
      if (String(text).indexOf("P4 SYSTEMIC") === 0) return;   // volume-level, never mutable
      var found = String(text).match(STAMP_IN_TEXT) || [];
      // Every stamp the line names must be offered together; muting only one of a multi-stamp
      // line would not silence it (the engine requires ALL named stamps to be muted), so
      // offering them individually would produce a button that visibly does nothing.
      found.forEach(function (s) {
        if (!seen[s]) { seen[s] = 1; out.push(s); }
      });
    });
    return out.sort();
  }

  // Every line the banner is showing gets a Mute button — notes included, stamp-less problems
  // included. Two flavours behind one button:
  //   - a per-stamp problem mutes the SNAPSHOT (also stops it being retried), which is the
  //     stronger, more meaningful action when it applies;
  //   - anything else mutes the LINE by shape, which is the only thing that can quiet a note.
  // Rows are held in a JS array and addressed by index, so arbitrary message text never has to
  // survive a round-trip through an HTML attribute.
  var muteRows = [];

  function renderMuteActions(lines) {
    var el = document.getElementById("mute-actions");
    muteRows = (lines || []).filter(function (t) { return t && String(t).trim(); })
      .map(function (text) {
        var s = mutableStampsFrom([text]);
        return (s.length === 1)
          ? { kind: "stamp", key: s[0], label: text }
          : { kind: "line", key: text, label: text };
      });
    if (!muteRows.length) { el.innerHTML = ""; return; }
    el.innerHTML = muteRows.map(function (r, i) {
      return '<div class="dedup-row"><span class="stamp">' + esc(r.label) + '</span>' +
             '<button class="mute-btn" data-idx="' + i + '">Mute</button></div>';
    }).join("");
    el.querySelectorAll(".mute-btn").forEach(function (btn) {
      btn.addEventListener("click", function (ev) {
        ev.stopPropagation();
        var r = muteRows[parseInt(btn.dataset.idx, 10)];
        if (!r) return;
        if (r.kind === "stamp") {
          if (!window.confirm(
                "Permanently mute snapshot " + r.key + "?\\n\\n" +
                "\\u2022 it will NOT be retried or copied to the replica\\n" +
                "\\u2022 its message leaves the banner\\n" +
                "\\u2022 it stays listed below as an acknowledged gap\\n\\n" +
                "Reversible with Unmute.")) return;
          postControl("/api/control/mute", r.key, btn, "Mute",
                      "muted from the monitor", "Muted — clears next pass");
          return;
        }
        if (!window.confirm(
              "Stop showing this message?\\n\\n" + r.label + "\\n\\n" +
              "It stays listed below with an Unmute button. Messages like it are matched by " +
              "shape, so changing numbers will not bring it back.")) return;
        postLineControl("/api/control/mute-line", { text: r.key }, btn, "Mute",
                        "Muted — clears next pass");
      });
    });
  }

  function postLineControl(endpoint, payload, btn, idleLabel, okLabel) {
    btn.disabled = true;
    btn.textContent = "Queuing…";
    payload.reason = payload.reason || "muted from the monitor";
    fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }).then(function (r) {
      return r.json().then(function (d) { return { ok: r.ok, body: d }; });
    }).then(function (res) {
      if (!res.ok) {
        btn.disabled = false;
        btn.textContent = idleLabel;
        alert("Could not mute that message: " + (res.body && res.body.error || "unknown error"));
        return;
      }
      btn.textContent = okLabel || "Done";
      fetchStatus();
    }).catch(function () {
      btn.disabled = false;
      btn.textContent = idleLabel;
      alert("Could not reach the monitor backend.");
    });
  }

  var mutedLineRows = [];

  function renderMutedList(muted, mutedLines) {
    var el = document.getElementById("muted-list");
    muted = muted || [];
    mutedLines = mutedLines || [];
    // A2/M8: rows older than 72 h arrive flagged hidden:true. Only the DISPLAY drops them --
    // suppression persists, and the control endpoints validate against the FULL status list,
    // so /api/control/retry and /unmute keep working for hidden rows via the API.
    var hiddenCount = 0;
    var visible = muted.filter(function (m) {
      if (m && m.hidden) { hiddenCount++; return false; }
      return true;
    });
    var visibleLines = mutedLines.filter(function (m) { return !(m && m.hidden); });
    if (!visible.length && !visibleLines.length && !hiddenCount) {
      el.innerHTML = ""; el.classList.remove("show"); return;
    }
    var html = visible.map(function (m) {
      var s = m && m.stamp ? m.stamp : "?";
      var why = (m && m.reason) ? m.reason : "no reason recorded";
      // Missing kind defaults to "muted" (F10): rows from an older engine build keep their
      // Unmute button; only an explicit kind="superseded" row gets "Retry copy" (A3) --
      // superseded stamps are never retried automatically, this button is the opt-back-in.
      var kind = (m && m.kind === "superseded") ? "superseded" : "muted";
      // A suppressed stamp that never reached the replica is a real hole in the archive.
      var gap = (m && m.on_primary && !m.on_replica) ? '<span class="gap">not on replica</span>' : "";
      var btn = (kind === "superseded")
        ? '<button class="retry-btn" data-stamp="' + esc(s) + '">Retry copy</button>'
        : '<button class="unmute-btn" data-stamp="' + esc(s) + '">Unmute</button>';
      return '<div class="muted-row"><span class="stamp">' + esc(s) + '</span>' +
             '<span class="why">' + kind + ' \\u2014 ' + esc(why) + '</span>' + gap + btn + '</div>';
    }).join("");

    mutedLineRows = visibleLines;
    html += visibleLines.map(function (m, i) {
      var sample = (m && m.sample) ? m.sample : (m && m.key) || "?";
      // "silencing now" tells you a mute is actively hiding something, vs one that is dormant.
      var live = (m && m.active) ? '<span class="gap">silencing now</span>' : "";
      return '<div class="muted-row"><span class="why">muted \\u2014 ' + esc(sample) + '</span>' +
             live + '<button class="unmute-line-btn" data-idx="' + i + '">Unmute</button></div>';
    }).join("");

    if (hiddenCount) {
      // F9: after 72 h the ROW hides but the suppression persists -- one line says so, so the
      // dropdown never silently understates what is being suppressed.
      html += '<div class="muted-row"><span class="why">' + hiddenCount +
              ' older suppressed snapshot' + (hiddenCount === 1 ? '' : 's') +
              ' hidden (older than 72 h)</span></div>';
    }

    el.innerHTML = html;
    el.classList.add("show");
    el.querySelectorAll(".unmute-btn").forEach(function (btn) {
      btn.addEventListener("click", function (ev) {
        ev.stopPropagation();
        postControl("/api/control/unmute", btn.dataset.stamp, btn, "Unmute",
                    "unmuted from the monitor", "Unmuted — retrying…");
      });
    });
    el.querySelectorAll(".retry-btn").forEach(function (btn) {
      btn.addEventListener("click", function (ev) {
        ev.stopPropagation();
        // The backend enforces the M8 cooldowns (already requested / failure < 30 min old /
        // 3 retries in 24 h) with a 409 whose error text lands in the alert below.
        postControl("/api/control/retry", btn.dataset.stamp, btn, "Retry copy",
                    "retry requested from the monitor", "Retry queued \\u2014 next pass");
      });
    });
    el.querySelectorAll(".unmute-line-btn").forEach(function (btn) {
      btn.addEventListener("click", function (ev) {
        ev.stopPropagation();
        var r = mutedLineRows[parseInt(btn.dataset.idx, 10)];
        if (!r) return;
        postLineControl("/api/control/unmute-line", { key: r.key }, btn, "Unmute", "Unmuted");
      });
    });
  }

  function renderForceSettleActions(stamps) {
    var el = document.getElementById("force-settle-actions");
    if (!stamps || !stamps.length) { el.innerHTML = ""; return; }
    el.innerHTML = stamps.map(function (s) {
      return '<div class="dedup-row"><span class="stamp">' + esc(s) + '</span>' +
             '<button class="force-settle-btn" data-stamp="' + esc(s) + '">Force resume</button></div>';
    }).join("");
    el.querySelectorAll(".force-settle-btn").forEach(function (btn) {
      btn.addEventListener("click", function (ev) {
        ev.stopPropagation();
        forceSettle(btn.dataset.stamp, btn);
      });
    });
  }

  function setActivity(open) {
    document.body.classList.toggle("activity-open", open);
    scheduleHeight();
  }

  document.querySelector("header").addEventListener("click", function (ev) {
    if (ev.target.closest && ev.target.closest("#banner")) return;
    setActivity(!document.body.classList.contains("activity-open"));
  });

  // The dropdown slides in over .17s; its final bottom edge is only known once
  // the transform settles, so remeasure then too.
  var activityEl = document.getElementById("activity");
  if (activityEl) activityEl.addEventListener("transitionend", reportHeight);

  // Dismissal: click anywhere outside the dropdown/header, or press Escape.
  document.addEventListener("click", function (ev) {
    if (!document.body.classList.contains("activity-open")) return;
    if (ev.target.closest && (ev.target.closest("#activity") || ev.target.closest("header"))) return;
    setActivity(false);
  });
  document.addEventListener("keydown", function (ev) {
    if (ev.key !== "Escape") return;
    setActivity(false);
    if (bannerOpen) { bannerOpen = false; bannerEl.classList.remove("open"); }
  });

  // Catch every in-flow size change (status re-render, banner expand, longer
  // problems list) without having to remember to call reportHeight at each site.
  if (window.ResizeObserver) {
    try { new ResizeObserver(scheduleHeight).observe(document.getElementById("app")); }
    catch (e) { /* fall back to the explicit calls below */ }
  }

  fetchStatus();
  fetchEvents();
  reportHeight();
  window.addEventListener("load", reportHeight);
  setInterval(fetchStatus, 10000);
  setInterval(fetchEvents, 30000);
})();
// Test hook only: if this literally never executes (e.g. a broken-parser
// regression like BUG-2 swallows this script tag), automated checks can
// detect it. Harmless in normal operation.
window.__BM_LOADED__ = true;
</script>
</body>
</html>
"""


def render_index_html():
    """Renders / with the CURRENT status + last 20 events embedded as a JSON
    bootstrap script tag, computed via the exact same functions /api/status
    and /api/events use. This is what makes "problem text appears in the
    HTML" true even with zero JS execution (e.g. plain curl): the raw
    response body already contains the current problems[]/notes[] text
    verbatim, not just after a client-side fetch. The JS on load hydrates
    from this same blob so there is no loading flash, then continues with
    the normal polling loop."""
    status_obj = build_status_response()
    events_obj = read_events(20)
    bootstrap_json = _script_safe_json({"status": status_obj, "events": events_obj})
    return INDEX_HTML.replace("__BOOTSTRAP_JSON__", bootstrap_json)


def _script_safe_json(obj):
    """JSON-encode obj for safe embedding inside a
    <script type="application/json"> tag.

    BUG-2 fix (second audit): the previous version only escaped the literal
    substring "</" to prevent a premature "</script>" close. That is NOT
    sufficient. The HTML tokenizer's script-data-escaped / script-data-
    double-escaped states are entered by "<!--" and "<script" sequences
    appearing INSIDE a <script> element's text, independent of any "</" --
    e.g. the byte sequence "<!--<script" alone can push the parser into a
    state where it swallows the remainder of the document (including our
    real UI <script> block) looking for the matching close sequence. This
    is realistically reachable: problems[]/notes[] strings and snapshot
    relpaths are freeform engine/filesystem text, and a filename containing
    that sequence would corrupt the page (availability bug -- confirmed by
    subtask 04 to NOT be an XSS/injection issue, since esc()/textContent are
    used everywhere for actual rendering; this is purely about the parser
    swallowing the script tag whole and never running our JS).

    The categorical fix: escape every '<', '>', and '&' character (as JSON
    \\uXXXX escapes, which JSON.parse decodes back to the literal character)
    so NO raw '<', '>', or '&' byte ever appears in the script tag's text
    content at all. With zero raw '<' characters present, the HTML
    tokenizer cannot enter ANY tag-like or comment-like state inside the
    script body -- not just the naive "</script>" case, but every variant
    (script-data-escaped, double-escaped, bogus comment, etc.), because all
    of those states are triggered by a literal '<' that no longer exists in
    the byte stream. json.dumps() already ensures valid JSON string escaping
    for quotes/backslashes/control chars; this only targets characters that
    are HTML-meaningful but JSON-harmless.
    """
    raw = json.dumps(obj)
    raw = raw.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return raw


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

# --------------------------------------------------------------------------- control (POST)
#
# The ONLY write path in this process, added 2026-08-25 for one narrow, explicit action: an
# operator (human click or an agent's API call) marking a specific stamp to skip the F8.5c
# dedup-inode-sharing assertion. This does NOT touch content verification (file count/bytes/
# listing_md5), which engine.py still enforces in full -- see its consume_skip_dedup(). This
# does not weaken the module's design elsewhere: every other endpoint stays pure GET/read-only.

def read_json(path, default=None):
    try:
        with open(path, "r") as fh:
            return json.load(fh)
    except (IOError, OSError, ValueError):
        return default


def _write_atomic(path, data):
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


def _write_json(path, obj):
    _write_atomic(path, json.dumps(obj, indent=1, sort_keys=True) + "\n")


def _current_dedup_failures():
    data, err = read_status_raw()
    if err is not None or not isinstance(data, dict):
        return []
    return list(data.get("dedup_failures") or [])


def _known_stamps():
    """Every snapshot the engine currently sees on either volume. Mute is validated against this
    rather than against a narrow candidate list, because the whole point is to write off a
    snapshot the engine keeps complaining about -- but it still refuses a stamp that exists
    nowhere, so a typo cannot silently create a permanent mute for a non-existent snapshot."""
    data, err = read_status_raw()
    if err is not None or not isinstance(data, dict):
        return []
    return sorted(set((data.get("primary_snapshots") or []) +
                      (data.get("replica_snapshots") or [])))


def _currently_superseded():
    """Superseded failure rows from STATUS -- the FULL list, hidden rows included (M8: the
    72 h row-hide is display-only; validation and the recovery path must outlive it). Missing
    STATUS or a STATUS without a muted list (F4_DEFAULTS has no muted key) yields [] and the
    endpoint 409s, which is the safe refusal."""
    data, err = read_status_raw()
    if err is not None or not isinstance(data, dict):
        return []
    out = []
    for m in (data.get("muted") or []):
        if isinstance(m, dict) and m.get("stamp") and m.get("kind") == "superseded":
            out.append(m)
    return out


def _line_mute_expired(rec):
    """True only for a record whose muted_at PARSES and is older than 72 h (A2). An
    unparseable/missing timestamp is never expired BY THE WRITER: the engine already ignores
    such an entry (loud-safe), but deleting a record this code cannot date would destroy the
    operator's ledger row, so it stays until unmuted by hand."""
    if not isinstance(rec, dict):
        return False
    dt = parse_ts(rec.get("muted_at"))
    if dt is None:
        return False
    now = datetime.datetime.now(dt.tzinfo)
    return (now - dt).total_seconds() > LINE_MUTE_EXPIRY_SECONDS


def _current_force_settle_candidates():
    data, err = read_status_raw()
    if err is not None or not isinstance(data, dict):
        return []
    return list(data.get("force_settle_candidates") or [])


def _kick_mirror():
    """Fire-and-forget: skip-dedup.json is only consumed on the NEXT pass, and a copy can run
    30-60+ min, so this must never block the HTTP response on it finishing -- same reasoning as
    the writer's own post-snapshot kick (nohup'd, detached). The UI/caller watches /api/status
    afterward, exactly as it already polls for everything else."""
    try:
        subprocess.Popen(
            ["/usr/bin/ssh", "-i", MIRROR_KEY, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
             "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15",
             "-o", "PreferredAuthentications=publickey", "localhost", "mirror"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        _log("could not kick mirror after skip-dedup: %s" % exc)


class Handler(BaseHTTPRequestHandler):
    server_version = "SnapshotMonitor/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        # Keep default access logging but route through our helper so it's
        # one line, never a traceback, and honors normal stderr redirection.
        try:
            _log("%s - %s" % (self.address_string(), fmt % args))
        except Exception:
            pass

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html, status=200):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/":
                self._send_html(render_index_html())
            elif path == "/api/status":
                self._send_json(build_status_response())
            elif path == "/api/events":
                qs = parse_qs(parsed.query)
                n = qs.get("n", ["50"])[0]
                self._send_json(read_events(n))
            else:
                self._send_json({"error": "not found"}, status=404)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            # Never let a traceback reach the client or the default
            # socketserver traceback-to-stderr handler.
            _log("unhandled error on %s: %s" % (self.path, e))
            try:
                self._send_json({"error": "internal"}, status=500)
            except Exception:
                pass

    def _handle_mute(self, path, raw, length):
        """POST /api/control/mute | /api/control/unmute -- the permanent per-snapshot mute.

        Kept OUT of the `routes` table above because it differs from skip-dedup/force-settle in
        two ways that table cannot express: unmute REMOVES a key rather than adding one, and mute
        validates against every known snapshot rather than a narrow candidate list.

        Deliberately does NOT _kick_mirror() on mute. A kick counts toward mirror.sh's own
        forced-command rate limiter, and exceeding that is itself an alarm (P16) -- so firing one
        to clear a banner could raise a different banner. Nothing needs to run for a mute to take
        effect: the engine re-reads muted.json at the top of every pass, so the banner clears on
        the next scheduled one (StartInterval 300 => within ~5 min). Unmute DOES kick, because
        there the operator is explicitly asking for the snapshot to be retried now.
        """
        if length <= 0:
            self._send_json({"error": "missing or oversized request body"}, status=400)
            return
        try:
            body = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._send_json({"error": "malformed JSON body"}, status=400)
            return
        stamp = body.get("stamp") if isinstance(body, dict) else None
        reason = body.get("reason") if isinstance(body, dict) else None
        if not isinstance(stamp, str) or not STAMP_RE.match(stamp):
            self._send_json({"error": "stamp missing or not a valid snapshot name"}, status=400)
            return
        existing = read_json(MUTED_PATH, {}) or {}
        if not isinstance(existing, dict):
            existing = {}

        if path.endswith("/unmute"):
            if stamp not in existing:
                self._send_json({"error": "stamp is not currently muted",
                                 "muted": sorted(existing)}, status=409)
                return
            existing.pop(stamp, None)
            _write_json(MUTED_PATH, existing)
            _log("UNMUTED %s by %s" % (stamp, self.address_string()))
            _kick_mirror()
            self._send_json({"status": "unmuted", "stamp": stamp})
            return

        known = _known_stamps()
        # An empty list means STATUS was unreadable, not that no snapshots exist. Validating
        # against nothing would refuse every mute at exactly the moment the operator most needs
        # one, so an unreadable STATUS falls back to the STAMP_RE check alone.
        if known and stamp not in known:
            self._send_json({"error": "stamp is not a snapshot on either volume",
                             "known_stamps": known}, status=409)
            return
        if stamp in existing:
            self._send_json({"status": "already muted", "stamp": stamp})
            return
        reason = reason if isinstance(reason, str) and reason.strip() else "no reason given"
        existing[stamp] = {
            "muted_at": datetime.datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z"),
            "reason": reason[:300],
        }
        _write_json(MUTED_PATH, existing)
        _log("MUTED %s permanently (reason: %s) by %s"
             % (stamp, reason[:80], self.address_string()))
        self._send_json({"status": "muted", "stamp": stamp})

    def _handle_mute_line(self, path, raw, length):
        """POST /api/control/mute-line | /unmute-line -- silence ANY banner line.

        Deliberately unrestricted, unlike the per-snapshot mute: the owner asked to be able to
        quiet every banner, including notes and stamp-less problems that MUTABLE_CODES cannot
        reach. What keeps that honest is not a restriction list but visibility -- every muted
        line ships back in STATUS.muted_lines with the text as it read when muted, its reason and
        timestamp, and whether it is silencing anything right now, and the monitor renders that
        ledger permanently. A silenced line is acknowledged, never invisible.

        Mutes are keyed by SHAPE (digit runs collapsed), so muting a message with a counter in it
        keeps working as the counter changes. Like the snapshot mute, this does NOT kick the
        mirror: nothing needs to run for it to take effect, and a kick would feed the P16 rate
        limiter. It lands on the next scheduled pass (<= ~5 min).
        """
        if length <= 0:
            self._send_json({"error": "missing or oversized request body"}, status=400)
            return
        try:
            body = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._send_json({"error": "malformed JSON body"}, status=400)
            return
        if not isinstance(body, dict):
            self._send_json({"error": "body must be a JSON object"}, status=400)
            return
        existing = read_json(MUTED_LINES_PATH, {}) or {}
        if not isinstance(existing, dict):
            existing = {}

        # A2: line mutes expire completely at 72 h and this process is the file's single
        # writer, so expired entries are garbage-collected here on ANY mute-line/unmute-line
        # POST (the engine only ignores them; it never writes this file). Only entries whose
        # timestamp actually parses are ever removed -- see _line_mute_expired().
        expired = [k for k, v in existing.items() if _line_mute_expired(v)]
        if expired:
            for k in expired:
                existing.pop(k, None)
            _write_json(MUTED_LINES_PATH, existing)
            _log("line-mute GC: removed %d expired entr%s (> 72 h): %s"
                 % (len(expired), "y" if len(expired) == 1 else "ies",
                    "; ".join(k[:80] for k in sorted(expired))))

        if path.endswith("/unmute-line"):
            key = body.get("key")
            if not isinstance(key, str) or not key.strip():
                self._send_json({"error": "key missing"}, status=400)
                return
            if key not in existing:
                self._send_json({"error": "line is not currently muted",
                                 "muted_lines": sorted(existing)}, status=409)
                return
            existing.pop(key, None)
            _write_json(MUTED_LINES_PATH, existing)
            _log("UNMUTED line: %s" % key[:120])
            _kick_mirror()          # unmute means "show me again now"
            self._send_json({"status": "unmuted", "key": key})
            return

        text = body.get("text")
        reason = body.get("reason")
        if not isinstance(text, str) or not text.strip():
            self._send_json({"error": "text missing"}, status=400)
            return
        if len(text) > 2000:
            self._send_json({"error": "text too long"}, status=400)
            return
        key = _line_key(text)
        if not key:
            self._send_json({"error": "text normalises to an empty key"}, status=400)
            return
        if key in existing:
            self._send_json({"status": "already muted", "key": key})
            return
        reason = reason if isinstance(reason, str) and reason.strip() else "muted from the monitor"
        existing[key] = {
            "sample": text[:300],
            "muted_at": datetime.datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z"),
            "reason": reason[:300],
        }
        _write_json(MUTED_LINES_PATH, existing)
        _log("MUTED line (%s): %s" % (reason[:40], key[:120]))
        self._send_json({"status": "muted", "key": key})

    def _handle_retry(self, raw, length):
        """POST /api/control/retry {stamp} -- opt a SUPERSEDED stamp back in (A3).

        A superseded stamp is never retried automatically; this is the operator's only way
        back. Validation is against the FULL status muted list (kind == "superseded", hidden
        rows included -- M8), then three cooldowns, each a 409, because every accepted request
        kicks mirror.sh and kicks burn the forced-command rate budget (exhaustion latches P16
        for 24 h -- a UI button must never be able to trip a security alarm), and every
        consumed retry burns a long USB copy attempt:
          1. already requested: the pending request has not been consumed yet -- one kick per
             request, so a hammered button cannot kick again until the engine consumes;
          2. the failure is < 30 min old (RETRY_MIN_FAILURE_AGE_SEC, from the row's failed_at);
          3. the engine has already consumed RETRY_MAX_PER_DAY retries for this stamp in 24 h
             (the row's retry_count -- the ENGINE increments it on consume, so it survives the
             failure record's deletion).
        On success: write retry-request.json (monitor-adds/engine-consumes; engine re-reads at
        its consume point) and kick. If a pass is already running the kick bounces and the
        request is consumed at the next scheduled pass instead -- fine, not an error."""
        if length <= 0:
            self._send_json({"error": "missing or oversized request body"}, status=400)
            return
        try:
            body = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._send_json({"error": "malformed JSON body"}, status=400)
            return
        stamp = body.get("stamp") if isinstance(body, dict) else None
        reason = body.get("reason") if isinstance(body, dict) else None
        if not isinstance(stamp, str) or not STAMP_RE.match(stamp):
            self._send_json({"error": "stamp missing or not a valid snapshot name"}, status=400)
            return
        rows = _currently_superseded()
        row = None
        for m in rows:
            if m.get("stamp") == stamp:
                row = m
                break
        if row is None:
            self._send_json({"error": "stamp is not currently a superseded copy failure",
                             "superseded": sorted(m.get("stamp") for m in rows)}, status=409)
            return
        # S11: distinguish "no requests" from "the request file is corrupt" -- overwriting a
        # corrupt file would silently destroy whatever request it held.
        existing = read_json(RETRY_REQUEST_PATH, None)
        if existing is None and os.path.exists(RETRY_REQUEST_PATH):
            self._send_json({"error": "retry-request.json exists but cannot be parsed; fix or "
                                      "remove it before requesting a retry"}, status=409)
            return
        if not isinstance(existing, dict):
            existing = {}
        if stamp in existing:
            prev = existing.get(stamp)
            self._send_json({"error": "retry already requested for this stamp; the engine "
                                      "consumes it at the start of its next pass",
                             "requested_at": (prev or {}).get("requested_at")
                             if isinstance(prev, dict) else None}, status=409)
            return
        failed_at = parse_ts(row.get("failed_at"))
        if failed_at is not None:
            age = (datetime.datetime.now(failed_at.tzinfo) - failed_at).total_seconds()
            if age < RETRY_MIN_FAILURE_AGE_SEC:
                self._send_json({"error": "failure is only %d minute(s) old; retry is allowed "
                                          "after %d minutes"
                                          % (int(age // 60), RETRY_MIN_FAILURE_AGE_SEC // 60)},
                                status=409)
                return
        rc = row.get("retry_count")
        if isinstance(rc, (int, float)) and not isinstance(rc, bool) \
                and rc >= RETRY_MAX_PER_DAY:
            self._send_json({"error": "retry limit reached: %d retries consumed in the last "
                                      "24 h for this stamp" % int(rc)}, status=409)
            return
        reason = reason if isinstance(reason, str) and reason.strip() else "no reason given"
        existing[stamp] = {
            "requested_at": datetime.datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z"),
            "reason": reason[:300],
        }
        _write_json(RETRY_REQUEST_PATH, existing)
        _log("RETRY requested for superseded %s (reason: %s) by %s"
             % (stamp, reason[:80], self.address_string()))
        _kick_mirror()          # exactly one kick per accepted request: every 409 above returns
        self._send_json({"status": "queued", "stamp": stamp})

    def do_POST(self):
        try:
            # HTTP/1.1 keep-alive: the body MUST be drained off the socket before responding to
            # ANY case (wrong path, oversized, etc.), or the leftover bytes desync the next
            # request on the same connection (observed directly: an unread body from a 404
            # response corrupted the following request's own request-line). Read it first,
            # unconditionally, before any branching.
            length = int(self.headers.get("Content-Length") or 0)
            if length > 4096:
                # Do not buffer an arbitrary declared size into memory (loopback-only, but a
                # broken/hostile client could still declare something huge). Force the
                # connection closed instead of draining -- safe either way, since a closed
                # connection can never desync a REUSED one.
                self.close_connection = True
                self._send_json({"error": "missing or oversized request body"}, status=400)
                return
            raw = self.rfile.read(length) if length > 0 else b""
            parsed = urlparse(self.path)
            if parsed.path in ("/api/control/mute", "/api/control/unmute"):
                self._handle_mute(parsed.path, raw, length)
                return
            if parsed.path in ("/api/control/mute-line", "/api/control/unmute-line"):
                self._handle_mute_line(parsed.path, raw, length)
                return
            if parsed.path == "/api/control/retry":
                # Kept out of the routes table: retry validates against superseded ROWS (it
                # needs failed_at/retry_count for the M8 cooldowns), not a bare stamp list.
                self._handle_retry(raw, length)
                return
            routes = {
                "/api/control/skip-dedup": (SKIP_DEDUP_PATH, _current_dedup_failures,
                                            "dedup_failures", "not currently a dedup failure"),
                "/api/control/force-settle": (FORCE_SETTLE_PATH, _current_force_settle_candidates,
                                              "force_settle_candidates",
                                              "not currently an eligible force-settle candidate "
                                              "(must be unsettled AND have been primary `latest` "
                                              "at some point -- engine.py itself re-checks and "
                                              "refuses this even if you bypass this validation)"),
            }
            if parsed.path not in routes:
                self._send_json({"error": "not found"}, status=404)
                return
            if length <= 0:
                self._send_json({"error": "missing or oversized request body"}, status=400)
                return
            try:
                body = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                self._send_json({"error": "malformed JSON body"}, status=400)
                return
            stamp = body.get("stamp") if isinstance(body, dict) else None
            reason = body.get("reason") if isinstance(body, dict) else None
            if not isinstance(stamp, str) or not STAMP_RE.match(stamp):
                self._send_json({"error": "stamp missing or not a valid snapshot name"},
                                status=400)
                return
            target_path, list_current, list_key, err_msg = routes[parsed.path]
            current = list_current()
            if stamp not in current:
                self._send_json({"error": "stamp is %s" % err_msg, list_key: current},
                                status=409)
                return
            reason = reason if isinstance(reason, str) and reason.strip() else "no reason given"
            existing = read_json(target_path, {}) or {}
            marked_at = datetime.datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")
            existing[stamp] = {"marked_at": marked_at, "reason": reason[:300]}
            _write_json(target_path, existing)
            _log("%s marked for %s (reason: %s) by %s"
                 % (parsed.path, stamp, reason[:80], self.address_string()))
            _kick_mirror()
            self._send_json({"status": "queued", "stamp": stamp})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            _log("unhandled error on POST %s: %s" % (self.path, e))
            try:
                self._send_json({"error": "internal"}, status=500)
            except Exception:
                pass

    # Silence noisy default per-request stdout logging; log_message above
    # already redirects to _log (stderr).
    def handle_one_request(self):
        try:
            BaseHTTPRequestHandler.handle_one_request(self)
        except (BrokenPipeError, ConnectionResetError):
            pass


def main():
    try:
        httpd = ThreadingHTTPServer((BIND_ADDR, PORT), Handler)
    except OSError as e:
        sys.stderr.write(
            "backup-monitor: cannot bind %s:%d (%s) -- is another instance "
            "already running?\n" % (BIND_ADDR, PORT, e)
        )
        sys.exit(1)

    _log("serving on http://%s:%d  state_dir=%s" % (BIND_ADDR, PORT, STATE_DIR))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
