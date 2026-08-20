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
import sys
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
}

# F10 post-second-audit constant: staleness suppression while mirror_running
# is capped at 6 hours. Beyond this, a claimed-in-flight copy no longer
# suppresses staleness and display_state may reach fail (FG6: an engine that
# leaves a foreign live pid in the lock file must not stay amber forever).
SUPPRESS_CAP = 21600


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
    over_suppress_cap = mirror_running and (mrs > SUPPRESS_CAP)

    # F10 display_state (second-audit version):
    #   fail IF healthy==false OR STATUS missing OR
    #        (stale_seconds>1800 AND (mirror_running==false OR mirror_running_seconds>SUPPRESS_CAP))
    #   warn IF notes nonempty OR (stale_seconds>900 AND mirror_running==false)
    #        OR mirror_running==true
    #   else ok
    # monitor_notes (the future-ts signal) folds into the same "notes
    # nonempty" warn trigger as engine notes[] -- a monitor-detected data
    # quality problem is exactly as warn-worthy as an engine-detected one.
    fail_stale = stale_seconds > 1800 and (not mirror_running or over_suppress_cap)
    if (not healthy) or fail_stale:
        display_state = "fail"
    elif notes or monitor_notes or (stale_seconds > 900 and not mirror_running) or mirror_running:
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
  #app { display: flex; flex-direction: column; min-height: 100vh; position: relative; overflow: hidden; }

  #banner {
    display: none;
    padding: 7px 11px;
    font-weight: 600;
    font-size: 11px;
    line-height: 1.45;
    white-space: pre-wrap;
    word-break: break-word;
    /* A long problems[] list (P1..P14 in a bad case) must stay legible in
       the 420x560 window rather than pushing the drives/timeline off-screen
       or overflowing the page horizontally -- cap the banner's height and
       let IT scroll, not the page. */
    max-height: 40vh;
    overflow-y: auto;
  }
  #banner.fail { display: block; background: var(--red); color: #fff; }
  #banner.warn { display: block; background: var(--amber); color: #1a1300; }
  #banner.unreachable { display: block; background: var(--red); color: #fff; }

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
  header {
    /* The WKWebView fills the window INCLUDING under the titlebar, so the first
       ~22px are behind the traffic-light buttons. Pad down to clear them. */
    padding: 23px 11px 5px 11px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    border-bottom: 1px solid var(--border);
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
  }
  .pill .dot { width: 7px; height: 7px; border-radius: 50%; background: currentColor; }
  .pill.ok   { background: var(--green-dim); color: var(--green); }
  .pill.warn { background: var(--amber-dim); color: var(--amber); }
  .pill.fail { background: var(--red-dim);   color: var(--red); }

  main { padding: 7px 11px 8px 11px; }

  .section-title { display: none; }              /* compact layout drops section headers */

  #status-line { font-size: 11px; color: var(--dim); line-height: 1.35; }
  #status-line strong { color: var(--text); font-weight: 600; }
  #inflight { margin-top: 3px; font-size: 11px; color: var(--amber); display: none; }
  #inflight.show { display: block; }

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
  #activity {
    /* Anchored BELOW the header so the title and the OK/WARN/FAIL pill stay
       visible while the dropdown is open -- you must never lose the status
       indicator at the moment you are inspecting the thing. */
    position: absolute; left: 0; right: 0; top: 47px;
    background: rgba(10,10,10,0.72);   /* dropdown: readable but you still see through */
    border-bottom: 1px solid var(--border);
    box-shadow: 0 10px 22px rgba(0,0,0,0.55);
    padding: 8px 11px 10px 11px;
    transform: translateY(-100%);
    opacity: 0;
    transition: transform .17s ease, opacity .17s ease;
    pointer-events: none;
    overflow: hidden;                      /* never scrolls */
  }
  /* `.hovering` is set by the app's native tracking area (works when the window is
     NOT focused); `#app:hover` is the fallback in a normal browser. */
  body.hovering #activity,
  #app:hover #activity { transform: translateY(0); opacity: 1; pointer-events: auto; }
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
  <div id="banner"></div>
  <header>
    <h1>Snapshot Monitor</h1>
    <span id="pill" class="pill ok"><span class="dot"></span><span id="pill-text">...</span></span>
  </header>
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
    <div id="inflight"></div>
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

  function fmtGB(kb) {
    if (kb === null || kb === undefined) return "\u2014";
    var gb = kb / 1048576;
    if (gb >= 1024) return (gb / 1024).toFixed(2) + " TB";
    if (gb >= 10)   return gb.toFixed(1) + " GB";
    return gb.toFixed(2) + " GB";
  }

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

  function renderBanner(state, lines) {
    var b = document.getElementById("banner");
    if (state === "fail" && lines && lines.length) {
      b.className = "fail";
      b.textContent = "\u26a0 " + lines.join("\\n\u26a0 ");
    } else if (state === "warn" && lines && lines.length) {
      b.className = "warn";
      b.textContent = lines.join("\\n");
    } else if (state === "unreachable") {
      b.className = "unreachable";
      b.textContent = "\u26a0 monitor backend unreachable \u2014 retrying\u2026";
    } else {
      b.className = "";
      b.textContent = "";
    }
  }

  // The writer's schedule, verified from the MacBook LaunchAgents on 2026-08-20:
  //   com.example.agentsnapshot.writer  StartCalendarInterval Hour=12 -> DAS snapshots
  //   com.example.agentsnapshot.archive    StartCalendarInterval Hour=0  -> shop PC archive
  // The DAS therefore NEVER receives a midnight backup. Showing "next" explicitly
  // exists so a missing overnight snapshot reads as "not due yet", not as a failure.
  var WRITER_SNAPSHOT_HOUR = 12;

  function nextRunInfo() {
    var now = new Date();
    var next = new Date(now.getFullYear(), now.getMonth(), now.getDate(), WRITER_SNAPSHOT_HOUR, 0, 0);
    var today = true;
    if (next.getTime() <= now.getTime()) { next.setDate(next.getDate() + 1); today = false; }
    var hh = WRITER_SNAPSHOT_HOUR % 12 || 12;
    var ap = WRITER_SNAPSHOT_HOUR < 12 ? "AM" : "PM";
    return { label: (today ? "today " : "tomorrow ") + hh + ":00 " + ap,
             secs: (next.getTime() - now.getTime()) / 1000 };
  }

  function stampAgeSeconds(stamp) {
    if (!stamp) return null;
    var m = /^(\d{4})-(\d{2})-(\d{2})_(\d{2})(\d{2})(\d{2})$/.exec(stamp);
    if (!m) return null;
    var t = new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]).getTime();
    return Math.max(0, (Date.now() - t) / 1000);
  }

  function fmtStamp(stamp) {
    var m = /^(\d{4})-(\d{2})-(\d{2})_(\d{2})(\d{2})(\d{2})$/.exec(stamp || "");
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

    if (state === "fail") {
      var flines = (d.problems && d.problems.length) ? d.problems.slice() : [];
      if (!flines.length && d.monitor_error) flines.push(d.monitor_error);
      flines = flines.concat(monitorNotes);
      renderBanner("fail", flines.length ? flines : ["unhealthy \u2014 no problem detail available"]);
    } else if (state === "warn") {
      var wlines = (d.notes && d.notes.length) ? d.notes.slice() : [];
      wlines = wlines.concat(monitorNotes);
      if (d.mirror_running) wlines.push("copy in progress");
      renderBanner("warn", wlines.length ? wlines : ["status is aging"]);
    } else {
      renderBanner("ok", []);
    }

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

    var inflight = document.getElementById("inflight");
    var pending = d.pending || [];
    if (d.mirror_running || pending.length) {
      var label = pending.length ? pending[0] : "in progress";
      inflight.textContent = "\u23f3 copying " + label + "\u2026";
      inflight.classList.add("show");
    } else {
      inflight.classList.remove("show");
    }
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

  fetchStatus();
  fetchEvents();
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
