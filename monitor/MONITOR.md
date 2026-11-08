# Snapshot Monitor

A small always-on status panel for the replica engine: a stdlib HTTP backend plus a native
macOS viewer window. It answers two questions at a glance — *is it working*, and *when did
backups actually happen*.

## Design constraint that shaped everything

**The monitor never touches the DAS volumes.** It reads only files the engine has already
written under `~/Library/`. That is deliberate and load-bearing: on macOS a LaunchAgent
cannot read removable volumes under TCC, so a monitor that stat'd the disks directly would
fail exactly when run unattended. Because it reads only its own state directory, it needs
no privacy grant and runs as an ordinary user agent. Grep the source for `/Volumes` — it
should appear only in comments.

A second constraint, learned the hard way: on a 13 TB volume holding ~15 GB, free-space and
percentage figures **cannot visibly change for months**. A panel showing only those reads as
frozen even when everything is healthy, which is indistinguishable from a dead poller. The
display therefore leads with things that move — last-snapshot age, next-expected run,
last-check age — and uses a fill bar with a minimum-visible sliver so a barely-filled drive
never renders as an empty track.

## Components

| path | role |
|---|---|
| `monitor.py`   | stdlib `http.server` backend; serves the UI and two JSON endpoints |
| `make_app.py`  | builds a native `.app` viewer (swiftc + WKWebView) around the URL |
| `selftest.sh`  | acceptance suite; run it on a free port (see below) |

Python is stdlib-only and 3.9-compatible, so it runs on the system interpreter with no
venv and no third-party packages. `make_app.py` optionally uses Pillow to generate an icon
and degrades gracefully without it.

## Endpoints

```
GET  /                            single-page UI (inline CSS/JS, no external assets)
GET  /api/status                  engine status + {stale_seconds, display_state, monitor_notes}
GET  /api/events?n=<N>            last N events, newest first (default 50, max 500)
POST /api/control/mute            {stamp, reason}  write a snapshot off (muted.json); no engine kick
POST /api/control/unmute          {stamp}          restore it; kicks one mirror pass
POST /api/control/mute-line       {text}           silence one banner line for <= 72 h
POST /api/control/unmute-line     {key}            restore it
POST /api/control/retry           {stamp}          opt a SUPERSEDED stamp back in (retry-request.json)
POST /api/control/skip-dedup      {stamp}          one-time skip of the dedup assertion for a stamp
POST /api/control/force-settle    {stamp}          one-time "treat as settled" for a stuck upload
```

The monitor is the **single writer** of every control file; the engine only consumes them.
Every control validates its input (stamp shape, "stamp exists on a volume", candidate lists)
and answers 400/409 rather than writing something the engine cannot use. `mute` deliberately
does not kick the engine — a kick counts toward `mirror.sh`'s rate limit, so clearing a banner
could raise P16 — and lands on the next 300 s pass. Kicks that do happen are fire-and-forget
ssh-to-localhost with the replica key, never a blocking call.

`display_state` is `ok` | `warn` | `fail` | `off`, computed as:

- **fail** if `healthy == false`, or the status file is missing/unparseable, or
  `stale_seconds > 1800` while no copy is running (or a copy has claimed to be running
  past the 12 h cap: `mirror_running_seconds + stale_seconds > 43200`);
- **off** if the engine reports `system_enabled == false` (paused on purpose, or the writer
  is unreachable) — a real problem always outranks "off";
- **warn** if the monitor itself cannot trust its input (`monitor_notes`, e.g. a status
  timestamp in the future), or `stale_seconds > 900` while no copy is running;
- **ok** otherwise.

Details worth preserving if you modify this:

- **A copy in flight is not a colour.** It shows as the activity row and a glyph. It used to
  render `warn`, which painted the board amber for a large part of every day while the system
  was doing exactly its job. It must never render `fail` either: a red monitor makes a human
  intervene mid-copy, which is when intervening is most harmful. Suppression is capped at
  12 h so `fail` stays reachable for a genuinely stuck copy.
- **Notes are banner text, not a colour.** The engine's contract is that every real alarm is a
  `problems[]` entry (which goes red); `notes[]` are informational by construction.
- **`stale_seconds` is clamped at 0 from below.** A status timestamp in the future must
  never read as maximally fresh; clock skew produced exactly that bug, and it reported
  healthy indefinitely.

## status.json schema (written by the engine, read here)

```jsonc
{
  "schema": 1,
  "ts": "2026-01-01T12:00:00-0500",     // when this pass wrote the status
  "pass_kind": "mirror",                 // or "deep-verify"
  "primary_mounted": true, "replica_mounted": true,
  "primary_total_kb": 0, "primary_used_kb": 0, "primary_free_kb": 0, "primary_iused": 0,
  "replica_total_kb": 0, "replica_used_kb": 0, "replica_free_kb": 0, "replica_iused": 0,
  "primary_snapshots": ["YYYY-MM-DD_HHMMSS"],
  "replica_snapshots": ["YYYY-MM-DD_HHMMSS"],
  "latest_primary": "YYYY-MM-DD_HHMMSS", "latest_replica": "YYYY-MM-DD_HHMMSS",
  "pending": [], "unsettled": [], "incoming": [],
  "last_copy": {"snapshot": "...", "started": "iso", "finished": "iso",
                "rc": 0, "files": 0, "bytes": 0, "link_dest": "...", "detail": "..."},
  "last_deep_verify": {"ts": "iso", "snapshots": ["..."], "result": "pass", "detail": ""},
  "mirror_running": false, "mirror_running_seconds": 0,
  "healthy": true,        // true IFF problems == []; never true merely because code ran
  "problems": [],         // human-readable strings -> monitor shows them verbatim
  "notes": [],            // advisory banner text (never a colour on its own)
  "system_enabled": true, "enabled_source": "handshake",   // on/off switch and why
  "handshake_reachable": true, "handshake_last_change": "iso",
  "control_override": "on",                 // manual enable/disable, if any
  "incomplete_uploads": [], "dedup_failures": [], "force_settle_candidates": [],
  "muted": [],            // muted + superseded rows: {stamp, kind, reason, hidden, ...}
  "muted_problems": [],   // problems silenced by a mute -- still listed, never dropped
  "muted_lines": []       // active per-line mutes
}
```

`healthy` is `true` **if and only if** `problems` is empty. It is never set true because a
pass completed. `events.jsonl` is append-only JSONL, one object per line, with kinds
`detected | copy_started | copied | copy_failed | verify_failed | pruned | orphan_partial |
superseded | retry_consumed | baseless_retry | dedup_skipped | force_settled | rate_limited |
error`.

## Native window

`make_app.py` builds a fixed-size WKWebView viewer. Newer page code also reports its rendered
height to the shell via `webkit.messageHandlers.resize` so a shell that implements that
handler can size the window to its content; the page checks the handler exists first, so the
bundled fixed-size viewer works unchanged.

## Install

```sh
# 1. backend
mkdir -p ~/Library/SnapshotMonitor
install -m 755 monitor.py ~/Library/SnapshotMonitor/monitor.py

# 2. LaunchAgent (edit the label/paths to taste)
cat > ~/Library/LaunchAgents/com.example.agentsnapshot.monitor.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.example.agentsnapshot.monitor</string>
  <key>ProgramArguments</key>
  <array><string>/usr/bin/python3</string><string>/Users/youruser/Library/SnapshotMonitor/monitor.py</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
</dict></plist>
PLIST
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/com.example.agentsnapshot.monitor.plist

# 3. native viewer window (optional)
python3 make_app.py          # installs ~/Applications/Snapshot Monitor.app
```

The backend binds **127.0.0.1 only**. Override with `SNAP_PORT`, and point it at alternate
state with `SNAP_STATE_DIR` / `SNAP_LOG`.

## Testing

```sh
SNAP_TEST_PORT=7899 ./selftest.sh      # use a free port
```

The suite refuses to run if the configured port is already listening, because a running
production monitor would otherwise answer the test's requests and every assertion would be
made against live state instead of fixtures — which reads as a wall of failures, or worse,
as false passes.
