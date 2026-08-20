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
GET /                      single-page UI (inline CSS/JS, no external assets)
GET /api/status            engine status + {stale_seconds, display_state}
GET /api/events?n=<N>      last N events, newest first (default 50, max 500)
```

`display_state` is `ok` | `warn` | `fail`, computed as:

- **fail** if `healthy == false`, or the status file is missing/unparseable, or
  `stale_seconds > 1800` while no copy is running (or a copy has claimed to be running
  past the 6 h cap);
- **warn** if any notes are present, a copy is in progress, or `stale_seconds > 900`;
- **ok** otherwise.

Two details worth preserving if you modify this:

- **A copy in flight must render `warn`, never `fail`.** A real incremental can exceed 30
  minutes; a red monitor makes a human intervene mid-copy, which is when intervening is
  most harmful. Staleness suppression is capped at 6 h so `fail` stays reachable for a
  genuinely stuck copy.
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
  "notes": []             // advisory -> amber
}
```

`healthy` is `true` **if and only if** `problems` is empty. It is never set true because a
pass completed. `events.jsonl` is append-only JSONL, one object per line, with kinds
`detected | copy_started | copied | copy_failed | verify_failed | pruned | orphan_partial | error`.

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
