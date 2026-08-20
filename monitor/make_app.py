#!/usr/bin/env python3
"""
Builds ~/Applications/Snapshot Monitor.app -- a pure-viewer WKWebView shell
around the Snapshot Monitor web backend at http://127.0.0.1:7788/, matching
the ~/mlx_dashboard/make_launcher.py idiom (see CONTEXT.md), but smaller:
this is a compact status panel, not a dashboard.

Run:  /usr/bin/python3 monitor/make_app.py

This script ONLY builds and installs the .app bundle under ~/Applications.
It does NOT install, load, or touch any LaunchAgent -- that is subtask 05's
job. The compiled app does not run launchctl either: unlike MLX Dashboard's
launcher (which kickstarts a supervised launchd service if down), Backup
Monitor's backend isn't installed as a service yet during this subtask, so
the app is a plain retrying viewer -- if 127.0.0.1:7788 is unreachable it
shows a small red "unreachable" page inline and keeps retrying the real
load on a timer, with no side effects.

stdlib only. Pillow is used ONLY here, at build time, if present, to draw a
simple .icns; if Pillow/iconutil aren't available the app ships with the
default generic icon -- that's an acceptable outcome per spec, not a bug.
"""

import plistlib
import shutil
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.resolve()
APP_NAME = "Snapshot Monitor"
DEST_DIR = Path.home() / "Applications"
APP_PATH = DEST_DIR / f"{APP_NAME}.app"
ICONSET_DIR = SCRIPT_DIR / "AppIcon.iconset"
ICNS_PATH = SCRIPT_DIR / "AppIcon.icns"

MONITOR_URL = "http://127.0.0.1:7788/"

# ── Optional icon (Pillow, build-time only) ─────────────────────────────────

BG = (8, 8, 8, 255)
CARD = (15, 15, 15, 255)
BORDER_COL = (28, 28, 28, 255)
TEXT_COL = (150, 150, 150, 255)
GREEN = (34, 140, 60, 255)
GREEN_DIM = (16, 60, 28, 255)


def _draw_rounded_rect(draw, xy, radius, fill, outline=None, outline_width=1):
    x0, y0, x1, y1 = xy
    r = radius
    draw.rectangle([x0 + r, y0, x1 - r, y1], fill=fill)
    draw.rectangle([x0, y0 + r, x1, y1 - r], fill=fill)
    draw.ellipse([x0, y0, x0 + 2 * r, y0 + 2 * r], fill=fill)
    draw.ellipse([x1 - 2 * r, y0, x1, y0 + 2 * r], fill=fill)
    draw.ellipse([x0, y1 - 2 * r, x0 + 2 * r, y1], fill=fill)
    draw.ellipse([x1 - 2 * r, y1 - 2 * r, x1, y1], fill=fill)
    if outline:
        draw.arc([x0, y0, x0 + 2 * r, y0 + 2 * r], 180, 270, fill=outline, width=outline_width)
        draw.arc([x1 - 2 * r, y0, x1, y0 + 2 * r], 270, 360, fill=outline, width=outline_width)
        draw.arc([x0, y1 - 2 * r, x0 + 2 * r, y1], 90, 180, fill=outline, width=outline_width)
        draw.arc([x1 - 2 * r, y1 - 2 * r, x1, y1], 0, 90, fill=outline, width=outline_width)
        draw.line([x0 + r, y0, x1 - r, y0], fill=outline, width=outline_width)
        draw.line([x0 + r, y1, x1 - r, y1], fill=outline, width=outline_width)
        draw.line([x0, y0 + r, x0, y1 - r], fill=outline, width=outline_width)
        draw.line([x1, y0 + r, x1, y1 - r], fill=outline, width=outline_width)


def _make_icon(size, Image, ImageDraw):
    s = size
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    pad = int(s * 0.04)
    r_bg = int(s * 0.22)
    _draw_rounded_rect(draw, (pad, pad, s - pad - 1, s - pad - 1), r_bg, fill=BG)

    card_pad = int(s * 0.15)
    card_r = int(s * 0.10)
    _draw_rounded_rect(
        draw, (card_pad, card_pad, s - card_pad, s - card_pad), card_r,
        fill=CARD, outline=BORDER_COL, outline_width=max(1, int(s * 0.006)),
    )

    # Simple "shield with a checkmark-ish dot" motif: a filled green disc.
    cx, cy = s // 2, int(s * 0.46)
    r = int(s * 0.14)
    halo_r = int(r * 1.8)
    _draw_rounded_rect(draw, (cx - halo_r, cy - halo_r, cx + halo_r, cy + halo_r), halo_r, fill=GREEN_DIM)
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=GREEN)

    # Two thin "drive" bars beneath, echoing the monitor's two-drive UI.
    bar_x0 = int(s * 0.30)
    bar_x1 = int(s * 0.70)
    bar_h = max(2, int(s * 0.035))
    bar_r = bar_h // 2
    for i, frac in enumerate((0.8, 0.55)):
        by = int(s * 0.68) + i * int(s * 0.09)
        _draw_rounded_rect(draw, (bar_x0, by, bar_x1, by + bar_h), bar_r, fill=(30, 30, 30, 255))
        fw = int((bar_x1 - bar_x0) * frac)
        _draw_rounded_rect(draw, (bar_x0, by, bar_x0 + fw, by + bar_h), bar_r, fill=TEXT_COL)

    return img


def make_iconset():
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        print("Pillow not available -- shipping without a custom icon (acceptable).")
        return False

    try:
        ICONSET_DIR.mkdir(exist_ok=True)
        sizes = {
            "icon_16x16.png": 16, "icon_16x16@2x.png": 32,
            "icon_32x32.png": 32, "icon_32x32@2x.png": 64,
            "icon_128x128.png": 128, "icon_128x128@2x.png": 256,
            "icon_256x256.png": 256, "icon_256x256@2x.png": 512,
            "icon_512x512.png": 512, "icon_512x512@2x.png": 1024,
        }
        master = _make_icon(1024, Image, ImageDraw)
        for name, px in sizes.items():
            master.resize((px, px), Image.LANCZOS).save(ICONSET_DIR / name)

        result = subprocess.run(
            ["iconutil", "-c", "icns", str(ICONSET_DIR), "-o", str(ICNS_PATH)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(f"iconutil error: {result.stderr}")
            return False
        shutil.rmtree(ICONSET_DIR)
        return True
    except Exception as e:
        print(f"Icon generation skipped ({e}) -- shipping without a custom icon.")
        return False


# ── Swift source: pure-viewer WKWebView shell ───────────────────────────────
# Idiom matches ~/mlx_dashboard/make_launcher.py: NSWindow + WKWebView filling
# the window incl. under the titlebar, frame autosave so the window reopens
# where the user left it. Deliberately does NOT run launchctl (no LaunchAgent
# exists yet for this subtask) -- unreachable-backend handling is local only:
# a small inline red page shown immediately on load failure, with a timer
# that keeps retrying the real URL.

SWIFT_SRC = """\
import AppKit
import WebKit
import Foundation

let logURL = URL(fileURLWithPath: "/tmp/backup_monitor_app.log")
func log(_ msg: String) {
    let line = "[\\(Date())] \\(msg)\\n"
    guard let data = line.data(using: .utf8) else { return }
    if FileManager.default.fileExists(atPath: logURL.path),
       let fh = try? FileHandle(forWritingTo: logURL) {
        fh.seekToEndOfFile(); fh.write(data); try? fh.close()
    } else {
        try? data.write(to: logURL)
    }
}

let monitorURL = URL(string: "http://127.0.0.1:7788/")!
let frameAutosaveName = "SnapshotMonitor"

let unreachableHTML = \"\"\"
<!doctype html><html><head><meta charset="utf-8">
<style>
  html,body{margin:0;padding:0;background:#0a0a0a;color:#fff;
    font-family:-apple-system,BlinkMacSystemFont,sans-serif;height:100%;}
  #wrap{display:flex;align-items:center;justify-content:center;height:100vh;
    padding:24px;text-align:center;box-sizing:border-box;}
  #box{background:#c0392b;border-radius:12px;padding:18px 20px;font-size:13px;
    font-weight:600;line-height:1.5;}
</style></head>
<body><div id="wrap"><div id="box">&#9888; monitor backend unreachable<br>
<span style="font-weight:400;font-size:11.5px;opacity:0.85">retrying 127.0.0.1:7788&hellip;</span>
</div></div></body></html>
\"\"\"

class AppDelegate: NSObject, NSApplicationDelegate, WKNavigationDelegate {
    var window: NSWindow!
    var webView: WKWebView!
    var retryTimer: Timer?
    // Tracks whether the in-flight/most-recent load is the real monitor
    // page (true) or the local unreachable-fallback HTML string (false).
    // Loading the fallback string itself completes successfully and fires
    // didFinish -- without this flag that would immediately cancel the
    // retry timer we just scheduled, so the app would show "unreachable"
    // once and then silently never retry.
    var pendingIsRealLoad = false

    func applicationDidFinishLaunching(_ n: Notification) {
        log("=== Snapshot Monitor app started PID=\\(ProcessInfo.processInfo.processIdentifier) ===")

        let rect = NSRect(x: 0, y: 0, width: 340, height: 146)
        window = NSWindow(
            contentRect: rect,
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = "Snapshot Monitor"
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.appearance = NSAppearance(named: .darkAqua)
        // Translucent: the wallpaper shows through a blurred vibrancy material.
        // Plain transparency would put text straight on top of an arbitrary photo and
        // wreck legibility, so we blur what is behind rather than just removing our own
        // background. NSVisualEffectView is the same material macOS uses for HUD panels.
        window.isOpaque = false
        window.backgroundColor = .clear
        window.isMovableByWindowBackground = true
        // Deliver mouse-moved events even when this window is NOT the key window.
        // Without this, macOS only tracks the pointer for the focused window, so the
        // hover-to-reveal activity dropdown silently does nothing unless you click the
        // app first -- useless for a monitor you glance at while working elsewhere.
        window.acceptsMouseMovedEvents = true
        window.minSize = NSSize(width: 250, height: 120)

        window.setFrameAutosaveName(frameAutosaveName)
        if !window.setFrameUsingName(frameAutosaveName) {
            window.center()
            log("No saved frame -- centering (first launch)")
        } else {
            log("Restored saved frame \\(NSStringFromRect(window.frame))")
        }

        // NO vibrancy / NO blur: the window is genuinely transparent, so the desktop
        // behind it is seen directly rather than frosted. Legibility comes from text
        // shadows in the page, not from an opaque backdrop.
        let cfg = WKWebViewConfiguration()
        webView = WKWebView(frame: window.contentView!.bounds, configuration: cfg)
        webView.autoresizingMask = [.width, .height]
        webView.navigationDelegate = self
        webView.setValue(false, forKey: "drawsBackground")   // let the vibrancy show through
        if #available(macOS 12.0, *) { webView.underPageBackgroundColor = .clear }
        window.contentView!.addSubview(webView)

        // HOVER TRACKING.
        // CSS :hover inside a WKWebView only fires when the window is KEY, and
        // `acceptsMouseMovedEvents` alone does not change that (verified). For a monitor
        // you glance at while working in another app, hover-to-reveal must work UNFOCUSED.
        // So we track natively with .activeAlways and toggle a class on <body> instead of
        // relying on :hover.
        let ta = NSTrackingArea(
            rect: .zero,
            options: [.mouseEnteredAndExited, .activeAlways, .inVisibleRect],
            owner: self,
            userInfo: nil
        )
        window.contentView!.addTrackingArea(ta)

        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)

        loadMonitor()
    }

    @objc func mouseEntered(with event: NSEvent) {
        setHover(true)
    }

    @objc func mouseExited(with event: NSEvent) {
        setHover(false)
    }

    func setHover(_ on: Bool) {
        let js = on
            ? "document.body && document.body.classList.add('hovering')"
            : "document.body && document.body.classList.remove('hovering')"
        webView?.evaluateJavaScript(js, completionHandler: nil)
    }

    func loadMonitor() {
        pendingIsRealLoad = true
        webView.load(URLRequest(url: monitorURL, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 3))
    }

    func showUnreachable() {
        pendingIsRealLoad = false
        webView.loadHTMLString(unreachableHTML, baseURL: nil)
        scheduleRetry()
    }

    func scheduleRetry() {
        retryTimer?.invalidate()
        retryTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: false) { [weak self] _ in
            log("retrying monitor load")
            self?.loadMonitor()
        }
    }

    func webView(_ wv: WKWebView, didFailProvisionalNavigation _: WKNavigation!, withError err: Error) {
        log("Navigation error: \\(err.localizedDescription) -- showing unreachable page")
        showUnreachable()
    }

    func webView(_ wv: WKWebView, didFail _: WKNavigation!, withError err: Error) {
        log("Navigation error (post-commit): \\(err.localizedDescription)")
    }

    func webView(_ wv: WKWebView, didFinish _: WKNavigation!) {
        // Only a successful load of the REAL monitor page should cancel the
        // retry loop -- loading the local unreachable-fallback string also
        // "finishes" and must not be mistaken for recovery.
        if pendingIsRealLoad {
            retryTimer?.invalidate()
            retryTimer = nil
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ s: NSApplication) -> Bool { true }
    func applicationWillTerminate(_ n: Notification) {
        window?.saveFrame(usingName: frameAutosaveName)
        log("App terminated")
    }
}

let app = NSApplication.shared
app.setActivationPolicy(.regular)
let delegate = AppDelegate()
app.delegate = delegate
app.run()
"""


def make_app():
    DEST_DIR.mkdir(parents=True, exist_ok=True)

    if APP_PATH.exists():
        shutil.rmtree(APP_PATH)

    swift_tmp = SCRIPT_DIR / "_backupmonitor_launcher.swift"
    swift_tmp.write_text(SWIFT_SRC)

    exe_tmp = SCRIPT_DIR / "_backupmonitor_bin"
    result = subprocess.run(
        ["swiftc",
         "-target", "arm64-apple-macos12",
         "-O",
         "-framework", "AppKit",
         "-framework", "WebKit",
         "-framework", "Foundation",
         "-o", str(exe_tmp),
         str(swift_tmp)],
        capture_output=True, text=True,
    )
    swift_tmp.unlink()

    if result.returncode != 0:
        print(f"swiftc error:\n{result.stderr}")
        return False

    macos_dir = APP_PATH / "Contents" / "MacOS"
    resources_dir = APP_PATH / "Contents" / "Resources"
    macos_dir.mkdir(parents=True)
    resources_dir.mkdir(parents=True)

    exe_path = macos_dir / APP_NAME
    exe_tmp.rename(exe_path)

    icon_name = ""
    if ICNS_PATH.exists():
        shutil.copy(ICNS_PATH, resources_dir / "AppIcon.icns")
        icon_name = "AppIcon"

    plist = {
        "CFBundleExecutable": APP_NAME,
        "CFBundleIdentifier": "com.example.agentsnapshot.monitor.app",
        "CFBundleName": APP_NAME,
        "CFBundleDisplayName": APP_NAME,
        "CFBundleVersion": "1.0",
        "CFBundleShortVersionString": "1.0",
        "CFBundleIconFile": icon_name,
        "CFBundlePackageType": "APPL",
        "LSUIElement": False,
        "NSHighResolutionCapable": True,
        "NSPrincipalClass": "NSApplication",
    }
    with open(APP_PATH / "Contents" / "Info.plist", "wb") as f:
        plistlib.dump(plist, f)

    subprocess.run(["touch", str(APP_PATH)], check=False)
    return True


def main():
    print(f"\nBuilding: {APP_NAME}.app\n")

    print("Generating icon (optional, Pillow build-time only)...")
    if not make_iconset():
        print("Proceeding without a custom icon.")

    print("\nCompiling + assembling .app bundle...")
    ok = make_app()
    if not ok:
        print("\nBUILD FAILED (swiftc error above).")
        sys.exit(1)

    print(f"\nInstalled: {APP_PATH}")


if __name__ == "__main__":
    main()
