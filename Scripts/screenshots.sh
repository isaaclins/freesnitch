#!/bin/bash
# Captures the README and website screenshots from the demo harness.
#
#   Scripts/screenshots.sh [output-dir]      (default: build/screenshots)
#
# Builds the contributor (monitor) flavour, ad-hoc signed, and runs it with
# FREESNITCH_DEMO=1. In demo mode the app shows fixed sample data, never
# registers or contacts the privileged helper and never activates the system
# extension, so nothing is installed and no real traffic from this Mac can end
# up in a picture. Each screen is captured as its own window, without shadow,
# in dark and light mode (the menu bar popover follows the menu bar).
#
# Needs: macOS with Xcode, xcodegen, and Screen Recording permission for the
# terminal that runs this. Leave the Mac alone while it runs: every screen opens
# in front for a few seconds.
set -euo pipefail

cd "$(dirname "$0")/.."
OUT="${1:-build/screenshots}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
# Main window size in points. The README and website use 1440x880.
WIDTH="${WIDTH:-1440}"
HEIGHT="${HEIGHT:-880}"

xcodegen generate --spec project.yml >/dev/null
xcodebuild -project FreeSnitch.xcodeproj -scheme FreeSnitch -configuration Debug \
  -derivedDataPath build/screenshot-build ONLY_ACTIVE_ARCH=YES \
  CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM= \
  PROVISIONING_PROFILE_SPECIFIER= CODE_SIGNING_REQUIRED=NO build >/dev/null
BIN="build/screenshot-build/Build/Products/Debug/FreeSnitch.app/Contents/MacOS/FreeSnitch"

# Window ids of the running demo app: "<id> <layer> <width>" per window.
window_ids() {
  swift - <<'SWIFT'
import CoreGraphics
let all = CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as! [[String: Any]]
for w in all where (w[kCGWindowOwnerName as String] as? String) == "FreeSnitch" {
    let b = w[kCGWindowBounds as String] as! [String: Any]
    print(w[kCGWindowNumber as String]!, w[kCGWindowLayer as String]!, b["Width"]!)
}
SWIFT
}

# The main window frame is passed in the argument domain, so the size is
# fixed for the run and nothing is written to the app's saved preferences.
SCREEN=$(swift - <<'SWIFT'
import AppKit
let f = NSScreen.main!.visibleFrame
print(Int(f.minX), Int(f.minY), Int(f.width), Int(f.height))
SWIFT
)
read -r SX SY SW SH <<<"$SCREEN"
FRAME="$((SX + (SW - WIDTH) / 2)) $((SY + (SH - HEIGHT) / 2)) $WIDTH $HEIGHT $SX $SY $SW $SH "

shoot() { # <window> <appearance>
  local window=$1 appearance=$2 extra=()
  [ "$appearance" = light ] && extra=(-NSRequiresAquaSystemAppearance YES)
  pkill -x FreeSnitch 2>/dev/null || true
  sleep 1
  FREESNITCH_DEMO=1 FREESNITCH_DEMO_WINDOW="$window" "$BIN" \
    -"NSWindow Frame FreeSnitch.MainWindow" "$FRAME" ${extra[@]+"${extra[@]}"} >/dev/null 2>&1 &
  sleep 6
  # The largest window is the screen under review: the main window, the alert
  # panel or the popover. The status item itself is a few points tall.
  local id
  id=$(window_ids | sort -k3 -n -r | awk '$3 > 60 { print $1; exit }')
  if [ -z "$id" ]; then echo "no window for $window" >&2; return 1; fi
  screencapture -x -o -l "$id" "$OUT/$window-$appearance.png"
  echo "$OUT/$window-$appearance.png"
}

for appearance in dark light; do
  for window in monitor rules insights profiles alert popover; do
    shoot "$window" "$appearance"
  done
done
pkill -x FreeSnitch 2>/dev/null || true
