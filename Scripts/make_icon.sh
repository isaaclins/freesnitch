#!/usr/bin/env bash
# Regenerates the FreeSnitch app icon, favicon, and social preview from
# Scripts/render_icon.swift, which draws the mark procedurally. There is no
# external design tool or vector dependency: swift is the only requirement.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RENDERER="$ROOT/Scripts/render_icon.swift"
ICONSET="$ROOT/Resources/Assets.xcassets/AppIcon.appiconset"
BRANDING="$ROOT/Resources/Branding"
DOCS="$ROOT/docs"

command -v swift >/dev/null 2>&1 || { echo "ERROR: swift is required"; exit 1; }
command -v sips >/dev/null 2>&1 || { echo "ERROR: sips is required"; exit 1; }

mkdir -p "$ICONSET" "$BRANDING"

MASTER="$BRANDING/freesnitch-mark-1024.png"
echo "Rendering master mark at 1024..."
swift "$RENDERER" "$MASTER" 1024 >/dev/null

# name:pixels for every entry in Contents.json
for entry in \
  icon_16x16:16 icon_16x16@2x:32 \
  icon_32x32:32 icon_32x32@2x:64 \
  icon_128x128:128 icon_128x128@2x:256 \
  icon_256x256:256 icon_256x256@2x:512 \
  icon_512x512:512 icon_512x512@2x:1024
do
  name="${entry%%:*}"
  px="${entry##*:}"
  cp -f "$MASTER" "$ICONSET/$name.png"
  sips -Z "$px" "$ICONSET/$name.png" >/dev/null
done
echo "Wrote $(ls "$ICONSET"/*.png | wc -l | tr -d ' ') icon files."

# Website assets derived from the same master.
cp -f "$MASTER" "$DOCS/favicon.png"
sips -Z 180 "$DOCS/favicon.png" >/dev/null
cp -f "$MASTER" "$DOCS/icon-512.png"
sips -Z 512 "$DOCS/icon-512.png" >/dev/null
echo "Wrote docs/favicon.png and docs/icon-512.png."
