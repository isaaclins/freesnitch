#!/usr/bin/env bash
set -euo pipefail

# Generates AppIcon at 1024x1024 then sips down to all required sizes,
# writes to Resources/Assets.xcassets/AppIcon.appiconset/

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ICONSET_DIR="$ROOT/Resources/Assets.xcassets/AppIcon.appiconset"
mkdir -p "$ICONSET_DIR"

TMP="$(mktemp -d)"
SWIFTSCRIPT="$TMP/render.swift"

cat > "$SWIFTSCRIPT" <<'SWIFT'
import AppKit
import Foundation

let size = NSSize(width: 1024, height: 1024)
let img = NSImage(size: size)
img.lockFocus()

// Background: deep gradient with orange accent
let bg = NSGradient(colors: [
    NSColor(srgbRed: 0.08, green: 0.08, blue: 0.10, alpha: 1),
    NSColor(srgbRed: 0.18, green: 0.10, blue: 0.05, alpha: 1)
])!
let bgPath = NSBezierPath(roundedRect: NSRect(origin: .zero, size: size), xRadius: 220, yRadius: 220)
bg.draw(in: bgPath, angle: 90)

// Outer ring
NSColor(srgbRed: 1.0, green: 0.45, blue: 0.30, alpha: 0.18).setFill()
let outer = NSBezierPath(ovalIn: NSRect(x: 90, y: 90, width: 844, height: 844))
outer.fill()

// Inner glow
NSColor(srgbRed: 1.0, green: 0.45, blue: 0.30, alpha: 0.06).setFill()
NSBezierPath(ovalIn: NSRect(x: 30, y: 30, width: 964, height: 964)).fill()

// Shield shape
let shield = NSBezierPath()
let cx: CGFloat = 512
let top: CGFloat = 860
let bot: CGFloat = 180
shield.move(to: NSPoint(x: cx, y: top))
shield.line(to: NSPoint(x: 800, y: 720))
shield.curve(to: NSPoint(x: 800, y: 500), controlPoint1: NSPoint(x: 800, y: 650), controlPoint2: NSPoint(x: 810, y: 580))
shield.curve(to: NSPoint(x: cx, y: bot), controlPoint1: NSPoint(x: 790, y: 360), controlPoint2: NSPoint(x: 650, y: 240))
shield.curve(to: NSPoint(x: 224, y: 500), controlPoint1: NSPoint(x: 374, y: 240), controlPoint2: NSPoint(x: 234, y: 360))
shield.curve(to: NSPoint(x: 224, y: 720), controlPoint1: NSPoint(x: 214, y: 580), controlPoint2: NSPoint(x: 224, y: 650))
shield.close()

let shieldGrad = NSGradient(colors: [
    NSColor(srgbRed: 1.0, green: 0.55, blue: 0.35, alpha: 1.0),
    NSColor(srgbRed: 1.0, green: 0.35, blue: 0.20, alpha: 1.0)
])!
shieldGrad.draw(in: shield, angle: 270)

// Inner shield highlight
NSColor.white.withAlphaComponent(0.18).setStroke()
shield.lineWidth = 8
shield.stroke()

// Checkmark
let check = NSBezierPath()
check.move(to: NSPoint(x: 340, y: 540))
check.line(to: NSPoint(x: 470, y: 410))
check.line(to: NSPoint(x: 720, y: 660))
check.lineWidth = 70
check.lineCapStyle = .round
check.lineJoinStyle = .round
NSColor.white.setStroke()
check.stroke()

img.unlockFocus()

guard let rep = NSBitmapImageRep(focusedViewRect: NSRect(origin: .zero, size: size)) else {
    // Re-render via tiff
    if let tiff = img.tiffRepresentation, let r = NSBitmapImageRep(data: tiff) {
        let data = r.representation(using: .png, properties: [:])!
        try? data.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
        exit(0)
    }
    exit(1)
}
if let tiff = img.tiffRepresentation, let r = NSBitmapImageRep(data: tiff) {
    let data = r.representation(using: .png, properties: [:])!
    try? data.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
}
SWIFT

OUT_1024="$TMP/icon_1024.png"
swift "$SWIFTSCRIPT" "$OUT_1024"

# Generate iconset sizes
generate() {
    local size="$1"
    local name="$2"
    sips -z "$size" "$size" "$OUT_1024" --out "$ICONSET_DIR/$name" >/dev/null
}

generate 16 icon_16x16.png
generate 32 icon_16x16@2x.png
generate 32 icon_32x32.png
generate 64 icon_32x32@2x.png
generate 128 icon_128x128.png
generate 256 icon_128x128@2x.png
generate 256 icon_256x256.png
generate 512 icon_256x256@2x.png
generate 512 icon_512x512.png
cp "$OUT_1024" "$ICONSET_DIR/icon_512x512@2x.png"

cat > "$ICONSET_DIR/Contents.json" <<'EOF'
{
  "images" : [
    { "filename" : "icon_16x16.png", "idiom" : "mac", "scale" : "1x", "size" : "16x16" },
    { "filename" : "icon_16x16@2x.png", "idiom" : "mac", "scale" : "2x", "size" : "16x16" },
    { "filename" : "icon_32x32.png", "idiom" : "mac", "scale" : "1x", "size" : "32x32" },
    { "filename" : "icon_32x32@2x.png", "idiom" : "mac", "scale" : "2x", "size" : "32x32" },
    { "filename" : "icon_128x128.png", "idiom" : "mac", "scale" : "1x", "size" : "128x128" },
    { "filename" : "icon_128x128@2x.png", "idiom" : "mac", "scale" : "2x", "size" : "128x128" },
    { "filename" : "icon_256x256.png", "idiom" : "mac", "scale" : "1x", "size" : "256x256" },
    { "filename" : "icon_256x256@2x.png", "idiom" : "mac", "scale" : "2x", "size" : "256x256" },
    { "filename" : "icon_512x512.png", "idiom" : "mac", "scale" : "1x", "size" : "512x512" },
    { "filename" : "icon_512x512@2x.png", "idiom" : "mac", "scale" : "2x", "size" : "512x512" }
  ],
  "info" : { "author" : "xcode", "version" : 1 }
}
EOF

echo "Icon generated at $ICONSET_DIR"
