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
let ctx = NSGraphicsContext.current!
ctx.imageInterpolation = .high

// Background squircle: deep charcoal with a warm bottom.
let bg = NSGradient(colors: [
    NSColor(srgbRed: 0.10, green: 0.10, blue: 0.12, alpha: 1),
    NSColor(srgbRed: 0.16, green: 0.09, blue: 0.06, alpha: 1)
])!
let bgPath = NSBezierPath(roundedRect: NSRect(origin: .zero, size: size), xRadius: 224, yRadius: 224)
bg.draw(in: bgPath, angle: 90)

// Warm radial glow behind the shield.
bgPath.addClip()
let glow = NSGradient(colors: [
    NSColor(srgbRed: 1.0, green: 0.45, blue: 0.30, alpha: 0.22),
    NSColor(srgbRed: 1.0, green: 0.45, blue: 0.30, alpha: 0.0)
])!
glow.draw(in: NSRect(x: 112, y: 112, width: 800, height: 800), relativeCenterPosition: .zero)

// Shield.
let shield = NSBezierPath()
let cx: CGFloat = 512
shield.move(to: NSPoint(x: cx, y: 866))
shield.line(to: NSPoint(x: 806, y: 726))
shield.curve(to: NSPoint(x: 806, y: 496), controlPoint1: NSPoint(x: 806, y: 654), controlPoint2: NSPoint(x: 816, y: 582))
shield.curve(to: NSPoint(x: cx, y: 168), controlPoint1: NSPoint(x: 796, y: 356), controlPoint2: NSPoint(x: 654, y: 232))
shield.curve(to: NSPoint(x: 218, y: 496), controlPoint1: NSPoint(x: 370, y: 232), controlPoint2: NSPoint(x: 228, y: 356))
shield.curve(to: NSPoint(x: 218, y: 726), controlPoint1: NSPoint(x: 208, y: 582), controlPoint2: NSPoint(x: 218, y: 654))
shield.close()

let shieldGrad = NSGradient(colors: [
    NSColor(srgbRed: 1.0, green: 0.56, blue: 0.36, alpha: 1.0),
    NSColor(srgbRed: 0.98, green: 0.33, blue: 0.19, alpha: 1.0)
])!
shieldGrad.draw(in: shield, angle: 270)
NSColor.white.withAlphaComponent(0.20).setStroke()
shield.lineWidth = 10
shield.stroke()

// Network motif: a central node watching three satellites (per-process
// connection monitoring), drawn in white inside the shield.
let center = NSPoint(x: cx, y: 512)
let satellites = [
    NSPoint(x: cx - 168, y: 612),
    NSPoint(x: cx + 168, y: 612),
    NSPoint(x: cx, y: 322)
]

NSColor.white.withAlphaComponent(0.92).setStroke()
for s in satellites {
    let link = NSBezierPath()
    link.move(to: center)
    link.line(to: s)
    link.lineWidth = 20
    link.lineCapStyle = .round
    link.stroke()
}

func dot(_ p: NSPoint, _ r: CGFloat, _ color: NSColor) {
    color.setFill()
    NSBezierPath(ovalIn: NSRect(x: p.x - r, y: p.y - r, width: r * 2, height: r * 2)).fill()
}
for s in satellites { dot(s, 40, NSColor.white) }
for s in satellites {
    NSColor(srgbRed: 0.98, green: 0.40, blue: 0.24, alpha: 0.25).setStroke()
    let ring = NSBezierPath(ovalIn: NSRect(x: s.x - 40, y: s.y - 40, width: 80, height: 80))
    ring.lineWidth = 6; ring.stroke()
}
// central node, larger, with an orange core (the watching "snitch" eye)
dot(center, 66, NSColor.white)
dot(center, 30, NSColor(srgbRed: 0.98, green: 0.36, blue: 0.20, alpha: 1.0))

img.unlockFocus()

guard let tiff = img.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff),
      let data = rep.representation(using: .png, properties: [:]) else {
    FileHandle.standardError.write("render failed\n".data(using: .utf8)!)
    exit(1)
}
try? data.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
SWIFT

OUT_1024="$TMP/icon_1024.png"
swift "$SWIFTSCRIPT" "$OUT_1024"

generate() {
    sips -z "$1" "$1" "$OUT_1024" --out "$ICONSET_DIR/$2" >/dev/null
}

generate 16  icon_16x16.png
generate 32  icon_16x16@2x.png
generate 32  icon_32x32.png
generate 64  icon_32x32@2x.png
generate 128 icon_128x128.png
generate 256 icon_128x128@2x.png
generate 256 icon_256x256.png
generate 512 icon_256x256@2x.png
generate 512 icon_512x512.png
cp "$OUT_1024" "$ICONSET_DIR/icon_512x512@2x.png"

echo "Icon generated at $ICONSET_DIR"
