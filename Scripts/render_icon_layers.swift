import AppKit
import Foundation

// The FreeSnitch mark split into layers for the Icon Composer document in
// Resources/AppIcon.icon (macOS 26 and later). Same geometry as
// render_icon.swift, but without the plate: the system draws the icon shape,
// its background fill and its light, dark, clear and tinted looks. Each layer
// is drawn in white; the document gives it its colour per appearance.
//
// Usage: swift render_icon_layers.swift <output directory>

let size: CGFloat = 1024

func arc(center: NSPoint, radius: CGFloat, heading: CGFloat, sweep: CGFloat, width: CGFloat) -> NSBezierPath {
    let path = NSBezierPath()
    path.appendArc(withCenter: center, radius: radius,
                   startAngle: heading - sweep / 2, endAngle: heading + sweep / 2)
    path.lineWidth = width
    path.lineCapStyle = .round
    return path
}

func render(_ draw: (NSPoint, CGFloat) -> Void) -> Data {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size), pixelsHigh: Int(size),
                               bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                               colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    NSGraphicsContext.current?.imageInterpolation = .high
    NSColor.white.setStroke()
    NSColor.white.setFill()
    draw(NSPoint(x: size / 2, y: size / 2), size)
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

// The legacy icon draws the mark on a plate 82.4 % of the canvas wide; here
// the shape is the whole canvas, so the mark keeps its size relative to it.
let radii: [CGFloat] = [0.15, 0.245, 0.34]
let outDir = URL(fileURLWithPath: CommandLine.arguments.dropFirst().first ?? ".")
try FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)

for (index, radius) in radii.enumerated() {
    let data = render { center, unit in
        for slot in 0..<3 {
            arc(center: center, radius: unit * radius, heading: CGFloat(slot) * 120 + CGFloat(index) * 40,
                sweep: 84, width: unit * 0.058).stroke()
        }
    }
    try data.write(to: outDir.appendingPathComponent("ring-\(index + 1).png"))
}

let core = render { center, unit in
    let r = unit * 0.075
    NSBezierPath(ovalIn: NSRect(x: center.x - r, y: center.y - r, width: r * 2, height: r * 2)).fill()
}
try core.write(to: outDir.appendingPathComponent("core.png"))
print("wrote layers to \(outDir.path)")
