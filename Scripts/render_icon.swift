import AppKit
import Foundation

// FreeSnitch icon, drawn entirely from first principles.
// Three concentric rings, each broken into three arcs, around a solid core.
// The core is this Mac; the rings are its outbound connections; the gaps are
// where a connection can be let through or refused. Every ring is offset from
// the one inside it, so the openings never line up into a single channel.
//
// The composition was sketched with SF Symbols, but Apple's SF Symbols licence
// forbids shipping their glyphs inside an app icon or logo, so every shape here
// is our own geometry.

func squirclePath(in rect: NSRect) -> NSBezierPath {
    let n = 5.0
    let steps = 720
    let path = NSBezierPath()
    let a = rect.width / 2, b = rect.height / 2
    let cx = rect.midX, cy = rect.midY
    for step in 0...steps {
        let t = Double(step) / Double(steps) * 2 * Double.pi
        let ct = cos(t), st = sin(t)
        let x = cx + a * pow(abs(ct), 2 / n) * (ct < 0 ? -1 : 1)
        let y = cy + b * pow(abs(st), 2 / n) * (st < 0 ? -1 : 1)
        if step == 0 { path.move(to: NSPoint(x: x, y: y)) } else { path.line(to: NSPoint(x: x, y: y)) }
    }
    path.close()
    return path
}

/// One arc segment with rounded caps, centred on `center`, facing `heading`.
func arc(center: NSPoint, radius: CGFloat, heading: CGFloat, sweep: CGFloat, width: CGFloat) -> NSBezierPath {
    let path = NSBezierPath()
    path.appendArc(withCenter: center, radius: radius,
                   startAngle: heading - sweep / 2, endAngle: heading + sweep / 2)
    path.lineWidth = width
    path.lineCapStyle = .round
    return path
}

func makeIcon(size: CGFloat) -> NSImage {
    let image = NSImage(size: NSSize(width: size, height: size))
    image.lockFocus()
    NSGraphicsContext.current?.imageInterpolation = .high

    let inset = size * 0.088
    let plate = NSRect(x: inset, y: inset * 1.18, width: size - inset * 2, height: size - inset * 2)
    let plated = squirclePath(in: plate)

    NSGraphicsContext.saveGraphicsState()
    let shadow = NSShadow()
    shadow.shadowColor = NSColor.black.withAlphaComponent(0.28)
    shadow.shadowBlurRadius = size * 0.032
    shadow.shadowOffset = NSSize(width: 0, height: -size * 0.011)
    shadow.set()
    NSColor.white.setFill()
    plated.fill()
    NSGraphicsContext.restoreGraphicsState()

    NSGraphicsContext.saveGraphicsState()
    plated.addClip()

    NSGradient(colors: [
        NSColor(calibratedRed: 1.00, green: 1.00, blue: 1.00, alpha: 1),
        NSColor(calibratedRed: 0.878, green: 0.898, blue: 0.937, alpha: 1)
    ])!.draw(in: plate, angle: -90)

    let center = NSPoint(x: plate.midX, y: plate.midY)
    let unit = plate.width

    // Soft highlight along the top edge, the way Apple's plates catch light.
    NSGradient(colors: [NSColor.white.withAlphaComponent(0.16), NSColor.white.withAlphaComponent(0.0)])!
        .draw(in: NSRect(x: plate.minX, y: plate.midY, width: plate.width, height: plate.height / 2), angle: -90)

    let accent = NSColor(calibratedRed: 0.231, green: 0.435, blue: 0.961, alpha: 1)
    let radii: [CGFloat] = [unit * 0.15, unit * 0.245, unit * 0.34]
    let stroke = unit * 0.058
    let sweep: CGFloat = 84

    for (index, radius) in radii.enumerated() {
        // Each ring fades slightly as it travels outward.
        accent.withAlphaComponent(1.0 - Double(index) * 0.22).setStroke()
        let offset = CGFloat(index) * 40
        for slot in 0..<3 {
            arc(center: center, radius: radius, heading: CGFloat(slot) * 120 + offset,
                sweep: sweep, width: stroke).stroke()
        }
    }

    // The Mac at the centre of its own traffic.
    let core = unit * 0.075
    NSColor(calibratedRed: 0.055, green: 0.071, blue: 0.098, alpha: 1).setFill()
    NSBezierPath(ovalIn: NSRect(x: center.x - core, y: center.y - core,
                                width: core * 2, height: core * 2)).fill()

    NSGraphicsContext.restoreGraphicsState()
    image.unlockFocus()
    return image
}

let args = Array(CommandLine.arguments.dropFirst())
let outPath = args.count > 0 ? args[0] : "/tmp/icon/native.png"
let size = args.count > 1 ? Double(args[1])! : 1024.0
let icon = makeIcon(size: size)
guard let tiff = icon.tiffRepresentation,
      let rep = NSBitmapImageRep(data: tiff),
      let data = rep.representation(using: .png, properties: [:]) else { fatalError("encode failed") }
try data.write(to: URL(fileURLWithPath: outPath))
print("wrote \(outPath) at \(Int(size))")
