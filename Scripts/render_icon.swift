import AppKit
import Foundation

// FreeSnitch icon, drawn entirely from first principles.
// The concentric-arc bloom was explored using SF Symbols as a sketching tool,
// but Apple's SF Symbols license forbids shipping their glyphs inside an app
// icon or logo, so every shape here is our own geometry.

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
        NSColor(calibratedRed: 0.93, green: 0.94, blue: 0.97, alpha: 1)
    ])!.draw(in: plate, angle: -90)

    let center = NSPoint(x: plate.midX, y: plate.midY)
    let unit = plate.width

    // Six directions, each a three-ring burst, overlapping into new hues.
    let colors: [NSColor] = [
        NSColor(calibratedRed: 0.25, green: 0.47, blue: 1.00, alpha: 1),
        NSColor(calibratedRed: 0.35, green: 0.78, blue: 0.98, alpha: 1),
        NSColor(calibratedRed: 0.20, green: 0.80, blue: 0.64, alpha: 1),
        NSColor(calibratedRed: 0.98, green: 0.75, blue: 0.18, alpha: 1),
        NSColor(calibratedRed: 0.98, green: 0.42, blue: 0.28, alpha: 1),
        NSColor(calibratedRed: 0.72, green: 0.35, blue: 0.95, alpha: 1)
    ]
    let radii: [CGFloat] = [unit * 0.148, unit * 0.236, unit * 0.324]
    let stroke = unit * 0.055
    let sweep: CGFloat = 62

    NSGraphicsContext.current?.compositingOperation = .multiply
    for (index, color) in colors.enumerated() {
        let heading = CGFloat(index) * 60
        color.withAlphaComponent(0.88).setStroke()
        for radius in radii {
            arc(center: center, radius: radius, heading: heading, sweep: sweep, width: stroke).stroke()
        }
    }
    NSGraphicsContext.current?.compositingOperation = .sourceOver

    // The Mac at the centre of its own traffic.
    let core = unit * 0.078
    NSColor(calibratedRed: 0.11, green: 0.13, blue: 0.19, alpha: 1).setFill()
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
