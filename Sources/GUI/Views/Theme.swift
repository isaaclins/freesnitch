import SwiftUI
import AppKit

enum PSTheme {
    static let bgPrimary = Color(NSColor(red: 0.075, green: 0.075, blue: 0.085, alpha: 1))
    static let bgSecondary = Color(NSColor(red: 0.105, green: 0.105, blue: 0.115, alpha: 1))
    static let bgTertiary = Color(NSColor(red: 0.135, green: 0.135, blue: 0.145, alpha: 1))
    static let bgSidebar = Color(NSColor(red: 0.085, green: 0.085, blue: 0.095, alpha: 1))
    static let bgRow = Color(NSColor(red: 0.115, green: 0.115, blue: 0.13, alpha: 1))
    static let bgRowAlt = Color(NSColor(red: 0.13, green: 0.13, blue: 0.145, alpha: 1))
    static let stroke = Color(NSColor(red: 0.22, green: 0.22, blue: 0.24, alpha: 1))
    static let accent = Color(NSColor(srgbRed: 0.231, green: 0.435, blue: 0.961, alpha: 1))
    static let accentGreen = Color(NSColor(red: 0.28, green: 0.78, blue: 0.45, alpha: 1))
    static let accentRed = Color(NSColor(red: 0.95, green: 0.30, blue: 0.30, alpha: 1))
    static let accentYellow = Color(NSColor(red: 1.0, green: 0.78, blue: 0.20, alpha: 1))
    static let accentBlue = Color(NSColor(red: 0.30, green: 0.55, blue: 1.0, alpha: 1))
    static let trafficIn = Color(NSColor(red: 0.95, green: 0.45, blue: 0.95, alpha: 1)) // pink/magenta
    static let trafficOut = Color(NSColor(red: 0.40, green: 0.60, blue: 1.0, alpha: 1)) // blue
    static let textPrimary = Color(NSColor(white: 0.95, alpha: 1))
    static let textSecondary = Color(NSColor(white: 0.65, alpha: 1))
    static let textMuted = Color(NSColor(white: 0.45, alpha: 1))
}

enum AppIcon {
    /// Resolves a real application icon from a bundle id, executable/app path,
    /// or app name. Returns nil if the app can't be located on this machine
    /// (callers fall back to an SF Symbol). NSWorkspace caches icons, so this
    /// is cheap enough to call from a list row.
    static func resolve(bundleId: String? = nil, path: String? = nil, name: String? = nil) -> NSImage? {
        let ws = NSWorkspace.shared
        if let bid = bundleId, !bid.isEmpty,
           let url = ws.urlForApplication(withBundleIdentifier: bid) {
            return ws.icon(forFile: url.path)
        }
        if let p = path, !p.isEmpty {
            var appPath = p
            // Match the LAST ".app/" so nested bundles (…/Foo.app/…/Bar.app/…)
            // resolve to the innermost app that owns the executable.
            if let r = appPath.range(of: ".app/", options: .backwards) {
                appPath = String(appPath[..<r.upperBound])
            }
            if FileManager.default.fileExists(atPath: appPath) {
                return ws.icon(forFile: appPath)
            }
        }
        if let n = name, !n.isEmpty {
            let dirs = ["/Applications",
                        "\(NSHomeDirectory())/Applications",
                        "/System/Applications",
                        "/Applications/Utilities",
                        "/System/Applications/Utilities"]
            for dir in dirs {
                let candidate = "\(dir)/\(n).app"
                if FileManager.default.fileExists(atPath: candidate) {
                    return ws.icon(forFile: candidate)
                }
            }
        }
        return nil
    }
}

enum PSFormat {
    static func bytes(_ n: Int64) -> String {
        let b = Double(n)
        if b < 1024 { return "\(Int(b)) B" }
        if b < 1024*1024 { return String(format: "%.1f KB", b/1024) }
        if b < 1024*1024*1024 { return String(format: "%.1f MB", b/1024/1024) }
        return String(format: "%.2f GB", b/1024/1024/1024)
    }
    static func bytesPerSec(_ n: Int64) -> String {
        return "\(bytes(n))/s"
    }
    static func compactCount(_ n: Int) -> String {
        if n < 1000 { return "\(n)" }
        if n < 1_000_000 { return String(format: "%.1fk", Double(n)/1000) }
        return String(format: "%.1fM", Double(n)/1_000_000)
    }
}

struct PSChip: View {
    let text: String
    let color: Color
    let icon: String?
    init(_ text: String, color: Color = PSTheme.accent, icon: String? = nil) {
        self.text = text; self.color = color; self.icon = icon
    }
    var body: some View {
        HStack(spacing: 4) {
            if let icon { Image(systemName: icon).font(.system(size: 9, weight: .bold)) }
            Text(text).font(.system(size: 10, weight: .semibold))
        }
        .padding(.horizontal, 6).padding(.vertical, 2)
        .background(color.opacity(0.18))
        .foregroundColor(color)
        .clipShape(Capsule())
        .overlay(Capsule().stroke(color.opacity(0.3), lineWidth: 0.5))
    }
}

struct PSPanel<Content: View>: View {
    let content: () -> Content
    init(@ViewBuilder content: @escaping () -> Content) { self.content = content }
    var body: some View {
        content()
            .background(PSTheme.bgSecondary)
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).stroke(PSTheme.stroke, lineWidth: 0.5))
    }
}
