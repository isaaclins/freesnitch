import SwiftUI
import AppKit

/// Semantic system colors, not a palette.
///
/// Every one of these used to be a fixed dark RGB value, which is why the app
/// looked like a dark app that happens to run on a Mac while Settings, the one
/// screen built from system controls, looked like it belonged. Fixed colors
/// also cannot follow the system appearance, honour the user's accent colour,
/// or respond to Increase Contrast.
///
/// The names are kept so the 272 call sites do not all have to change at once;
/// what changes is that each one now resolves through AppKit. New code should
/// prefer the system colors directly, or better, use a native container that
/// needs no colour at all.
enum PSTheme {
    /// Window and content backgrounds. `bgSidebar` is deliberately clear so the
    /// sidebar's own material shows through instead of being painted over,
    /// which is the top source of wrong-looking Mac UI.
    static let bgPrimary = Color(nsColor: .windowBackgroundColor)
    static let bgSecondary = Color(nsColor: .controlBackgroundColor)
    static let bgTertiary = Color(nsColor: .underPageBackgroundColor)
    static let bgSidebar = Color.clear
    static let bgRow = Color(nsColor: .alternatingContentBackgroundColors.first ?? .controlBackgroundColor)
    static let bgRowAlt = Color(nsColor: .alternatingContentBackgroundColors.last ?? .windowBackgroundColor)
    static let stroke = Color(nsColor: .separatorColor)
    /// Follows the accent colour the user picked in System Settings.
    static let accent = Color.accentColor
    static let accentGreen = Color(nsColor: .systemGreen)
    static let accentRed = Color(nsColor: .systemRed)
    static let accentYellow = Color(nsColor: .systemYellow)
    static let accentBlue = Color(nsColor: .systemBlue)
    /// Traffic direction stays deliberately distinct from the accent colour,
    /// because these two encode meaning (in versus out) rather than emphasis,
    /// and must not change when the user changes their accent.
    static let trafficIn = Color(nsColor: .systemPink)
    static let trafficOut = Color(nsColor: .systemBlue)
    static let textPrimary = Color(nsColor: .labelColor)
    static let textSecondary = Color(nsColor: .secondaryLabelColor)
    static let textMuted = Color(nsColor: .tertiaryLabelColor)
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
    /// The system's own byte formatter, so a number here means the same thing
    /// as the same number in Finder and Activity Monitor. This used to divide
    /// by 1024 and label the result KB, MB and GB, which disagrees with every
    /// other size on the Mac (#132).
    private static let byteFormatter: ByteCountFormatter = {
        let f = ByteCountFormatter()
        f.countStyle = .file
        f.allowsNonnumericFormatting = false
        return f
    }()

    static func bytes(_ n: Int64) -> String {
        byteFormatter.string(fromByteCount: max(0, n))
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
    /// A quiet annotation, not a button.
    ///
    /// These used to be saturated tinted capsules with a matching border, which
    /// read as small buttons sitting next to the real ones. The colour now
    /// survives only in the symbol, where it still carries the severity, while
    /// the text stays a system label on a neutral fill.
    var body: some View {
        HStack(spacing: 4) {
            if let icon {
                Image(systemName: icon)
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(color)
            }
            Text(text)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 6).padding(.vertical, 2)
        .background(.quaternary, in: Capsule())
    }
}

struct PSPanel<Content: View>: View {
    let content: () -> Content
    init(@ViewBuilder content: @escaping () -> Content) { self.content = content }
    var body: some View {
        content()
            .background(PSTheme.bgSecondary)
            // 8 was a guess. Apple's grouped containers use 10 at this size,
            // and the separator carries the edge, so the stroke is gone.
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}
