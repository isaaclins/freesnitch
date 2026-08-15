import SwiftUI
import AppKit

/// The two colours that carry meaning rather than emphasis.
///
/// Everything else the app draws now uses a system colour, a semantic label
/// colour, or a native container that needs no colour at all, which is what
/// let the app-wide `PSTheme` palette go. These two stay named because in and
/// out are the one distinction the app makes with colour, and they must not
/// move when the user changes their accent colour (#68).
enum TrafficColor {
    static let sent = Color(nsColor: .systemBlue)
    static let received = Color(nsColor: .systemPink)
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
    init(_ text: String, color: Color = .accentColor, icon: String? = nil) {
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
            .background(Color(nsColor: .controlBackgroundColor))
            // 8 was a guess. Apple's grouped containers use 10 at this size,
            // and the separator carries the edge, so the stroke is gone.
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}
