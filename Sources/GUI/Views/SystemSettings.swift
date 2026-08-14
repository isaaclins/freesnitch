import AppKit

/// Deep links into System Settings.
///
/// When the app tells someone to go and approve something, it should take them
/// there rather than describe the route. These are the documented
/// `x-apple.systempreferences:` URLs; if one stops resolving on a future macOS,
/// the fallback opens System Settings at all rather than doing nothing.
enum SystemSettings {
    /// General > Login Items, where a background helper is approved.
    static func openLoginItems() {
        open("x-apple.systempreferences:com.apple.LoginItems-Settings.extension")
    }

    /// Privacy & Security, where a blocked system extension is allowed.
    static func openPrivacyAndSecurity() {
        open("x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension")
    }

    private static func open(_ string: String) {
        guard let url = URL(string: string), NSWorkspace.shared.open(url) else {
            if let fallback = URL(string: "x-apple.systempreferences:") {
                NSWorkspace.shared.open(fallback)
            }
            return
        }
    }
}
