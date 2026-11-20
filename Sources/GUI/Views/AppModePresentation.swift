import SwiftUI

/// How a mode is shown, in one place.
///
/// The mode is the most consequential setting in the app, and it used to be
/// three bare words in a menu: a reader had to stop and translate each one
/// (#87). One symbol and one tint per mode, used in every picker, the menu bar
/// popover and anywhere else a mode appears, turns it into something
/// recognisable without reading.
extension AppMode {
    var title: String {
        switch self {
        case .alert: return String(localized: "Alert", comment: "Name of the mode that asks about each new connection")
        case .silentAllow: return String(localized: "Silent Allow")
        case .silentDeny: return String(localized: "Silent Deny")
        }
    }

    var symbol: String {
        switch self {
        case .alert: return "bell.fill"
        case .silentAllow: return "checkmark.shield.fill"
        case .silentDeny: return "hand.raised.fill"
        }
    }

    var tint: Color {
        switch self {
        case .alert: return .orange
        case .silentAllow: return .green
        case .silentDeny: return .red
        }
    }

    /// What the mode actually does, for a picker's help text.
    var explanation: String {
        switch self {
        case .alert: return String(localized: "Ask about connections that no rule covers.")
        case .silentAllow: return String(localized: "Permit everything no rule covers, and record it.")
        case .silentDeny: return String(localized: "Refuse everything no rule covers.")
        }
    }
}

/// The words for the enforcement switch, in one place.
///
/// The same switch was called "Block traffic" in Settings and "Blocklists" in
/// the Rules sidebar, and the Settings caption claimed that off meant "purely a
/// traffic monitor" while rules in the extension went on blocking. One switch
/// gets one name and one sentence (#139).
enum EnforcementControl {
    static let title = String(localized: "Enforce rules and blocklists")

    static let help = String(localized: "Loads the pf firewall anchor and runs the local DNS proxy, so rules and blocklists take effect.")

    static let explanation = String(localized: "Off by default. Turning this on lets FreeSnitch load a pf firewall anchor and run a DNS proxy, which changes how this Mac resolves names and filters packets. With it off, blocklists and pf rules do nothing, though decisions you make in Alert mode still apply to new connections.")
}
