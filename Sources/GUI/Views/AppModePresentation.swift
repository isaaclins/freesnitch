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
        case .alert: return "Alert"
        case .silentAllow: return "Silent Allow"
        case .silentDeny: return "Silent Deny"
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
        case .alert: return "Ask about connections that no rule covers."
        case .silentAllow: return "Permit everything no rule covers, and record it."
        case .silentDeny: return "Refuse everything no rule covers."
        }
    }
}
