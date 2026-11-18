import Foundation

/// Whether the content filter is off, as the app last saw it, and what a
/// change of that means for the could-not-save banner (#321).
///
/// While the filter is off nothing restarts with the saved boot policy, so a
/// failed save there is only logged. Turning the filter on, in the app or in
/// System Settings, saves the current rules again, and a failure from then on
/// shows the banner as before.
///
/// Pure, so the harness can run the off and on sequences directly.
public struct FilterOffState: Equatable, Sendable {
    /// What the app should do after a change.
    public enum Change: Equatable, Sendable {
        case none
        /// The filter is off: an earlier save-failure warning no longer applies.
        case clearBanner
        /// The filter was turned on outside the app: save the current rules.
        case saveCurrentRules
    }

    public private(set) var isOff = false

    public init() {}

    /// A failed boot policy save warns only while the filter can restart with
    /// the saved rules.
    public var saveFailureShowsBanner: Bool { !isOff }

    /// The app asked to turn the filter on, or a turn-on save succeeded.
    public mutating func turnedOn() {
        isOff = false
    }

    /// The app turned the filter off or removed its configuration. A turn-on
    /// asked for meanwhile waits behind this and decides the state. Returns
    /// whether the filter now counts as off, so the app stops showing it as
    /// filtering whatever macOS later answers about the extension (#335).
    @discardableResult
    public mutating func turnedOff(turnOnPending: Bool) -> Bool {
        guard !turnOnPending else { return false }
        isOff = true
        return true
    }

    /// A turn-on that followed the filter being turned on in System Settings
    /// stands at its save cycle's load only while it is still on there: turned
    /// off or removed there again meanwhile, what is set there wins and the
    /// cycle must neither turn it back on nor recreate it (#361). A turn-on
    /// asked for by activation always stands.
    public static func turnOnStands(fromSettings: Bool, configured: Bool, enabled: Bool) -> Bool {
        !fromSettings || (configured && enabled)
    }

    /// The filter preferences were read. `fromOutside` is true when the read
    /// follows a change notification rather than the app's own save cycle,
    /// which is already saving the current rules.
    public mutating func observed(configured: Bool, enabled: Bool, fromOutside: Bool) -> Change {
        let wasOff = isOff
        isOff = !configured || !enabled
        if isOff { return .clearBanner }
        return wasOff && fromOutside ? .saveCurrentRules : .none
    }
}
