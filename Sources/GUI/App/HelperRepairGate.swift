import Foundation

enum HelperRepairState: Equatable {
    case idle
    case inProgress
    case manualRequired(String)
}

/// Lets one Repair Helper attempt run at a time (#216).
///
/// An attempt holds the gate from the click until its privileged work is over
/// (the authorization prompt and kickstart, or the registration call). After a
/// registration the state stays `.inProgress` while FreeSnitch waits for the
/// helper to reconnect, and that wait still counts as the same attempt: a
/// second click then would register again or open a second prompt. The banner
/// shows the button as "Repairing…" and disabled for as long as this refuses.
struct HelperRepairGate {
    /// True while privileged repair work runs. Polling pauses meanwhile.
    private(set) var isHeld = false

    /// Starts an attempt, or returns false when one is still running.
    mutating func begin(state: HelperRepairState) -> Bool {
        guard !isHeld, state != .inProgress else { return false }
        isHeld = true
        return true
    }

    /// The privileged part is over. A later attempt can start once the state
    /// has left `.inProgress` too.
    mutating func release() {
        isHeld = false
    }
}
