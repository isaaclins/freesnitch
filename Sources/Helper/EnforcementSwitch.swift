import Foundation

/// Turns enforcement (the pf anchor plus the DNS proxy) on and off as one
/// step at a time (#248).
///
/// The app and the command line tool can ask at the same moment, and their
/// XPC handlers run on different queues. Without one lock across the whole
/// transition, an enable could load pf, a disable could then stop DNS, empty
/// pf and reply success, and the enable could resume and start the DNS proxy
/// with pf off: a successful "off" that left the proxy filtering. Holding the
/// lock for the full transition means requests complete one after the other,
/// the state on and off is the one of the last request to complete, and a
/// successful "off" reply means the proxy is stopped.
///
/// The lock is never held across a reply: `setEnabled` returns the outcome and
/// the caller replies after it is released, so a reply handler that turns
/// enforcement on or off again cannot deadlock here.
final class EnforcementSwitch: @unchecked Sendable {
    /// The real work of a transition, handed in so the ordering and rollback
    /// here are the code that runs in the helper and in the test harness.
    struct Steps {
        /// Loads the pf anchor with the rules in force.
        let installPF: () throws -> Void
        /// Empties the pf anchor.
        let uninstallPF: () throws -> Void
        let startDNS: () throws -> Void
        let stopDNS: () -> Void
        /// pf did what was asked; any earlier pf error is cleared from status.
        let pfSucceeded: () -> Void
        /// pf refused; the error stays in status (issue #211).
        let pfFailed: (Error) -> Void
    }

    private let lock = NSLock()

    /// Runs `body` while no enforcement transition is in progress, so a direct
    /// pf install or flush cannot land in the middle of one.
    func serialized<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }

    /// Turns enforcement on or off and returns the reply to send. Fails open:
    /// a turn-on that cannot complete is rolled back to off.
    func setEnabled(_ enabled: Bool, steps: Steps) -> (Bool, String?) {
        serialized {
            enabled ? Self.turnOn(steps) : Self.turnOff(steps)
        }
    }

    private static func turnOn(_ steps: Steps) -> (Bool, String?) {
        do {
            do {
                try steps.installPF()
                steps.pfSucceeded()
            } catch {
                steps.pfFailed(error)
                throw error
            }
            try steps.startDNS()
            return (true, nil)
        } catch {
            // A rollback that cannot empty the anchor leaves pf on, so it
            // is recorded like a failed turn-off (issue #211).
            do { try steps.uninstallPF() } catch let rollbackError { steps.pfFailed(rollbackError) }
            steps.stopDNS()
            return (false, error.localizedDescription)
        }
    }

    private static func turnOff(_ steps: Steps) -> (Bool, String?) {
        steps.stopDNS()
        do {
            try steps.uninstallPF()
            steps.pfSucceeded()
            return (true, nil)
        } catch {
            // The old rules may still be in pf, so this is not "off":
            // keep the error in status and tell the caller (issue #211).
            steps.pfFailed(error)
            return (false, error.localizedDescription)
        }
    }
}
