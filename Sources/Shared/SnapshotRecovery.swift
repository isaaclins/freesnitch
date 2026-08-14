import Foundation

/// Decides whether the app should restart the content filter provider after the
/// extension refused the helper's authoritative snapshot.
///
/// The extension's retained policy is the only state involved in such a
/// refusal, and it lives in the provider process, so stopping and starting that
/// provider clears it. Nothing here deactivates the system extension,
/// unregisters the helper, or touches enforcement of established flows.
///
/// Pure and clock-injectable so the production sources can be exercised
/// directly by the harness.
public struct FilterRestartRecovery: Sendable {
    /// Restarting the provider tears down and relaunches a process, so
    /// attempts are spaced and bounded rather than retried in a loop.
    public static let cooldown: TimeInterval = 30
    public static let maximumAttempts = 3

    public enum Decision: Equatable, Sendable {
        /// The status does not describe a refusal the restart can clear.
        case notNeeded
        /// Restart the filter provider now.
        case restartFilter
        /// A restart happened recently; give it time to take effect.
        case waitForCooldown
        /// Restarts are used up. The user must be told what to do by hand.
        case exhausted
    }

    public private(set) var attempts = 0
    private var lastAttempt: Date?

    public init() {}

    public mutating func decide(for status: SharedRuleBridge.SnapshotStatus,
                                now: Date = Date()) -> Decision {
        guard status.needsFilterRestart else { return .notNeeded }
        if let lastAttempt, now.timeIntervalSince(lastAttempt) < Self.cooldown {
            return .waitForCooldown
        }
        guard attempts < Self.maximumAttempts else { return .exhausted }
        attempts += 1
        lastAttempt = now
        return .restartFilter
    }

    /// A snapshot the extension accepted proves the rejection is gone, so the
    /// budget is returned for any later, unrelated episode.
    public mutating func noteHealthy() {
        attempts = 0
        lastAttempt = nil
    }
}
