import Foundation

/// Decides when the app connects to the network extension again after the
/// link dropped (#212).
///
/// The link is lost whenever the extension's filter is restarted (to clear a
/// rejected snapshot, #70) or macOS replaces the extension process. Until the
/// app registers again, rule changes never reach the extension and it has
/// nobody to ask about new connections, so it lets them through. That fails
/// open, but it is not what the user set up.
///
/// A new extension process may not be listening yet when the app first tries,
/// so attempts are spaced and bounded rather than retried in a loop. Pure and
/// free of timers so the production source can be exercised by the harness.
public struct ExtensionReconnect: Sendable {
    /// Seconds to wait before each attempt. About a minute and a half in all,
    /// which covers a provider that takes a while to start without trying
    /// forever against an extension that will not take the connection.
    public static let delays: [TimeInterval] = [0.5, 1, 2, 4, 8, 15, 30, 30]

    public enum Decision: Equatable, Sendable {
        /// Try to register again after this many seconds.
        case retry(after: TimeInterval)
        /// An attempt is already scheduled; this loss changes nothing.
        case alreadyScheduled
        /// The attempts are used up. Say so once and stop.
        case exhausted
        /// The attempts were already used up and reported.
        case gaveUp
    }

    public private(set) var attempts = 0
    public private(set) var scheduled = false
    private var reportedExhausted = false

    public init() {}

    /// The link was lost, or an attempt to restore it failed.
    public mutating func linkLost() -> Decision {
        guard !scheduled else { return .alreadyScheduled }
        guard attempts < Self.delays.count else {
            if reportedExhausted { return .gaveUp }
            reportedExhausted = true
            return .exhausted
        }
        let delay = Self.delays[attempts]
        attempts += 1
        scheduled = true
        return .retry(after: delay)
    }

    /// The scheduled attempt is starting now.
    public mutating func attemptStarted() {
        scheduled = false
    }

    /// The extension took the registration: the budget is returned for the
    /// next time the link drops.
    public mutating func connected() {
        attempts = 0
        scheduled = false
        reportedExhausted = false
    }

    /// Something else starts a fresh connection (the filter was turned on or
    /// restarted), or the filter is off and nothing should reconnect. Any
    /// scheduled attempt is dropped and the budget starts over.
    public mutating func reset() {
        connected()
    }
}
