import Foundation

/// The helper session identifier carried next to the policy generation.
///
/// # Why a persisted counter
///
/// The generation orders policy *changes*; it says nothing about which helper
/// process produced them. The extension keeps its policy in memory across
/// helper and app restarts, so after an update it compared a fresh helper's
/// generation against one it had learned from the previous helper and rejected
/// the owner of the policy forever (#70). The epoch is the missing half of the
/// ordering: it says which helper session is speaking.
///
/// Three representations were considered.
///
/// - A boot-time UUID is trivial to produce and needs no storage, but it is
///   unordered. The extension could only ask "is this different", and any
///   client that invented a fresh UUID would outrank the real helper. That
///   turns an ordering fix into a trust hole, so it was rejected.
/// - The helper's launchd start time is ordered and free, but it is ordered by
///   the clock. A backwards clock step, which is ordinary after an NTP
///   correction, a dead battery, or a dual boot, makes a genuinely newer helper
///   look older and re-creates exactly the bug being fixed.
/// - A counter persisted next to the policy, incremented once per helper
///   session, is a total order that does not depend on the clock at all. It
///   costs one settings row and one write per helper start.
///
/// The counter wins, and this file is its whole definition.
///
/// # When the counter cannot be read or written
///
/// The counter lives in the same SQLite database as the policy, so a database
/// that cannot be opened stops the helper long before this value matters. If
/// the row is missing, it reads as `unknown` and the first session becomes
/// `first`, which is strictly greater than everything a pre-epoch build ever
/// published; that is precisely the upgrade path.
///
/// If the row can be read but not written, the session still advances the value
/// *in memory*, so this helper session is authoritative for as long as it runs.
/// The cost is that a following session computes the same epoch again, and the
/// two sessions then compare by generation exactly as builds did before this
/// change: never weaker than the old behaviour, and recoverable without a
/// reboot because the app restarts the filter provider when the extension does
/// reject the helper.
public enum PolicyEpoch {
    /// What a snapshot from a build that predates the epoch decodes as, and
    /// what an unopened session reports. Never authoritative against anything.
    public static let unknown: UInt64 = 0

    /// The first session of an epoch-aware helper.
    public static let first: UInt64 = 1

    /// The session identifier that follows a persisted value.
    ///
    /// Saturating rather than wrapping: wrapping would hand a future session a
    /// lower epoch than the extension already holds, which is the rollback this
    /// value exists to prevent. Reaching `UInt64.max` needs more helper starts
    /// than a machine can perform.
    public static func next(after stored: UInt64) -> UInt64 {
        guard stored >= first else { return first }
        return stored == UInt64.max ? UInt64.max : stored + 1
    }
}
