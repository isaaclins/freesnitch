import Foundation

/// What the app does with one status ping (#452).
///
/// The status carries the mode the helper enforces (the active profile's) and
/// the policy generation it belongs to. The app shows that mode at once, and
/// asks for the full snapshot again until it holds the snapshot of that
/// generation: the snapshot is what the network extension is given, so a
/// fetch that failed is retried on the next ping instead of leaving the
/// extension on the old policy while the app shows the new mode.
struct EnforcedModeSync: Equatable {
    /// The mode to show, or nil when it is already shown.
    var showMode: AppMode?
    /// Whether to fetch the authoritative snapshot again.
    var fetchSnapshot: Bool

    static func decide(statusMode: AppMode,
                       statusGeneration: UInt64?,
                       shownMode: AppMode,
                       snapshotGeneration: UInt64?) -> EnforcedModeSync {
        let modeChanged = statusMode != shownMode
        // An older helper sends no generation; then only a mode change says
        // the snapshot is out of date, as before.
        let snapshotBehind = statusGeneration.map { $0 != snapshotGeneration } ?? false
        return EnforcedModeSync(showMode: modeChanged ? statusMode : nil,
                                fetchSnapshot: modeChanged || snapshotBehind)
    }
}
