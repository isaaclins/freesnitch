import Foundation

/// Runs load-then-save sequences on `NEFilterManager.shared()` one at a time,
/// in the order they were asked for (#309).
///
/// `NEFilterManager.shared()` is one object. A sequence loads the stored
/// preferences into it, changes fields, and saves the whole object back. Two
/// sequences that overlap can each save what the other loaded: a boot-policy
/// save that was started to turn the filter on could write `isEnabled = true`
/// after the user turned the filter off. Making every sequence wait for the
/// one before it means the last request (turn off, remove, save, restart) is
/// the one whose result ends up in the preferences.
///
/// Every operation must call its `done` handler exactly once, on the main
/// queue, after its final save has completed or it gave up. Not thread safe:
/// use it from the main queue only.
final class FilterPreferencesLine {
    typealias Operation = (_ done: @escaping () -> Void) -> Void

    private var running = false
    private var waiting: [Operation] = []

    init() {}

    /// True while an operation runs or waits.
    var isBusy: Bool { running || !waiting.isEmpty }

    /// Runs `operation` now if nothing else is running, otherwise after every
    /// operation queued before it has finished.
    func run(_ operation: @escaping Operation) {
        waiting.append(operation)
        startNextIfIdle()
    }

    private func startNextIfIdle() {
        guard !running, !waiting.isEmpty else { return }
        running = true
        let next = waiting.removeFirst()
        var finished = false
        next { [weak self] in
            guard let self, !finished else { return }
            finished = true
            self.running = false
            self.startNextIfIdle()
        }
    }
}

/// What the end of a boot-policy save cycle reports about the filter (#318).
///
/// A save that was started to turn the filter on can finish after the user
/// turned it off or removed it. The line saves the turn-off after it, so the
/// preferences end up off; this decides what the app says meanwhile.
enum FilterSaveCompletion: Equatable {
    /// A plain policy save: nothing to report about the filter itself.
    case none
    /// The enabling save landed and nothing overtook it: the filter is on.
    case active
    /// The enabling save failed and nothing overtook it: say so.
    case failed
    /// Turned off or removed meanwhile: the filter stays off.
    case stayedOff
    /// Turned off and then on again meanwhile: the next cycle saves the
    /// fresh policy and reports the result itself.
    case awaitReenable

    /// - Parameters:
    ///   - enabling: the cycle was started to turn the filter on.
    ///   - turnOffsAtLoad: the turn-off count when the cycle started.
    ///   - turnOffsNow: the turn-off count when its save finished.
    ///   - enableRequestedNow: an enable request is waiting now.
    ///   - saveFailed: the save returned an error.
    static func decide(enabling: Bool, turnOffsAtLoad: Int, turnOffsNow: Int,
                       enableRequestedNow: Bool, saveFailed: Bool) -> FilterSaveCompletion {
        guard enabling else { return .none }
        guard turnOffsNow == turnOffsAtLoad else {
            return enableRequestedNow ? .awaitReenable : .stayedOff
        }
        return saveFailed ? .failed : .active
    }
}
