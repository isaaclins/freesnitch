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
