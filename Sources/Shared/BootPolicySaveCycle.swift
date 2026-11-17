import Foundation

extension SharedRuleBridge {
    /// The decisions of the app's boot-policy save cycle, without
    /// NEFilterManager. `SystemExtensionManager` feeds it what the system
    /// answered (load failed, a configuration exists, save failed) and carries
    /// out what it returns, so every branch can run in a test (#310).
    ///
    /// One cycle is: `begin`, load the preferences, `afterLoad`, save them,
    /// `afterSave`. Only one cycle runs at a time; a request that arrives
    /// during one stays queued for the next.
    public struct BootPolicySaveCycle: Sendable {
        /// What to do once a step is over.
        public enum Next: Equatable, Sendable {
            /// Nothing: no newer work, or a retry already owns it.
            case none
            /// Start another cycle right away.
            case now
            /// Retry the kept snapshot after this many seconds.
            case retry(after: TimeInterval)
            /// The kept snapshot was not saved and the retries are used up.
            /// The next rule change, Send Rules Again or an app restart saves.
            case retriesUsedUp
        }

        /// Why a loaded cycle saves nothing.
        public enum StopReason: Equatable, Sendable {
            /// The filter was turned on while loading, which dropped the queue.
            /// Only the helper's fresh answer may enable it.
            case enableWithoutFreshSnapshot
            /// No filter is configured (never enabled, or removed for
            /// uninstall). A boot-policy save must not create one.
            /// An earlier "could not save" warning no longer applies (#311).
            case noConfiguration
            /// Turned off or removed while loading: nothing left to save.
            case cancelledDuringLoad
        }

        /// A started cycle: where the queue and the cancellations stood when
        /// the load began.
        public struct Load: Equatable, Sendable {
            public let generation: Int
            public let cancellations: Int
        }

        /// What `afterLoad` decided.
        public enum AfterLoad: Equatable, Sendable {
            /// The preferences could not be loaded. `failActivation` when the
            /// user was turning the filter on; the enable request is then
            /// over, and the queued work is retried as a plain save (#345).
            case loadFailed(failActivation: Bool, next: Next)
            /// The load failed, but the filter was turned on, off or removed
            /// meanwhile: it no longer matters, raise no warning and fail no
            /// activation. Log it only.
            case cancelledLoadFailed(next: Next)
            /// The queued save is the removal of the saved policy, there is
            /// none saved and the filter is not being turned on: writing the
            /// preferences unchanged would happen on every rule edit over the
            /// limit (#320).
            case nothingToRemove(next: Next)
            case stop(StopReason)
            /// Write `pending` (when there is one) to the configuration, and
            /// enable the filter when `enable`.
            case save(Save)
        }

        public struct Save: Equatable, Sendable {
            public let pending: NewestWriteWinsQueue.Pending?
            public let enable: Bool
            public let load: Load
            /// The save takes the saved policy out instead of writing one,
            /// because the newest policy is too big to keep (#320).
            public let removesSavedPolicy: Bool
            /// A saved policy was there when this cycle loaded.
            public let hadSavedPolicy: Bool
        }

        /// What `afterSave` decided.
        public struct AfterSave: Equatable, Sendable {
            /// Turning the filter on failed; report it.
            public var failActivation = false
            /// The save failed and still matters: raise the warning. False
            /// when the filter was turned on, off or removed meanwhile.
            public var reportFailure = false
            /// A policy was written to the configuration.
            public var savedPolicy = false
            /// The saved policy was taken out (#320). The "can't keep these
            /// rules for a restart" warning stays.
            public var removedSavedPolicy = false
            /// The newest policy is saved: clear the "could not save" warning.
            public var clearWarning = false
            /// The filter was turned on.
            public var activated = false
            /// What happens to a failed save: `.retry`, `.retriesUsedUp`, or
            /// `.none` when it was not kept (cancelled, or newer work won).
            /// A failed turn-on is kept too and retried without enabling.
            public var next = Next.none
            /// Start another cycle right away (newer work, or an enable
            /// request arrived during this one). Replaces a scheduled retry.
            public var runAgainNow = false
        }

        public private(set) var queue = NewestWriteWinsQueue()
        public private(set) var retry: RetrySchedule
        public private(set) var inFlight = false
        public private(set) var enableRequested = false
        /// Bumped by every `cancel`, so a cycle already running can tell its
        /// result no longer matters.
        public private(set) var cancellations = 0
        /// A save was refused because the filter settings changed outside the
        /// app after the load, and the one immediate save again is used up.
        /// Cleared by a save that goes through or a newer policy (#368).
        public private(set) var changedOutsideRetried = false

        public init(retryDelays: [TimeInterval] = RetrySchedule.defaultDelays) {
            retry = RetrySchedule(delays: retryDelays)
        }

        // MARK: Requests

        /// Queue the newest encoded policy. A newer policy starts the retries over.
        public mutating func enqueue(_ data: Data) {
            queue.enqueue(data)
            retry.reset()
            changedOutsideRetried = false
        }

        /// The newest policy cannot be kept for the next start (for example
        /// it is over the boot policy's rule limit), though the extension
        /// enforces it live. An older snapshot kept for a retry must not be
        /// saved in its place and a save in flight must not count as newest,
        /// so both are dropped, and the saved policy is removed instead: the
        /// next start fails open until the app sends the live rules (#320).
        /// Turning the filter on goes ahead with the live policy.
        public mutating func queueRemoval() {
            cancel()
            queue.enqueue(SharedRuleBridge.bootSnapshotRemoval)
            changedOutsideRetried = false
        }

        /// The user turns the filter on. A snapshot kept for a retry is never
        /// what activation saves: only the helper's fresh answer may.
        public mutating func requestEnable() {
            cancel()
            enableRequested = true
        }

        /// The filter is turned on, off or removed: drop what is queued and
        /// invalidate a save in flight, so it cannot be put back if it fails.
        public mutating func cancel() {
            cancellations &+= 1
            queue.invalidateAll()
            retry.reset()
        }

        /// The filter is turned off or removed. Turning it on and then off
        /// before the helper answered must not let that answer turn it back
        /// on (#309).
        public mutating func dropEnableRequest() {
            enableRequested = false
        }

        /// The helper gave no policy while the filter was being turned on and
        /// no save is queued or running: give up on activation. True when the
        /// caller must report that.
        public mutating func abandonEnableIfIdle() -> Bool {
            guard enableRequested, !queue.hasPending, !inFlight else { return false }
            enableRequested = false
            return true
        }

        // MARK: The cycle

        /// Start a cycle. Nil when one is running or nothing is queued (an
        /// enable request without a snapshot is a fetch failure, not
        /// permission to save stale state). The app then waits for its turn on
        /// the filter preferences and takes `currentLoad` when the load starts.
        public mutating func begin() -> Load? {
            guard !inFlight, queue.hasPending else { return nil }
            inFlight = true
            return currentLoad
        }

        /// Where the queue and the cancellations stand right now.
        public var currentLoad: Load {
            Load(generation: queue.generation, cancellations: cancellations)
        }

        public mutating func afterLoad(_ load: Load, loadFailed: Bool,
                                       configurationExists: Bool, hasSavedPolicy: Bool) -> AfterLoad {
            let generationAtLoad = load.generation
            if loadFailed {
                inFlight = false
                if cancellations != load.cancellations {
                    return .cancelledLoadFailed(next: queue.hasPending || enableRequested ? .now : .none)
                }
                // Turning the filter on failed. The request ends here, so the
                // retry below or a later rule change saves without turning the
                // filter on; only the user does that.
                let failActivation = enableRequested
                enableRequested = false
                if queue.hasNewerWork(since: generationAtLoad) {
                    return .loadFailed(failActivation: failActivation, next: .now)
                }
                // The snapshot (or the removal of an older saved policy, #320)
                // was never taken, so it is still queued, also when turning
                // the filter on failed. Leaving the older saved policy as the
                // last word is #213 and #345: retry.
                return .loadFailed(failActivation: failActivation, next: nextRetry())
            }

            let enable = enableRequested
            if enable && !queue.hasPending {
                inFlight = false
                return .stop(.enableWithoutFreshSnapshot)
            }
            if !enable && !configurationExists {
                inFlight = false
                queue.discardThrough(queue.generation)
                return .stop(.noConfiguration)
            }
            let pending = queue.takeNewest()
            if !enable && pending == nil {
                inFlight = false
                return .stop(.cancelledDuringLoad)
            }
            enableRequested = false
            let removes = pending?.data == SharedRuleBridge.bootSnapshotRemoval
            if removes && !hasSavedPolicy && !enable {
                inFlight = false
                return .nothingToRemove(next: queue.hasPending ? .now : .none)
            }
            return .save(Save(pending: pending, enable: enable, load: load,
                              removesSavedPolicy: removes, hadSavedPolicy: hasSavedPolicy))
        }

        /// `changedOutside`: the system refused the save because the filter
        /// settings changed after this cycle loaded them, for example the
        /// filter was turned off in System Settings (#368). Writing what was
        /// loaded would undo that change, so nothing was written: load again
        /// right away and save the same policy onto what the user set. Once
        /// per policy; after that it is an ordinary failed save.
        public mutating func afterSave(_ save: Save, saveFailed: Bool, changedOutside: Bool = false) -> AfterSave {
            inFlight = false
            var result = AfterSave()
            if saveFailed && changedOutside && !save.enable && !changedOutsideRetried
                && cancellations == save.load.cancellations {
                changedOutsideRetried = true
                // Requeue fails only when newer work arrived; that runs next.
                if let pending = save.pending { queue.requeueFailed(pending) }
                result.runAgainNow = queue.hasPending || enableRequested
                return result
            }
            if saveFailed {
                result.reportFailure = cancellations == save.load.cancellations
                result.failActivation = save.enable
                // Also after a failed turn-on (#345): the enable request was
                // cleared when this cycle loaded, so the retry saves the
                // policy (or the removal) and never turns the filter on.
                if let pending = save.pending, queue.requeueFailed(pending) {
                    // Nothing newer arrived during the save, so the saved
                    // policy is still older than the one being enforced.
                    result.next = nextRetry()
                }
            } else {
                changedOutsideRetried = false
                if save.removesSavedPolicy {
                    // The live rules could not be kept for the next start;
                    // the warning stays until a policy that can be kept is saved.
                    retry.reset()
                    result.removedSavedPolicy = true
                } else if let pending = save.pending {
                    result.savedPolicy = true
                    // Only a save of the newest policy clears the warning; an
                    // older one finishing late does not.
                    if !queue.hasNewerWork(since: pending.generation) {
                        retry.reset()
                        result.clearWarning = true
                    }
                }
                result.activated = save.enable
            }

            // A request that arrived during this cycle could not be folded
            // into the completed write: start another one. Measured from the
            // snapshot this cycle took, not from the load: one that arrived
            // during the load was taken already. A requeued snapshot is not
            // newer, so the spaced retry (or the give-up after the last one)
            // keeps it; only an enable request may jump ahead (#312).
            let attempted = save.pending?.generation ?? save.load.generation
            if enableRequested || queue.hasNewerWork(since: attempted) {
                result.runAgainNow = true
            }
            return result
        }

        private mutating func nextRetry() -> Next {
            guard let delay = retry.nextDelay() else { return .retriesUsedUp }
            return .retry(after: delay)
        }
    }
}
