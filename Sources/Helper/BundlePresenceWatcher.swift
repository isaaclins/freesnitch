import Foundation

/// Issue #71: dragging FreeSnitch.app to the Trash is how Macs work, and it
/// leaves this root daemon enforcing a firewall on behalf of an app that no
/// longer exists.
///
/// What this file does, and deliberately does not do
/// ------------------------------------------------
/// It STANDS DOWN. When the containing app bundle is provably gone it stops
/// enforcing: the FreeSnitch pf anchor is flushed and the DNS proxy is stopped,
/// through the same `setEnforcementEnabled(false)` path the user's own toggle
/// uses. Nothing else.
///
/// It never unregisters the launchd service, never boots itself out, never
/// deletes a file, and above all never touches the policy database, which is
/// deliberately preserved so a reinstall comes back with the user's rules. #24
/// is the incident where unregistering an enabled helper destroyed the service,
/// and an update is exactly the moment when a bundle can be briefly absent. A
/// helper that can delete itself during an upgrade is a worse bug than the one
/// this fixes.
///
/// Standing down is fully reversible: the daemon stays registered, and when the
/// app is reinstalled `AppState.bootstrap()` re-enables enforcement on connect.
/// If the bundle reappears, the tracker forgets everything it saw.

// MARK: - One look at the disk

/// What a single observation proved. "I did not see it" is not "it is gone".
enum BundlePresence: Equatable {
    /// The bundle is there, with the parts that make it a real bundle.
    case present
    /// Provably gone: the enclosing directory was readable, nothing about the
    /// bundle was on disk, and no install or update looked to be in flight.
    case absent
    /// Nothing was proven. An unreadable directory, an unmounted volume, a
    /// half-copied bundle or an installer mid-flight all land here, and none of
    /// them may ever accumulate towards a stand-down.
    case inconclusive(String)
}

/// The record that is logged before anything is acted on, so a wrong stand-down
/// is explainable afterwards from the system log alone.
struct BundleAbsenceEvidence: Equatable {
    let bundlePath: String
    /// Every accepted absence observation, oldest first.
    let observations: [Date]
    let decidedAt: Date

    var count: Int { observations.count }
    var span: TimeInterval {
        guard let first = observations.first, let last = observations.last else { return 0 }
        return last.timeIntervalSince(first)
    }

    var summary: String {
        let formatter = ISO8601DateFormatter()
        let stamps = observations.map { formatter.string(from: $0) }.joined(separator: ", ")
        return "bundle=\(bundlePath) absent_observations=\(count) span=\(Int(span))s observed_at=[\(stamps)]"
    }
}

// MARK: - The decision, with no side effects

/// Accumulates separated absence observations and decides, once, that the app
/// is gone.
///
/// Every threshold here exists to make a single unlucky read harmless:
/// * `requiredConsecutiveAbsences` observations must all say absent,
/// * consecutive absences closer together than `minimumObservationInterval` do
///   not count, so a burst of polls cannot satisfy the count,
/// * and the accepted observations must span `minimumAbsenceSpan` in total.
/// Anything that is not a proven absence clears the streak.
struct BundleAbsenceTracker {
    /// Five separated observations. Not one, not two.
    static let requiredConsecutiveAbsences = 5
    /// Two absences closer together than this are the same look at the disk.
    static let minimumObservationInterval: TimeInterval = 120
    /// The accepted observations must cover at least this much wall time, so an
    /// in-place update, which replaces a bundle in seconds, cannot be mistaken
    /// for a removal.
    static let minimumAbsenceSpan: TimeInterval = 600

    enum Outcome: Equatable {
        /// The bundle is there, or nothing was proven. The streak is cleared.
        case standingBy(reason: String)
        /// An absence arrived too soon after the previous one to be independent.
        case tooSoon(sinceLast: TimeInterval)
        case accumulating(count: Int, required: Int)
        case standDown(BundleAbsenceEvidence)
        /// Already stood down; there is nothing left to do and nothing to redo.
        case alreadyStoodDown
    }

    private let bundlePath: String
    private(set) var absences: [Date] = []
    private(set) var hasStoodDown = false

    init(bundlePath: String) {
        self.bundlePath = bundlePath
    }

    mutating func observe(_ presence: BundlePresence, at now: Date) -> Outcome {
        switch presence {
        case .present:
            // A bundle that came back resets everything, including the latch,
            // so a later removal is judged from scratch.
            let hadHistory = !absences.isEmpty || hasStoodDown
            absences.removeAll()
            hasStoodDown = false
            return .standingBy(reason: hadHistory
                ? "the app bundle is present again; absence history discarded"
                : "the app bundle is present")

        case .inconclusive(let reason):
            // Not seeing the bundle for a reason that proves nothing must never
            // count towards removal, and must not revive a stand-down either.
            absences.removeAll()
            return .standingBy(reason: reason)

        case .absent:
            if hasStoodDown { return .alreadyStoodDown }

            if let last = absences.last {
                let gap = now.timeIntervalSince(last)
                // A negative gap means the clock moved; treat it exactly like a
                // too-close reading rather than trusting it.
                if gap < Self.minimumObservationInterval {
                    return .tooSoon(sinceLast: gap)
                }
            }

            absences.append(now)
            guard absences.count >= Self.requiredConsecutiveAbsences,
                  let first = absences.first,
                  now.timeIntervalSince(first) >= Self.minimumAbsenceSpan else {
                return .accumulating(count: absences.count,
                                     required: Self.requiredConsecutiveAbsences)
            }

            hasStoodDown = true
            return .standDown(BundleAbsenceEvidence(bundlePath: bundlePath,
                                                    observations: absences,
                                                    decidedAt: now))
        }
    }
}

// MARK: - Looking at the disk

/// Answers "is my app bundle still there" with evidence, never with a guess.
struct BundlePresenceProbe {
    /// While the enclosing directory has changed this recently, an install,
    /// update or Finder copy could be in flight and no absence is trustworthy.
    static let installQuietPeriod: TimeInterval = 120

    /// The bundle path frozen at process start. Resolving it again later would
    /// let a path that resolves differently look like a removal.
    let bundleURL: URL?
    private let fileManager: FileManager

    init(bundleURL: URL?, fileManager: FileManager = .default) {
        self.bundleURL = bundleURL
        self.fileManager = fileManager
    }

    func observe(at now: Date) -> BundlePresence {
        guard let bundleURL else {
            return .inconclusive("the containing app bundle could not be resolved from this executable")
        }

        let bundlePath = bundleURL.path
        let parent = bundleURL.deletingLastPathComponent()

        // A bundle that is there is there. Checked first, and completely: a
        // directory that exists but has no Info.plist is a copy in progress.
        var isDirectory: ObjCBool = false
        if fileManager.fileExists(atPath: bundlePath, isDirectory: &isDirectory) {
            guard isDirectory.boolValue else {
                return .inconclusive("\(bundlePath) exists but is not a bundle directory")
            }
            let info = bundleURL.appendingPathComponent("Contents/Info.plist").path
            let macOS = bundleURL.appendingPathComponent("Contents/MacOS").path
            if fileManager.fileExists(atPath: info), fileManager.fileExists(atPath: macOS) {
                return .present
            }
            return .inconclusive("\(bundlePath) is present but incomplete; a copy may be in flight")
        }

        // Absence must mean absence, not "I could not look". An unreadable or
        // missing parent is an unmounted volume or a sandbox denial.
        var parentIsDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: parent.path, isDirectory: &parentIsDirectory),
              parentIsDirectory.boolValue else {
            return .inconclusive("\(parent.path) is not readable, so the bundle's absence proves nothing")
        }

        guard let entries = try? fileManager.contentsOfDirectory(atPath: parent.path) else {
            return .inconclusive("\(parent.path) could not be listed, so the bundle's absence proves nothing")
        }

        // An installer stages the new bundle beside the old one under a
        // temporary name before swapping it in. Seeing one means an install is
        // in flight, which is the single most dangerous moment to act.
        let bundleName = bundleURL.lastPathComponent
        let stem = (bundleName as NSString).deletingPathExtension
        if let staged = entries.first(where: { $0 != bundleName && $0.contains(stem) }) {
            return .inconclusive("\(parent.path) contains \(staged); an install or update may be in flight")
        }

        if let modified = try? fileManager.attributesOfItem(atPath: parent.path)[.modificationDate] as? Date {
            let age = now.timeIntervalSince(modified)
            if age >= 0, age < Self.installQuietPeriod {
                return .inconclusive("\(parent.path) changed \(Int(age))s ago; an install or update may be in flight")
            }
        }

        // The running executable lives inside the bundle. If it is still
        // readable the bundle cannot be gone, whatever the directory says.
        if let executable = executablePath, fileManager.fileExists(atPath: executable) {
            return .inconclusive("\(bundlePath) is missing but \(executable) is still on disk")
        }

        return .absent
    }

    private var executablePath: String? {
        guard let bundleURL else { return nil }
        // Same shape as the launchd BundleProgram, resolved from the frozen
        // bundle path rather than from argv.
        return bundleURL.appendingPathComponent("Contents/MacOS/FreeSnitchHelper").path
    }
}

// MARK: - The running watchdog

/// Polls the probe on a timer and stands the helper down once, with its
/// evidence logged first.
final class HelperBundleWatchdog: @unchecked Sendable {
    static let pollInterval: TimeInterval = 180

    static let shared = HelperBundleWatchdog(bundleURL: AppBundleIdentity.containingAppURL)

    private let probe: BundlePresenceProbe
    private let lock = NSLock()
    private var tracker: BundleAbsenceTracker
    private var timer: DispatchSourceTimer?
    private let queue = DispatchQueue(label: "io.isaaclins.freesnitch.bundle-watchdog", qos: .utility)
    private var standDown: ((@escaping (Bool, String?) -> Void) -> Void)?

    init(bundleURL: URL?, fileManager: FileManager = .default) {
        self.probe = BundlePresenceProbe(bundleURL: bundleURL, fileManager: fileManager)
        self.tracker = BundleAbsenceTracker(bundlePath: bundleURL?.path ?? "<unresolved>")
    }

    /// Starts watching on behalf of a live helper. The only action available to
    /// this watchdog is the user-facing enforcement toggle.
    func startWatching(service: HelperService) {
        start { completion in
            service.setEnforcementEnabled(false, reply: completion)
        }
    }

    /// The testable entry point: any stand-down action, on a timer.
    func start(standDown: @escaping (@escaping (Bool, String?) -> Void) -> Void) {
        lock.lock()
        self.standDown = standDown
        let alreadyRunning = timer != nil
        lock.unlock()
        guard !alreadyRunning else { return }

        guard probe.bundleURL != nil else {
            PSLog.info(PSLog.helper,
                       "bundle watchdog: the containing app bundle could not be resolved; not watching")
            return
        }

        let source = DispatchSource.makeTimerSource(queue: queue)
        source.schedule(deadline: .now() + Self.pollInterval, repeating: Self.pollInterval)
        source.setEventHandler { [weak self] in
            guard let self else { return }
            _ = self.poll(at: Date())
        }
        lock.lock()
        timer = source
        lock.unlock()
        source.resume()
        PSLog.info(PSLog.helper,
                   "bundle watchdog: watching \(probe.bundleURL?.path ?? "") every \(Int(Self.pollInterval))s; "
                       + "\(BundleAbsenceTracker.requiredConsecutiveAbsences) separated absences over "
                       + "\(Int(BundleAbsenceTracker.minimumAbsenceSpan))s are required before enforcement is stood down")
    }

    func stop() {
        lock.lock()
        timer?.cancel()
        timer = nil
        lock.unlock()
    }

    /// One observation and its consequence. Returns the outcome so a harness can
    /// assert on the real decision path rather than on a copy of it.
    @discardableResult
    func poll(at now: Date) -> BundleAbsenceTracker.Outcome {
        let presence = probe.observe(at: now)
        lock.lock()
        let outcome = tracker.observe(presence, at: now)
        let action = standDown
        lock.unlock()

        switch outcome {
        case .standDown(let evidence):
            // Logged BEFORE anything is acted on, so a wrong decision survives
            // in the log even if the action itself goes badly.
            PSLog.error(PSLog.helper,
                        "AUDIT: the containing app bundle is gone; standing down enforcement. \(evidence.summary). "
                            + "The launchd registration, the policy database and the shared pf anchor file are left untouched; "
                            + "reinstalling FreeSnitch restores enforcement.")
            guard let action else {
                PSLog.error(PSLog.helper, "AUDIT: no stand-down action is wired; enforcement was left as it was")
                break
            }
            action { ok, message in
                if ok {
                    PSLog.error(PSLog.helper,
                                "AUDIT: enforcement stood down after bundle removal; the pf anchor is flushed and the DNS proxy is stopped")
                } else {
                    PSLog.error(PSLog.helper,
                                "AUDIT: standing down enforcement after bundle removal failed: \(message ?? "unknown error")")
                }
            }
        case .accumulating(let count, let required):
            PSLog.info(PSLog.helper,
                       "bundle watchdog: app bundle absent, observation \(count) of \(required); taking no action yet")
        case .standingBy(let reason):
            PSLog.debug(PSLog.helper, "bundle watchdog: standing by: \(reason)")
        case .tooSoon(let sinceLast):
            PSLog.debug(PSLog.helper,
                        "bundle watchdog: absence seen \(Int(sinceLast))s after the previous one; not an independent observation")
        case .alreadyStoodDown:
            break
        }
        return outcome
    }

    /// Test seam: the tracker state, for assertions.
    var absenceCount: Int {
        lock.lock(); defer { lock.unlock() }
        return tracker.absences.count
    }

    var hasStoodDown: Bool {
        lock.lock(); defer { lock.unlock() }
        return tracker.hasStoodDown
    }
}
