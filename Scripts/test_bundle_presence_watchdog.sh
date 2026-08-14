#!/usr/bin/env bash
# Regression harness for #71: the helper stands down when its app bundle is
# genuinely gone, and never on a guess.
#
# The harness is compiled from the real helper and shared sources, never from a
# copy, and it runs from inside a throwaway .app so the production path that
# resolves the containing bundle, looks at the disk, and decides is the one
# under test. The only thing simulated is the clock and the stand-down action.
#
# It asserts, in order:
#   1. one missed observation never triggers anything,
#   2. a burst of observations cannot substitute for separated ones,
#   3. sustained absence across the required separated observations does trigger,
#      exactly once,
#   4. a bundle that reappears between observations resets the state completely,
#      so the full evidence is required again afterwards,
#   5. an install in flight, a half-copied bundle and an unreadable parent are
#      all inconclusive and never accumulate,
#   6. nothing on disk is deleted, in particular not the policy database.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-bundle-watchdog.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

SDK="$(xcrun --show-sdk-path)"
TARGET="arm64-apple-macos13.0"
STAGE="$TMP/stage"
APP="$STAGE/FreeSnitch.app"
SUPPORT="$TMP/support"

mkdir -p "$APP/Contents/MacOS" "$SUPPORT"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>io.isaaclins.freesnitch</string>
    <key>CFBundleShortVersionString</key>
    <string>0.4.4</string>
    <key>CFBundleVersion</key>
    <string>44</string>
</dict>
</plist>
PLIST

# The database the uninstall path deliberately preserves. Nothing in this test
# may remove it.
printf 'fake policy database\n' > "$SUPPORT/freesnitch.sqlite"
printf 'fake insights database\n' > "$SUPPORT/insights.sqlite"

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

/// Collects every failure so one run reports all broken invariants.
final class Failures {
    private var messages: [String] = []

    func expect(_ condition: Bool, _ message: @autoclosure () -> String) {
        if !condition { messages.append(message()) }
    }

    var all: [String] { messages }
}

/// Counts stand-downs and answers them the way the helper's enforcement toggle
/// does. It is the only thing in this harness that is not production code.
final class StandDownRecorder {
    private(set) var invocations = 0

    func action(_ completion: @escaping (Bool, String?) -> Void) {
        invocations += 1
        completion(true, nil)
    }
}

@main
struct BundleWatchdogHarness {
    static let fm = FileManager.default

    static func die(_ message: String) -> Never {
        FileHandle.standardError.write(Data("bundle watchdog harness: FAIL: \(message)\n".utf8))
        exit(1)
    }

    /// Every path under a root, so "this code deleted something" is provable
    /// rather than assumed.
    static func snapshot(_ root: URL, skipping skipped: URL) -> [String] {
        guard let walker = fm.enumerator(atPath: root.path) else { return [] }
        // The bundle itself is removed and restored by this harness, so it is
        // excluded by its path relative to the root.
        let skip = String(skipped.path.dropFirst(root.path.count).drop(while: { $0 == "/" }))
        var out: [String] = []
        for case let path as String in walker {
            if path == skip || path.hasPrefix(skip + "/") { continue }
            out.append(path)
        }
        return out.sorted()
    }

    static func removeBundle(_ appURL: URL) {
        do { try fm.removeItem(at: appURL) } catch { die("could not remove the test bundle: \(error)") }
        ageParent(of: appURL)
    }

    /// Removing the bundle stamps the enclosing directory, and the probe treats
    /// a freshly changed directory as a possible install in flight. Age it so
    /// the disk state under test is "removed a while ago", which is the case
    /// this harness is about. The quiet period itself is asserted separately.
    static func ageParent(of appURL: URL) {
        let parent = appURL.deletingLastPathComponent()
        try? fm.setAttributes([.modificationDate: Date(timeIntervalSinceNow: -3600)],
                              ofItemAtPath: parent.path)
    }

    static func restoreBundle(_ appURL: URL) {
        do {
            try fm.createDirectory(at: appURL.appendingPathComponent("Contents/MacOS"),
                                   withIntermediateDirectories: true)
            let plist = """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
                <key>CFBundleIdentifier</key>
                <string>io.isaaclins.freesnitch</string>
                <key>CFBundleShortVersionString</key>
                <string>0.4.4</string>
                <key>CFBundleVersion</key>
                <string>44</string>
            </dict>
            </plist>
            """
            try Data(plist.utf8).write(to: appURL.appendingPathComponent("Contents/Info.plist"))
        } catch {
            die("could not restore the test bundle: \(error)")
        }
    }

    static func main() {
        let failures = Failures()

        guard let appURL = AppBundleIdentity.containingAppURL else {
            die("the harness is not running inside an .app")
        }
        let stage = appURL.deletingLastPathComponent()
        let tmp = stage.deletingLastPathComponent()
        let before = snapshot(tmp, skipping: appURL)

        let interval = BundleAbsenceTracker.minimumObservationInterval
        let required = BundleAbsenceTracker.requiredConsecutiveAbsences
        let span = BundleAbsenceTracker.minimumAbsenceSpan

        failures.expect(required >= 3, "a stand-down needs only \(required) observations")
        failures.expect(interval >= 60, "observations only need to be \(interval)s apart")
        failures.expect(span >= 300, "the absence only needs to span \(span)s")

        // The cadence a real run uses: five polls, each a poll interval apart.
        let step = max(interval, HelperBundleWatchdog.pollInterval)
        func schedule(from base: Date, count: Int) -> [Date] {
            (0..<count).map { base.addingTimeInterval(Double($0) * step) }
        }

        // --- 1. one missed observation never triggers anything ---------------
        removeBundle(appURL)
        let base = Date()
        let single = HelperBundleWatchdog(bundleURL: appURL)
        let singleRecorder = StandDownRecorder()
        single.start(standDown: singleRecorder.action)
        let firstOutcome = single.poll(at: base)
        failures.expect(firstOutcome == .accumulating(count: 1, required: required),
                        "one missed observation produced \(firstOutcome)")
        failures.expect(singleRecorder.invocations == 0,
                        "one missed observation stood the helper down")
        failures.expect(!single.hasStoodDown, "one missed observation latched a stand-down")

        // --- 2. a burst is not evidence --------------------------------------
        let burst = HelperBundleWatchdog(bundleURL: appURL)
        let burstRecorder = StandDownRecorder()
        burst.start(standDown: burstRecorder.action)
        for tick in 0..<(required * 4) {
            let outcome = burst.poll(at: base.addingTimeInterval(Double(tick)))
            if tick > 0, case .tooSoon = outcome {} else if tick > 0 {
                failures.expect(false, "a burst observation \(tick)s later was accepted: \(outcome)")
            }
        }
        failures.expect(burstRecorder.invocations == 0,
                        "\(required * 4) rapid observations stood the helper down")
        failures.expect(burst.absenceCount == 1,
                        "a burst accumulated \(burst.absenceCount) observations")

        // --- 3. sustained absence stands the helper down, once ---------------
        let sustained = HelperBundleWatchdog(bundleURL: appURL)
        let sustainedRecorder = StandDownRecorder()
        sustained.start(standDown: sustainedRecorder.action)
        var standDownEvidence: BundleAbsenceEvidence?
        for (index, at) in schedule(from: base, count: required).enumerated() {
            let outcome = sustained.poll(at: at)
            if index < required - 1 {
                failures.expect(outcome == .accumulating(count: index + 1, required: required),
                                "observation \(index + 1) produced \(outcome)")
                failures.expect(sustainedRecorder.invocations == 0,
                                "the helper stood down after \(index + 1) observations")
            } else {
                if case .standDown(let evidence) = outcome {
                    standDownEvidence = evidence
                } else {
                    failures.expect(false, "sustained absence produced \(outcome) instead of a stand-down")
                }
            }
        }
        failures.expect(sustainedRecorder.invocations == 1,
                        "sustained absence produced \(sustainedRecorder.invocations) stand-downs")
        if let evidence = standDownEvidence {
            failures.expect(evidence.count == required,
                            "the logged evidence has \(evidence.count) observations")
            failures.expect(evidence.span >= span,
                            "the logged evidence spans only \(Int(evidence.span))s")
            failures.expect(evidence.bundlePath == appURL.path,
                            "the logged evidence names \(evidence.bundlePath)")
            failures.expect(evidence.summary.contains("absent_observations=\(required)"),
                            "the logged evidence does not state its observation count: \(evidence.summary)")
        }
        // Nothing to repeat and nothing to redo.
        let after = sustained.poll(at: base.addingTimeInterval(step * Double(required + 4)))
        failures.expect(after == .alreadyStoodDown, "a stood-down watchdog produced \(after)")
        failures.expect(sustainedRecorder.invocations == 1,
                        "the stand-down was repeated: \(sustainedRecorder.invocations) times")

        // A bundle that comes back clears the latch, so the daemon is usable
        // again after a reinstall without being restarted.
        restoreBundle(appURL)
        let recovered = sustained.poll(at: base.addingTimeInterval(step * Double(required + 8)))
        if case .standingBy = recovered {} else {
            failures.expect(false, "a restored bundle produced \(recovered)")
        }
        failures.expect(!sustained.hasStoodDown, "a restored bundle left the stand-down latched")

        // --- 4. a bundle that reappears resets the state completely ----------
        removeBundle(appURL)
        let interrupted = HelperBundleWatchdog(bundleURL: appURL)
        let interruptedRecorder = StandDownRecorder()
        interrupted.start(standDown: interruptedRecorder.action)
        for at in schedule(from: base, count: required - 1) {
            _ = interrupted.poll(at: at)
        }
        failures.expect(interrupted.absenceCount == required - 1,
                        "the interrupted run accumulated \(interrupted.absenceCount) observations")

        restoreBundle(appURL)
        let backAt = base.addingTimeInterval(step * Double(required))
        let backOutcome = interrupted.poll(at: backAt)
        if case .standingBy = backOutcome {} else {
            failures.expect(false, "a reappearing bundle produced \(backOutcome)")
        }
        failures.expect(interrupted.absenceCount == 0,
                        "a reappearing bundle left \(interrupted.absenceCount) observations behind")

        // Gone again: the full evidence is required from scratch, so the
        // observations from before the reappearance cannot be reused.
        removeBundle(appURL)
        let restart = backAt.addingTimeInterval(step)
        for (index, at) in schedule(from: restart, count: required - 1).enumerated() {
            let outcome = interrupted.poll(at: at)
            failures.expect(outcome == .accumulating(count: index + 1, required: required),
                            "after a reappearance, observation \(index + 1) produced \(outcome)")
        }
        failures.expect(interruptedRecorder.invocations == 0,
                        "the state before the reappearance was reused to stand the helper down")
        let finalOutcome = interrupted.poll(at: restart.addingTimeInterval(step * Double(required - 1)))
        if case .standDown = finalOutcome {} else {
            failures.expect(false, "a full second round of evidence produced \(finalOutcome)")
        }
        failures.expect(interruptedRecorder.invocations == 1,
                        "a full second round of evidence did not stand the helper down")

        // --- 5. inconclusive readings never accumulate ------------------------
        var clock = Date(timeIntervalSince1970: 0)
        var tracker = BundleAbsenceTracker(bundlePath: appURL.path)
        for _ in 0..<(required - 1) {
            _ = tracker.observe(.absent, at: clock)
            clock = clock.addingTimeInterval(step)
        }
        failures.expect(tracker.absences.count == required - 1,
                        "the tracker holds \(tracker.absences.count) observations")
        _ = tracker.observe(.inconclusive("volume not mounted"), at: clock)
        failures.expect(tracker.absences.isEmpty,
                        "an inconclusive reading left \(tracker.absences.count) observations behind")
        clock = clock.addingTimeInterval(step)
        let afterInconclusive = tracker.observe(.absent, at: clock)
        failures.expect(afterInconclusive == .accumulating(count: 1, required: required),
                        "an inconclusive reading did not clear the streak: \(afterInconclusive)")

        // The disk-level readings that must be inconclusive.
        let probe = BundlePresenceProbe(bundleURL: appURL)
        failures.expect(probe.observe(at: Date()) == .absent,
                        "a removed bundle in a quiet directory was not read as absent")

        // An install in flight: the new bundle staged beside the old name.
        let staged = stage.appendingPathComponent("FreeSnitch.app.tmp-install")
        try? fm.createDirectory(at: staged, withIntermediateDirectories: true)
        ageParent(of: appURL)
        if case .inconclusive = probe.observe(at: Date()) {} else {
            failures.expect(false, "a staged install copy was not treated as an install in flight")
        }
        try? fm.removeItem(at: staged)
        ageParent(of: appURL)

        // A directory that changed a moment ago: something is happening there.
        try? fm.setAttributes([.modificationDate: Date()], ofItemAtPath: stage.path)
        if case .inconclusive = probe.observe(at: Date()) {} else {
            failures.expect(false, "a directory that changed a moment ago was treated as a settled removal")
        }
        ageParent(of: appURL)

        // A half-copied bundle: the directory is there, the contents are not.
        try? fm.createDirectory(at: appURL, withIntermediateDirectories: true)
        if case .inconclusive = probe.observe(at: Date()) {} else {
            failures.expect(false, "a half-copied bundle was not treated as a copy in flight")
        }
        try? fm.removeItem(at: appURL)
        ageParent(of: appURL)

        // A path that cannot be resolved proves nothing at all.
        let unresolved = BundlePresenceProbe(bundleURL: nil)
        if case .inconclusive = unresolved.observe(at: Date()) {} else {
            failures.expect(false, "an unresolvable bundle path was treated as a removal")
        }
        let unresolvedWatchdog = HelperBundleWatchdog(bundleURL: nil)
        let unresolvedRecorder = StandDownRecorder()
        unresolvedWatchdog.start(standDown: unresolvedRecorder.action)
        for at in schedule(from: base, count: required * 2) {
            _ = unresolvedWatchdog.poll(at: at)
        }
        failures.expect(unresolvedRecorder.invocations == 0,
                        "an unresolvable bundle path stood the helper down")

        // An unreadable parent is not an absent bundle. Root can read anything,
        // so this only proves something as a normal user.
        if getuid() != 0 {
            let sealed = tmp.appendingPathComponent("sealed")
            let sealedApp = sealed.appendingPathComponent("FreeSnitch.app")
            try? fm.createDirectory(at: sealed, withIntermediateDirectories: true)
            try? fm.setAttributes([.posixPermissions: 0o000], ofItemAtPath: sealed.path)
            if case .inconclusive = BundlePresenceProbe(bundleURL: sealedApp).observe(at: Date()) {} else {
                failures.expect(false, "an unreadable parent directory was treated as a removal")
            }
            try? fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: sealed.path)
            try? fm.removeItem(at: sealed)
        }

        // --- 6. nothing was deleted ------------------------------------------
        restoreBundle(appURL)
        let policyDatabase = tmp.appendingPathComponent("support/freesnitch.sqlite")
        failures.expect(fm.fileExists(atPath: policyDatabase.path),
                        "the policy database at \(policyDatabase.path) was deleted")
        failures.expect(fm.fileExists(atPath: tmp.appendingPathComponent("support/insights.sqlite").path),
                        "the Insights database was deleted")
        let after6 = snapshot(tmp, skipping: appURL)
        let missing = Set(before).subtracting(after6)
        failures.expect(missing.isEmpty,
                        "the stand-down path deleted: \(missing.sorted().joined(separator: ", "))")

        let problems = failures.all
        guard problems.isEmpty else {
            for problem in problems {
                FileHandle.standardError.write(Data(("bundle watchdog harness: FAIL: " + problem + "\n").utf8))
            }
            exit(1)
        }
        print("bundle watchdog harness: one missed observation and \(required * 4) rapid ones changed nothing")
        print("bundle watchdog harness: \(required) separated observations over \(Int(span))s stood enforcement down exactly once")
        print("bundle watchdog harness: a reappearing bundle cleared the evidence and the latch")
        print("bundle watchdog harness: staged installs, half-copied bundles and unreadable parents stayed inconclusive")
        print("bundle watchdog harness: the policy database and every other file survived")
        print("bundle watchdog harness: PASS")
    }
}
SWIFT

# shellcheck disable=SC2046
xcrun swiftc -O -sdk "$SDK" -target "$TARGET" -parse-as-library \
  -o "$TMP/harness-binary" \
  $(ls "$ROOT"/Sources/Helper/*.swift | grep -v '/main.swift$') \
  "$ROOT"/Sources/Shared/*.swift \
  "$TMP/verify.swift"
cp "$TMP/harness-binary" "$APP/Contents/MacOS/FreeSnitchHelper"

printf 'bundle watchdog harness: running from %s\n' "$APP/Contents/MacOS/FreeSnitchHelper"
"$APP/Contents/MacOS/FreeSnitchHelper"

# The stand-down must stay a stand-down. #24 showed that unregistering an
# enabled helper can remove the service entirely, and an update is exactly when
# a bundle can look absent.
WATCHER="$ROOT/Sources/Helper/BundlePresenceWatcher.swift"
# Comments explain what this file must never do, so the check reads the code.
WATCHER_CODE="$(sed -e 's,//.*,,' "$WATCHER")"
for forbidden in bootout unregister SMAppService launchctl removeItem trashItem "unlink(" "Process(" pfctl; do
  if grep -Fq -- "$forbidden" <(printf '%s\n' "$WATCHER_CODE"); then
    printf 'bundle watchdog harness: FAIL: the bundle watcher uses `%s`; it may only stand enforcement down\n' "$forbidden" >&2
    exit 1
  fi
done
grep -Fq 'setEnforcementEnabled(false' "$WATCHER" \
  || { printf 'bundle watchdog harness: FAIL: the bundle watcher no longer stands down through the enforcement toggle\n' >&2; exit 1; }
grep -Fq 'HelperBundleWatchdog.shared.startWatching(service: service)' "$ROOT/Sources/Helper/main.swift" \
  || { printf 'bundle watchdog harness: FAIL: the helper no longer starts the bundle watchdog\n' >&2; exit 1; }

printf 'bundle presence watchdog verification: PASS\n'
