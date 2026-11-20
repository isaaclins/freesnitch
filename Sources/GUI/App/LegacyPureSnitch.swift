import AppKit
import Foundation

/// Finds an old PureSnitch install and removes it from inside the app (#370).
///
/// The README used to say "run Scripts/uninstall_puresnitch.sh first", which
/// only exists in a source checkout. Someone who downloaded the disk image had
/// no way to follow it, and the old and new content filters must not run
/// together.
///
/// Like PrivilegedUninstall, every path here is a fixed compile-time constant,
/// and nothing named FreeSnitch is ever touched. PureSnitch's own user data is
/// kept. The shared `puresnitch` pf anchor is FreeSnitch's now and is left
/// alone too.
enum LegacyPureSnitch {
    static let app = URL(fileURLWithPath: "/Applications/PureSnitch.app", isDirectory: true)
    static let daemonPlist = URL(fileURLWithPath: "/Library/LaunchDaemons/io.isaaclins.puresnitch.helper.plist")
    static let extensionBundleID = "io.isaaclins.puresnitch.netext"

    struct Found: Equatable {
        var app: Bool
        var daemon: Bool
        /// macOS still runs PureSnitch's network extension. Since macOS 15.3
        /// moving the app to the Trash no longer reliably removes it (see
        /// PrivilegedUninstall.trashApplicationBundle), and FreeSnitch can't
        /// deactivate another app's extension, so this is checked on its own
        /// and the user is pointed to System Settings while it stays.
        var extensionActive: Bool = false
        var any: Bool { app || daemon || extensionActive }
    }

    static func detect(listing: () -> String? = { readExtensionListing() },
                       fileExists: (String) -> Bool = FileManager.default.fileExists(atPath:)) -> Found {
        Found(app: fileExists(app.path),
              daemon: fileExists(daemonPlist.path),
              extensionActive: listing().map(extensionStillActive(in:)) ?? false)
    }

    /// `systemextensionsctl list` needs no privileges. nil when it can't run
    /// or doesn't answer within `timeout`, which counts as "not seen": the app
    /// and plist checks still apply, and launch never waits on it for long.
    static func readExtensionListing(timeout: TimeInterval = 3,
                                     tool: String = "/usr/bin/systemextensionsctl",
                                     arguments: [String] = ["list"]) -> String? {
        guard FileManager.default.isExecutableFile(atPath: tool) else { return nil }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = arguments
        let output = FileManager.default.temporaryDirectory
            .appendingPathComponent("freesnitch-sysext-\(UUID().uuidString).txt")
        guard FileManager.default.createFile(atPath: output.path, contents: nil),
              let handle = try? FileHandle(forWritingTo: output) else { return nil }
        defer { try? handle.close(); try? FileManager.default.removeItem(at: output) }
        process.standardOutput = handle
        process.standardError = FileHandle.nullDevice
        let done = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in done.signal() }
        do { try process.run() } catch { return nil }
        guard done.wait(timeout: .now() + timeout) == .success else {
            process.terminate()
            return nil
        }
        return try? String(contentsOf: output, encoding: .utf8)
    }

    /// True when a listed PureSnitch extension is still active. One that is
    /// already terminated or waiting to be removed at the next restart doesn't
    /// count: a restart finishes that by itself.
    static func extensionStillActive(in listing: String) -> Bool {
        listing.components(separatedBy: .newlines)
            .filter { $0.contains(extensionBundleID) }
            .map { $0.lowercased() }
            .contains { line in
                let leaving = line.contains("terminated") || line.contains("uninstall")
                    || line.contains("deactivated") || line.contains("disabled")
                return !leaving && (line.contains("activated") || line.contains("enabled"))
            }
    }

    /// Stops the old helper and removes its launchd plist, behind one
    /// authorization prompt. The plist is only removed once launchd no longer
    /// has the service, so a helper that refused to stop is never orphaned
    /// without its plist (the script's #262 mistake).
    private static let removeDaemon = """
    do shell script "/bin/launchctl bootout system/io.isaaclins.puresnitch.helper 2>/dev/null; \
    if /bin/launchctl print system/io.isaaclins.puresnitch.helper >/dev/null 2>&1; then echo 'The old PureSnitch helper would not stop.' >&2; exit 1; fi; \
    /bin/rm -f /Library/LaunchDaemons/io.isaaclins.puresnitch.helper.plist" with administrator privileges
    """

    enum Outcome: Equatable {
        case removed
        case cancelled
        case failed(String)
    }

    /// Stops the old helper. Blocks on the authorization prompt; call it off
    /// the main thread.
    static func removeHelper(_ found: Found) -> Outcome {
        if found.daemon {
            guard let script = NSAppleScript(source: removeDaemon) else {
                return .failed(String(localized: "The removal could not be prepared."))
            }
            var errorInfo: NSDictionary?
            script.executeAndReturnError(&errorInfo)
            if let errorInfo {
                if (errorInfo[NSAppleScript.errorNumber] as? Int) == -128 { return .cancelled }
                return .failed((errorInfo[NSAppleScript.errorMessage] as? String)
                               ?? String(localized: "The old PureSnitch helper could not be removed."))
            }
        }
        return .removed
    }

    /// Hands PureSnitch.app to Finder's Trash. On older macOS that also made
    /// macOS remove its system extension; since 15.3 it may not, which is why
    /// `extensionActive` is checked separately on every launch.
    @MainActor
    static func trashApp(completion: @escaping (Outcome) -> Void) {
        NSWorkspace.shared.recycle([app]) { _, error in
            DispatchQueue.main.async {
                if let error {
                    completion(.failed(String(localized: "PureSnitch could not be moved to the Trash: \(error.localizedDescription) Drag PureSnitch from Applications to the Trash in Finder.")))
                } else {
                    completion(.removed)
                }
            }
        }
    }

    /// What the question says, built from what is actually there: the
    /// password prompt only comes when the old helper has to be stopped, and
    /// the Trash only when the app is still in Applications (#399).
    static func removalText(_ found: Found) -> String {
        let action: String
        switch (found.daemon, found.app) {
        case (true, true):
            action = String(localized: "FreeSnitch can stop PureSnitch's helper and move PureSnitch to the Trash; macOS asks for your password once.")
        case (true, false):
            action = String(localized: "PureSnitch's helper is still installed. FreeSnitch can stop and remove that helper; macOS asks for your password once.")
        default:
            action = String(localized: "FreeSnitch can move PureSnitch to the Trash.")
        }
        return String(localized: "PureSnitch is still installed on this Mac. Its network filter and FreeSnitch's must not run together. \(action) Your PureSnitch data is kept.")
    }

    /// Only the extension is left: FreeSnitch can't remove another app's
    /// extension, so it says exactly where the user can.
    static let extensionOnlyText = String(localized: "PureSnitch's app is gone, but macOS is still running its network extension, and its filter and FreeSnitch's must not run together. If you just removed PureSnitch, restart your Mac first. If it is still there after that, open System Settings > General > Login Items & Extensions, find PureSnitch under Extensions, click its info button and delete its network extension there.")

    /// Asks at launch when an old install is present. Shown on every launch
    /// until it is gone, because both filters running together is a real
    /// conflict, but "Not Now" always lets FreeSnitch carry on.
    ///
    /// `continueStartup` runs exactly once: at once when there is nothing to
    /// remove or the user says Not Now, and only after the removal has
    /// finished (or failed, or was cancelled) when they choose Remove, so
    /// FreeSnitch's own filter never starts while PureSnitch is still being
    /// taken out.
    @MainActor
    static func offerRemovalAtLaunch(then continueStartup: @escaping @MainActor () -> Void) {
        let demoPreview = ProcessInfo.processInfo.environment["FREESNITCH_DEMO"] == "1"
        let demoWindow = ProcessInfo.processInfo.environment["FREESNITCH_DEMO_WINDOW"]
        if demoPreview {
            guard demoWindow == "puresnitch" || demoWindow == "puresnitch-extension" else { return continueStartup() }
        }
        if demoPreview {
            ask(demoWindow == "puresnitch-extension" ? Found(app: false, daemon: false, extensionActive: true) : Found(app: true, daemon: true),
                demoPreview: true, then: continueStartup)
            return
        }
        // Reading the extension list runs a system tool; keep it off the main
        // thread so the menu bar never waits on it.
        DispatchQueue.global(qos: .userInitiated).async {
            let found = detect()
            DispatchQueue.main.async { ask(found, demoPreview: false, then: continueStartup) }
        }
    }

    @MainActor
    private static func ask(_ found: Found, demoPreview: Bool, then continueStartup: @escaping @MainActor () -> Void) {
        guard found.any else { return continueStartup() }

        if !found.app && !found.daemon {
            NSApp.activate(ignoringOtherApps: true)
            let alert = NSAlert()
            alert.messageText = String(localized: "PureSnitch's network filter is still on")
            alert.informativeText = extensionOnlyText
            alert.addButton(withTitle: String(localized: "Open Network Extensions"))
            alert.addButton(withTitle: String(localized: "Not Now"))
            if alert.runModal() == .alertFirstButtonReturn, !demoPreview { openNetworkExtensionsSettings() }
            return continueStartup()
        }

        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = String(localized: "Remove the old PureSnitch?")
        alert.informativeText = removalText(found)
        alert.addButton(withTitle: String(localized: "Remove PureSnitch"))
        alert.addButton(withTitle: String(localized: "Not Now"))
        guard alert.runModal() == .alertFirstButtonReturn, !demoPreview else { return continueStartup() }

        performRemoval(found, then: continueStartup)
    }

    /// The removal steps in order, then the report, then `continueStartup`.
    /// The steps are parameters so the ordering can be tested without a
    /// password prompt or a real PureSnitch.
    @MainActor
    static func performRemoval(_ found: Found,
                               removeHelper: @escaping (Found) -> Outcome = removeHelper,
                               trashApp: @escaping @MainActor (@escaping @MainActor (Outcome) -> Void) -> Void = { trashApp(completion: $0) },
                               report: @escaping @MainActor (Outcome) -> Void = report,
                               then continueStartup: @escaping @MainActor () -> Void) {
        let finish: @MainActor (Outcome) -> Void = { outcome in
            report(outcome)
            continueStartup()
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let helper = removeHelper(found)
            DispatchQueue.main.async {
                guard helper == .removed, found.app else { return finish(helper) }
                trashApp(finish)
            }
        }
    }

    @MainActor
    private static func openNetworkExtensionsSettings() {
        for raw in ["x-apple.systempreferences:com.apple.LoginItems-Settings.extension?NetworkExtensions",
                    "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"] {
            if let url = URL(string: raw), NSWorkspace.shared.open(url) { return }
        }
    }

    @MainActor
    private static func report(_ outcome: Outcome) {
        let alert = NSAlert()
        switch outcome {
        case .cancelled:
            return
        case .removed:
            alert.messageText = String(localized: "PureSnitch was removed")
            alert.informativeText = String(localized: "Restart your Mac when it suits you; that finishes removing PureSnitch's network extension. If macOS keeps it, FreeSnitch tells you where to delete it in System Settings.")
        case .failed(let reason):
            alert.alertStyle = .warning
            alert.messageText = String(localized: "PureSnitch could not be removed")
            alert.informativeText = String(localized: "\(reason) FreeSnitch will ask again next time it opens.")
        }
        alert.runModal()
    }
}
