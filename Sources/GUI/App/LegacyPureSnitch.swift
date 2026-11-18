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

    struct Found: Equatable {
        var app: Bool
        var daemon: Bool
        var any: Bool { app || daemon }
    }

    static func detect(fileExists: (String) -> Bool = FileManager.default.fileExists(atPath:)) -> Found {
        Found(app: fileExists(app.path), daemon: fileExists(daemonPlist.path))
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
                return .failed("The removal could not be prepared.")
            }
            var errorInfo: NSDictionary?
            script.executeAndReturnError(&errorInfo)
            if let errorInfo {
                if (errorInfo[NSAppleScript.errorNumber] as? Int) == -128 { return .cancelled }
                return .failed((errorInfo[NSAppleScript.errorMessage] as? String)
                               ?? "The old PureSnitch helper could not be removed.")
            }
        }
        return .removed
    }

    /// Hands PureSnitch.app to Finder's Trash, the same way
    /// PrivilegedUninstall.trashApplicationBundle does: moving an app that
    /// hosts a system extension to the Trash through Finder is what makes
    /// macOS remove that extension too. A plain file move or rm doesn't.
    @MainActor
    static func trashApp(completion: @escaping (Outcome) -> Void) {
        NSWorkspace.shared.recycle([app]) { _, error in
            DispatchQueue.main.async {
                if let error {
                    completion(.failed("PureSnitch could not be moved to the Trash: \(error.localizedDescription) Drag PureSnitch from Applications to the Trash in Finder."))
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
            action = "FreeSnitch can stop PureSnitch's helper and move PureSnitch to the Trash; macOS asks for your password once."
        case (true, false):
            action = "PureSnitch's helper is still installed. FreeSnitch can stop and remove that helper; macOS asks for your password once."
        default:
            action = "FreeSnitch can move PureSnitch to the Trash."
        }
        return "PureSnitch is still installed on this Mac. Its network filter and FreeSnitch's must not run together. \(action) Your PureSnitch data is kept. A restart finishes removing its network extension."
    }

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
        if demoPreview {
            guard ProcessInfo.processInfo.environment["FREESNITCH_DEMO_WINDOW"] == "puresnitch" else { return continueStartup() }
        }
        let found = demoPreview ? Found(app: true, daemon: true) : detect()
        guard found.any else { return continueStartup() }

        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Remove the old PureSnitch?"
        alert.informativeText = removalText(found)
        alert.addButton(withTitle: "Remove PureSnitch")
        alert.addButton(withTitle: "Not Now")
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
    private static func report(_ outcome: Outcome) {
        let alert = NSAlert()
        switch outcome {
        case .cancelled:
            return
        case .removed:
            alert.messageText = "PureSnitch was removed"
            alert.informativeText = "Restart your Mac when it suits you; macOS finishes removing PureSnitch's network extension then."
        case .failed(let reason):
            alert.alertStyle = .warning
            alert.messageText = "PureSnitch could not be removed"
            alert.informativeText = "\(reason) FreeSnitch will ask again next time it opens."
        }
        alert.runModal()
    }
}
