import AppKit
import Foundation

/// Moves FreeSnitch into /Applications when it was opened from somewhere
/// macOS won't install its helper from (#370).
///
/// macOS refuses background helpers and system extensions for an app that runs
/// from a mounted disk image or from Downloads. The app used to only say so in
/// a banner and leave the dragging to the user. This copies the bundle into
/// /Applications, removes the Downloads original, and reopens from there.
///
/// It never replaces or deletes a FreeSnitch that is already in Applications:
/// that copy may host the running system extension, and throwing it away is
/// what removes the extension (see PrivilegedUninstall.trashApplicationBundle).
enum InstallLocation {
    static let bundleName = "FreeSnitch.app"

    /// Why a firewall build in ~/Applications is asked to move (#412).
    static let userApplicationsReason = String(localized: "macOS only turns on FreeSnitch's network filter when it runs from the main Applications folder, not the one in your home folder.")

    enum Plan: Equatable {
        /// Nothing at the destination yet: copy this bundle there.
        case copy(to: URL)
        /// A copy is already installed. `isOlder` when that copy has a lower
        /// build number than this one, so opening it would be a downgrade.
        case existing(URL, isOlder: Bool)
    }

    enum MoveError: Error, Equatable {
        case failed(String)
    }

    static func plan(source: URL, applications: URL) -> Plan {
        let destination = applications.appendingPathComponent(bundleName, isDirectory: true)
        guard FileManager.default.fileExists(atPath: destination.path) else {
            return .copy(to: destination)
        }
        return .existing(destination, isOlder: buildNumber(of: destination) < buildNumber(of: source))
    }

    static func buildNumber(of bundle: URL) -> Int {
        let info = bundle.appendingPathComponent("Contents/Info.plist")
        guard let dict = NSDictionary(contentsOf: info),
              let raw = dict["CFBundleVersion"] as? String else { return 0 }
        return Int(raw) ?? 0
    }

    /// Copies `source` to `destination` through a hidden staging name, so a
    /// copy that fails halfway never leaves a broken FreeSnitch.app behind,
    /// and clears the download quarantine on the copy.
    ///
    /// Clearing quarantine matters: a quarantined app that was not moved by
    /// Finder is run from a randomised read-only path (App Translocation),
    /// which is outside Applications again and would loop straight back here.
    /// The user already opened this exact signed, notarized bundle, so
    /// Gatekeeper has nothing left to decide about it.
    static func copyBundle(from source: URL, to destination: URL) -> Result<Void, MoveError> {
        let fm = FileManager.default
        guard !fm.fileExists(atPath: destination.path) else {
            return .failure(.failed(String(localized: "\(destination.path) already exists.")))
        }
        removeLeftoverStaging(in: destination.deletingLastPathComponent())
        let staging = destination.deletingLastPathComponent()
            .appendingPathComponent("\(stagingPrefix)\(UUID().uuidString)", isDirectory: true)
        do {
            try fm.copyItem(at: source, to: staging)
            // A copy that keeps the flag would run translocated again, so it
            // doesn't count as moved and the original stays where it was.
            guard clearQuarantine(at: staging) else {
                removeStaging(staging)
                return .failure(.failed(String(localized: "The download flag could not be removed from the copy.")))
            }
            try fm.moveItem(at: staging, to: destination)
            return .success(())
        } catch {
            removeStaging(staging)
            return .failure(.failed(error.localizedDescription))
        }
    }

    /// The hidden name a copy is staged under, followed by a UUID.
    static let stagingPrefix = ".\(bundleName).partial-"

    /// Whether `name` is one of the staging folders `copyBundle` makes:
    /// exactly the prefix and an uppercase UUID, as `UUID().uuidString`
    /// writes it. Anything else, even a close match, isn't ours.
    static func isStagingName(_ name: String) -> Bool {
        guard name.hasPrefix(stagingPrefix) else { return false }
        let id = String(name.dropFirst(stagingPrefix.count))
        return UUID(uuidString: id)?.uuidString == id
    }

    /// Removes staging folders a move left behind when the app crashed or was
    /// force-quit mid-copy (#413). Only real folders with exactly the staging
    /// name are touched, never a symlink and never anything else in `folder`.
    static func removeLeftoverStaging(in folder: URL) {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: folder.path) else { return }
        for name in names where isStagingName(name) {
            let leftover = folder.appendingPathComponent(name, isDirectory: true)
            var info = stat()
            guard lstat(leftover.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR else { continue }
            removeStaging(leftover)
        }
    }

    /// The copy keeps the source's permissions, and a read-only folder can't
    /// be emptied, so make the staging tree writable before removing it.
    private static func removeStaging(_ staging: URL) {
        let fm = FileManager.default
        guard fm.fileExists(atPath: staging.path) else { return }
        var paths = [staging.path]
        if let walker = fm.enumerator(atPath: staging.path) {
            for case let relative as String in walker { paths.append(staging.appendingPathComponent(relative).path) }
        }
        for path in paths {
            var info = stat()
            if lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR {
                chmod(path, info.st_mode | S_IRWXU)
            }
        }
        try? fm.removeItem(at: staging)
    }

    /// Returns whether the bundle itself is free of the flag afterwards,
    /// which is what decides whether macOS translocates it.
    @discardableResult
    static func clearQuarantine(at root: URL) -> Bool {
        let attribute = "com.apple.quarantine"
        removexattr(root.path, attribute, XATTR_NOFOLLOW)
        if let walker = FileManager.default.enumerator(atPath: root.path) {
            for case let relative as String in walker {
                removexattr(root.appendingPathComponent(relative).path, attribute, XATTR_NOFOLLOW)
            }
        }
        return getxattr(root.path, attribute, nil, 0, 0, XATTR_NOFOLLOW) < 0
    }

    /// Where the bundle really is when macOS runs it translocated, so the
    /// Downloads original can be removed after the move. nil when it isn't
    /// translocated or the answer isn't available.
    static func translocatedOriginal(of url: URL) -> URL? {
        typealias IsTranslocated = @convention(c) (CFURL, UnsafeMutablePointer<Bool>, UnsafeMutablePointer<Unmanaged<CFError>?>?) -> Bool
        typealias OriginalPath = @convention(c) (CFURL, UnsafeMutablePointer<Unmanaged<CFError>?>?) -> Unmanaged<CFURL>?
        guard let security = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY) else { return nil }
        defer { dlclose(security) }
        guard let isSym = dlsym(security, "SecTranslocateIsTranslocatedURL"),
              let origSym = dlsym(security, "SecTranslocateCreateOriginalPathForURL") else { return nil }
        let isTranslocated = unsafeBitCast(isSym, to: IsTranslocated.self)
        let originalPath = unsafeBitCast(origSym, to: OriginalPath.self)
        var translocated = false
        guard isTranslocated(url as CFURL, &translocated, nil), translocated,
              let original = originalPath(url as CFURL, nil) else { return nil }
        return original.takeRetainedValue() as URL
    }

    /// The one rule for "FreeSnitch is installed" (#401): the move question,
    /// helper registration and the banner all ask this.
    ///
    /// /Applications always counts. ~/Applications counts only for a build
    /// without the network filter: macOS activates a system extension only
    /// from an app in /Applications, so the firewall build there could
    /// register its helper but never filter per process (#412).
    /// `embedsSystemExtension` is read from the bundle when not given.
    static func isInApplications(_ url: URL, home: String = NSHomeDirectory(),
                                 embedsSystemExtension: Bool? = nil) -> Bool {
        if url.resolvingSymlinksInPath().path.hasPrefix("/Applications/") { return true }
        guard isInUserApplications(url, home: home) else { return false }
        return !(embedsSystemExtension ?? Self.embedsSystemExtension(url))
    }

    /// The Applications folder in the user's home folder.
    static func isInUserApplications(_ url: URL, home: String = NSHomeDirectory()) -> Bool {
        let userApps = (home as NSString).appendingPathComponent("Applications") + "/"
        return url.resolvingSymlinksInPath().path.hasPrefix(userApps)
    }

    /// Whether a FreeSnitch already in ~/Applications is where the move should
    /// stop. Not when either build carries the network filter: a firewall
    /// build must land in /Applications, and an old monitor copy there is not
    /// a substitute for it (#412).
    static func userCopyCountsAsInstalled(source: URL, userCopy: URL) -> Bool {
        !embedsSystemExtension(source) && !embedsSystemExtension(userCopy)
    }

    /// Where this copy really is: the original behind a translocated copy.
    static var runningOriginal: URL {
        translocatedOriginal(of: Bundle.main.bundleURL) ?? Bundle.main.bundleURL
    }

    /// Set by a copy out of ~/Applications to the path of the new copy (#418).
    static let reregisterKey = "PSReregisterHelperAfterMoveTo"

    /// Whether this launch is the new copy a ~/Applications copy just made,
    /// which must register the helper again even though macOS reports it
    /// enabled: launchd may still run it from the old copy. Registering again
    /// never unregisters (#24); if it fails, the old registration stays.
    static func shouldReregister(requestedPath: String?, running: URL) -> Bool {
        guard let requestedPath else { return false }
        return requestedPath == running.resolvingSymlinksInPath().path
    }

    /// Reads and clears the request, so it is acted on at most once.
    static func takeReregisterRequest(running: URL = Bundle.main.bundleURL) -> Bool {
        let requested = UserDefaults.standard.string(forKey: reregisterKey)
        guard requested != nil else { return false }
        UserDefaults.standard.removeObject(forKey: reregisterKey)
        return shouldReregister(requestedPath: requested, running: running)
    }

    /// Whether the bundle carries the network filter (the firewall build).
    /// The monitor-only build doesn't.
    static func embedsSystemExtension(_ bundle: URL) -> Bool {
        let dir = bundle.appendingPathComponent("Contents/Library/SystemExtensions")
        guard let urls = try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) else { return false }
        return urls.contains { $0.pathExtension == "systemextension" }
    }

    /// Passed to the copy FreeSnitch reopens after clearing the flag on its
    /// own Applications copy (#375). If macOS still translocates that copy,
    /// the reopened app sees this and explains instead of reopening again, so
    /// the automatic reopen happens at most once per launch.
    static let reopenedAfterClearingArgument = "--freesnitch-reopened-after-clearing-quarantine"

    /// Whether to reopen the Applications copy after clearing its flag: only
    /// when the flag really went and this launch isn't already that reopen.
    static func shouldReopenAfterClearing(cleared: Bool, arguments: [String]) -> Bool {
        cleared && !arguments.contains(reopenedAfterClearingArgument)
    }

    /// The copy in Applications that macOS is running translocated, when
    /// there is one. Moving can't help that copy: it is already installed,
    /// and every "move" would only offer to open it again (#375).
    static func translocatedInstalledCopy(original: URL?) -> URL? {
        guard let original, isInApplications(original) else { return nil }
        return original
    }

    /// The /bin/sh arguments that wait for `pid` to exit and then open `app`,
    /// handing `arguments` to the new copy. The path and the arguments go in
    /// as positional values, never into the script text.
    static func relaunchScript(pid: Int32, app: URL, arguments: [String], open: String = "/usr/bin/open") -> [String] {
        let openApp = arguments.isEmpty ? "\"$open\" \"$app\"" : "\"$open\" \"$app\" --args \"$@\""
        return ["-c", "pid=\"$1\"; app=\"$2\"; open=\"$3\"; shift 3; while /bin/kill -0 \"$pid\" 2>/dev/null; do /bin/sleep 0.2; done; \(openApp)",
                "sh", String(pid), app.path, open] + arguments
    }

    /// Whether launch should ask the move question: only for a copy that came
    /// from a download, meaning a disk image (read-only), anything under
    /// ~/Downloads, or a copy still carrying the download flag (which macOS
    /// runs translocated). A build a contributor runs from Xcode or the build
    /// folder is none of these and only gets the banner with its Move button,
    /// so it isn't asked on every run (#400).
    static func cameFromDownload(_ url: URL, home: String = NSHomeDirectory()) -> Bool {
        let path = url.resolvingSymlinksInPath().path
        let downloads = (home as NSString).appendingPathComponent("Downloads") + "/"
        return isOnReadOnlyVolume(url)
            || path.hasPrefix(downloads)
            || hasQuarantine(url)
    }

    /// Where Homebrew keeps the casks it installed, on Apple silicon and Intel.
    static let homebrewCaskrooms = ["/opt/homebrew/Caskroom/freesnitch", "/usr/local/Caskroom/freesnitch"]

    /// Whether FreeSnitch was installed with `brew install --cask` (#407):
    /// Homebrew then owns the copy, and reinstalling goes through it. Only the
    /// two standard Homebrew prefixes are known; anything else gets the disk
    /// image advice, which also works.
    static func installedWithHomebrew(caskrooms: [String] = homebrewCaskrooms,
                                      exists: (String) -> Bool = { FileManager.default.fileExists(atPath: $0) }) -> Bool {
        caskrooms.contains(where: exists)
    }

    /// The command a Homebrew install reinstalls with (#407, #408).
    static let brewReinstallCommand = "brew reinstall --cask freesnitch"

    /// How to put a stuck installed copy back so macOS runs it from
    /// Applications again, for the way it was installed (#375, #407).
    /// The Homebrew advice is only given for a copy this user owns whose flag
    /// is already gone (homebrewRouteApplies). Whether a brew reinstall then
    /// gets it out of translocation is not checked on a real Mac.
    static func reinstallSteps(homebrew: Bool) -> String {
        homebrew
            ? String(localized: "Reinstall it with \(brewReinstallCommand) in Terminal.")
            : String(localized: "Move FreeSnitch from Applications to the Trash in Finder, then drag it in again from the disk image.")
    }

    /// Whether this Mac's copy came from Homebrew. Worked out once: the
    /// install doesn't change while the app runs. The demo shows the Homebrew
    /// wording with FREESNITCH_DEMO_HOMEBREW=1 so it can be reviewed.
    static let isHomebrewInstall: Bool = {
        let env = ProcessInfo.processInfo.environment
        if env["FREESNITCH_DEMO"] == "1" { return env["FREESNITCH_DEMO_HOMEBREW"] == "1" }
        return installedWithHomebrew()
    }()

    /// Whether the Homebrew advice can help (#380 review): only when this
    /// user could clear the flag, i.e. owns the copy. A copy whose flag stays
    /// belongs to another account, whose Homebrew this user can't run
    /// either, so it gets the Finder and disk image advice.
    /// `canRunBrew`: this user can write to FreeSnitch's Caskroom folder, so
    /// the brew command will work for them; a missing flag alone doesn't
    /// prove the copy is theirs.
    static func homebrewRouteApplies(homebrew: Bool, flagCleared: Bool, canRunBrew: Bool) -> Bool {
        homebrew && flagCleared && canRunBrew
    }

    /// Whether this user can write to an existing FreeSnitch Caskroom folder.
    static func canRunBrewReinstall(caskrooms: [String] = homebrewCaskrooms,
                                    writable: (String) -> Bool = { access($0, W_OK) == 0 }) -> Bool {
        caskrooms.contains(where: writable)
    }

    static func hasQuarantine(_ url: URL) -> Bool {
        getxattr(url.path, "com.apple.quarantine", nil, 0, 0, XATTR_NOFOLLOW) >= 0
    }

    /// The route for this Mac's stuck copy. The demo follows
    /// FREESNITCH_DEMO_HOMEBREW alone.
    @MainActor
    static var usesHomebrewRoute: Bool {
        if ProcessInfo.processInfo.environment["FREESNITCH_DEMO"] == "1" { return isHomebrewInstall }
        guard let installed = stuckInstalledCopy else { return false }
        return homebrewRouteApplies(homebrew: isHomebrewInstall, flagCleared: !hasQuarantine(installed),
                                    canRunBrew: canRunBrewReinstall())
    }

    @MainActor
    static var reinstallAdvice: String { reinstallSteps(homebrew: usesHomebrewRoute) }

    /// The stuck-copy title and button, matched to the advice (#408): a
    /// Homebrew install is fixed in Terminal, so its button copies the
    /// command; a disk image install is fixed in Finder.
    @MainActor
    static var stuckCopyTitle: String {
        usesHomebrewRoute ? String(localized: "Reinstall FreeSnitch with Homebrew") : String(localized: "Put FreeSnitch into Applications again")
    }
    @MainActor
    static var stuckCopyButton: String { usesHomebrewRoute ? String(localized: "Copy Command") : String(localized: "Show in Finder") }

    /// What the stuck-copy button does. The demo only shows the button.
    /// `confirm` says the command was copied when nothing else on screen
    /// would show it (the banner); the explanation closes instead.
    @MainActor
    static func stuckCopyAction(_ installed: URL, confirm: Bool = false) {
        guard ProcessInfo.processInfo.environment["FREESNITCH_DEMO"] != "1" else { return }
        if usesHomebrewRoute {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(brewReinstallCommand, forType: .string)
            if confirm {
                let alert = NSAlert()
                alert.messageText = String(localized: "Command copied")
                alert.informativeText = String(localized: "Paste it into Terminal and press Return, then open FreeSnitch again.")
                alert.addButton(withTitle: String(localized: "OK"))
                alert.runModal()
            }
        } else {
            NSWorkspace.shared.activateFileViewerSelecting([installed])
        }
    }

    /// After a successful move, only a downloaded original is moved to the
    /// Trash (Downloads clutter that would land here again). A disk image
    /// can't be changed, and a contributor's build output stays where it is.
    ///
    /// A copy in ~/Applications stays too: its helper may still be registered
    /// with macOS, and trashing it would leave that registration pointing at
    /// nothing.
    static func shouldTrashOriginal(_ original: URL, home: String = NSHomeDirectory()) -> Bool {
        !isOnReadOnlyVolume(original) && cameFromDownload(original, home: home)
            && !isInUserApplications(original, home: home)
    }

    /// Whether launch asks the move question for a copy that isn't installed:
    /// a download, or a firewall build someone put in ~/Applications (#412).
    /// A contributor's build folder only gets the banner (#400).
    static func asksAtLaunch(_ url: URL, home: String = NSHomeDirectory()) -> Bool {
        cameFromDownload(url, home: home) || isInUserApplications(url, home: home)
    }

    /// With a FreeSnitch already installed, "Open It" only makes sense for a
    /// downloaded copy of the same or an older build. An older install, or a
    /// build from a folder (a rebuilt build keeps its build number, so it can
    /// be newer code than the installed one), gets "replace it in Finder"
    /// instead of quietly opening the installed copy.
    ///
    /// `sourceFromDownload` also covers a copy in ~/Applications: that one is
    /// an installed release, not a contributor's newer build.
    ///
    /// The installed copy must also be the same build flavour. The firewall
    /// build and the monitor-only build share build numbers, so opening the
    /// other one would quietly swap firewall for monitor or back, and the
    /// network filter would never come (#417).
    static func offersOpenInstalled(isOlder: Bool, sourceFromDownload: Bool, sameFlavour: Bool = true) -> Bool {
        !isOlder && sourceFromDownload && sameFlavour
    }

    /// What the "already in Applications" question says when it doesn't offer
    /// Open It: which build is installed and how to replace it.
    static func replaceMessage(isOlder: Bool, sourceIsFirewall: Bool, installedIsFirewall: Bool) -> (title: String, text: String) {
        let howTo = String(localized: "Quit FreeSnitch, then drag this copy onto it in Finder and choose Replace.")
        guard sourceIsFirewall != installedIsFirewall else {
            return (isOlder ? String(localized: "An older FreeSnitch is already in Applications") : String(localized: "FreeSnitch is already in Applications"),
                    String(localized: "FreeSnitch won't replace it for you, because that copy may be running the network filter. \(howTo)"))
        }
        if sourceIsFirewall {
            return (String(localized: "Applications has the monitor-only FreeSnitch"),
                    String(localized: "The copy in Applications is the build without the network filter, so opening it would leave per-app filtering off. This copy is the firewall build. \(howTo)"))
        }
        return (String(localized: "Applications has the firewall build of FreeSnitch"),
                String(localized: "The copy in Applications is the build with the network filter. This copy is the monitor-only build, so replacing it turns per-app filtering off. To keep filtering, open FreeSnitch from Applications instead. To replace it anyway: \(howTo)"))
    }

    /// The disk image case: there is no original to tidy up there.
    static func isOnReadOnlyVolume(_ url: URL) -> Bool {
        (try? url.resourceValues(forKeys: [.volumeIsReadOnlyKey]).volumeIsReadOnly) == true
    }
}

// MARK: - The prompt

@MainActor
extension InstallLocation {
    private static var isDemo: Bool { ProcessInfo.processInfo.environment["FREESNITCH_DEMO"] == "1" }

    /// Asks once at launch. Returns true when FreeSnitch is about to quit and
    /// reopen from Applications, so the caller must start nothing else.
    @discardableResult
    static func offerMoveAtLaunch() -> Bool {
        // The demo never moves anything; FREESNITCH_DEMO_WINDOW=move or
        // =stuck only shows the question so it can be reviewed.
        if isDemo {
            switch ProcessInfo.processInfo.environment["FREESNITCH_DEMO_WINDOW"] {
            case "move":
                NSApp.activate(ignoringOtherApps: true)
                _ = moveAlert().runModal()
            case "stuck":
                // The Homebrew advice only goes with a cleared flag, as for real.
                explainStuckInstalledCopy(URL(fileURLWithPath: "/Applications/FreeSnitch.app"), flagCleared: isHomebrewInstall)
            default: break
            }
            return false
        }
        // A move cut off mid-copy (crash, force quit) leaves its hidden
        // staging folder behind; tidy those up whichever copy this is (#413).
        for folder in ["/Applications", (NSHomeDirectory() as NSString).appendingPathComponent("Applications")] {
            removeLeftoverStaging(in: URL(fileURLWithPath: folder, isDirectory: true))
        }
        guard !HelperClient.isInApplicationsFolder else { return false }
        // Already in Applications but quarantined and put there without
        // Finder, so macOS runs it translocated. Moving can't help; clearing
        // the flag on that copy and reopening it does, once. A bundle this
        // user can't change (installed by another account or with sudo), or
        // one macOS translocates even without the flag, would otherwise
        // reopen and land here again, forever.
        if let installed = stuckInstalledCopy {
            let cleared = clearQuarantine(at: installed)
            if shouldReopenAfterClearing(cleared: cleared, arguments: CommandLine.arguments) {
                relaunch(at: installed, arguments: [reopenedAfterClearingArgument])
                return true
            }
            explainStuckInstalledCopy(installed, flagCleared: cleared)
            return false
        }
        // Translocated means it still carries the download flag.
        let running = Bundle.main.bundleURL
        guard translocatedOriginal(of: running) != nil || asksAtLaunch(running) else { return false }
        NSApp.activate(ignoringOtherApps: true)
        guard moveAlert().runModal() == .alertFirstButtonReturn else { return false }
        return moveToApplications()
    }

    /// The installed copy macOS keeps running from a temporary location,
    /// worked out once: the running bundle doesn't change.
    /// The demo never touches the real bundle; FREESNITCH_DEMO_STUCK=1 makes
    /// it act as such a copy so the banner can be reviewed.
    static let stuckInstalledCopy: URL? = isDemo
        ? (ProcessInfo.processInfo.environment["FREESNITCH_DEMO_STUCK"] == "1" ? URL(fileURLWithPath: "/Applications/FreeSnitch.app") : nil)
        : translocatedInstalledCopy(original: translocatedOriginal(of: Bundle.main.bundleURL))

    /// What the helper repair says when FreeSnitch isn't running from
    /// Applications. A stuck installed copy needs a reinstall, not a move.
    static var wrongLocationRepairAdvice: String {
        stuckInstalledCopy == nil
            ? String(localized: "Move FreeSnitch to /Applications before registering the helper.")
            : String(localized: "macOS runs FreeSnitch from a temporary copy. \(reinstallAdvice) Then register the helper.")
    }

    /// Says what the user has to do (in Finder, or in Terminal for a
    /// Homebrew install), since FreeSnitch can't.
    static func explainStuckInstalledCopy(_ installed: URL, flagCleared: Bool) {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = usesHomebrewRoute ? stuckCopyTitle : String(localized: "macOS is running FreeSnitch from a temporary copy")
        let why = flagCleared
            ? String(localized: "macOS still runs the copy in Applications from a temporary location")
            : String(localized: "The copy in Applications still carries the download flag and FreeSnitch isn't allowed to clear it")
        alert.informativeText = String(localized: "\(why), so FreeSnitch can't install its helper. \(reinstallAdvice)")
        alert.addButton(withTitle: stuckCopyButton)
        alert.addButton(withTitle: String(localized: "Not Now"))
        if alert.runModal() == .alertFirstButtonReturn {
            stuckCopyAction(installed)
        }
    }

    private static func moveAlert() -> NSAlert {
        let alert = NSAlert()
        // From ~/Applications it copies and leaves the original, whose helper
        // may still be registered, so it says copy and doesn't suggest
        // deleting that copy.
        let fromHome = isInUserApplications(runningOriginal)
        if fromHome {
            alert.messageText = String(localized: "Copy FreeSnitch to the main Applications folder?")
            alert.informativeText = String(localized: "\(userApplicationsReason) FreeSnitch can copy itself there and reopen.")
        } else {
            alert.messageText = String(localized: "Move FreeSnitch to Applications?")
            alert.informativeText = String(localized: "macOS only lets FreeSnitch install its helper and network filter when it runs from the Applications folder. FreeSnitch can move itself there and reopen.")
        }
        alert.addButton(withTitle: fromHome ? String(localized: "Copy to Applications") : String(localized: "Move to Applications"))
        alert.addButton(withTitle: String(localized: "Not Now"))
        return alert
    }

    /// Does the move, or says what's in the way. Also the banner's button.
    @discardableResult
    static func moveToApplications() -> Bool {
        // The demo's banner only shows the button; it never moves anything.
        guard !isDemo else { return false }
        // Opening the installed copy would only run this same copy again.
        // Defensive: launch and the banner already route a stuck copy to the
        // explanation, so nothing should reach this today. It only explains;
        // the one automatic clear-and-reopen belongs to launch.
        if let installed = stuckInstalledCopy {
            let flagGone = !hasQuarantine(installed)
            explainStuckInstalledCopy(installed, flagCleared: flagGone)
            return false
        }
        let running = Bundle.main.bundleURL
        // Where the user actually put it, not the translocated mirror.
        let original = translocatedOriginal(of: running) ?? running
        let applications = URL(fileURLWithPath: "/Applications", isDirectory: true)
        let userApplications = URL(fileURLWithPath: (NSHomeDirectory() as NSString).appendingPathComponent("Applications"), isDirectory: true)
        // A copy in ~/Applications counts as installed too when the shared
        // rule says so, so the move never adds a second one. For the firewall
        // build it doesn't, and the move goes to /Applications (#412).
        let userPlan = plan(source: running, applications: userApplications)
        let chosen: Plan
        if case .existing(let userCopy, _) = userPlan, userCopyCountsAsInstalled(source: running, userCopy: userCopy) {
            chosen = userPlan
        } else {
            chosen = plan(source: running, applications: applications)
        }
        switch chosen {
        case .existing(let installed, let isOlder):
            let alert = NSAlert()
            let sourceIsFirewall = embedsSystemExtension(running)
            let installedIsFirewall = embedsSystemExtension(installed)
            if !offersOpenInstalled(isOlder: isOlder, sourceFromDownload: asksAtLaunch(original),
                                    sameFlavour: sourceIsFirewall == installedIsFirewall) {
                let message = replaceMessage(isOlder: isOlder, sourceIsFirewall: sourceIsFirewall, installedIsFirewall: installedIsFirewall)
                alert.messageText = message.title
                alert.informativeText = message.text
                alert.addButton(withTitle: String(localized: "Show in Finder"))
                alert.addButton(withTitle: String(localized: "Cancel"))
                if alert.runModal() == .alertFirstButtonReturn {
                    NSWorkspace.shared.activateFileViewerSelecting([original, installed])
                }
                return false
            }
            alert.messageText = String(localized: "FreeSnitch is already in Applications")
            alert.informativeText = String(localized: "Open that copy instead of this one.")
            alert.addButton(withTitle: String(localized: "Open It"))
            alert.addButton(withTitle: String(localized: "Cancel"))
            guard alert.runModal() == .alertFirstButtonReturn else { return false }
            relaunch(at: installed)
            return true
        case .copy(let destination):
            switch copyBundle(from: running, to: destination) {
            case .failure(.failed(let reason)):
                let alert = NSAlert()
                alert.alertStyle = .warning
                alert.messageText = String(localized: "FreeSnitch couldn't move itself")
                alert.informativeText = String(localized: "\(reason) Drag FreeSnitch into Applications in Finder, then open it from there.")
                alert.addButton(withTitle: String(localized: "Show in Finder"))
                alert.addButton(withTitle: String(localized: "Cancel"))
                if alert.runModal() == .alertFirstButtonReturn {
                    NSWorkspace.shared.activateFileViewerSelecting([original])
                }
                return false
            case .success:
                // The home-folder copy stays, and its helper registration may
                // still point into it. The new copy registers the helper again
                // once at launch, so launchd runs it from /Applications (#418).
                if isInUserApplications(original) {
                    UserDefaults.standard.set(destination.resolvingSymlinksInPath().path, forKey: reregisterKey)
                    UserDefaults.standard.synchronize()
                }
                if shouldTrashOriginal(original) {
                    // Synchronous: the process quits right after this.
                    try? FileManager.default.trashItem(at: original, resultingItemURL: nil)
                }
                relaunch(at: destination)
                return true
            }
        }
    }

    /// Opens `app` once this process has exited, so two copies never run at
    /// once, then quits. The path goes in as an argument, never into the
    /// script text.
    private static func relaunch(at app: URL, arguments: [String] = []) {
        let waiter = Process()
        waiter.executableURL = URL(fileURLWithPath: "/bin/sh")
        waiter.arguments = relaunchScript(pid: ProcessInfo.processInfo.processIdentifier, app: app, arguments: arguments)
        try? waiter.run()
        NSApp.terminate(nil)
    }
}
