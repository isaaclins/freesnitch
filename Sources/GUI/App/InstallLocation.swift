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
            return .failure(.failed("\(destination.path) already exists."))
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
                return .failure(.failed("The download flag could not be removed from the copy."))
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

    /// The same rule as HelperClient.isInApplicationsFolder, for any path.
    static func isInApplications(_ url: URL, home: String = NSHomeDirectory()) -> Bool {
        let path = url.resolvingSymlinksInPath().path
        let userApps = (home as NSString).appendingPathComponent("Applications") + "/"
        return path.hasPrefix("/Applications/") || path.hasPrefix(userApps)
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
            || getxattr(url.path, "com.apple.quarantine", nil, 0, 0, XATTR_NOFOLLOW) >= 0
    }

    /// After a successful move, only a downloaded original is moved to the
    /// Trash (Downloads clutter that would land here again). A disk image
    /// can't be changed, and a contributor's build output stays where it is.
    static func shouldTrashOriginal(_ original: URL, home: String = NSHomeDirectory()) -> Bool {
        !isOnReadOnlyVolume(original) && cameFromDownload(original, home: home)
    }

    /// With a FreeSnitch already installed, "Open It" only makes sense for a
    /// downloaded copy of the same or an older build. An older install, or a
    /// build from a folder (a rebuilt build keeps its build number, so it can
    /// be newer code than the installed one), gets "replace it in Finder"
    /// instead of quietly opening the installed copy.
    static func offersOpenInstalled(isOlder: Bool, sourceFromDownload: Bool) -> Bool {
        !isOlder && sourceFromDownload
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
        // The demo never moves anything; FREESNITCH_DEMO_WINDOW=move only
        // shows the question so it can be reviewed.
        if isDemo {
            guard ProcessInfo.processInfo.environment["FREESNITCH_DEMO_WINDOW"] == "move" else { return false }
            NSApp.activate(ignoringOtherApps: true)
            _ = moveAlert().runModal()
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
        // the flag on that copy and reopening it does.
        // Only when the flag really went: a bundle this user can't change
        // (installed by another account or with sudo) would otherwise reopen
        // translocated and land here again, forever.
        if let original = translocatedOriginal(of: Bundle.main.bundleURL), isInApplications(original) {
            if clearQuarantine(at: original) {
                relaunch(at: original)
                return true
            }
            // Moving would only offer to open this same copy again.
            NSApp.activate(ignoringOtherApps: true)
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "macOS is running FreeSnitch from a temporary copy"
            alert.informativeText = "The copy in Applications still carries the download flag and FreeSnitch isn't allowed to clear it, so macOS won't let it install its helper. Move FreeSnitch from Applications to the Trash in Finder, then drag it in again from the disk image."
            alert.addButton(withTitle: "Show in Finder")
            alert.addButton(withTitle: "Not Now")
            if alert.runModal() == .alertFirstButtonReturn {
                NSWorkspace.shared.activateFileViewerSelecting([original])
            }
            return false
        }
        // Translocated means it still carries the download flag.
        let running = Bundle.main.bundleURL
        guard translocatedOriginal(of: running) != nil || cameFromDownload(running) else { return false }
        NSApp.activate(ignoringOtherApps: true)
        guard moveAlert().runModal() == .alertFirstButtonReturn else { return false }
        return moveToApplications()
    }

    private static func moveAlert() -> NSAlert {
        let alert = NSAlert()
        alert.messageText = "Move FreeSnitch to Applications?"
        alert.informativeText = "macOS only lets FreeSnitch install its helper and network filter when it runs from the Applications folder. FreeSnitch can move itself there and reopen."
        alert.addButton(withTitle: "Move to Applications")
        alert.addButton(withTitle: "Not Now")
        return alert
    }

    /// Does the move, or says what's in the way. Also the banner's button.
    @discardableResult
    static func moveToApplications() -> Bool {
        // The demo's banner only shows the button; it never moves anything.
        guard !isDemo else { return false }
        let running = Bundle.main.bundleURL
        // Where the user actually put it, not the translocated mirror.
        let original = translocatedOriginal(of: running) ?? running
        let applications = URL(fileURLWithPath: "/Applications", isDirectory: true)
        let userApplications = URL(fileURLWithPath: (NSHomeDirectory() as NSString).appendingPathComponent("Applications"), isDirectory: true)
        // A copy in ~/Applications counts as installed too, so the move never
        // adds a second one.
        let userPlan = plan(source: running, applications: userApplications)
        let chosen: Plan
        if case .existing = userPlan { chosen = userPlan } else { chosen = plan(source: running, applications: applications) }
        switch chosen {
        case .existing(let installed, let isOlder):
            let alert = NSAlert()
            if !offersOpenInstalled(isOlder: isOlder, sourceFromDownload: cameFromDownload(original)) {
                alert.messageText = isOlder ? "An older FreeSnitch is already in Applications" : "FreeSnitch is already in Applications"
                alert.informativeText = "FreeSnitch won't replace it for you, because that copy may be running the network filter. Quit FreeSnitch, then drag this copy onto it in Finder and choose Replace."
                alert.addButton(withTitle: "Show in Finder")
                alert.addButton(withTitle: "Cancel")
                if alert.runModal() == .alertFirstButtonReturn {
                    NSWorkspace.shared.activateFileViewerSelecting([original, installed])
                }
                return false
            }
            alert.messageText = "FreeSnitch is already in Applications"
            alert.informativeText = "Open that copy instead of this one."
            alert.addButton(withTitle: "Open It")
            alert.addButton(withTitle: "Cancel")
            guard alert.runModal() == .alertFirstButtonReturn else { return false }
            relaunch(at: installed)
            return true
        case .copy(let destination):
            switch copyBundle(from: running, to: destination) {
            case .failure(.failed(let reason)):
                let alert = NSAlert()
                alert.alertStyle = .warning
                alert.messageText = "FreeSnitch couldn't move itself"
                alert.informativeText = "\(reason) Drag FreeSnitch into Applications in Finder, then open it from there."
                alert.addButton(withTitle: "Show in Finder")
                alert.addButton(withTitle: "Cancel")
                if alert.runModal() == .alertFirstButtonReturn {
                    NSWorkspace.shared.activateFileViewerSelecting([original])
                }
                return false
            case .success:
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
    private static func relaunch(at app: URL) {
        let waiter = Process()
        waiter.executableURL = URL(fileURLWithPath: "/bin/sh")
        waiter.arguments = ["-c", "while /bin/kill -0 \"$1\" 2>/dev/null; do /bin/sleep 0.2; done; /usr/bin/open \"$2\"",
                            "sh", String(ProcessInfo.processInfo.processIdentifier), app.path]
        try? waiter.run()
        NSApp.terminate(nil)
    }
}
