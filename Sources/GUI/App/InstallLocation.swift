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
        let staging = destination.deletingLastPathComponent()
            .appendingPathComponent(".\(bundleName).partial-\(UUID().uuidString)", isDirectory: true)
        do {
            try fm.copyItem(at: source, to: staging)
            clearQuarantine(at: staging)
            try fm.moveItem(at: staging, to: destination)
            return .success(())
        } catch {
            try? fm.removeItem(at: staging)
            return .failure(.failed(error.localizedDescription))
        }
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
        guard !HelperClient.isInApplicationsFolder else { return false }
        // Already in Applications but quarantined and put there without
        // Finder, so macOS runs it translocated. Moving can't help; clearing
        // the flag on that copy and reopening it does.
        // Only when the flag really went: a bundle this user can't change
        // (installed by another account or with sudo) would otherwise reopen
        // translocated and land here again, forever. Then the prompt below
        // explains instead.
        if let original = translocatedOriginal(of: Bundle.main.bundleURL), isInApplications(original),
           clearQuarantine(at: original) {
            relaunch(at: original)
            return true
        }
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
            if isOlder {
                alert.messageText = "An older FreeSnitch is already in Applications"
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
                // A copy left in Downloads (or wherever it was) is clutter, and
                // opening it later lands here again. A disk image can't be
                // changed and is left.
                if !isOnReadOnlyVolume(original) {
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
