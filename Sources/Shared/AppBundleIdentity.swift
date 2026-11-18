import Darwin
import Foundation

/// Resolves the identity of the app that contains the running executable.
///
/// Helpers and command-line tools are Mach-O executables rather than bundles,
/// so Bundle.main describes the executable itself instead of the app that
/// shipped it. The executable path supplied by the system is the reliable
/// starting point, including when launchd supplies a relative argv[0].
public enum AppBundleIdentity {
    /// The containing app for the current executable, if one can be found.
    public static var containingAppURL: URL? {
        guard let executableURL = currentExecutableURL else { return nil }
        return containingAppURL(for: executableURL)
    }

    /// The marketing version and build of the app containing the current
    /// executable, for example "0.2.0 (15)", as it is on disk right now.
    public static var current: String? {
        guard let appURL = containingAppURL else { return nil }
        return identity(from: appURL)
    }

    /// The identity of the bundle on disk, read at call time. After an in-place
    /// update this is the new build, whatever the running processes are.
    public static var installed: String? { current }

    /// The identity of the bundle as it was when this process started running.
    ///
    /// This is the only value that describes the code actually executing. The
    /// on-disk Info.plist is replaced under a running daemon by an in-place
    /// update, so reading it at call time makes a stale process claim the new
    /// build's version, which is exactly the incident behind #36. Resolved once
    /// and then frozen for the lifetime of the process.
    public static let running: String? = current

    /// The containing app as it was when this process started. A helper keeps
    /// running from the copy that registered it, so this is the copy whose
    /// code is executing, wherever the user opened FreeSnitch from (#418).
    public static let runningAppPath: String? = containingAppURL?.path

    /// The helper's app copy when it is known to differ from `thisAppPath`,
    /// otherwise nil. Both paths are compared with symlinks resolved, so the
    /// same copy reached through a link is not a different copy. An unknown
    /// path proves nothing, like `isStale`.
    public static func otherCopy(helperAppPath: String?, thisAppPath: String?) -> String? {
        guard let helperAppPath, !helperAppPath.isEmpty,
              let thisAppPath, !thisAppPath.isEmpty else { return nil }
        let canonical: (String) -> String = {
            URL(fileURLWithPath: $0).resolvingSymlinksInPath().standardizedFileURL.path
        }
        return canonical(helperAppPath) == canonical(thisAppPath) ? nil : helperAppPath
    }

    /// Forces the running identity to be resolved now, at process start, rather
    /// than on whichever later call happens to ask first. Call this before any
    /// work that could outlive an update.
    @discardableResult
    public static func captureRunningIdentity() -> String? {
        _ = runningAppPath
        return running
    }

    /// A running process is stale only when both identities are known and they
    /// differ. An unknown value proves nothing, and a firewall that cries wolf
    /// gets ignored.
    public static func isStale(running: String?, installed: String?) -> Bool {
        guard let running, let installed else { return false }
        return running != installed
    }

    /// The running and installed identities of the current process, kept apart
    /// so no surface can collapse them into one misleading string.
    public struct Report: Equatable, Sendable {
        public let running: String?
        public let installed: String?

        public init(running: String?, installed: String?) {
            self.running = running
            self.installed = installed
        }

        public var isStale: Bool { AppBundleIdentity.isStale(running: running, installed: installed) }
    }

    public static func report() -> Report {
        Report(running: running, installed: installed)
    }

    /// Finds the canonical `.app` ancestor of an executable path.
    public static func containingAppURL(for executableURL: URL) -> URL? {
        var current = executableURL
            .resolvingSymlinksInPath()
            .standardizedFileURL

        while true {
            if current.pathExtension.caseInsensitiveCompare("app") == .orderedSame {
                return current
            }

            let parent = current.deletingLastPathComponent()
            if parent == current { return nil }
            current = parent
        }
    }

    /// The Info.plist of the app bundle at `appPath`.
    ///
    /// A Mac app keeps it in `Contents/Info.plist`. An iPhone or iPad app
    /// running on an Apple silicon Mac sits inside a wrapper
    /// (`X.app/Wrapper/X.app/X`) and keeps a shallow iOS bundle, with its
    /// Info.plist at the bundle root and no `Contents` folder. A bundle with a
    /// `Contents` folder is always read as a Mac bundle.
    public static func infoPlistPath(forAppPath appPath: String) -> String {
        let app = appPath as NSString
        var isDirectory: ObjCBool = false
        let contents = app.appendingPathComponent("Contents")
        if !FileManager.default.fileExists(atPath: contents, isDirectory: &isDirectory) || !isDirectory.boolValue {
            let shallow = app.appendingPathComponent("Info.plist")
            if FileManager.default.fileExists(atPath: shallow) { return shallow }
        }
        return app.appendingPathComponent("Contents/Info.plist")
    }

    /// Reads an app's `Contents/Info.plist` directly and returns its build
    /// identity. An app without a build number is represented by its marketing
    /// version rather than by an invented build number.
    public static func identity(from appURL: URL) -> String? {
        let infoURL = appURL.appendingPathComponent("Contents/Info.plist")
        guard let data = try? Data(contentsOf: infoURL),
              let info = try? PropertyListSerialization.propertyList(
                  from: data,
                  options: [],
                  format: nil
              ) as? [String: Any],
              let version = info["CFBundleShortVersionString"] as? String else {
            return nil
        }

        guard let build = info["CFBundleVersion"] as? String, !build.isEmpty else {
            return version
        }
        return "\(version) (\(build))"
    }

    private static var currentExecutableURL: URL? {
        var size: UInt32 = 0
        _ = _NSGetExecutablePath(nil, &size)
        guard size > 0 else { return nil }

        var buffer = [Int8](repeating: 0, count: Int(size))
        guard _NSGetExecutablePath(&buffer, &size) == 0 else { return nil }
        return String(cString: buffer).isEmpty
            ? nil
            : URL(fileURLWithPath: String(cString: buffer))
    }
}

/// What FreeSnitch says when its helper runs from another app copy (#418).
/// One text for the app's banner and for `freesnitch doctor`.
public enum HelperOtherCopyMessage {
    public static func detail(other: String, this: String) -> String {
        "macOS is running FreeSnitch's helper from \(other), not from this copy at \(this), so updates to this copy don't reach the helper. \(keep(other: other))"
    }

    /// What to do about a helper older than the installed build. When it
    /// runs from another copy, a kickstart only restarts that same old copy,
    /// so the advice is to keep that copy instead (#421).
    public static func staleHelperAction(other: String?, kickstartCommand: String) -> String {
        guard let other else {
            return "The helper is still registered. Do not unregister it; run: \(kickstartCommand)"
        }
        return "The helper runs from \(other), so restarting it would only start that same older copy again. Do not unregister it. \(keep(other: other))"
    }

    public static func keep(other: String) -> String {
        "Keep \(other) where it is until you have restarted your Mac and this message is gone. Deleting it before that leaves FreeSnitch without its helper, which runs the traffic monitor and the firewall rules."
    }
}
