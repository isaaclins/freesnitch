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

    /// Forces the running identity to be resolved now, at process start, rather
    /// than on whichever later call happens to ask first. Call this before any
    /// work that could outlive an update.
    @discardableResult
    public static func captureRunningIdentity() -> String? { running }

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
