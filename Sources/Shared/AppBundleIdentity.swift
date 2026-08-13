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
    /// executable, for example "0.2.0 (15)".
    public static var current: String? {
        guard let appURL = containingAppURL else { return nil }
        return identity(from: appURL)
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
