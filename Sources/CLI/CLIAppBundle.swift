import Foundation

enum CLIAppBundle {
    static var appURL: URL? {
        AppBundleIdentity.containingAppURL
    }

    /// The build identity currently installed on disk, read at call time. This
    /// is what a helper is expected to be running, and it is what an in-place
    /// update changes.
    /// A bare CLI outside an app falls back to its marketing version only, so
    /// it cannot make a false stale-helper claim.
    static var expectedBuildIdentity: String {
        AppBundleIdentity.installed ?? AppConstants.version
    }

    static var hasEmbeddedNetworkExtension: Bool {
        guard let appURL else { return false }
        let directory = appURL
            .appendingPathComponent("Contents/Library/SystemExtensions", isDirectory: true)
        return (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil))?
            .contains { $0.pathExtension == "systemextension" } ?? false
    }
}
