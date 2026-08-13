import Foundation

enum CLIAppBundle {
    static var appURL: URL? {
        AppBundleIdentity.containingAppURL
    }

    /// The build identity of the app bundle this CLI was shipped inside.
    /// A bare CLI outside an app falls back to its marketing version only, so
    /// it cannot make a false stale-helper claim.
    static var expectedBuildIdentity: String {
        AppBundleIdentity.current ?? AppConstants.version
    }

    static var hasEmbeddedNetworkExtension: Bool {
        guard let appURL else { return false }
        let directory = appURL
            .appendingPathComponent("Contents/Library/SystemExtensions", isDirectory: true)
        return (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil))?
            .contains { $0.pathExtension == "systemextension" } ?? false
    }
}
