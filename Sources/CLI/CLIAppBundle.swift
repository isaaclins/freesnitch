import Foundation

enum CLIAppBundle {
    static var appURL: URL? {
        let executable = URL(fileURLWithPath: CommandLine.arguments.first ?? "")
            .standardizedFileURL
        var current = executable
        while current.path != "/" {
            if current.pathExtension == "app" { return current }
            current.deleteLastPathComponent()
        }
        if Bundle.main.bundleURL.pathExtension == "app" { return Bundle.main.bundleURL }
        return nil
    }

    /// The build identity of the app bundle this CLI was shipped inside.
    ///
    /// The CLI is a bare tool with no Info.plist of its own, so it cannot read
    /// its own build number. Reading the containing app's Info.plist is also
    /// the more meaningful question: the CLI wants to know whether the helper
    /// came from this app, not from this executable.
    static var expectedBuildIdentity: String {
        guard let appURL,
              let info = NSDictionary(contentsOf: appURL.appendingPathComponent("Contents/Info.plist")),
              let short = info["CFBundleShortVersionString"] as? String else {
            return AppConstants.buildIdentity
        }
        guard let build = info["CFBundleVersion"] as? String else { return short }
        return "\(short) (\(build))"
    }

    static var hasEmbeddedNetworkExtension: Bool {
        guard let appURL else { return false }
        let directory = appURL
            .appendingPathComponent("Contents/Library/SystemExtensions", isDirectory: true)
        return (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil))?
            .contains { $0.pathExtension == "systemextension" } ?? false
    }
}
