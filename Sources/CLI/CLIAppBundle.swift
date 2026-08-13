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

    static var hasEmbeddedNetworkExtension: Bool {
        guard let appURL else { return false }
        let directory = appURL
            .appendingPathComponent("Contents/Library/SystemExtensions", isDirectory: true)
        return (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil))?
            .contains { $0.pathExtension == "systemextension" } ?? false
    }
}
