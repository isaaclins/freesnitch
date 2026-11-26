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

    /// Whether this app bundle embeds the network extension. Only a missing
    /// `Contents/Library/SystemExtensions` folder (or one without a
    /// `.systemextension` inside) counts as a monitor-only build. A folder that
    /// exists but cannot be listed is reported as unreadable, with the error,
    /// so doctor never calls a firewall build monitor-only by mistake (#256).
    static var embeddedNetworkExtension: EmbeddedExtensionPresence {
        guard let appURL else { return .absent }
        return EmbeddedExtensionPresence.inspect(
            appURL.appendingPathComponent("Contents/Library/SystemExtensions", isDirectory: true))
    }
}

enum EmbeddedExtensionPresence: Equatable {
    case present
    case absent
    case unreadable(String)

    static func inspect(_ directory: URL, fileManager: FileManager = .default) -> EmbeddedExtensionPresence {
        do {
            let entries = try fileManager.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            return entries.contains { $0.pathExtension == "systemextension" } ? .present : .absent
        } catch {
            if isMissing(error) { return .absent }
            return .unreadable("\(directory.path) could not be read: \(describe(error))")
        }
    }

    private static func isMissing(_ error: Error) -> Bool {
        let ns = error as NSError
        if ns.domain == NSCocoaErrorDomain,
           ns.code == NSFileReadNoSuchFileError || ns.code == NSFileNoSuchFileError {
            return true
        }
        if ns.domain == NSPOSIXErrorDomain, ns.code == Int(ENOENT) {
            return true
        }
        if let underlying = ns.userInfo[NSUnderlyingErrorKey] as? NSError,
           underlying.domain == NSPOSIXErrorDomain,
           underlying.code == Int(ENOENT) {
            return true
        }
        return false
    }

    private static func describe(_ error: Error) -> String {
        let ns = error as NSError
        if let underlying = ns.userInfo[NSUnderlyingErrorKey] as? NSError, underlying.domain == NSPOSIXErrorDomain,
           let code = POSIXErrorCode(rawValue: Int32(underlying.code)) {
            return "\(String(cString: strerror(code.rawValue))) (\(ns.domain) \(ns.code), POSIX \(underlying.code))"
        }
        return "\(ns.localizedDescription) (\(ns.domain) \(ns.code))"
    }
}
