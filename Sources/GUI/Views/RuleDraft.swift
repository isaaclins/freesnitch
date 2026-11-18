import Foundation

/// What the Add Rule sheet starts from when a rule is made from something the
/// app has already seen, such as a destination in Insights (#446). The person
/// still sees every field and picks Allow or Deny before anything is added.
///
/// Foundation only, so the harness can check it without the window.
struct RuleDraft: Equatable {
    /// The file the sheet should load as the rule's app: the outermost app
    /// bundle the process ran from, or the executable itself when it is not
    /// inside one. Nil when nothing on disk names the app.
    var appFilePath: String?
    /// Only filled when there is no app path to go on. A rule that names both
    /// an app folder and a bundle id would stop matching the app's helpers,
    /// which carry their own bundle ids.
    var processBundleID: String
    /// The recorded bundle id, for when the app at `appFilePath` is gone from
    /// disk and the sheet can't load it.
    var fallbackBundleID: String?
    var remoteHost: String
    var remoteIP: String
    var scope: RuleScope

    /// A name when one is known, the address only when it is not, the same
    /// way Insights' own suggestions are scoped (D7).
    init(processPath: String?, processBundleId: String?, domain: String?, remoteIP: String?) {
        let path = processPath.flatMap { Self.trimmed($0) }
        appFilePath = path.map(Self.appFilePath(forExecutable:))
        let bundleID = processBundleId.flatMap { Self.trimmed($0) }
        processBundleID = path == nil ? (bundleID ?? "") : ""
        fallbackBundleID = path == nil ? nil : bundleID
        if let domain = domain.flatMap({ Self.trimmed($0) }) {
            remoteHost = domain
            self.remoteIP = ""
            scope = .domain
        } else {
            remoteHost = ""
            self.remoteIP = remoteIP.flatMap { Self.trimmed($0) } ?? ""
            scope = self.remoteIP.isEmpty ? .process : .ip
        }
    }

    /// Choosing an app on the Rules page makes a rule for its bundle folder,
    /// which also covers the helpers inside it, where browsers and Electron
    /// apps do their networking. A rule started from a recorded process does
    /// the same, so both ways of making a rule for an app make the same rule.
    static func appFilePath(forExecutable path: String) -> String {
        let components = (path as NSString).pathComponents
        guard let index = components.firstIndex(where: { $0.lowercased().hasSuffix(".app") && $0 != ".app" }) else {
            return path
        }
        return NSString.path(withComponents: Array(components[...index]))
    }

    private static func trimmed(_ value: String) -> String? {
        let value = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : value
    }
}
