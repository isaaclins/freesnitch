import Foundation

/// What the rule sheet writes over a rule it edits (#433).
///
/// The sheet shows the fields a user picks when making a rule. Saving an edit
/// writes those and leaves everything else as it was: the id (so the helper
/// stores it in place of the old one), priority, group, hit count, dates, and
/// whether it is temporary and when it ends.
public struct RuleEdit: Equatable, Sendable {
    /// The process the rule names. `.unchanged` keeps the rule's own path and
    /// name: an alert rule names the executable rather than the bundle, and an
    /// app that was moved or deleted can't be loaded again to rebuild them.
    public enum Process: Equatable, Sendable {
        case unchanged
        case app(path: String, name: String)
        case anyApp
    }

    public var process: Process
    public var bundleId: String?
    public var remoteHost: String?
    public var remoteIP: String?
    public var remotePort: Int?
    public var direction: RuleDirection
    public var action: RuleAction
    public var scope: RuleScope
    public var profile: String
    public var notes: String?
    public var enabled: Bool

    public init(process: Process, bundleId: String?, remoteHost: String?, remoteIP: String?,
                remotePort: Int?, direction: RuleDirection, action: RuleAction, scope: RuleScope,
                profile: String, notes: String?, enabled: Bool) {
        self.process = process
        self.bundleId = bundleId
        self.remoteHost = remoteHost
        self.remoteIP = remoteIP
        self.remotePort = remotePort
        self.direction = direction
        self.action = action
        self.scope = scope
        self.profile = profile
        self.notes = notes
        self.enabled = enabled
    }

    /// The rule as the sheet leaves it, when it opened on that same rule.
    public func applied(to original: Rule) -> Rule {
        applied(to: original, openedWith: original)
    }

    /// Writes only what the user changed in the sheet, compared with the
    /// rule it opened with, over the rule as it is now. Something changed
    /// elsewhere while the sheet was open (a toggle or profile move from the
    /// CLI, a learned signing team) stays, unless the user changed that same
    /// field in the sheet.
    public func applied(to current: Rule, openedWith snapshot: Rule) -> Rule {
        var rule = current
        switch process {
        case .unchanged: break
        case .app(let path, let name):
            rule.processPath = path
            rule.processName = name
        case .anyApp:
            // Only a removal: a rule that opened without an app keeps a path
            // set elsewhere meanwhile.
            if Self.present(snapshot.processPath) || Self.present(snapshot.processName) {
                rule.processPath = nil
                rule.processName = nil
            }
        }
        if Self.text(bundleId) != Self.text(snapshot.processBundleId) {
            rule.processBundleId = bundleId
            // The signing team belongs to the bundle id the rule was made
            // for. A new bundle id has to learn its own team, never inherit
            // the old one.
            if Self.text(rule.processBundleId) != Self.text(current.processBundleId) { rule.processTeamId = nil }
        }
        if Self.text(remoteHost) != Self.text(snapshot.remoteHost) { rule.remoteHost = remoteHost }
        if Self.text(remoteIP) != Self.text(snapshot.remoteIP) { rule.remoteIP = remoteIP }
        // The sheet shows port 0 as 0 (#218), so only a different port, or
        // clearing it, counts as a change.
        if remotePort != snapshot.remotePort { rule.remotePort = remotePort }
        if direction != snapshot.direction { rule.direction = direction }
        if action != snapshot.action { rule.action = action }
        if scope != snapshot.scope { rule.scope = scope }
        if profile != snapshot.profile { rule.profile = profile }
        if Self.text(notes) != Self.text(snapshot.notes) { rule.notes = notes }
        if enabled != snapshot.enabled { rule.enabled = enabled }
        return rule
    }

    private static func present(_ value: String?) -> Bool { !(value ?? "").isEmpty }
    private static func text(_ value: String?) -> String? {
        let trimmed = (value ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
