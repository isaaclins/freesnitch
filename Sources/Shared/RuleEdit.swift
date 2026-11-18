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

    public func applied(to original: Rule) -> Rule {
        var rule = original
        switch process {
        case .unchanged: break
        case .app(let path, let name):
            rule.processPath = path
            rule.processName = name
        case .anyApp:
            rule.processPath = nil
            rule.processName = nil
        }
        rule.processBundleId = bundleId
        // The signing team belongs to the bundle id the rule was made for. A
        // new bundle id has to learn its own team, never inherit the old one.
        if rule.processBundleId != original.processBundleId {
            rule.processTeamId = nil
        }
        rule.remoteHost = remoteHost
        rule.remoteIP = remoteIP
        rule.remotePort = remotePort
        rule.direction = direction
        rule.action = action
        rule.scope = scope
        rule.profile = profile
        rule.notes = notes
        rule.enabled = enabled
        return rule
    }
}
