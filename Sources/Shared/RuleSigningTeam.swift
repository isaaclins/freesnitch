import Foundation

/// Binding bundle-id rules to the team that signed their app (#364).
///
/// A Developer ID holder can sign a binary with any identifier, say
/// `com.google.Chrome`: Developer ID does not register bundle ids the way the
/// App Store does. So a rule records who signed the app it was made for, and
/// an allow or ask rule only matches that team's code (`RuleMatcher`).
///
/// A rule made from an alert records the team at once. A rule without one (made
/// before #364, by hand, from the CLI or from an import) learns it the first
/// time a signed process with its bundle id is seen, and keeps it from then on.
public enum RuleSigningTeam {
    /// A signed process the extension saw.
    public struct Sighting: Hashable, Sendable {
        public let bundleId: String
        public let team: String
        public let processPath: String

        public init(bundleId: String, team: String, processPath: String) {
            self.bundleId = bundleId
            self.team = team
            self.processPath = processPath
        }

        public init?(_ observation: FlowObservation) {
            guard let bundleId = observation.processBundleId, !bundleId.isEmpty,
                  let team = observation.processTeamId, !team.isEmpty else { return nil }
            self.init(bundleId: bundleId, team: team, processPath: observation.processPath)
        }
    }

    /// True when the rule names an app by bundle id and has no team yet.
    public static func needsTeam(_ rule: Rule) -> Bool {
        !(rule.processBundleId ?? "").isEmpty && (rule.processTeamId ?? "").isEmpty
    }

    /// The bundle ids some rule is still waiting to learn a team for.
    public static func teamlessBundleIds(_ rules: [Rule]) -> Set<String> {
        Set(rules.lazy.filter(needsTeam).compactMap(\.processBundleId))
    }

    /// The rules with every team the sightings teach, and the sightings that
    /// taught one, or nil when none learned anything. A rule that also names a
    /// path learns only from a process under that path, the same way it
    /// matches. When one batch shows the same id signed by two teams, the first
    /// sighting wins: that is the order the processes were seen in.
    public static func learn(rules: [Rule], from sightings: [Sighting]) -> (rules: [Rule], taught: [Sighting])? {
        var learned = rules
        var taught: [Sighting] = []
        for index in learned.indices where needsTeam(learned[index]) {
            let rule = learned[index]
            let path = rule.processPath.flatMap { $0.isEmpty ? nil : $0 }
            guard let sighting = sightings.first(where: { sighting in
                sighting.bundleId == rule.processBundleId
                    && (path.map { sighting.processPath.hasPrefix($0) } ?? true)
            }) else { continue }
            learned[index].processTeamId = sighting.team
            if !taught.contains(sighting) { taught.append(sighting) }
        }
        return taught.isEmpty ? nil : (learned, taught)
    }

    /// What the Rules list shows for a rule's team.
    public static func label(_ team: String?) -> String {
        guard let team, !team.isEmpty else { return "Not known yet" }
        return team == CodeSigningIdentity.appleTeam ? "Apple" : "Team \(team)"
    }
}
