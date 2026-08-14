import Foundation
import SwiftUI

/// Owns the monitor tree between the live connection list and the rows.
///
/// Three jobs, and nothing else:
///
/// 1. Rebuild the grouping on a background task, coalescing bursts, so the
///    render path never groups anything.
/// 2. Keep expansion state, which belongs to the user and therefore survives
///    every refresh of the underlying data.
/// 3. Send an explicit allow/deny to the helper through the same
///    `HelperClient.addRule` ingest path the rules screen uses, and then
///    re-read the helper's authoritative snapshot. Nothing here is enforced
///    from GUI state.
@MainActor
final class MonitorTreeController: ObservableObject {
    @Published private(set) var snapshot = MonitorTreeSnapshot()
    @Published private(set) var decisions = MonitorDecisionIndex()
    @Published private(set) var expandedAppIDs: Set<String> = []
    /// Rows waiting for the helper to answer. The control stays visible and
    /// disabled rather than disappearing under the pointer.
    @Published private(set) var pendingTargets: Set<MonitorRuleTarget> = []
    @Published var errorMessage: String?

    private var order = MonitorRowOrder()
    private var revision: UInt64 = 0
    private var isBuilding = false
    private var queued: [Connection]?
    private var lastDecisionKey: DecisionKey?

    /// Expansion is remembered for apps that are not on screen right now, so a
    /// process that goes quiet for a moment comes back expanded. The set is
    /// still bounded: past this many entries it is trimmed to what exists.
    private static let maxRememberedExpansions = 512

    private struct DecisionKey: Equatable {
        let profile: String
        let ruleIDs: [UUID]
        let actions: [RuleAction]
        let enabled: [Bool]
    }

    // MARK: Grouping

    /// Hands a connection list to a background task. While one build runs, at
    /// most one further list is kept, so a fast producer cannot queue work
    /// without bound.
    func ingest(connections: [Connection]) {
        guard !isBuilding else {
            queued = connections
            return
        }
        startBuild(with: connections)
    }

    private func startBuild(with connections: [Connection]) {
        isBuilding = true
        revision &+= 1
        let order = self.order
        let revision = self.revision
        Task.detached(priority: .utility) { [weak self] in
            let build = MonitorTreeBuilder.build(connections: connections, order: order, revision: revision)
            await self?.finishBuild(build)
        }
    }

    private func finishBuild(_ build: MonitorTreeBuild) {
        // A build started before the newest one must not overwrite it.
        guard build.snapshot.revision >= snapshot.revision else {
            isBuilding = false
            drainQueue()
            return
        }
        order = build.order
        snapshot = build.snapshot
        trimExpansionsIfNeeded()
        isBuilding = false
        drainQueue()
    }

    private func drainQueue() {
        guard let next = queued else { return }
        queued = nil
        startBuild(with: next)
    }

    // MARK: Expansion

    func isExpanded(_ app: MonitorAppNode) -> Bool {
        expandedAppIDs.contains(app.id)
    }

    func toggleExpansion(_ app: MonitorAppNode) {
        if expandedAppIDs.contains(app.id) {
            expandedAppIDs.remove(app.id)
        } else {
            expandedAppIDs.insert(app.id)
        }
    }

    func collapseAll() {
        expandedAppIDs.removeAll()
    }

    private func trimExpansionsIfNeeded() {
        guard expandedAppIDs.count > Self.maxRememberedExpansions else { return }
        let present = Set(snapshot.apps.map(\.id))
        expandedAppIDs.formIntersection(present)
    }

    // MARK: Decisions

    /// Rebuilds the decision index when, and only when, the helper's rules
    /// actually changed. `AppState.rules` is republished on every refresh.
    func updateDecisions(rules: [Rule], profile: String) {
        let key = DecisionKey(profile: profile,
                              ruleIDs: rules.map(\.id),
                              actions: rules.map(\.action),
                              enabled: rules.map(\.enabled))
        guard key != lastDecisionKey else { return }
        lastDecisionKey = key
        decisions = MonitorDecisionIndex(rules: rules, profile: profile)
    }

    func decision(for target: MonitorRuleTarget?) -> Rule? {
        decisions.rule(for: target)
    }

    func isPending(_ target: MonitorRuleTarget?) -> Bool {
        guard let target else { return false }
        return pendingTargets.contains(target)
    }

    /// An explicit allow or deny for one row. Never called from a tap on the
    /// row itself: only the row's own allow and deny controls call this.
    func apply(_ action: RuleAction,
               to target: MonitorRuleTarget,
               processName: String?,
               state: AppState) {
        guard state.helperConnected else {
            errorMessage = "Approve the FreeSnitch helper before deciding anything here. Rules are stored by the helper, not by this window."
            return
        }
        let existing = decisions.rule(for: target)
        guard let rule = MonitorRuleDraft.rule(for: target,
                                               processName: processName,
                                               action: action,
                                               profile: state.activeProfile,
                                               existing: existing) else {
            errorMessage = "This row has no destination a rule can name, so nothing was changed."
            return
        }
        pendingTargets.insert(target)
        state.helper.addRule(rule) { [weak self] ok, message in
            guard let self else { return }
            self.pendingTargets.remove(target)
            guard ok else {
                self.errorMessage = "The helper refused this rule: \(message ?? "no reason given"). Nothing was changed."
                return
            }
            // Read policy back from the helper. What the row shows next is
            // whatever the helper stored, not what this window asked for.
            state.refreshRules()
        }
    }

    /// Removes the rule this row created, which is what makes a decision made
    /// here reversible from here.
    func clearDecision(for target: MonitorRuleTarget, state: AppState) {
        guard let rule = decisions.rule(for: target) else { return }
        guard state.helperConnected else {
            errorMessage = "Approve the FreeSnitch helper before deciding anything here. Rules are stored by the helper, not by this window."
            return
        }
        pendingTargets.insert(target)
        state.helper.removeRule(id: rule.id) { [weak self] ok, message in
            guard let self else { return }
            self.pendingTargets.remove(target)
            guard ok else {
                self.errorMessage = "The helper refused to remove this rule: \(message ?? "no reason given"). Nothing was changed."
                return
            }
            state.refreshRules()
        }
    }
}
