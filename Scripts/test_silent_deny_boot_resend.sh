#!/usr/bin/env bash
# Filtering keeps going after the extension restarts in Silent Deny (#455).
#
# When the network extension starts from a saved Silent Deny policy that is
# more than a day old, it loads it as Alert (applyingBootPolicySafety). The app
# then resends the current policy from the same helper session and generation,
# still Silent Deny. Compared with the relaxed copy, that looked like a
# different mode under the same generation; the extension refused it as
# split-brain and stopped filtering, and Send Rules Again could not help.
#
# Replayed with the shipping shared code: snapshots come from the real rules
# database the way HelperService.authoritativeSnapshot builds them, the saved
# copy goes through the real boot encoding and safety step, and the live resend
# is checked by the extension's split-brain condition and the real gate, both
# fed by policyForLiveComparison exactly as FilterDataProvider feeds them.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-silent-deny-boot.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

@main
struct Verify {
    static var failures = 0

    static func check(_ ok: Bool, _ label: String) {
        if ok {
            print("silent deny boot resend: PASS: \(label)")
        } else {
            failures += 1
            print("silent deny boot resend: FAIL: \(label)")
        }
    }

    static func helperSnapshot(_ store: RuleStore) -> SharedRuleBridge.Snapshot {
        let state = store.activePolicyState()
        return SharedRuleBridge.Snapshot(mode: state.mode, rules: state.rules,
                                         generation: state.generation, epoch: state.epoch)
    }

    /// The extension starting from its saved policy: decode, then the safety step.
    static func extensionStart(from saved: SharedRuleBridge.Snapshot) throws
        -> (enforced: SharedRuleBridge.Snapshot, saved: SharedRuleBridge.Snapshot) {
        let data = try SharedRuleBridge.encodeBootSnapshot(saved)
        let decoded = try SharedRuleBridge.decodeBootSnapshot(data)
        return (SharedRuleBridge.applyingBootPolicySafety(decoded), decoded)
    }

    /// FilterDataProvider.receiveSnapshot while running on a boot policy.
    static func extensionReceives(_ received: SharedRuleBridge.Snapshot,
                                  enforced: SharedRuleBridge.Snapshot,
                                  saved: SharedRuleBridge.Snapshot)
        -> (splitBrain: Bool, decision: SharedRuleBridge.LiveSnapshotDecision, nowEnforced: SharedRuleBridge.Snapshot?) {
        let comparable = SharedRuleBridge.policyForLiveComparison(enforced: enforced, savedBootPolicy: saved)
        let splitBrain = SharedRuleBridge.SnapshotAuthority.compare(received: received, against: enforced) == .sameSession
            && received.generation == enforced.generation
            && !SharedRuleBridge.PolicyContent.same(received, comparable)
        var gate = SharedRuleBridge.LiveSnapshotGate(current: comparable)
        let decision = gate.apply(received)
        return (splitBrain, decision, gate.current)
    }

    static func main() throws {
        let store = try RuleStore(path: CommandLine.arguments[1])
        _ = store.beginPolicySession()
        let deny = Rule(remoteHost: "*.doubleclick.net", direction: .outgoing, action: .deny,
                        scope: .domain, priority: 60)
        _ = try store.mutatePolicy { draft in
            draft.mode = .silentDeny
            draft.activeProfileMode = .silentDeny
            draft.rules = [deny]
        }

        // The app saved the policy 25 hours ago and nothing has changed since.
        var saved = helperSnapshot(store)
        saved.updatedAt = Date().addingTimeInterval(-25 * 60 * 60)
        let start = try extensionStart(from: saved)
        check(start.enforced.mode == .alert, "the stale Silent Deny boot policy is loaded as Alert (unchanged safety step)")

        // The app resends the current policy: same session, same generation.
        let resend = helperSnapshot(store)
        check(resend.mode == .silentDeny && resend.generation == saved.generation && resend.epoch == saved.epoch,
              "the resend is the same policy: Silent Deny, same session and generation")
        let result = extensionReceives(resend, enforced: start.enforced, saved: start.saved)
        check(!result.splitBrain, "the extension does not call the resend split-brain (it did before #455)")
        check(result.decision == .idempotent, "the gate takes the resend as the policy it already has")
        check(result.nowEnforced?.mode == .silentDeny, "after the resend the extension enforces Silent Deny again")

        // A fresh boot policy (not relaxed) behaves exactly as before.
        let freshStart = try extensionStart(from: helperSnapshot(store))
        check(freshStart.enforced.mode == .silentDeny, "a fresh Silent Deny boot policy is kept as Silent Deny")
        check(extensionReceives(resend, enforced: freshStart.enforced, saved: freshStart.saved).decision == .idempotent,
              "a resend over a fresh boot policy is the same policy, as before")

        // Real conflicts are still refused.
        var otherRule = resend
        otherRule.rules = [Rule(id: deny.id, remoteHost: "*.doubleclick.net", direction: .outgoing,
                                action: .allow, scope: .domain, priority: 60)]
        let conflict = extensionReceives(otherRule, enforced: start.enforced, saved: start.saved)
        check(conflict.splitBrain && conflict.decision == .rejectedConflict(currentGeneration: saved.generation),
              "a different rule under the same generation is still split-brain")
        var alertResend = resend
        alertResend.mode = .alert
        let modeConflict = extensionReceives(alertResend, enforced: start.enforced, saved: start.saved)
        check(modeConflict.splitBrain, "a mode that was never saved under this generation is still split-brain")

        // Only a saved policy of the same session, generation and rules is used.
        var elsewhere = start.saved
        elsewhere.generation += 1
        check(SharedRuleBridge.policyForLiveComparison(enforced: start.enforced, savedBootPolicy: elsewhere).mode == .alert,
              "a saved policy of another generation is not used for the comparison")
        var otherSaved = start.saved
        otherSaved.rules = []
        check(SharedRuleBridge.policyForLiveComparison(enforced: start.enforced, savedBootPolicy: otherSaved).mode == .alert,
              "a saved policy with other rules is not used for the comparison")
        check(SharedRuleBridge.policyForLiveComparison(enforced: start.enforced, savedBootPolicy: nil).mode == .alert,
              "without a saved policy the enforced one is compared")

        // A newer generation from the app is accepted either way.
        _ = try store.mutatePolicy { draft in draft.rules.append(Rule(remoteHost: "tracker.example", direction: .outgoing,
                                                                      action: .deny, scope: .domain)) }
        check(extensionReceives(helperSnapshot(store), enforced: start.enforced, saved: start.saved).decision == .accepted,
              "a newer generation replaces the boot policy")

        if failures == 0 {
            print("silent deny boot resend: PASS (all checks)")
        } else {
            print("silent deny boot resend: \(failures) FAILURES")
            exit(1)
        }
    }
}
SWIFT

xcrun swiftc -O -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos13.0 -parse-as-library \
  -o "$TMP/run" "$ROOT"/Sources/Shared/*.swift "$TMP/verify.swift" -lsqlite3
"$TMP/run" "$TMP/rules.sqlite"
