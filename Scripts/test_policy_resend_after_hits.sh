#!/usr/bin/env bash
# Resending the rules after a counted match must not stop filtering (#438).
#
# Since #434 the helper adds every counted match to a rule's hit count and
# last-used time, without a new policy generation: counters are bookkeeping,
# not policy. The extension refuses a snapshot that repeats its generation with
# different policy content ("split-brain"). When that check compared whole
# rules, the next resend after a counted match carried the same generation and
# different counters, the extension refused it, and filtering stopped.
#
# This replays the resends that happen in the app, each after counted matches,
# with snapshots built the way HelperService.authoritativeSnapshot builds them
# from the real rules database, against the real snapshot gate and the shared
# policy-content definition the extension uses:
#   - Send Rules Again
#   - quitting and reopening FreeSnitch, including the extension restarting from
#     its saved boot policy, which carries older counters
#   - the app reconnecting to the same helper, and the helper restarting
# A real policy change under the same generation must still be refused.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-resend-after-hits.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

@main
struct Verify {
    static var failures = 0

    static func check(_ ok: Bool, _ label: String) {
        if ok {
            print("resend after hits: PASS: \(label)")
        } else {
            failures += 1
            print("resend after hits: FAIL: \(label)")
        }
    }

    /// Exactly what HelperService.authoritativeSnapshot publishes.
    static func helperSnapshot(_ store: RuleStore) -> SharedRuleBridge.Snapshot {
        let state = store.activePolicyState()
        return SharedRuleBridge.Snapshot(mode: state.mode, rules: state.rules,
                                         generation: state.generation, epoch: state.epoch)
    }

    /// The extension's split-brain condition (FilterDataProvider.receiveSnapshot).
    static func extensionCallsItSplitBrain(_ received: SharedRuleBridge.Snapshot,
                                           holding current: SharedRuleBridge.Snapshot) -> Bool {
        SharedRuleBridge.SnapshotAuthority.compare(received: received, against: current) == .sameSession
            && received.generation == current.generation
            && !SharedRuleBridge.PolicyContent.same(received, current)
    }

    static func hit(_ rule: Rule, _ count: Int) -> RuleHit {
        RuleHit(ruleID: rule.id, count: count, lastMatchedAt: Date())
    }

    static func main() throws {
        let path = CommandLine.arguments[1]
        let deny = Rule(remoteHost: "*.doubleclick.net", direction: .outgoing, action: .deny,
                        scope: .domain, priority: 60)
        let allow = Rule(processPath: "/Applications/Safari.app/Contents/MacOS/Safari", processName: "Safari",
                         remoteHost: "example.com", direction: .outgoing, action: .allow,
                         scope: .domain, priority: 50)

        // The helper starts, the user has two rules, the extension takes them
        // and the app saves the same policy as the boot policy.
        var store: RuleStore? = try RuleStore(path: path)
        _ = store!.beginPolicySession()
        _ = try store!.mutatePolicy { draft in
            draft.mode = .alert
            draft.rules = [deny, allow]
        }
        let first = helperSnapshot(store!)
        var gate = SharedRuleBridge.LiveSnapshotGate()
        check(gate.apply(first) == .accepted, "the extension takes the first policy")
        let savedBootPolicy = first

        // Matches are counted. No new generation: counters are not policy.
        try store!.recordRuleHits([hit(deny, 5), hit(allow, 2)])
        let afterHits = helperSnapshot(store!)
        check(afterHits.generation == first.generation && afterHits.epoch == first.epoch,
              "counting matches keeps the session and generation")
        check(afterHits.rules != first.rules,
              "the resent rules really do carry the new counters (this is the case that broke)")
        check(SharedRuleBridge.PolicyContent.same(afterHits, first),
              "the shared policy content ignores the counters")
        check(SharedRuleBridge.LivePolicyWatermark(afterHits).contentDigest
                == SharedRuleBridge.LivePolicyWatermark(first).contentDigest,
              "the watermark digest uses the same policy content")

        // 1. Send Rules Again.
        check(!extensionCallsItSplitBrain(afterHits, holding: gate.current!),
              "Send Rules Again: the extension does not call the resend split-brain")
        check(gate.apply(afterHits) == .idempotent, "Send Rules Again: the resend is accepted as the same policy")

        // 2. Quit and reopen FreeSnitch: the app resends after more matches.
        try store!.recordRuleHits([hit(deny, 3)])
        let relaunch = helperSnapshot(store!)
        check(!extensionCallsItSplitBrain(relaunch, holding: gate.current!),
              "relaunch: the extension does not call the resend split-brain")
        check(gate.apply(relaunch) == .idempotent, "relaunch: the resend is accepted")

        // 2b. The extension itself restarted and loaded the saved boot policy,
        //     whose counters are older than the ones the app sends now.
        check(!extensionCallsItSplitBrain(relaunch, holding: savedBootPolicy),
              "extension restart: the live resend is not split-brain against the older saved copy")
        var restartedGate = SharedRuleBridge.LiveSnapshotGate(current: savedBootPolicy)
        check(restartedGate.apply(relaunch) == .idempotent,
              "extension restart: the live resend replaces the saved copy")

        // 3. The app reconnects to the same helper process after more matches.
        try store!.recordRuleHits([hit(allow, 4)])
        let reconnect = helperSnapshot(store!)
        check(!extensionCallsItSplitBrain(reconnect, holding: gate.current!),
              "helper reconnect: the extension does not call the resend split-brain")
        check(gate.apply(reconnect) == .idempotent, "helper reconnect: the resend is accepted")

        // 3b. The helper restarts: a new session, after more matches.
        store = nil
        let restarted = try RuleStore(path: path)
        _ = restarted.beginPolicySession()
        try restarted.recordRuleHits([hit(deny, 1)])
        let afterRestart = helperSnapshot(restarted)
        check(afterRestart.epoch > reconnect.epoch, "a restarted helper opens a newer session")
        check(gate.apply(afterRestart) == .accepted, "helper restart: the new session's policy is accepted")

        // A real policy change under the same generation is still refused.
        var changedRule = afterRestart
        changedRule.rules = changedRule.rules.map { rule in
            var edited = rule
            if edited.id == deny.id { edited.action = .allow }
            return edited
        }
        check(extensionCallsItSplitBrain(changedRule, holding: gate.current!),
              "a changed rule under the same generation is still split-brain")
        var probe = gate
        check(probe.apply(changedRule) == .rejectedConflict(currentGeneration: afterRestart.generation),
              "the gate still refuses a changed rule under the same generation")
        var changedMode = afterRestart
        changedMode.mode = .silentDeny
        probe = gate
        check(probe.apply(changedMode) == .rejectedConflict(currentGeneration: afterRestart.generation),
              "the gate still refuses a changed mode under the same generation")
        var disabled = afterRestart
        disabled.rules = disabled.rules.map { rule in
            var edited = rule
            if edited.id == allow.id { edited.enabled = false }
            return edited
        }
        check(!SharedRuleBridge.PolicyContent.same(disabled, afterRestart),
              "turning a rule off is a policy change")

        if failures == 0 {
            print("resend after hits: PASS (all checks)")
        } else {
            print("resend after hits: \(failures) FAILURES")
            exit(1)
        }
    }
}
SWIFT

xcrun swiftc -O -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos13.0 -parse-as-library \
  -o "$TMP/run" "$ROOT"/Sources/Shared/*.swift "$TMP/verify.swift" -lsqlite3
"$TMP/run" "$TMP/rules.sqlite"
