#!/usr/bin/env bash
# A rule's Hits and Last used show that it is matching (issue #434).
#
# The rule inspector has always shown both, but nothing ever counted a match:
# every rule read "Hits 0, Last used Never" however much traffic it decided,
# so nobody could tell whether a rule was doing anything.
#
# Compiled from the real shared sources and run through the same steps a match
# takes in the app: the prepared verdict path names the rule that decided, the
# extension's tally counts it, the observation batch carries it to the helper,
# and the rules database adds it to the rule. The app then saves its rules with
# its own, older copy of the counters, which must not wipe what was counted.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-rule-hits.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

@main
struct Verify {
    static var failures = 0

    static func check(_ ok: Bool, _ label: String) {
        if ok {
            print("rule hits harness: PASS: \(label)")
        } else {
            failures += 1
            print("rule hits harness: FAIL: \(label)")
        }
    }

    static func flow(host: String, ip: String = "93.184.216.34", path: String = "/Applications/Safari.app/Contents/MacOS/Safari") -> Connection {
        Connection(pid: 321, processName: (path as NSString).lastPathComponent, processPath: path,
                   remoteHost: host, remoteIP: ip, remotePort: 443, direction: .outgoing)
    }

    static func main() throws {
        let matcher = RuleMatcher()
        let deny = Rule(remoteHost: "*.doubleclick.net", direction: .outgoing, action: .deny,
                        scope: .domain, priority: 60, profile: "default")
        let allow = Rule(processPath: "/Applications/Safari.app/Contents/MacOS/Safari", processName: "Safari",
                         remoteHost: "example.com", direction: .outgoing, action: .allow,
                         scope: .domain, priority: 50, profile: "default")
        let prepared = PreparedRuleSet(rules: [allow, deny])

        // 1. The verdict path names the rule that decided, in every mode.
        for mode in [AppMode.alert, .silentAllow, .silentDeny] {
            let blocked = matcher.explainedDecision(for: flow(host: "ad.doubleclick.net"), prepared: prepared, defaultMode: mode)
            check(blocked.action == .deny && blocked.matchedRuleID == deny.id,
                  "\(mode.rawValue): a deny rule that drops a flow is named as the deciding rule")
            let allowed = matcher.explainedDecision(for: flow(host: "example.com"), prepared: prepared, defaultMode: mode)
            check(allowed.action == .allow && allowed.matchedRuleID == allow.id,
                  "\(mode.rawValue): an allow rule that lets a flow through is named as the deciding rule")
            let uncovered = matcher.explainedDecision(for: flow(host: "unrelated.org"), prepared: prepared, defaultMode: mode)
            check(uncovered.matchedRuleID == nil, "\(mode.rawValue): a flow no rule covers names no rule")
        }
        let expired = Rule(remoteHost: "old.example", direction: .outgoing, action: .deny, scope: .domain,
                           priority: 99, profile: "default", expiresAt: Date().addingTimeInterval(-60))
        let pastExpiry = matcher.explainedDecision(for: flow(host: "old.example"), prepared: PreparedRuleSet(rules: [expired, allow]),
                                                   defaultMode: .silentAllow)
        check(pastExpiry.matchedRuleID == nil, "an expired rule is never credited with a match")

        // 2. The extension's tally counts matches per rule.
        let tally = RuleHitTally(capacity: 2)
        let t0 = Date().addingTimeInterval(-30)
        for i in 0..<5 { tally.record(deny.id, at: t0.addingTimeInterval(Double(i))) }
        tally.record(allow.id, at: t0)
        check(!tally.record(UUID(), at: t0), "a full tally refuses a new rule instead of growing")
        check(tally.record(deny.id, at: t0.addingTimeInterval(10)), "a full tally still counts rules it already holds")
        var drained = tally.drain(maximum: 10)
        let denyHit = drained.first { $0.ruleID == deny.id }
        check(denyHit?.count == 6, "six matches of the deny rule are counted as six")
        check(denyHit?.lastMatchedAt == t0.addingTimeInterval(10), "the tally keeps the latest match time")
        check(tally.drain(maximum: 10).isEmpty, "a drain empties what it took")
        tally.restore(drained)
        tally.record(deny.id, at: t0.addingTimeInterval(20))
        drained = tally.drain(maximum: 10)
        check(drained.first { $0.ruleID == deny.id }?.count == 7,
              "counts from a batch that could not be sent are kept and added to new ones")

        // 3. The batch carries the hits to the helper, and stays readable both ways.
        let batch = FlowObservationBatch(observations: [], ruleHits: drained)
        let wire = try FreeSnitchWireCodec.encode(batch)
        let decoded = try FreeSnitchWireCodec.decode(FlowObservationBatch.self, from: wire)
        check(decoded.ruleHits.map(Set.init) == Set(drained), "rule hits survive the trip to the helper")
        do { try decoded.validate(payloadBytes: wire.count); check(true, "a batch of real hits passes validation") }
        catch { check(false, "a batch of real hits passes validation (\(error))") }
        let older = try FreeSnitchWireCodec.decode(FlowObservationBatch.self,
                                                   from: Data(#"{"schemaVersion":1,"observations":[]}"#.utf8))
        check(older.ruleHits == nil, "a batch from an extension without hit counting still decodes")
        func rejects(_ hits: [RuleHit], _ label: String) {
            let candidate = FlowObservationBatch(observations: [], ruleHits: hits)
            check((try? candidate.validate(payloadBytes: 100)) != nil, "\(label): the batch itself is still accepted")
            check(candidate.validRuleHits().count == 1, label)
        }
        let good = RuleHit(ruleID: allow.id, count: 1, lastMatchedAt: Date())
        rejects([good, RuleHit(ruleID: deny.id, count: 0, lastMatchedAt: Date())], "a hit with no matches is dropped")
        rejects([good, RuleHit(ruleID: deny.id, count: 1, lastMatchedAt: Date().addingTimeInterval(3600))],
                "a hit from the future is dropped")
        rejects([good, RuleHit(ruleID: allow.id, count: 2, lastMatchedAt: Date())],
                "the same rule twice in one batch is counted once")
        let flood = FlowObservationBatch(observations: [], ruleHits: (0...InsightsLimits.maxBatchCount).map { _ in good })
        check((try? flood.validate(payloadBytes: 100)) == nil, "a batch with more hits than the limit is rejected")

        // 4. The rules database adds the hits, and a save with an older copy keeps them.
        let store = try RuleStore(path: CommandLine.arguments[1])
        let gone = UUID()
        _ = try store.mutatePolicy { draft in draft.rules = [deny, allow] }
        let staleCopy = store.allRules()
        try store.recordRuleHits(drained + [RuleHit(ruleID: gone, count: 3, lastMatchedAt: Date())])
        var stored = store.allRules().first { $0.id == deny.id }
        check(stored?.hitCount == 7, "the deny rule shows 7 hits after its matches are recorded (was 0 before #434)")
        check(stored?.lastUsedAt.map { abs($0.timeIntervalSince(t0.addingTimeInterval(20))) < 0.01 } == true,
              "Last used is the time of the latest match")
        check(store.allRules().first { $0.id == allow.id }?.hitCount == 1, "the allow rule shows its one hit")
        check(!store.allRules().contains { $0.id == gone }, "a hit for a deleted rule creates nothing")

        try store.recordRuleHits([RuleHit(ruleID: deny.id, count: 2, lastMatchedAt: t0)])
        stored = store.allRules().first { $0.id == deny.id }
        check(stored?.hitCount == 9, "later hits add to the count")
        check(stored?.lastUsedAt.map { abs($0.timeIntervalSince(t0.addingTimeInterval(20))) < 0.01 } == true,
              "an older match time never moves Last used back")

        // The app's copy still says 0 hits. Editing a note and saving must not wipe the count.
        _ = try store.mutatePolicy { draft in
            draft.rules = staleCopy.map { rule in
                var edited = rule
                if edited.id == deny.id { edited.notes = "Ad tracker" }
                return edited
            }
        }
        stored = store.allRules().first { $0.id == deny.id }
        check(stored?.notes == "Ad tracker", "the edit itself is saved")
        check(stored?.hitCount == 9 && stored?.lastUsedAt != nil,
              "saving rules from an older copy keeps the counted hits and Last used")
        var single = staleCopy.first { $0.id == allow.id }!
        single.notes = "Mine"
        try store.upsertRule(single)
        check(store.allRules().first { $0.id == allow.id }?.hitCount == 1, "saving one rule from an older copy keeps its hits")

        if failures == 0 {
            print("rule hits harness: PASS (all checks)")
        } else {
            print("rule hits harness: \(failures) FAILURES")
            exit(1)
        }
    }
}
SWIFT

xcrun swiftc -O -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos13.0 -parse-as-library \
  -o "$TMP/run" "$ROOT"/Sources/Shared/*.swift "$TMP/verify.swift" -lsqlite3
"$TMP/run" "$TMP/rules.sqlite"
