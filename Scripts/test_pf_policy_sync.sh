#!/usr/bin/env bash
# Harness for the policy pf and the DNS proxy are handed (issues #184, #185).
#
# The harness is compiled from the real helper and shared sources, never from a
# copy. It checks that:
#
#   1. A policy mutation hands pf and the DNS proxy exactly the list the
#      extension's snapshot carries: the Always rules, then the active
#      profile's, in the same order, and the active profile's mode. A rule in
#      a profile that is not active is not in it.
#   2. A profile switch changes that list.
#   3. pf records every rule change while enforcement is off, so turning
#      enforcement on renders the rules in force, and a rule deleted while
#      enforcement was off cannot come back on the next feed refresh.
#
# Nothing here loads a pf anchor: PFManager is never installed, so every pf
# call takes the "enforcement off" path and no pfctl command runs. The store
# and PFManager are driven directly; that HelperService hands pf what the
# store publishes, on every path, is checked by Scripts/audit_firewall_safety.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-pf-policy.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

SDK="$(xcrun --show-sdk-path)"
TARGET="arm64-apple-macos13.0"

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

final class Checks {
    private var failures: [String] = []
    private var passed = 0

    func expect(_ condition: Bool, _ message: String) {
        if condition {
            passed += 1
        } else {
            failures.append(message)
        }
    }

    func finish() {
        guard failures.isEmpty else {
            for failure in failures {
                FileHandle.standardError.write(Data(("pf policy harness: FAIL: " + failure + "\n").utf8))
            }
            exit(1)
        }
        print("pf policy harness: real sources: \(passed) assertions PASS")
    }
}

@main
struct Verify {
    static func main() throws {
        let checks = Checks()
        let storePath = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("freesnitch-pf-policy-\(UUID().uuidString).sqlite")
        defer { try? FileManager.default.removeItem(atPath: storePath) }
        let store = try RuleStore(path: storePath)
        _ = store.beginPolicySession()
        _ = try store.createProfile(name: "office", mode: .silentDeny)
        _ = try store.createProfile(name: "work", mode: .alert)
        try store.setActiveProfile(name: "office")

        let clock = Date(timeIntervalSince1970: 1_800_000_000)
        // The example from #184: Always allows one address (older), the active
        // profile denies its network (newer), both at priority 100.
        let alwaysAllow = Rule(remoteIP: "203.0.113.7", action: .allow, scope: .ip,
                               profile: Profile.alwaysName, createdAt: clock)
        let homeDeny = Rule(remoteIP: "203.0.113.0/24", action: .deny, scope: .ip,
                            profile: "office", createdAt: clock.addingTimeInterval(60))
        let workDeny = Rule(remoteIP: "198.51.100.50", action: .deny, scope: .ip,
                            profile: "work", createdAt: clock.addingTimeInterval(120))

        // 1. What a mutation publishes is what the extension's snapshot holds.
        let published = try store.mutateActivePolicy { draft in
            draft.rules = [workDeny, homeDeny, alwaysAllow]
        }
        let snapshot = store.activePolicyState()
        checks.expect(published.rules.map(\.id) == [alwaysAllow.id, homeDeny.id],
                      "a mutation must publish the Always rules, then the active profile's, got \(published.rules.map(\.remoteIP))")
        checks.expect(published.rules.map(\.id) == snapshot.rules.map(\.id),
                      "pf and the DNS proxy must get the extension's list in the extension's order")
        checks.expect(published.mode == .silentDeny && published.mode == snapshot.mode,
                      "a mutation must publish the active profile's mode, got \(published.mode)")
        checks.expect(published.generation == snapshot.generation,
                      "the published policy must carry the committed generation")
        checks.expect(store.policyState().rules.contains { $0.id == workDeny.id },
                      "the store must keep the inactive profile's rule; it is only not enforced")

        let pf = PFManager()
        let wrote = try pf.applyRules(published.rules)
        checks.expect(!wrote, "with enforcement off pf must not write the anchor")
        checks.expect(pf.currentRules.map(\.id) == published.rules.map(\.id),
                      "with enforcement off pf must still record the rules in force")
        let anchor = pf.renderAnchor(rules: pf.currentRules, now: clock)
        checks.expect(!anchor.contains("198.51.100.50"),
                      "a deny in a profile that is not active must not reach pf")
        checks.expect(anchor.contains("203.0.113.0/24") && anchor.contains("203.0.113.7"),
                      "the active profile's and the Always rules must reach pf")

        // 2. A profile switch changes what is enforced.
        try store.setActiveProfile(name: "work")
        let switched = store.activePolicyState()
        checks.expect(switched.rules.map(\.id) == [alwaysAllow.id, workDeny.id],
                      "after a switch the Always rules and the new profile's must be enforced, got \(switched.rules.map(\.remoteIP))")
        checks.expect(switched.mode == .alert, "after a switch the new profile's mode must be enforced")
        try pf.applyRules(switched.rules)
        checks.expect(pf.currentRules.map(\.id) == switched.rules.map(\.id),
                      "a profile switch must reach pf")

        // A mode change lands in the active profile, in the same commit, so
        // every layer enforces it. Other profiles keep their own mode.
        let modeChanged = try store.mutateActivePolicy { draft in
            draft.mode = .silentAllow
            draft.activeProfileMode = .silentAllow
        }
        checks.expect(modeChanged.mode == .silentAllow && store.activePolicyState().mode == .silentAllow,
                      "a mode change must be enforced through the active profile, got \(modeChanged.mode)")
        checks.expect(store.profile(named: "office")?.mode == AppMode.silentDeny,
                      "a mode change must not touch a profile that is not active")
        let ruleEdit = try store.mutateActivePolicy { draft in draft.rules = draft.rules }
        checks.expect(ruleEdit.mode == .silentAllow, "a rule edit must keep the active profile's mode")

        // 3. A deny deleted while enforcement is off must not come back. The
        //    feed refresh renders the recorded rules, so they must be the
        //    current ones, and with the anchor unloaded it must write nothing.
        let afterDelete = try store.mutateActivePolicy { draft in
            draft.rules.removeAll { $0.id == workDeny.id }
        }
        try pf.applyRules(afterDelete.rules)
        try pf.setIPBlocklist(IPBlocklistSet(entries: ["192.0.2.0/24"]))
        checks.expect(!pf.currentRules.contains { $0.id == workDeny.id },
                      "a deny deleted while enforcement was off must not stay recorded in pf")
        checks.expect(!pf.renderAnchor(rules: pf.currentRules).contains("198.51.100.50"),
                      "a deny deleted while enforcement was off must not come back in the anchor")
        checks.expect(!pf.isLoaded, "the harness must never load the anchor")

        checks.finish()
    }
}
SWIFT

printf 'pf policy harness: building from the real helper and shared sources\n'
# shellcheck disable=SC2046
xcrun swiftc -O -sdk "$SDK" -target "$TARGET" -parse-as-library \
  -o "$TMP/run" \
  $(ls "$ROOT"/Sources/Helper/*.swift | grep -v '/main.swift$') \
  "$ROOT"/Sources/Shared/*.swift \
  "$TMP/verify.swift"

"$TMP/run"

printf 'pf policy verification: PASS\n'
