import Foundation

// Regression check for #57 using the exact legacy shapes found in the live
// store: reverse-DNS rules created by earlier builds.
var failures: [String] = []
func check(_ ok: Bool, _ m: String) { if !ok { failures.append(m) } }

let legacy = [
    Rule(processName: "mDNSResponder", remoteHost: "11.176.156.17.in-addr.arpa", action: .deny),
    Rule(processName: "mDNSResponder", remoteHost: "0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.b.6.7.0.6.2.ip6.arpa", action: .deny),
]
let normal = [
    Rule(processName: "curl", remoteHost: "example.com", remotePort: 443, action: .deny),
    Rule(processName: "Safari", remoteIP: "203.0.113.7", action: .allow),
]
let mixed = legacy + normal

// 1. A stored batch containing legacy rows must still encode and decode.
do {
    let data = try RuleTransportBoundary.encodeRuleBatch(mixed)
    let back = try FreeSnitchWireCodec.decode([Rule].self, from: data)
    check(back.count == mixed.count, "rule batch lost rules: \(back.count) of \(mixed.count)")
    check(!data.isEmpty, "rule batch encoded to empty data")
} catch {
    failures.append("listing a stored batch with legacy rules still fails: \(error)")
}

// 2. A snapshot containing legacy rows must still reach the extension.
do {
    let snapshot = SharedRuleBridge.Snapshot(mode: .alert, rules: mixed, updatedAt: Date())
    let data = try SharedRuleBridge.encode(snapshot)
    let back = try SharedRuleBridge.decode(data)
    check(back.rules.count == mixed.count, "snapshot lost rules: \(back.rules.count) of \(mixed.count)")
} catch {
    failures.append("delivering a snapshot with legacy rules still fails: \(error)")
}

// 3. Ingest must STILL refuse a reverse-DNS rule, which is the #15 guarantee.
for rule in legacy {
    do {
        try RuleTransportBoundary.validate(rule: rule)
        failures.append("ingest accepted a reverse-DNS rule, which #15 forbids: \(rule.remoteHost ?? "?")")
    } catch { /* expected */ }
}

// 4. Bounds must still be enforced on transport.
do {
    try RuleTransportBoundary.validateBounds(rules: (0..<(RuleTransportBoundary.maximumDecodedRuleCount + 1)).map { _ in Rule() })
    failures.append("an over-count batch was accepted")
} catch { /* expected */ }

if failures.isEmpty {
    print("legacy rules present: \(legacy.count), total in batch: \(mixed.count)")
    print("listing and snapshot delivery both survive legacy rows; ingest still refuses them")
    print("legacy rule egress verification: PASS")
} else {
    for f in failures { print("FAIL \(f)") }
    print("legacy rule egress verification: FAIL (\(failures.count))")
    exit(1)
}
