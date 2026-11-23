#!/usr/bin/env bash
# A rule's port 0 matches nothing, never every port (issue #218).
#
# Port 0 used to be read as "no port". A deny rule whose only field was port 0
# then had no condition left and blocked every outgoing connection the Network
# Extension saw, and pf dropped the port from an address rule, so a deny for
# 203.0.113.7 port 0 blocked every port of that address. Compiled from the real
# helper and shared sources; nothing here loads pf (renderAnchor only builds
# the text, and the pfctl path is never run).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-port-zero.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

SDK="$(xcrun --show-sdk-path)"
TARGET="arm64-apple-macos13.0"

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

@main
struct Verify {
    static var failures = 0
    static func check(_ condition: Bool, _ label: String) {
        if condition { print("port zero harness: PASS: \(label)") }
        else { failures += 1; print("port zero harness: FAIL: \(label)") }
    }

    static func conn(_ port: Int, ip: String = "198.51.100.1") -> Connection {
        Connection(pid: 1, processName: "curl", processPath: "/usr/bin/curl", remoteIP: ip, remotePort: port)
    }

    /// The verdict through both matcher paths: the prepared set the extension
    /// and the DNS proxy use, and matches(rule:connection:) the helper uses.
    static func verdicts(_ rule: Rule, _ c: Connection) -> (prepared: RuleAction, direct: Bool) {
        let matcher = RuleMatcher()
        return (matcher.decision(for: c, rules: [rule], defaultMode: .silentAllow),
                matcher.matches(rule: rule, connection: c))
    }

    static func main() {
        // The report: a deny rule with port 0 and nothing else.
        let portZero = Rule(remotePort: 0, direction: .outgoing, action: .deny, scope: .port)
        for port in [80, 443] {
            let v = verdicts(portZero, conn(port))
            check(v.prepared == .allow && !v.direct, "a port 0 deny leaves port \(port) alone")
        }
        // A connection whose port is not known yet is recorded with port 0;
        // a port 0 rule matches nothing, so it never catches those either.
        let zero = verdicts(portZero, conn(0))
        check(zero.prepared == .allow && !zero.direct, "a port 0 deny leaves a flow with no known port alone")
        // The DNS proxy decides a lookup with a connection that has only a
        // host, so its port is 0 (Sources/Helper/DNSProxy.swift).
        let lookup = Connection(pid: 0, processName: "", processPath: "", remoteHost: "example.com", direction: .outgoing, status: .pending)
        let dns = verdicts(portZero, lookup)
        check(dns.prepared == .allow && !dns.direct, "a port 0 deny does not turn DNS lookups into NXDOMAIN")
        let dnsDefaultDeny = RuleMatcher().decision(for: lookup, rules: [Rule(remoteHost: "example.com", remotePort: 0, direction: .outgoing, action: .deny, scope: .domain)], defaultMode: .silentAllow)
        check(dnsDefaultDeny == .allow, "a host deny with port 0 does not block the host's lookups")

        // With an address, port 0 narrows the rule instead of vanishing.
        let addressZero = Rule(remoteIP: "203.0.113.7", remotePort: 0, direction: .outgoing, action: .deny, scope: .ip)
        let addr = verdicts(addressZero, conn(443, ip: "203.0.113.7"))
        check(addr.prepared == .allow && !addr.direct, "an address deny with port 0 leaves port 443 of that address alone")

        // A real port still works as before.
        let port443 = Rule(remotePort: 443, direction: .outgoing, action: .deny, scope: .port)
        check(verdicts(port443, conn(443)).prepared == .deny, "a port 443 deny still blocks port 443")
        check(verdicts(port443, conn(80)).prepared == .allow, "a port 443 deny leaves port 80 alone")
        let none = Rule(remoteIP: "203.0.113.7", direction: .outgoing, action: .deny, scope: .ip)
        check(verdicts(none, conn(8443, ip: "203.0.113.7")).prepared == .deny, "an address deny without a port still covers every port")

        // pf: the port is never dropped, so the address is not blocked on every port.
        var rejected: [String] = []
        let anchor = PFManager(anchorPath: "/nonexistent/freesnitch-test", pfctl: "/usr/bin/false")
            .renderAnchor(rules: [addressZero, portZero]) { _, reason in rejected.append(reason) }
        check(!anchor.split(separator: "\n").contains { $0.hasPrefix("block") && $0.contains("203.0.113.7") },
              "pf does not block every port of an address for a port 0 rule")
        check(!anchor.split(separator: "\n").contains { $0.hasPrefix("block") && $0.contains("port 0") },
              "pf gets no port 0 line")
        check(rejected.count == 2, "pf reports both port 0 rules as left to the Network Extension (\(rejected))")
        let real = PFManager(anchorPath: "/nonexistent/freesnitch-test", pfctl: "/usr/bin/false")
            .renderAnchor(rules: [Rule(remoteIP: "203.0.113.7", remotePort: 8443, direction: .outgoing, action: .deny, scope: .ip)])
        check(real.split(separator: "\n").contains { $0.hasPrefix("block") && $0.contains("203.0.113.7 port 8443") },
              "pf still gets an address rule with a real port")

        // Editing: the sheet shows port 0 as 0, so clearing it removes it and
        // leaving it keeps it.
        let edited: (Int?) -> Rule = { port in
            RuleEdit(process: .anyApp, bundleId: nil, remoteHost: nil, remoteIP: "203.0.113.7", remotePort: port,
                     direction: addressZero.direction, action: addressZero.action, scope: addressZero.scope,
                     profile: addressZero.profile, notes: nil, enabled: true)
                .applied(to: addressZero, openedWith: addressZero)
        }
        check(edited(nil).remotePort == nil, "clearing port 0 in the editor removes it")
        check(edited(0).remotePort == 0, "an untouched port 0 is kept as it was")
        check(edited(443).remotePort == 443, "a new port replaces port 0")

        if failures > 0 { print("port zero harness: \(failures) FAILED"); exit(1) }
        print("port zero verification: PASS")
    }
}
SWIFT

# shellcheck disable=SC2046
xcrun swiftc -O -sdk "$SDK" -target "$TARGET" -parse-as-library \
  -o "$TMP/run" \
  $(ls "$ROOT"/Sources/Helper/*.swift | grep -v '/main.swift$') \
  "$ROOT"/Sources/Shared/*.swift \
  "$TMP/verify.swift"
"$TMP/run"
