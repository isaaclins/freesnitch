#!/usr/bin/env bash
# Deterministic harness for the IP and CIDR blocklists (issue #51).
#
# The harness is compiled from the real helper and shared sources, never from a
# copy, so it exercises the shipping IPBlocklistSet, IPBlocklistPolicy,
# BlocklistManager and PFManager. It asserts, in this order:
#
#   1. IPv4 and IPv6 CIDR membership, including both boundaries of a range.
#   2. A prefix above 32 for IPv4 or above 128 for IPv6 is rejected, and a
#      rejected entry matches nothing rather than everything.
#   3. Loopback, the configured resolvers, DHCP and the app's own traffic are
#      never blocked, even when a feed lists them explicitly, and the pf anchor
#      never emits them.
#      Deny rules that name an app are never written to pf (issue #155), nor
#      are denies that name a hostname and an address (issue #302).
#   4. A malformed or unreachable feed leaves enforcement fail-open, and an
#      address feed never leaks into the domain blocklist.
#   5. Matching is bounded: a lookup allocates nothing that grows with the set,
#      and a lookup takes at most floor(log2(n)) + 1 search steps, counted, not timed.
#   6. A feed of more than 100k entries loads fully and answers correctly. The
#      load and lookup times are printed, and only checked against a limit when
#      FREESNITCH_BENCH=1 is set, so a busy machine cannot fail the harness
#      (issue #356). Lookup cost is already bounded by the counted steps in 5.
#   7. Every anchor rendered above is valid pf: each rule line is checked
#      against the grammar here, and parsed by `pfctl -n` (parse only, nothing
#      is loaded) wherever pfctl can run. One line pf refuses makes it refuse
#      the whole anchor (issue #298).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-ip-blocklists.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

SDK="$(xcrun --show-sdk-path)"
TARGET="arm64-apple-macos13.0"

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation
import Darwin

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

    func note(_ message: String) {
        print("ip blocklist harness: \(message)")
    }

    func finish(_ label: String) {
        guard failures.isEmpty else {
            for failure in failures {
                FileHandle.standardError.write(Data(("ip blocklist harness: FAIL: " + failure + "\n").utf8))
            }
            exit(1)
        }
        print("ip blocklist harness: \(label): \(passed) assertions PASS")
    }
}

/// pf takes `port` only after a `from` or `to` host (pf.conf(5), `hosts`).
/// A bare `port N` is a syntax error, and pfctl then refuses the whole anchor
/// (issue #298). The rendered anchor is also kept for `pfctl -n` below.
func checkPFSyntax(_ name: String, _ anchor: String, _ checks: Checks) {
    for line in anchor.split(separator: "\n").map(String.init)
    where !line.hasPrefix("#") && line.contains(" port ") {
        let beforePort = line.components(separatedBy: " port ")[0]
        checks.expect(beforePort.contains(" to ") || beforePort.contains(" from "),
                      "\(name): pf refuses a port without a host before it: '\(line)'")
    }
    if let dir = ProcessInfo.processInfo.environment["PF_SYNTAX_DIR"] {
        do {
            try anchor.write(toFile: "\(dir)/\(name).conf", atomically: true, encoding: .utf8)
        } catch {
            checks.expect(false, "\(name): could not keep the anchor for pfctl: \(error)")
        }
    }
}

/// The outgoing half of a user's deny.
func blocks(_ anchor: String, _ target: String) -> Bool {
    anchor.contains("block out quick proto { tcp udp } \(target)\n")
}

func generatedEntries(_ count: Int) -> [String] {
    // Distinct, non-adjacent /25 networks, so nothing merges and the range
    // count really is the entry count. 33.0.0.0 and up is ordinary public
    // space: none of it is loopback, private, link-local or multicast.
    var entries: [String] = []
    entries.reserveCapacity(count)
    for index in 0..<count {
        let a = 33 + index / 65_536
        let b = (index / 256) % 256
        let c = index % 256
        entries.append("\(a).\(b).\(c).0/25")
    }
    return entries
}

@main
struct IPBlocklistHarness {
    static func main() async {
        let checks = Checks()

        // 1. IPv4 membership and boundaries.
        let v4 = IPBlocklistSet(entries: ["203.0.113.0/24", "198.51.100.7", "8.8.4.0/30"])
        checks.expect(v4.acceptedEntryCount == 3, "three valid IPv4 entries should be accepted, got \(v4.acceptedEntryCount)")
        checks.expect(v4.contains("203.0.113.0"), "the first address of 203.0.113.0/24 must match")
        checks.expect(v4.contains("203.0.113.255"), "the last address of 203.0.113.0/24 must match")
        checks.expect(!v4.contains("203.0.112.255"), "the address below 203.0.113.0/24 must not match")
        checks.expect(!v4.contains("203.0.114.0"), "the address above 203.0.113.0/24 must not match")
        checks.expect(v4.contains("198.51.100.7"), "a bare IPv4 literal must match itself")
        checks.expect(!v4.contains("198.51.100.8"), "a bare IPv4 literal must not match its neighbour")
        checks.expect(v4.contains("8.8.4.0") && v4.contains("8.8.4.3"), "both ends of a /30 must match")
        checks.expect(!v4.contains("8.8.4.4"), "the address past a /30 must not match")
        checks.expect(!v4.contains("2001:db8::1"), "an IPv4 set must never answer for an IPv6 address")

        // 2. IPv6 membership and boundaries.
        let v6 = IPBlocklistSet(entries: ["2001:db8::/32", "2606:4700::1"])
        checks.expect(v6.acceptedEntryCount == 2, "two valid IPv6 entries should be accepted, got \(v6.acceptedEntryCount)")
        checks.expect(v6.contains("2001:db8::"), "the first address of 2001:db8::/32 must match")
        checks.expect(v6.contains("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"), "the last address of 2001:db8::/32 must match")
        checks.expect(!v6.contains("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff"), "the address below 2001:db8::/32 must not match")
        checks.expect(!v6.contains("2001:db9::"), "the address above 2001:db8::/32 must not match")
        checks.expect(v6.contains("2606:4700:0000::1"), "an IPv6 literal must match another spelling of the same address")
        checks.expect(!v6.contains("2606:4700::2"), "an IPv6 literal must not match its neighbour")
        checks.expect(!v6.contains("192.0.2.1"), "an IPv6 set must never answer for an IPv4 address")

        // 3. Prefix length bounds, the #37 and #41 rule.
        let overlong = IPBlocklistSet(entries: [
            "203.0.113.0/33",
            "203.0.113.0/64",
            "2001:db8::/129",
            "2001:db8::/255",
            "203.0.113.0/-1",
            "203.0.113.0/x",
            "203.0.113.0/"
        ])
        checks.expect(overlong.acceptedEntryCount == 0, "no over-long or non-numeric prefix may be accepted, got \(overlong.acceptedEntryCount)")
        checks.expect(overlong.rejectedEntryCount == 7, "every malformed prefix must be counted as rejected, got \(overlong.rejectedEntryCount)")
        checks.expect(overlong.isEmpty, "a set built only from malformed prefixes must be empty")
        checks.expect(!overlong.contains("203.0.113.5"), "a rejected /33 must not match its own network")
        checks.expect(!overlong.contains("1.2.3.4"), "a rejected prefix must never widen into a match-everything mask")
        checks.expect(!overlong.contains("2001:db8::1"), "a rejected /129 must not match its own network")

        let edge = IPBlocklistSet(entries: ["203.0.113.5/32", "2001:db8::5/128", "203.0.113.0/31"])
        checks.expect(edge.acceptedEntryCount == 3, "the maximum legal prefix lengths must still be accepted")
        checks.expect(edge.contains("203.0.113.5") && !edge.contains("203.0.113.6"), "a /32 must cover exactly one address")
        checks.expect(edge.contains("2001:db8::5") && !edge.contains("2001:db8::6"), "a /128 must cover exactly one address")
        checks.expect(edge.contains("203.0.113.0") && edge.contains("203.0.113.1"), "a /31 must cover exactly two addresses")

        // 4. A hostile feed. Everything protected is refused at load, and the
        //    bypasses outrank whatever survives.
        let hostileEntries = [
            "127.0.0.1", "127.0.0.0/8", "::1", "localhost",
            "0.0.0.0", "0.0.0.0/0", "::/0", "255.255.255.255",
            "10.0.0.0/8", "172.16.0.0/12", "192.168.1.0/24", "169.254.0.0/16",
            "224.0.0.0/4", "ff00::/8", "fe80::/10", "fc00::/7",
            "9.9.9.9", "203.0.113.9", "2606:4700::1"
        ]
        let hostile = IPBlocklistSet(entries: hostileEntries)
        checks.expect(hostile.acceptedEntryCount == 3, "only the three non-protected entries may enter the set, got \(hostile.acceptedEntryCount)")
        for refused in ["127.0.0.1", "127.0.0.53", "::1", "0.0.0.0", "255.255.255.255",
                        "10.1.2.3", "172.16.9.9", "192.168.1.4", "169.254.1.1",
                        "224.0.0.251", "ff02::fb", "fe80::1", "fd00::1"] {
            checks.expect(!hostile.contains(refused), "a feed must never be able to block \(refused)")
        }
        checks.expect(hostile.contains("203.0.113.9"), "an ordinary public address from the feed must match")
        checks.expect(hostile.contains("9.9.9.9"), "a public resolver address is in the set; the bypass, not the set, must protect it")

        let resolvers = ["9.9.9.9", "192.168.1.1", "2606:4700:4700::1111"]
        let policy = IPBlocklistPolicy(
            enforcementEnabled: true,
            blocked: hostile,
            resolverAddresses: resolvers,
            feeds: [IPBlocklistFeed(name: "harness", url: "https://example.invalid/feed", enabled: true, entryCount: 3)]
        )
        checks.expect(policy.verdict(remoteIP: "203.0.113.9", remotePort: 443, isOwnTraffic: false) == .blocked,
                      "an enforced feed entry must block")
        checks.expect(policy.verdict(remoteIP: "2606:4700::1", remotePort: 443, isOwnTraffic: false) == .blocked,
                      "an enforced IPv6 feed entry must block")
        checks.expect(policy.verdict(remoteIP: "203.0.113.9", remotePort: 443, isOwnTraffic: true) == .exemptOwnTraffic,
                      "FreeSnitch's own traffic must never be blocked by a feed")
        checks.expect(policy.verdict(remoteIP: "127.0.0.1", remotePort: 443, isOwnTraffic: false) == .exemptLoopback,
                      "loopback must never be blocked by a feed")
        checks.expect(policy.verdict(remoteIP: "::1", remotePort: 443, isOwnTraffic: false) == .exemptLoopback,
                      "IPv6 loopback must never be blocked by a feed")
        checks.expect(policy.verdict(remoteIP: "0:0:0:0:0:0:0:1", remotePort: 443, isOwnTraffic: false) == .exemptLoopback,
                      "expanded IPv6 loopback must never be blocked by a feed")
        for dnsOrDHCPPort in [53, 67, 68, 546, 547] {
            checks.expect(policy.verdict(remoteIP: "203.0.113.9", remotePort: dnsOrDHCPPort, isOwnTraffic: false) == .exemptInfrastructurePort,
                          "port \(dnsOrDHCPPort) carries DNS or DHCP and must never be blocked by a feed")
        }
        checks.expect(policy.verdict(remoteIP: "9.9.9.9", remotePort: 443, isOwnTraffic: false) == .exemptResolver,
                      "a configured resolver must never be blocked by a feed, on any port")
        checks.expect(policy.verdict(remoteIP: "2606:4700:4700::1111", remotePort: 443, isOwnTraffic: false) == .exemptResolver,
                      "a configured IPv6 resolver must never be blocked by a feed")
        checks.expect(policy.verdict(remoteIP: "198.51.100.1", remotePort: 443, isOwnTraffic: false) == .allowed,
                      "an address no feed lists must be allowed")
        if let parsed = IPBlocklistAddress.parse("203.0.113.9") {
            checks.expect(policy.verdict(address: parsed, remotePort: 443, isOwnTraffic: false) == .blocked,
                          "the pre-parsed verdict path must block without reparsing")
        } else {
            checks.expect(false, "the test address must be parseable for the allocation-free verdict path")
        }

        // 5. Honest state. Enforcement off means blocking nothing.
        let observing = policy.withEnforcement(false)
        checks.expect(observing.verdict(remoteIP: "203.0.113.9", remotePort: 443, isOwnTraffic: false) == .notEnforced,
                      "with enforcement off a listed address must not be reported as blocked")
        checks.expect(observing.status.blockingEntryCount == 0,
                      "with enforcement off the blocking count must be zero, got \(observing.status.blockingEntryCount)")
        checks.expect(observing.status.loadedEntryCount == 3,
                      "with enforcement off the loaded count must still be honest, got \(observing.status.loadedEntryCount)")
        checks.expect(observing.status.summary.contains("blocking nothing"),
                      "the disabled summary must say the list is blocking nothing, got '\(observing.status.summary)'")
        checks.expect(policy.status.blockingEntryCount == 3,
                      "with enforcement on the blocking count must equal the loaded count")

        // 6. The pf anchor. The bypasses are rendered ahead of the block, and
        //    nothing protected is ever emitted.
        let pf = PFManager()
        let anchor = pf.renderAnchor(rules: [], ipBlocklist: hostile, resolverAddresses: resolvers)
        checkPFSyntax("feed", anchor, checks)
        checks.expect(anchor.contains("set skip on lo0"), "the anchor must keep skipping loopback")
        checks.expect(anchor.contains("table <freesnitch_ipblock> persist {"), "the anchor must render the feed as one pf table")
        checks.expect(anchor.contains("block out quick proto { tcp udp } to <freesnitch_ipblock>"),
                      "the anchor must block traffic to the feed table")
        checks.expect(anchor.contains("pass out quick proto { tcp udp } to any port 53"), "the anchor must pass DNS ahead of the feed")
        checks.expect(anchor.contains("pass out quick proto { tcp udp } to any port { 67 68 }"), "the anchor must pass DHCP ahead of the feed")
        checks.expect(anchor.contains("pass out quick to 9.9.9.9"), "the anchor must pass the configured resolver ahead of the feed")
        checks.expect(anchor.contains("203.0.113.9"), "the anchor table must carry the feed entry")
        for refused in ["127.0.0.0/8", "10.0.0.0/8", "169.254.0.0/16", "224.0.0.4", "255.255.255.255", "fe80::/10"] {
            checks.expect(!anchor.contains(refused), "the anchor must never carry \(refused)")
        }
        let passIndex = anchor.range(of: "pass out quick proto { tcp udp } to any port 53")?.lowerBound
        let blockIndex = anchor.range(of: "block out quick proto { tcp udp } to <freesnitch_ipblock>")?.lowerBound
        checks.expect(passIndex != nil && blockIndex != nil && passIndex! < blockIndex!,
                      "the DNS and DHCP passes must precede the feed block, since every rule here is quick")
        let plain = pf.renderAnchor(rules: [])
        checkPFSyntax("plain", plain, checks)
        checks.expect(!plain.contains("freesnitch_ipblock"),
                      "an anchor with no feed loaded must not mention the feed table at all")

        // Deny rules that name an app never reach pf, which cannot tell
        // processes apart (issue #155). Allow rules still do, so a feed can
        // never block what the user allowed for an app. Which rules name an
        // app is decided exactly as the matcher decides it.
        let appScoped = pf.renderAnchor(rules: [
            Rule(processBundleId: "com.hnc.Discord", remoteIP: "162.159.128.233", action: .deny, scope: .ip),
            Rule(processPath: "/Applications/Firefox.app/", remotePort: 443, action: .deny, scope: .port),
            Rule(processPath: "/usr/bin/curl", remoteIP: "198.51.100.21", action: .allow, scope: .ip),
            Rule(processName: "Discord", remoteIP: "198.51.100.20", action: .deny, scope: .ip),
            Rule(processBundleId: "  ", remoteIP: "198.51.100.30", action: .deny, scope: .ip),
            Rule(processBundleId: "", processPath: "", remoteIP: "198.51.100.31", action: .deny, scope: .ip),
            Rule(remotePort: 8443, action: .deny, scope: .port)
        ], ipBlocklist: hostile, resolverAddresses: resolvers)
        checkPFSyntax("app-scoped", appScoped, checks)
        for leaked in ["162.159.128.233", "port 443", "198.51.100.30"] {
            checks.expect(!appScoped.contains(leaked),
                          "a deny rule that names an app must not be written to pf, but the anchor carries \(leaked)")
        }
        checks.expect(appScoped.contains("pass out quick proto { tcp udp } to 198.51.100.21"),
                      "an app's allow rule must still reach pf, so the feed cannot block what the user allowed")
        checks.expect(blocks(appScoped, "to 198.51.100.20"),
                      "a name alone identifies no app for the matcher, so pf must treat the rule as every app's too")
        checks.expect(blocks(appScoped, "to 198.51.100.31"),
                      "empty app fields are no app, as in the matcher")
        checks.expect(blocks(appScoped, "to any port 8443"),
                      "a rule with no app must still be written to pf")
        let allowIndex = appScoped.range(of: "to 198.51.100.21")?.lowerBound
        let feedIndex = appScoped.range(of: "to <freesnitch_ipblock>")?.lowerBound
        checks.expect(allowIndex != nil && feedIndex != nil && allowIndex! < feedIndex!,
                      "the user's allow must come before the feed's block")

        // A rule that names a hostname and an address matches only when both
        // fit, but pf sees only the address (issue #302). A deny written as
        // the address would block every name on it, so it stays out of pf and
        // the refusal is reported. An allow still goes out as the address: a
        // pass can only block less, and the feed must not block what the user
        // allowed.
        var hostAndAddressRefusals: [String] = []
        let hostAndAddress = pf.renderAnchor(rules: [
            Rule(remoteHost: "tracker.example.com", remoteIP: "198.51.100.40", action: .deny, scope: .ip),
            Rule(remoteHost: "*.example.net", remoteIP: "198.51.100.0/24", remotePort: 443, action: .deny, scope: .ip),
            Rule(remoteHost: "api.example.org", remoteIP: "198.51.100.41", action: .allow, scope: .ip),
            Rule(remoteIP: "198.51.100.42", action: .deny, scope: .ip)
        ], ipBlocklist: hostile, resolverAddresses: resolvers) { _, reason in
            hostAndAddressRefusals.append(reason)
        }
        for leaked in ["198.51.100.40", "198.51.100.0/24"] {
            checks.expect(!hostAndAddress.contains(leaked),
                          "a deny that names a hostname and an address must not reach pf as the address alone, but the anchor carries \(leaked)")
        }
        checks.expect(hostAndAddressRefusals.count == 2
                      && hostAndAddressRefusals.allSatisfy { $0.contains("names hostname") },
                      "both skipped hostname-and-address denies must be reported, got \(hostAndAddressRefusals)")
        checks.expect(hostAndAddress.contains("pass out quick proto { tcp udp } to 198.51.100.41"),
                      "an allow that names a hostname and an address must still reach pf as the address")
        checks.expect(hostAndAddress.contains("block out quick proto { tcp udp } to 198.51.100.42"),
                      "a deny with an address and no hostname must still be written to pf")
        let hostAllowIndex = hostAndAddress.range(of: "to 198.51.100.41")?.lowerBound
        let hostFeedIndex = hostAndAddress.range(of: "to <freesnitch_ipblock>")?.lowerBound
        checks.expect(hostAllowIndex != nil && hostFeedIndex != nil && hostAllowIndex! < hostFeedIndex!,
                      "the hostname-and-address allow must come before the feed's block")

        // An address typed into the hostname field (no remoteIP) is written
        // to pf as that address, so the matcher must apply it to every flow
        // to that address, including one macOS reports under a name. Then pf
        // and the Network Extension agree on what the rule covers (#307).
        let addressInHost = [
            Rule(remoteHost: "203.0.113.70", action: .deny, scope: .domain),
            Rule(remoteHost: "198.51.100.0/24", remotePort: 8443, action: .deny, scope: .domain),
            Rule(remoteHost: "2001:db8::70", action: .deny, scope: .domain),
            Rule(remoteHost: "203.0.113.71", action: .allow, scope: .domain),
            Rule(remoteHost: "tracker.example.com", action: .deny, scope: .domain)
        ]
        let addressInHostAnchor = pf.renderAnchor(rules: addressInHost)
        checks.expect(addressInHostAnchor.contains("block out quick proto { tcp udp } to 203.0.113.70"),
                      "an address in the hostname field of a deny is written to pf as that address")
        checks.expect(addressInHostAnchor.contains("block out quick proto { tcp udp } to 198.51.100.0/24 port 8443"),
                      "a range in the hostname field of a deny is written to pf as that range")
        checks.expect(addressInHostAnchor.contains("pass out quick proto { tcp udp } to 203.0.113.71"),
                      "an address in the hostname field of an allow is written to pf as that address")
        checks.expect(!addressInHostAnchor.contains("tracker.example.com"),
                      "a real hostname must still stay out of pf")
        let matcher = RuleMatcher()
        let preparedAddressInHost = PreparedRuleSet(rules: addressInHost)
        func verdict(host: String, ip: String, port: Int = 443) -> (RuleAction, RuleAction) {
            let flow = Connection(pid: 1, processName: "curl", processPath: "/usr/bin/curl",
                                  remoteHost: host, remoteIP: ip, remotePort: port)
            return (matcher.decision(for: flow, prepared: preparedAddressInHost, defaultMode: .silentAllow),
                    matcher.decision(for: flow, rules: addressInHost, defaultMode: .silentAllow))
        }
        func expectVerdict(_ expected: RuleAction, host: String, ip: String, port: Int = 443, _ why: String) {
            let (prepared, unprepared) = verdict(host: host, ip: ip, port: port)
            checks.expect(prepared == expected && unprepared == expected,
                          "\(why): expected \(expected), prepared \(prepared), unprepared \(unprepared)")
            let flow = Connection(pid: 1, processName: "curl", processPath: "/usr/bin/curl",
                                  remoteHost: host, remoteIP: ip, remotePort: port)
            let single = addressInHost.first { matcher.matches(rule: $0, connection: flow) }?.action ?? .allow
            checks.expect(single == expected,
                          "\(why): matches(rule:connection:) gave \(single)")
        }
        expectVerdict(.deny, host: "cdn.example.com", ip: "203.0.113.70",
                      "a flow to the address that arrives under a name must match the deny, as pf blocks it")
        expectVerdict(.deny, host: "203.0.113.70", ip: "203.0.113.70",
                      "a flow to the address with no name must still match the deny")
        expectVerdict(.deny, host: "api.example.net", ip: "198.51.100.9", port: 8443,
                      "a named flow inside the range on the rule's port must match the deny")
        expectVerdict(.allow, host: "api.example.net", ip: "198.51.100.9", port: 443,
                      "a flow inside the range on another port must not match the deny")
        expectVerdict(.deny, host: "v6.example.com", ip: "2001:0db8:0000:0000:0000:0000:0000:0070",
                      "an IPv6 address in the hostname field must match the flow's address in any spelling")
        expectVerdict(.allow, host: "cdn.example.com", ip: "203.0.113.72",
                      "a named flow to another address must not match the address deny")
        expectVerdict(.deny, host: "tracker.example.com", ip: "203.0.113.99",
                      "a hostname rule must still match by name")
        expectVerdict(.allow, host: "other.example.com", ip: "203.0.113.99",
                      "a hostname rule must not match by address")
        let allowFirst = [
            Rule(remoteHost: "203.0.113.71", action: .allow, scope: .domain, priority: 200),
            Rule(remoteIP: "203.0.113.0/24", action: .deny, scope: .ip)
        ]
        let namedToAllowed = Connection(pid: 1, processName: "curl", processPath: "/usr/bin/curl",
                                        remoteHost: "cdn.example.com", remoteIP: "203.0.113.71", remotePort: 443)
        checks.expect(matcher.decision(for: namedToAllowed, rules: allowFirst, defaultMode: .silentDeny) == .allow,
                      "an address in the hostname field of an allow must match a named flow, as pf passes it")
        checks.expect(Rule(remoteHost: "203.0.113.70", remoteIP: "203.0.113.80", action: .deny).addressInHostField == nil,
                      "a rule with its own address keeps the hostname field as a name")

        // A user's deny can never take DHCP or DHCPv6 away, whatever the
        // direction (issue #186). The refusal is reported, not silent.
        var refusedPorts: [String] = []
        let infrastructure = pf.renderAnchor(rules: [
            Rule(remotePort: 67, action: .deny, scope: .port),
            Rule(remotePort: 68, direction: .incoming, action: .deny, scope: .port),
            Rule(remotePort: 546, action: .deny, scope: .port),
            Rule(remotePort: 546, direction: .incoming, action: .deny, scope: .port),
            Rule(remoteIP: "203.0.113.40", remotePort: 547, direction: .outgoing, action: .deny, scope: .ip),
            Rule(remotePort: 547, action: .allow, scope: .port),
            Rule(remotePort: 548, action: .deny, scope: .port),
            Rule(remotePort: 549, direction: .incoming, action: .deny, scope: .port),
            Rule(remotePort: 550, direction: .any, action: .allow, scope: .port)
        ]) { _, reason in refusedPorts.append(reason) }
        checkPFSyntax("infrastructure", infrastructure, checks)
        let blockLines = infrastructure.split(separator: "\n").filter { $0.hasPrefix("block") }
        for port in [67, 68, 546] {
            checks.expect(!blockLines.contains { $0.split(separator: " ").map(String.init).contains("\(port)") },
                          "a deny on port \(port) must never be written to pf")
        }
        checks.expect(!infrastructure.contains("203.0.113.40"),
                      "a deny on port 547 must never be written to pf, even with an address")
        checks.expect(infrastructure.contains("pass out quick proto { tcp udp } to any port 547"),
                      "an allow on a DHCPv6 port must still be written, since a pass can only block less")
        checks.expect(blocks(infrastructure, "to any port 548"),
                      "a deny on an ordinary port next to DHCPv6 must still be written")
        // A rule with only a port matches any host (issue #298).
        checks.expect(infrastructure.contains("pass out quick proto { tcp udp } to any port 550\n")
                        && !infrastructure.contains("from any port 550"),
                      "a port-only allow in both directions must be written as its outgoing half only")
        checks.expect(refusedPorts.contains { $0.contains("incoming half of an allow with only a port") },
                      "a port-only allow in both directions must report that its incoming half stays out of pf, got \(refusedPorts)")
        // An incoming deny names the remote side, so pf gets `from`, never
        // `in ... to`, which would be this Mac's own port. Its TCP half only
        // stops new connections, and its UDP half is left to the extension,
        // since pf cannot tell a new incoming datagram from a reply.
        checks.expect(infrastructure.contains("block in quick proto tcp from any port 549 flags S/SA\n"),
                      "an incoming port-only deny must be written as from any port, SYN only")
        checks.expect(!infrastructure.contains("udp from any port 549") && !infrastructure.contains("to any port 549"),
                      "an incoming-only deny must not block UDP replies or this Mac's own port")
        checks.expect(!blockLines.contains { $0.hasPrefix("block quick") || ($0.hasPrefix("block in") && $0.contains(" to ")) },
                      "a deny must never be written as a block on this Mac's own address or port")
        checks.expect(refusedPorts.filter { $0.contains("could disable DHCP") && !$0.contains("DHCPv6") }.count == 2,
                      "every DHCP refusal must be reported with a reason, got \(refusedPorts)")
        let bothWays = pf.renderAnchor(rules: [
            Rule(remoteIP: "203.0.113.41", remotePort: 8080, direction: .any, action: .deny, scope: .ip),
            Rule(remotePort: 8081, direction: .any, action: .deny, scope: .port)
        ])
        checkPFSyntax("both-ways", bothWays, checks)
        checks.expect(blocks(bothWays, "to 203.0.113.41 port 8080")
                        && blocks(bothWays, "to any port 8081"),
                      "a deny in both directions must block going out")
        // Both ways means new incoming connections from the remote side too,
        // blocked by their own line rather than only by dropped replies.
        for remote in ["from 203.0.113.41 port 8080", "from any port 8081"] {
            checks.expect(bothWays.contains("block in quick proto tcp \(remote) flags S/SA\n")
                            && bothWays.contains("block in quick proto udp \(remote)\n"),
                          "a deny in both directions must block coming in from the remote side: \(remote)")
        }
        // A block keeps no state in pf, so an incoming TCP line without
        // `flags S/SA` would drop the replies to this Mac's own connections.
        for anchorText in [appScoped, infrastructure, bothWays] {
            for line in anchorText.split(separator: "\n") where line.hasPrefix("block in") {
                checks.expect(line.hasPrefix("block in quick proto tcp from ") && line.hasSuffix(" flags S/SA")
                                || line.hasPrefix("block in quick proto udp from "),
                              "an incoming deny must only block new TCP connections from the remote side, got '\(line)'")
            }
        }
        checks.expect(!infrastructure.contains("block in quick proto udp"),
                      "only a deny in both directions may block incoming UDP, which pf cannot tell from a reply")
        checks.expect(refusedPorts.filter { $0.contains("could disable DHCPv6") }.count == 3,
                      "every DHCPv6 refusal must be reported with a reason, got \(refusedPorts)")

        // An allow names the remote peer, as the matcher and the Network
        // Extension read remoteIP and remotePort. For an incoming connection
        // that peer is where the packet comes from, so pf must get `from`;
        // `pass in ... to X port N` would name this Mac's own address and
        // port, letting anything in on that local port past the system's own
        // pf.conf (#301). The peer is also in a feed: the pass keeps state,
        // so this Mac's replies to it are not dropped by the feed's block.
        let peerFeed = IPBlocklistSet(entries: ["203.0.113.50"])
        var incomingRefusals: [String] = []
        let incomingAllows = pf.renderAnchor(rules: [
            Rule(remoteIP: "203.0.113.50", remotePort: 51000, direction: .incoming, action: .allow, scope: .ip),
            Rule(remotePort: 51001, direction: .incoming, action: .allow, scope: .port),
            Rule(remoteIP: "203.0.113.51", direction: .any, action: .allow, scope: .ip),
            Rule(remoteIP: "203.0.113.52", remotePort: 51002, direction: .outgoing, action: .allow, scope: .ip)
        ], ipBlocklist: peerFeed, resolverAddresses: resolvers) { _, reason in incomingRefusals.append(reason) }
        checkPFSyntax("incoming-allows", incomingAllows, checks)
        let passLines = incomingAllows.split(separator: "\n").map(String.init).filter { $0.hasPrefix("pass") }
        checks.expect(passLines.contains("pass in quick proto { tcp udp } from 203.0.113.50 port 51000"),
                      "an incoming allow with an address and port must be written as from the remote peer")
        // `pass in ... from any port N` would let anyone using source port N
        // reach every local port, so a port-only incoming allow stays with
        // the extension, and says so.
        checks.expect(!incomingAllows.contains("51001"),
                      "a port-only incoming allow must never be written to pf")
        checks.expect(incomingRefusals.contains { $0.contains("incoming allow with only a port") },
                      "a port-only incoming allow left out of pf must be reported with a reason, got \(incomingRefusals)")
        checks.expect(!passLines.contains { $0.hasPrefix("pass in") && $0.contains("from any") },
                      "an incoming pass must always name the peer's address")
        checks.expect(passLines.contains("pass out quick proto { tcp udp } to 203.0.113.51")
                        && passLines.contains("pass in quick proto { tcp udp } from 203.0.113.51"),
                      "an allow in both directions must be written as both halves")
        checks.expect(passLines.contains("pass out quick proto { tcp udp } to 203.0.113.52 port 51002")
                        && !incomingAllows.contains("from 203.0.113.52"),
                      "an outgoing allow must stay to the remote peer and nothing else")
        checks.expect(!passLines.contains { $0.hasPrefix("pass in") && $0.contains(" to ") },
                      "an incoming allow must never name this Mac's own side with to")
        checks.expect(!passLines.contains { $0.hasPrefix("pass quick") },
                      "an allow must always name its direction, so to and from mean the remote peer")

        // A temporary rule leaves pf when it expires, as it leaves the matcher,
        // and the next expiry is when the anchor must be rendered again
        // (issue #180).
        let clock = Date(timeIntervalSince1970: 1_800_000_000)
        let temporary = [
            Rule(remoteIP: "203.0.113.5", action: .deny, scope: .ip, temporary: true,
                 expiresAt: clock.addingTimeInterval(-1)),
            Rule(remoteIP: "203.0.113.6", action: .allow, scope: .ip, temporary: true,
                 expiresAt: clock.addingTimeInterval(-3600)),
            Rule(remoteIP: "203.0.113.7", action: .deny, scope: .ip, temporary: true,
                 expiresAt: clock.addingTimeInterval(3600)),
            Rule(remoteIP: "203.0.113.8", action: .deny, scope: .ip, temporary: true,
                 expiresAt: clock),
            Rule(remoteIP: "203.0.113.9", action: .deny, scope: .ip, enabled: false, temporary: true,
                 expiresAt: clock.addingTimeInterval(60)),
            Rule(remoteIP: "203.0.113.10", action: .deny, scope: .ip)
        ]
        let expiring = pf.renderAnchor(rules: temporary, now: clock)
        checkPFSyntax("expiring", expiring, checks)
        checks.expect(!expiring.contains("203.0.113.5"), "an expired temporary deny must leave the pf anchor")
        checks.expect(!expiring.contains("203.0.113.6"), "an expired temporary allow must leave the pf anchor")
        checks.expect(blocks(expiring, "to 203.0.113.7"),
                      "a temporary deny that has not expired must stay in the anchor")
        checks.expect(expiring.contains("to 203.0.113.8"),
                      "a rule still applies at the instant it expires, as in the matcher")
        checks.expect(expiring.contains("to 203.0.113.10"), "a rule without an expiry must stay in the anchor")
        checks.expect(PFManager.nextExpiry(of: temporary, after: clock) == clock,
                      "the next render must come at the earliest expiry the anchor still carries")
        checks.expect(PFManager.nextExpiry(of: temporary, after: clock.addingTimeInterval(1)) == clock.addingTimeInterval(3600),
                      "after one rule runs out, the next render must come at the following expiry")
        checks.expect(PFManager.nextExpiry(of: temporary, after: clock.addingTimeInterval(7200)) == nil,
                      "with every temporary rule expired no render may be scheduled")
        checks.expect(PFManager.nextExpiry(of: [temporary[4], temporary[5]], after: clock) == nil,
                      "a disabled or permanent rule must never schedule a render")
        let appOnlyTemporary = Rule(processBundleId: "com.hnc.Discord", remoteIP: "203.0.113.11", action: .deny,
                                    scope: .ip, temporary: true, expiresAt: clock.addingTimeInterval(60))
        checks.expect(PFManager.nextExpiry(of: [appOnlyTemporary, temporary[2]], after: clock) == clock.addingTimeInterval(3600),
                      "a temporary rule pf never carries, such as an app's deny, must not schedule a render")

        // 7. Feed handling: unreachable, malformed, then usable. All fail open.
        let storePath = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("freesnitch-ipbl-\(UUID().uuidString).sqlite")
        guard let store = try? RuleStore(path: storePath) else {
            FileHandle.standardError.write(Data("ip blocklist harness: FAIL: could not open a temporary RuleStore\n".utf8))
            exit(1)
        }
        defer { try? FileManager.default.removeItem(atPath: storePath) }

        let manager = BlocklistManager(store: store)
        let feedID = IPBlocklistCatalog.defaults[0].id.uuidString
        checks.expect(IPBlocklistCatalog.defaults.allSatisfy { !$0.enabled },
                      "every catalog address feed must ship disabled")
        checks.expect(manager.setIPFeedEnabled(idString: feedID, enabled: true),
                      "enabling a known address feed must succeed")
        checks.expect(!manager.setIPFeedEnabled(idString: UUID().uuidString, enabled: true),
                      "enabling an unknown address feed must report failure rather than do nothing quietly")

        var updates = 0
        manager.onIPBlocklistUpdate = { _, _ in updates += 1 }

        manager.ipFeedFetcher = { _ in .failure("simulated network unreachable") }
        await manager.refreshIPBlocklists()
        checks.expect(manager.currentIPBlocklist().isEmpty, "an unreachable feed must leave the set empty")
        checks.expect(manager.ipBlocklistPolicy(enforcementEnabled: true)
                        .verdict(remoteIP: "203.0.113.9", remotePort: 443, isOwnTraffic: false) == .allowed,
                      "an unreachable feed must fail open, not block")
        checks.expect(manager.ipFeeds().first(where: { $0.id.uuidString == feedID })?.lastError != nil,
                      "an unreachable feed must record why it is enforcing nothing")
        checks.expect(manager.domains.isEmpty, "an address feed must never reach the domain blocklist")

        manager.ipFeedFetcher = { _ in
            .body("<html><head><title>404</title></head><body>Not Found</body></html>\nnot-an-ip\n999.1.1.1/24\nexample.com\n203.0.113.0/33\n")
        }
        await manager.refreshIPBlocklists()
        checks.expect(manager.currentIPBlocklist().isEmpty, "a malformed feed body must produce no entries")
        checks.expect(manager.ipBlocklistPolicy(enforcementEnabled: true)
                        .verdict(remoteIP: "203.0.113.9", remotePort: 443, isOwnTraffic: false) == .allowed,
                      "a malformed feed must fail open, not block")
        let malformedFeed = manager.ipFeeds().first(where: { $0.id.uuidString == feedID })
        checks.expect(malformedFeed?.entryCount == 0, "a malformed feed must report zero usable entries")
        checks.expect((malformedFeed?.rejectedCount ?? 0) > 0, "a malformed feed must report what it rejected")
        checks.expect(manager.domains.isEmpty, "a malformed address feed must never reach the domain blocklist")

        manager.ipFeedFetcher = { _ in
            .body("""
            # a comment
            ; another comment
            203.0.113.0/24 ; SBL0000
            9.9.9.9
            127.0.0.1
            192.168.1.0/24
            2001:db8::/32\r
            """)
        }
        await manager.refreshIPBlocklists()
        let loaded = manager.currentIPBlocklist()
        checks.expect(loaded.acceptedEntryCount == 3,
                      "a usable feed must accept exactly its non-protected entries, got \(loaded.acceptedEntryCount)")
        checks.expect(loaded.contains("203.0.113.7"), "a usable feed entry must match")
        checks.expect(loaded.contains("2001:db8::dead"), "a usable IPv6 feed entry must match")
        checks.expect(!loaded.contains("127.0.0.1") && !loaded.contains("192.168.1.4"),
                      "a usable feed must still not be able to block loopback or a local network")
        let live = manager.ipBlocklistPolicy(enforcementEnabled: true, resolverAddresses: ["9.9.9.9"])
        checks.expect(live.verdict(remoteIP: "203.0.113.7", remotePort: 443, isOwnTraffic: false) == .blocked,
                      "with enforcement on, a loaded feed entry must block")
        checks.expect(live.verdict(remoteIP: "9.9.9.9", remotePort: 443, isOwnTraffic: false) == .exemptResolver,
                      "the configured resolver must stay reachable even though the feed lists it")
        checks.expect(manager.ipBlocklistPolicy(enforcementEnabled: false)
                        .verdict(remoteIP: "203.0.113.7", remotePort: 443, isOwnTraffic: false) == .notEnforced,
                      "with enforcement off, a loaded feed entry must block nothing")
        checks.expect(updates == 3, "every refresh must publish exactly one set, got \(updates)")
        checks.expect(manager.domains.isEmpty, "a usable address feed must never reach the domain blocklist")

        // Feed metadata survives a restart, and it is stored under its own key.
        let reopened = BlocklistManager(store: store)
        checks.expect(reopened.ipFeeds().first(where: { $0.id.uuidString == feedID })?.enabled == true,
                      "address feed state must persist under its own settings key")
        checks.expect(store.allBlocklists().allSatisfy { $0.url != IPBlocklistCatalog.defaults[0].url },
                      "an address feed must never appear in the domain blocklist table")

        // 8. Size and time. A feed of this size is ordinary for this data.
        // Wall-clock limits only apply in the opt-in benchmark (issue #356):
        // timing depends on the machine's load, not on the code.
        let benchmark = ProcessInfo.processInfo.environment["FREESNITCH_BENCH"] == "1"
        let bigEntries = generatedEntries(120_000)
        let buildStart = Date()
        let big = IPBlocklistSet(entries: bigEntries)
        let buildSeconds = Date().timeIntervalSince(buildStart)
        checks.expect(big.acceptedEntryCount == 120_000, "the large feed must load fully, got \(big.acceptedEntryCount)")
        checks.expect(big.rangeCount == 120_000, "non-adjacent networks must stay distinct ranges, got \(big.rangeCount)")
        checks.expect(!big.truncated, "120k entries is below the bound and must not be truncated")
        if benchmark {
            checks.expect(buildSeconds < 20, "loading 120k entries took \(buildSeconds)s, which is not a sane load time")
        }
        checks.note(String(format: "loaded 120000 entries in %.3fs", buildSeconds))

        var hits = 0
        var misses = 0
        let lookupStart = Date()
        for index in 0..<200_000 {
            let sourceIndex = index % 120_000
            let probe = index % 2 == 0
                ? "\(33 + sourceIndex / 65_536).\((sourceIndex / 256) % 256).\(sourceIndex % 256).5"
                : "\(33 + sourceIndex / 65_536).\((sourceIndex / 256) % 256).\(sourceIndex % 256).200"
            if big.contains(probe) { hits += 1 } else { misses += 1 }
        }
        let lookupSeconds = Date().timeIntervalSince(lookupStart)
        checks.expect(hits == 100_000, "every address inside a /25 must hit, got \(hits)")
        checks.expect(misses == 100_000, "every address outside a /25 must miss, got \(misses)")
        if benchmark {
            checks.expect(lookupSeconds < 5, "200k lookups took \(lookupSeconds)s, which is not a sane lookup time")
        }
        checks.note(String(format: "200000 string lookups in %.3fs", lookupSeconds))

        // Bounded: the ceiling truncates instead of growing without limit.
        let bounded = IPBlocklistSet(entries: generatedEntries(5_000), limit: 1_000)
        checks.expect(bounded.rangeCount == 1_000, "the range ceiling must be enforced, got \(bounded.rangeCount)")
        checks.expect(bounded.truncated, "hitting the ceiling must be reported, not hidden")
        checks.expect(big.pfTableEntries().count == 120_000,
                      "a 120k feed must not be silently truncated in the pf anchor")
        checks.expect(big.pfTableEntries(limit: 50_000).count == 50_000,
                      "the pf table renderer must honor an explicit smaller bound")

        // No per-lookup allocation of the set. The typed path is the verdict
        // path's shape: parse once, then binary search.
        let addresses: [UInt32] = (0..<50_000).map { index in
            let a = UInt32(33 + index / 65_536)
            let b = UInt32((index / 256) % 256)
            let c = UInt32(index % 256)
            return (a << 24) | (b << 16) | (c << 8) | 5
        }
        var typedHits = 0
        let beforeTyped = mstats()
        for address in addresses where big.contains(ipv4: address) { typedHits += 1 }
        let afterTyped = mstats()
        let typedGrowth = Int(afterTyped.bytes_used) - Int(beforeTyped.bytes_used)
        checks.expect(typedHits == 50_000, "the typed lookup must agree with the textual one, got \(typedHits)")
        checks.expect(typedGrowth < 64 * 1024,
                      "50k typed lookups grew the heap by \(typedGrowth) bytes, so the lookup path is allocating")

        // Lookup cost must not scale with the set. Counted in binary-search
        // steps, not wall-clock time, so a busy machine cannot fail it
        // (issue #326). A bounded search over n ranges takes at most
        // floor(log2(n)) + 1 steps, whatever the probe.
        func maxSteps(_ count: Int) -> Int {
            count <= 0 ? 0 : (Int.bitWidth - count.leadingZeroBitCount)
        }
        let tiny = IPBlocklistSet(entries: generatedEntries(12))
        let missesV4: [UInt32] = [0, 1, 0x2100_0000 - 1, UInt32.max, 0x2100_0080, 0x2300_0000]
        var tinyWorst = 0
        var bigWorst = 0
        var bigTotal = 0
        var stepHits = 0
        for address in addresses + missesV4 {
            tinyWorst = max(tinyWorst, tiny.lookupProbes(ipv4: address).probes)
            let result = big.lookupProbes(ipv4: address)
            bigWorst = max(bigWorst, result.probes)
            bigTotal += result.probes
            if result.found { stepHits += 1 }
        }
        checks.expect(stepHits == 50_000, "the counting lookup must agree with the plain one, got \(stepHits)")
        checks.expect(tinyWorst <= maxSteps(tiny.rangeCount),
                      "a lookup over \(tiny.rangeCount) ranges took \(tinyWorst) steps, more than \(maxSteps(tiny.rangeCount))")
        checks.expect(bigWorst <= maxSteps(big.rangeCount),
                      "a lookup over \(big.rangeCount) ranges took \(bigWorst) steps, more than \(maxSteps(big.rangeCount)), which is not a bounded search")
        checks.expect(bigWorst >= maxSteps(big.rangeCount) - 1,
                      "a lookup over \(big.rangeCount) ranges took only \(bigWorst) steps, so the step counter is not counting")

        let v6Big = IPBlocklistSet(entries: (0..<4_096).map { String(format: "2001:db8:%x::/48", $0 * 2) })
        var v6Worst = 0
        var v6Hits = 0
        let v6Probes = ["::1", "2001:db7:ffff::1", "ffff::1"] + (0..<8_192).map { String(format: "2001:db8:%x::1", $0) }
        for text in v6Probes {
            if let probe = IPBlocklistAddress.ipv6(text) {
                let result = v6Big.lookupProbes(ipv6: probe)
                v6Worst = max(v6Worst, result.probes)
                if result.found { v6Hits += 1 }
            } else {
                checks.expect(false, "the IPv6 probe \(text) must parse")
            }
        }
        checks.expect(v6Big.rangeCount == 4_096, "distinct IPv6 /48s must stay distinct ranges, got \(v6Big.rangeCount)")
        checks.expect(v6Hits == 4_096, "every even IPv6 /48 probe must hit and every odd one miss, got \(v6Hits) hits")
        checks.expect(v6Worst >= maxSteps(v6Big.rangeCount) - 1,
                      "an IPv6 lookup over \(v6Big.rangeCount) ranges took only \(v6Worst) steps, so the step counter is not counting")
        checks.expect(v6Worst <= maxSteps(v6Big.rangeCount),
                      "an IPv6 lookup over \(v6Big.rangeCount) ranges took \(v6Worst) steps, more than \(maxSteps(v6Big.rangeCount))")
        checks.note("lookup steps: at most \(tinyWorst) over \(tiny.rangeCount) ranges, at most \(bigWorst) over \(big.rangeCount) ranges (\(String(format: "%.2f", Double(bigTotal) / Double(addresses.count + missesV4.count))) average), at most \(v6Worst) over \(v6Big.rangeCount) IPv6 ranges")

        checks.finish("real sources")
    }
}
SWIFT

printf 'ip blocklist harness: building from the real helper and shared sources\n'
# shellcheck disable=SC2046
xcrun swiftc -O -sdk "$SDK" -target "$TARGET" -parse-as-library \
  -o "$TMP/run" \
  $(ls "$ROOT"/Sources/Helper/*.swift | grep -v '/main.swift$') \
  "$ROOT"/Sources/Shared/*.swift \
  "$TMP/verify.swift"

mkdir -p "$TMP/pf-syntax"
PF_SYNTAX_DIR="$TMP/pf-syntax" "$TMP/run"

# Parse every rendered anchor with pf's own parser. `-n` loads nothing; it
# needs no root on macOS. Where pfctl cannot run at all (no pfctl, a sandbox
# without /dev/pf), the grammar checks above still ran.
PFCTL="${PFCTL:-/sbin/pfctl}"
printf 'pass out all\n' > "$TMP/pf-probe.conf"
if [[ -x "$PFCTL" ]] && "$PFCTL" -n -f "$TMP/pf-probe.conf" >/dev/null 2>&1; then
  parsed=0
  for conf in "$TMP"/pf-syntax/*.conf; do
    if ! out="$("$PFCTL" -n -f "$conf" 2>&1)"; then
      printf 'ip blocklist harness: FAIL: pfctl refuses the %s anchor:\n%s\n' "$(basename "$conf" .conf)" "$out" >&2
      exit 1
    fi
    parsed=$((parsed + 1))
  done
  # A failed write is an assertion failure above, so every anchor is here.
  [[ "$parsed" -gt 0 ]] || { printf 'ip blocklist harness: FAIL: no rendered anchor reached pfctl\n' >&2; exit 1; }
  printf 'ip blocklist harness: pfctl -n parsed all %d rendered anchors\n' "$parsed"
elif [[ "${CI:-}" == "true" ]]; then
  # CI runs on macOS, where pfctl -n must work: a runner that cannot run it
  # must not turn the parse check into a silent pass.
  printf 'ip blocklist harness: FAIL: pfctl -n cannot run on this CI runner, so no anchor was parsed\n' >&2
  exit 1
else
  printf 'ip blocklist harness: pfctl -n cannot run here; the grammar checks stand in for it\n'
fi

printf 'ip blocklist verification: PASS\n'
