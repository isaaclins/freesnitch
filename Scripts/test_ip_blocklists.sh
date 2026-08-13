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
#   4. A malformed or unreachable feed leaves enforcement fail-open, and an
#      address feed never leaks into the domain blocklist.
#   5. Matching is bounded: a lookup allocates nothing that grows with the set,
#      and lookup cost does not scale with the number of entries.
#   6. A feed of more than 100k entries loads and answers within a sane time.
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
        checks.expect(!plain.contains("freesnitch_ipblock"),
                      "an anchor with no feed loaded must not mention the feed table at all")

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
        let bigEntries = generatedEntries(120_000)
        let buildStart = Date()
        let big = IPBlocklistSet(entries: bigEntries)
        let buildSeconds = Date().timeIntervalSince(buildStart)
        checks.expect(big.acceptedEntryCount == 120_000, "the large feed must load fully, got \(big.acceptedEntryCount)")
        checks.expect(big.rangeCount == 120_000, "non-adjacent networks must stay distinct ranges, got \(big.rangeCount)")
        checks.expect(!big.truncated, "120k entries is below the bound and must not be truncated")
        checks.expect(buildSeconds < 20, "loading 120k entries took \(buildSeconds)s, which is not a sane load time")
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
        checks.expect(lookupSeconds < 5, "200k lookups took \(lookupSeconds)s, which is not a sane lookup time")
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

        // Lookup cost must not scale with the set. Same probes, 12 entries
        // against 120k entries.
        let tiny = IPBlocklistSet(entries: generatedEntries(12))
        let tinyStart = Date()
        for address in addresses { _ = tiny.contains(ipv4: address) }
        let tinySeconds = Date().timeIntervalSince(tinyStart)
        let bigStart = Date()
        for address in addresses { _ = big.contains(ipv4: address) }
        let bigSeconds = Date().timeIntervalSince(bigStart)
        let ratio = tinySeconds > 0 ? bigSeconds / tinySeconds : 0
        checks.expect(ratio < 12,
                      String(format: "a 10000x larger set cost %.1fx more per lookup, which is not a bounded search", ratio))
        checks.note(String(format: "50000 typed lookups: %.4fs over 12 entries, %.4fs over 120000 entries", tinySeconds, bigSeconds))

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

"$TMP/run"

printf 'ip blocklist verification: PASS\n'
