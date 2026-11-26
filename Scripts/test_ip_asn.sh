#!/usr/bin/env bash
# Harness for the offline network owner data and the RDAP record parser (#194).
#
# Compiled from the real shared sources. Every database is a local fixture in
# the same columns as DB-IP ASN Lite (start, end, asn, organisation), handed to
# the cache through its fetcher, so the run is offline. It asserts:
#
#   1. The address from the report, 130.12.92.92, answers AS16909, "imput LLC"
#      and 130.12.92.0/24, and IPv6 and IPv4-mapped addresses resolve too.
#   2. Addresses in a hole between ranges, before the first range and after
#      the last one answer nil, never the neighbouring network.
#   3. Private, loopback, link-local and multicast addresses answer nil.
#   4. A range that is not one CIDR block is shown as start – end, and quoted
#      organisation names with commas survive.
#   5. A malformed, unsorted, overlapping or unreachable database leaves the
#      loaded data in place, and a first-run failure still fires onReady.
#   6. The prefix arithmetic agrees with brute force for IPv4 and IPv6.
#   7. RDAP records from ARIN- and RIPE-shaped answers parse; junk, the wrong
#      object class and oversized bodies are refused.
#   8. A large database builds within bounds and lookups stay fast.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-asn.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
SDK="$(xcrun --show-sdk-path)"
TARGET="arm64-apple-macos13.0"
FIXTURES="$TMP/fixtures"
mkdir -p "$FIXTURES"

cat > "$FIXTURES/asn-ipv4.csv" <<'CSV'
1.0.0.0,1.0.0.255,13335,"Cloudflare, Inc."
1.0.4.0,1.0.7.255,38803,Gtelecom Pty Ltd
130.12.91.0,130.12.91.255,401175,Nexix Inc.
130.12.92.0,130.12.92.255,16909,imput LLC
130.12.93.0,130.12.95.255,26954,Odd Range Networks
140.82.112.0,140.82.127.255,36459,"GitHub, Inc."
CSV
# An organisation name longer than the 1024-byte cap whose cut falls inside
# a two-byte character: the stored name must end before it, not on half of it.
printf '150.0.0.0,150.0.0.255,64500,%s\xc3\xa9 tail\n' "$(printf 'a%.0s' $(seq 1 1023))" >> "$FIXTURES/asn-ipv4.csv"

cat > "$FIXTURES/asn-ipv6.csv" <<'CSV'
2001:200::,2001:200:5ff:ffff:ffff:ffff:ffff:ffff,2500,WIDE Project
2606:4700::,2606:4700:ffff:ffff:ffff:ffff:ffff:ffff,13335,"Cloudflare, Inc."
2a00:1450::,2a00:1450:ffff:ffff:ffff:ffff:ffff:ffff,15169,Google LLC
CSV

cat > "$FIXTURES/unsorted-ipv4.csv" <<'CSV'
9.0.0.0,9.0.0.255,1,Later
8.0.0.0,8.0.0.255,2,Earlier
CSV
cat > "$FIXTURES/overlap-ipv4.csv" <<'CSV'
8.0.0.0,8.0.1.255,1,Wide
8.0.1.0,8.0.1.255,2,Inside
CSV
printf 'this is not a database\n' > "$FIXTURES/garbage.csv"
printf '8.0.0.0,8.0.0.255,AS12,Letters in the number\n' > "$FIXTURES/bad-asn.csv"

awk 'BEGIN {
  for (i = 0; i < 400000; i++) {
    a = 33 + int(i / 65536); b = int(i / 256) % 256; c = i % 256;
    printf "%d.%d.%d.0,%d.%d.%d.255,%d,Org %d\n", a, b, c, a, b, c, 64512 + (i % 1000), i % 5000;
  }
}' > "$FIXTURES/big-ipv4.csv"
awk 'BEGIN {
  for (i = 0; i < 80000; i++) {
    printf "%x:%x::,%x:%x:ffff:ffff:ffff:ffff:ffff:ffff,%d,Org %d\n", 8192 + int(i / 65536), i % 65536, 8192 + int(i / 65536), i % 65536, 64512 + (i % 1000), i % 5000;
  }
}' > "$FIXTURES/big-ipv6.csv"

cat > "$FIXTURES/rdap-arin.json" <<'JSON'
{"objectClassName":"ip network","handle":"NET-130-12-92-0-1","startAddress":"130.12.92.0","endAddress":"130.12.92.255",
 "ipVersion":"v4","name":"HELIUM-NET","type":"DIRECT ALLOCATION","country":"US",
 "cidr0_cidrs":[{"v4prefix":"130.12.92.0","length":24}],
 "entities":[{"objectClassName":"entity","handle":"IL-123","roles":["registrant"],
   "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","imput LLC"],["kind",{},"text","org"]]]},
  {"objectClassName":"entity","handle":"NOC-1","roles":["technical"],
   "vcardArray":["vcard",[["fn",{},"text","Network Operations"]]]}]}
JSON
cat > "$FIXTURES/rdap-ripe.json" <<'JSON'
{"objectClassName":"ip network","handle":"2a00:1450::/32","startAddress":"2a00:1450::/32","endAddress":"2a00:1450:ffff:ffff:ffff:ffff:ffff:ffff/32",
 "name":"DE-GOOGLE\n  SECOND LINE","country":"ie",
 "entities":[{"handle":"MNT-GOOG-PROD","roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","MNT-GOOG-PROD"]]]},
  {"handle":"GOOG1-RIPE","roles":["technical"],"entities":[{"handle":"ORG-GIL1-RIPE","roles":["registrant"],
   "vcardArray":["vcard",[["fn",{},"text","Google Ireland Limited"]]]}]}]}
JSON
printf '{"objectClassName":"entity","handle":"X"}' > "$FIXTURES/rdap-entity.json"
printf '<html>Rate limited</html>' > "$FIXTURES/rdap-html.txt"

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

var failures: [String] = []
var passed = 0
func expect(_ condition: Bool, _ message: String) {
    if condition { passed += 1 } else { failures.append(message) }
}

let fixtures = URL(fileURLWithPath: ProcessInfo.processInfo.environment["FIXTURES"]!)
func fixture(_ name: String) -> String { fixtures.appendingPathComponent(name).path }

final class Fetcher: @unchecked Sendable {
    private let lock = NSLock()
    var mapping: [String: String] = [:]
    var failure: String?
    var count = 0
    var fetcher: IPGeoCache.SourceFetcher {
        { [self] url, destination in
            lock.lock(); count += 1
            let source = mapping[url]; let failure = failure
            lock.unlock()
            if let failure { return failure }
            guard let source else { return "no fixture for \(url)" }
            try? FileManager.default.removeItem(at: destination)
            do { try FileManager.default.copyItem(at: URL(fileURLWithPath: source), to: destination) } catch {
                return error.localizedDescription
            }
            return nil
        }
    }
}

func waitReady(_ cache: IPASNCache) {
    let done = DispatchSemaphore(value: 0)
    cache.onReady { done.signal() }
    if done.wait(timeout: .now() + 60) == .timedOut { failures.append("onReady never fired") }
}

func reload(_ cache: IPASNCache, force: Bool = true) {
    let done = DispatchSemaphore(value: 0)
    cache.reload(force: force) { done.signal() }
    if done.wait(timeout: .now() + 120) == .timedOut { failures.append("reload never finished") }
}

func cacheDirectory(_ name: String) -> URL {
    let url = fixtures.deletingLastPathComponent().appendingPathComponent(name)
    try? FileManager.default.removeItem(at: url)
    return url
}

@main
struct Harness {
    static func main() {
        let fetch = Fetcher()
        fetch.mapping[IPASNCache.ipv4Source.url] = fixture("asn-ipv4.csv")
        fetch.mapping[IPASNCache.ipv6Source.url] = fixture("asn-ipv6.csv")
        let cache = IPASNCache(cacheDirectory: cacheDirectory("cache"), fetcher: fetch.fetcher)
        waitReady(cache)
        expect(cache.status.hasDatabase, "the fixture database loads: \(cache.status.lastError ?? "no error")")

        // 1. The report's own example.
        let helium = cache.lookup("130.12.92.92")
        expect(helium?.asn == 16909, "130.12.92.92 is AS16909, got \(String(describing: helium?.asn))")
        expect(helium?.asnText == "AS16909", "the ASN reads AS16909")
        expect(helium?.organization == "imput LLC", "130.12.92.92 belongs to imput LLC")
        expect(helium?.prefix == "130.12.92.0/24", "130.12.92.92 is in 130.12.92.0/24, got \(helium?.rangeText ?? "nil")")
        expect(cache.lookup(" 130.12.92.0 ")?.asn == 16909 && cache.lookup("130.12.92.255")?.asn == 16909,
               "both ends of the range answer, with surrounding whitespace ignored")
        expect(cache.lookup("130.12.91.255")?.asn == 401175 && cache.lookup("130.12.93.0")?.asn == 26954,
               "the neighbours answer their own networks")
        expect(cache.lookup("1.0.4.9")?.prefix == "1.0.4.0/22", "a /22 is shown as one prefix")
        expect(cache.lookup("1.0.0.1")?.organization == "Cloudflare, Inc.", "a quoted name with a comma survives")
        let long = cache.lookup("150.0.0.1")?.organization
        expect(long == String(repeating: "a", count: 1023),
               "a name cut at the cap drops the split character, got \(long?.count ?? -1) characters ending \(long?.suffix(3) ?? "nil")")
        expect(cache.lookup("::ffff:130.12.92.92")?.asn == 16909, "an IPv4-mapped address uses the IPv4 table")
        let google = cache.lookup("2a00:1450:4001:82f::2003")
        expect(google?.asn == 15169 && google?.organization == "Google LLC", "an IPv6 address resolves")
        expect(google?.prefix == "2a00:1450::/32", "the IPv6 range is 2a00:1450::/32, got \(google?.rangeText ?? "nil")")
        let wide = cache.lookup("2001:200:5ff::1")
        expect(wide?.prefix == nil && wide?.rangeText == "2001:200:: – 2001:200:5ff:ffff:ffff:ffff:ffff:ffff",
               "an IPv6 range that is not one block shows both ends, got \(wide?.rangeText ?? "nil")")

        // 2. Holes and edges.
        expect(cache.lookup("1.0.1.0") == nil, "a hole between ranges answers nil, not the previous network")
        expect(cache.lookup("1.0.8.0") == nil, "the address after a range's end answers nil")
        expect(cache.lookup("0.255.255.255") == nil, "an address before the first range answers nil")
        expect(cache.lookup("200.1.1.1") == nil, "an address after the last range answers nil")
        expect(cache.lookup("2001:1ff::1") == nil, "an IPv6 address before the first range answers nil")
        expect(cache.lookup("2606:4701::1") == nil, "an IPv6 hole answers nil")

        // 3. Addresses with no owner on the internet.
        for local in ["10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "224.0.0.251",
                      "::1", "fe80::1", "fd00::1", "ff02::fb", "not an address", ""] {
            expect(cache.lookup(local) == nil, "\(local) has no network owner")
        }

        // 4. A range that is not one prefix.
        let odd = cache.lookup("130.12.94.1")
        expect(odd?.prefix == nil && odd?.rangeText == "130.12.93.0 – 130.12.95.255",
               "a three-block range shows its two ends, got \(odd?.rangeText ?? "nil")")

        // 5. Damaged sources keep what is loaded.
        for bad in ["garbage.csv", "unsorted-ipv4.csv", "overlap-ipv4.csv", "bad-asn.csv"] {
            fetch.mapping[IPASNCache.ipv4Source.url] = fixture(bad)
            reload(cache)
            expect(cache.lookup("130.12.92.92")?.asn == 16909, "\(bad) leaves the working database in place")
            expect(cache.status.lastError != nil, "\(bad) is reported as an error")
        }
        fetch.mapping[IPASNCache.ipv4Source.url] = fixture("asn-ipv4.csv")
        fetch.failure = "HTTP status 503"
        reload(cache)
        expect(cache.lookup("130.12.92.92")?.asn == 16909, "an unreachable server leaves the database in place")
        fetch.failure = nil
        reload(cache)
        expect(cache.status.lastError == nil, "a good refresh clears the error")

        // A cache that has never loaded and cannot download still says ready.
        let offline = Fetcher()
        offline.failure = "offline"
        let empty = IPASNCache(cacheDirectory: cacheDirectory("offline"), fetcher: offline.fetcher)
        waitReady(empty)
        expect(!empty.status.hasDatabase && empty.status.isLoaded && empty.status.lastError != nil,
               "a first-run failure is loaded, without data, with an error")
        expect(empty.lookup("130.12.92.92") == nil, "no data answers nil")

        // A second cache on the same directory opens the index without a fetch.
        let before = fetch.count
        let reopened = IPASNCache(cacheDirectory: fixtures.deletingLastPathComponent().appendingPathComponent("cache"),
                                  fetcher: fetch.fetcher)
        waitReady(reopened)
        expect(reopened.lookup("130.12.92.92")?.asn == 16909 && fetch.count == before,
               "a fresh index on disk is used as is, with no download")

        // A corrupt index on disk is rebuilt, not trusted.
        let corruptDir = cacheDirectory("corrupt")
        try? FileManager.default.createDirectory(at: corruptDir, withIntermediateDirectories: true)
        try? Data(repeating: 0x41, count: 4096).write(to: corruptDir.appendingPathComponent(IPASNCache.indexFileName))
        let rebuilt = IPASNCache(cacheDirectory: corruptDir, fetcher: fetch.fetcher)
        waitReady(rebuilt)
        expect(rebuilt.lookup("130.12.92.92")?.asn == 16909, "a corrupt index is rebuilt from the sources")

        // 6. Prefix arithmetic against brute force.
        func bruteV4(_ start: UInt32, _ end: UInt32) -> Int? {
            for length in 0...32 {
                let mask: UInt32 = length == 0 ? 0 : ~UInt32(0) << UInt32(32 - length)
                if start & ~mask == 0 && end == start | ~mask { return length }
            }
            return nil
        }
        var generator = SystemRandomNumberGenerator()
        var v4Agree = true
        for _ in 0..<20000 {
            let start = UInt32.random(in: 0...UInt32.max, using: &generator) & (~UInt32(0) << UInt32.random(in: 0...12))
            let span = UInt32.random(in: 0...4096)
            let end = start &+ span < start ? UInt32.max : start &+ span
            if IPASNCache.prefixLength(ipv4: start, end: end) != bruteV4(start, end) { v4Agree = false }
        }
        expect(v4Agree, "IPv4 prefix lengths agree with brute force")
        expect(IPASNCache.prefixLength(ipv4: 0, end: .max) == 0, "the whole IPv4 space is /0")
        expect(IPASNCache.prefixLength(ipv4: 5, end: 5) == 32, "a single address is /32")
        let v6 = { (u: UInt64, l: UInt64) in IPv6Value(upper: u, lower: l) }
        expect(IPASNCache.prefixLength(ipv6: v6(0x2a00_1450_0000_0000, 0), end: v6(0x2a00_1450_ffff_ffff, .max)) == 32, "a /32 in IPv6")
        expect(IPASNCache.prefixLength(ipv6: v6(1, 0), end: v6(1, .max)) == 64, "a /64 in IPv6")
        expect(IPASNCache.prefixLength(ipv6: v6(1, 0x100), end: v6(1, 0x1ff)) == 120, "a /120 in IPv6")
        expect(IPASNCache.prefixLength(ipv6: v6(1, 0x100), end: v6(1, 0x2ff)) == nil, "two /120s are not one prefix")
        expect(IPASNCache.prefixLength(ipv6: v6(1, 0x80), end: v6(1, 0x17f)) == nil, "an unaligned block is not a prefix")
        expect(IPASNCache.prefixLength(ipv6: v6(0, 0), end: v6(.max, .max)) == 0, "the whole IPv6 space is /0")
        expect(IPASNCache.prefixLength(ipv6: v6(2, 0), end: v6(3, .max)) == 63, "a /63 crossing the 64-bit halves")
        expect(IPASNCache.prefixLength(ipv6: v6(2, 1), end: v6(3, .max)) == nil, "an unaligned start across halves is not a prefix")
        expect(IPASNCache.ipv6Text(v6(0x2001_0200_0000_0000, 0)) == "2001:200::", "IPv6 text is the compressed form")

        // 7. RDAP.
        func record(_ name: String) -> RDAPNetworkRecord? {
            RDAPNetworkRecord.parse((try? Data(contentsOf: URL(fileURLWithPath: fixture(name)))) ?? Data())
        }
        let arin = record("rdap-arin.json")
        expect(arin?.name == "HELIUM-NET" && arin?.handle == "NET-130-12-92-0-1", "the ARIN record's name and handle")
        expect(arin?.owner == "imput LLC", "the registrant is the registrant role, not the technical contact")
        expect(arin?.rangeText == "130.12.92.0/24" && arin?.country == "US", "cidr0 prefixes and country")
        let ripe = record("rdap-ripe.json")
        expect(ripe?.owner == "Google Ireland Limited", "a RIPE maintainer is skipped and a nested registrant is found, got \(ripe?.owner ?? "nil")")
        expect(ripe?.country == "IE", "a lowercase country code is normalised")
        expect(ripe?.name == "DE-GOOGLE SECOND LINE", "a multi-line name is one line")
        expect(ripe?.rangeText?.contains(" – ") == true, "without cidr0 the range is start – end")
        expect(record("rdap-entity.json") == nil, "an entity record is not a network")
        expect(record("rdap-html.txt") == nil, "an HTML error page is refused")
        let huge = Data(("{\"objectClassName\":\"ip network\",\"name\":\"" + String(repeating: "a", count: RDAPNetworkRecord.maxBodyBytes) + "\"}").utf8)
        expect(RDAPNetworkRecord.parse(huge) == nil, "an oversized answer is refused")
        expect(RDAPNetworkRecord.lookupURL(for: "130.12.92.92")?.absoluteString == "https://rdap.org/ip/130.12.92.92", "the lookup URL")
        expect(RDAPNetworkRecord.lookupURL(for: "example.com/../x") == nil, "only an address goes into the lookup URL")

        // 8. Size and speed.
        let bigFetch = Fetcher()
        bigFetch.mapping[IPASNCache.ipv4Source.url] = fixture("big-ipv4.csv")
        bigFetch.mapping[IPASNCache.ipv6Source.url] = fixture("big-ipv6.csv")
        let started = Date()
        let big = IPASNCache(cacheDirectory: cacheDirectory("big"), fetcher: bigFetch.fetcher)
        waitReady(big)
        let buildSeconds = Date().timeIntervalSince(started)
        expect(big.status.ipv4RangeCount == 400_000 && big.status.ipv6RangeCount == 80_000, "every row of the big database is indexed")
        var hits = 0
        let lookupStart = Date()
        for i in 0..<200_000 {
            let n = i * 2 % 400_000
            if big.lookup("\(33 + n / 65536).\(n / 256 % 256).\(n % 256).7") != nil { hits += 1 }
        }
        let perLookup = Date().timeIntervalSince(lookupStart) / 200_000
        expect(hits == 200_000, "every big lookup answers")
        expect(perLookup < 0.0002, "a lookup stays well under a millisecond (\(perLookup * 1_000_000) µs)")
        print("asn harness: big build \(String(format: "%.2f", buildSeconds)) s, lookup \(String(format: "%.2f", perLookup * 1_000_000)) µs")

        guard failures.isEmpty else {
            for failure in failures { FileHandle.standardError.write(Data(("asn harness: FAIL: " + failure + "\n").utf8)) }
            exit(1)
        }
        print("asn harness: \(passed) assertions PASS")
    }
}
SWIFT

printf 'asn harness: building from the real shared sources\n'
xcrun swiftc -O -sdk "$SDK" -target "$TARGET" -parse-as-library \
  -o "$TMP/run" \
  "$ROOT"/Sources/Shared/*.swift \
  "$TMP/verify.swift"

FIXTURES="$FIXTURES" "$TMP/run"
printf 'asn verification: PASS\n'
