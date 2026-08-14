#!/usr/bin/env bash
# Deterministic harness for offline IP geolocation (issues #61 and #60).
#
# The harness is compiled from the real shared sources, never from a copy, so it
# exercises the shipping IPGeoCache, its index builder and its memory-mapped
# reader. Every database it loads is a local fixture handed to the cache through
# its fetcher, so the whole run is offline and a network call would fail it.
# It asserts, in this order:
#
#   1. IPv4 and IPv6 addresses both resolve, from the same sorted binary search.
#   2. An IPv4-mapped IPv6 address resolves through the IPv4 tables.
#   3. Private, loopback, link-local, unique-local and multicast addresses stay
#      unlocatable in both families.
#   4. Two addresses in the same country but different cities get different
#      coordinates, which is the whole point of #60.
#   5. An unknown city degrades to the country centroid and is reported as
#      country level, never presented as a precise place.
#   6. A malformed, truncated, oversized or unreachable database leaves the
#      previously loaded data intact and never crashes or hangs.
#   7. The text parser agrees with inet_pton across a wide address sample.
#   8. Loading never blocks the caller and the ready callback always fires.
#   9. Lookups are bounded: cost does not scale with the database, the search
#      allocates nothing, and nothing on the lookup path touches the network.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-ipgeo.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

SDK="$(xcrun --show-sdk-path)"
TARGET="arm64-apple-macos13.0"
FIXTURES="$TMP/fixtures"
mkdir -p "$FIXTURES"

# ---------------------------------------------------------------------------
# Fixtures. Same columns as the DB-IP City Lite CSVs that ship in production:
# start, end, country, state1, state2, city, postcode, latitude, longitude, tz.
# ---------------------------------------------------------------------------

cat > "$FIXTURES/countries.csv" <<'CSV'
country,latitude,longitude,name
DE,51.165691,10.451526,Germany
FR,46.227638,2.213749,France
US,37.09024,-95.712891,United States
CH,46.818188,8.227512,Switzerland
CSV

# Two German cities with different coordinates, a French row with no city at
# all, a US row, and a quoted city name containing a comma.
cat > "$FIXTURES/city-ipv4.csv" <<'CSV'
1.0.0.0,1.0.0.255,US,California,,Mountain View,,37.4220,-122.0840,
5.10.0.0,5.10.0.255,DE,Berlin,,Berlin,,52.5200,13.4050,
5.10.1.0,5.10.1.255,DE,Bavaria,,Munich,,48.1372,11.5756,
5.10.2.0,5.10.2.255,DE,North Rhine-Westphalia,,"Cologne (Ehrenfeld, Cologne)",,50.9523,6.8997,
5.10.3.0,5.10.3.255,FR,,,,,,,
5.10.4.0,5.10.4.255,ZZ,,,Nowhere,,10.5,20.25,
80.0.0.0,80.0.0.255,CH,Bern,,Bern,,46.9480,7.4474,
CSV

cat > "$FIXTURES/city-ipv6.csv" <<'CSV'
2001:200::,2001:200:ffff:ffff:ffff:ffff:ffff:ffff,DE,Berlin,,Berlin,,52.5200,13.4050,
2001:201::,2001:201:ffff:ffff:ffff:ffff:ffff:ffff,DE,Bavaria,,Munich,,48.1372,11.5756,
2001:202::,2001:202:ffff:ffff:ffff:ffff:ffff:ffff,FR,,,,,,,
2606:4700::,2606:4700:ffff:ffff:ffff:ffff:ffff:ffff,US,California,,San Francisco,,37.7749,-122.4194,
2a00:1450::,2a00:1450:ffff:ffff:ffff:ffff:ffff:ffff,DE,Hesse,,Frankfurt am Main,,50.1109,8.6821,
CSV

# A large, ordinary-shaped database for the timing and boundedness numbers.
# 400k IPv4 ranges and 400k IPv6 ranges over 4000 distinct cities.
awk 'BEGIN {
  for (i = 0; i < 400000; i++) {
    a = 33 + int(i / 65536); b = int(i / 256) % 256; c = i % 256;
    city = i % 4000;
    lat = -60 + (city % 120); lon = -170 + (city % 340);
    printf "%d.%d.%d.0,%d.%d.%d.255,DE,State%d,,City%d,,%d.25,%d.75,\n", a, b, c, a, b, c, city % 50, city, lat, lon;
  }
}' > "$FIXTURES/big-ipv4.csv"

awk 'BEGIN {
  for (i = 0; i < 400000; i++) {
    hi = 8192 + int(i / 65536); mid = i % 65536;
    city = i % 4000;
    lat = -60 + (city % 120); lon = -170 + (city % 340);
    printf "%x:%x::,%x:%x:ffff:ffff:ffff:ffff:ffff:ffff,US,State%d,,City%d,,%d.25,%d.75,\n", hi, mid, hi, mid, city % 50, city, lat, lon;
  }
}' > "$FIXTURES/big-ipv6.csv"

# Gzip copies, because the production databases are published only as gzip and
# the reader has to decompress them while streaming.
gzip -kf "$FIXTURES/city-ipv4.csv" "$FIXTURES/city-ipv6.csv" "$FIXTURES/big-ipv4.csv" "$FIXTURES/big-ipv6.csv"

# Damaged databases.
head -c 4096 "$FIXTURES/big-ipv4.csv.gz" > "$FIXTURES/truncated.csv.gz"
printf 'this is not a database at all\nnor is this\n' > "$FIXTURES/garbage.csv"
printf '\037\213\010\000\000\000\000\000\000\003garbage-after-a-valid-gzip-header' > "$FIXTURES/garbage.csv.gz"
# Out of order and overlapping rows: the builder must refuse the whole file.
cat > "$FIXTURES/unsorted-ipv4.csv" <<'CSV'
9.0.0.0,9.0.0.255,DE,Berlin,,Berlin,,52.5200,13.4050,
8.0.0.0,8.0.0.255,DE,Bavaria,,Munich,,48.1372,11.5756,
CSV
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
        print("ipgeo harness: \(message)")
    }

    func finish(_ label: String) {
        guard failures.isEmpty else {
            for failure in failures {
                FileHandle.standardError.write(Data(("ipgeo harness: FAIL: " + failure + "\n").utf8))
            }
            exit(1)
        }
        print("ipgeo harness: \(label): \(passed) assertions PASS")
    }
}

func fileSize(_ path: String) -> Int {
    guard let attributes = try? FileManager.default.attributesOfItem(atPath: path),
          let size = attributes[.size] as? Int else { return 0 }
    return size
}

func footprint() -> Int {
    var info = task_vm_info_data_t()
    var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size)
    let result = withUnsafeMutablePointer(to: &info) {
        $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
            task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
        }
    }
    return result == KERN_SUCCESS ? Int(info.phys_footprint) : 0
}

/// Counts every fetch, so "no online access" is asserted rather than assumed:
/// a fetcher that never opens a socket cannot silently become one that does.
final class FixtureFetcher: @unchecked Sendable {
    private let lock = NSLock()
    private var mapping: [String: String]
    private(set) var fetchCount = 0
    var failureMessage: String?
    var delay: TimeInterval = 0

    init(_ mapping: [String: String]) { self.mapping = mapping }

    func set(_ url: String, to path: String) {
        lock.lock(); mapping[url] = path; lock.unlock()
    }

    var fetcher: IPGeoCache.SourceFetcher {
        { [self] url, destination in
            lock.lock()
            fetchCount += 1
            let source = mapping[url]
            let failure = failureMessage
            let pause = delay
            lock.unlock()
            if pause > 0 { Thread.sleep(forTimeInterval: pause) }
            if let failure { return failure }
            guard let source else { return "no fixture for \(url)" }
            do {
                try? FileManager.default.removeItem(at: destination)
                try FileManager.default.copyItem(at: URL(fileURLWithPath: source), to: destination)
                return nil
            } catch {
                return error.localizedDescription
            }
        }
    }

    var count: Int {
        lock.lock(); defer { lock.unlock() }
        return fetchCount
    }
}

@main
struct IPGeoHarness {
    static let fixtures = ProcessInfo.processInfo.environment["FIXTURES"] ?? "."
    static func path(_ name: String) -> String { fixtures + "/" + name }

    static func makeCache(_ directory: String, _ fetcher: FixtureFetcher) -> IPGeoCache {
        IPGeoCache(cacheDirectory: URL(fileURLWithPath: directory), fetcher: fetcher.fetcher, startLoading: false)
    }

    static func loadSynchronously(_ cache: IPGeoCache, force: Bool = false) {
        let semaphore = DispatchSemaphore(value: 0)
        cache.reload(force: force) { semaphore.signal() }
        _ = semaphore.wait(timeout: .now() + 300)
    }

    static func main() {
        let checks = Checks()
        let root = NSTemporaryDirectory() + "freesnitch-ipgeo-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: root) }

        let smallMapping = [
            IPGeoCache.ipv4Source.url: path("city-ipv4.csv.gz"),
            IPGeoCache.ipv6Source.url: path("city-ipv6.csv.gz"),
            IPGeoCache.countrySource.url: path("countries.csv")
        ]
        let fetcher = FixtureFetcher(smallMapping)
        let cache = makeCache(root + "/small", fetcher)
        loadSynchronously(cache)

        let status = cache.status
        checks.expect(status.isLoaded && status.hasDatabase,
                      "the fixture database must load, got isLoaded=\(status.isLoaded) hasDatabase=\(status.hasDatabase) error=\(status.lastError ?? "none")")
        checks.expect(fetcher.count == 3, "one bulk fetch per source and no more, got \(fetcher.count)")

        // 1. IPv4 and IPv6 both resolve.
        guard let berlin = cache.lookup("5.10.0.7"), let munich = cache.lookup("5.10.1.7") else {
            FileHandle.standardError.write(Data("ipgeo harness: FAIL: the IPv4 fixture rows did not resolve (status \(cache.status), fetches \(fetcher.count))\n".utf8))
            exit(1)
        }
        checks.expect(berlin.city == "Berlin" && berlin.countryCode == "DE" && berlin.country == "Germany",
                      "an IPv4 address must resolve to its city and country, got \(berlin)")
        checks.expect(berlin.precision == .city && berlin.isCityLevel, "a known city must be reported as city level")
        guard let berlin6 = cache.lookup("2001:200::dead:beef"), let munich6 = cache.lookup("2001:201::1") else {
            FileHandle.standardError.write(Data("ipgeo harness: FAIL: the IPv6 fixture rows did not resolve, which is issue #61\n".utf8))
            exit(1)
        }
        checks.expect(berlin6.city == "Berlin" && berlin6.countryCode == "DE",
                      "an IPv6 address must resolve to its city, got \(berlin6)")
        checks.expect(cache.lookup("2a00:1450:4001:80e::200e")?.city == "Frankfurt am Main",
                      "an IPv6 address inside a range must resolve, not only the range start")
        checks.expect(cache.lookup("2606:4700:4700::1111")?.countryCode == "US",
                      "an IPv6 address in a second range must resolve")
        checks.expect(cache.lookup("5.10.2.9")?.city == "Cologne (Ehrenfeld, Cologne)",
                      "a quoted city name containing a comma must survive parsing, got \(cache.lookup("5.10.2.9")?.city ?? "nil")")

        // 2. IPv4-mapped IPv6 resolves through the IPv4 path.
        let mapped = cache.lookup("::ffff:5.10.0.7")
        checks.expect(mapped?.city == berlin.city && mapped?.lat == berlin.lat && mapped?.lon == berlin.lon,
                      "an IPv4-mapped IPv6 address must resolve exactly like its IPv4 form, got \(mapped as Any)")
        checks.expect(cache.lookup("::ffff:050a:0007")?.city == "Berlin",
                      "the hex spelling of an IPv4-mapped address must resolve identically")

        // 3. Nothing local, private or multicast is locatable.
        for unlocatable in ["0.0.0.0", "10.1.2.3", "172.16.9.9", "192.168.1.4", "127.0.0.1", "127.0.0.53",
                            "169.254.1.1", "100.64.0.1", "224.0.0.251", "239.1.2.3",
                            "::", "::1", "0:0:0:0:0:0:0:1", "fe80::1", "fe80::abcd:1", "fc00::1", "fd00::1",
                            "ff02::fb", "ff00::1", "::ffff:127.0.0.1", "::ffff:192.168.1.4"] {
            checks.expect(cache.lookup(unlocatable) == nil, "\(unlocatable) must never be geolocated")
        }
        for malformed in ["", "not-an-ip", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.-1", "::gggg",
                         "2001:200::1::2", "12345::1", "fe80::1%en0", "5.10.0.7 "] {
            checks.expect(cache.lookup(malformed) == nil, "'\(malformed)' is not an address and must not resolve")
        }

        // 4. Same country, different cities, different coordinates. This is the
        //    property the old country-centroid database could never have.
        checks.expect(berlin.countryCode == munich.countryCode,
                      "the two fixture addresses must share a country for this assertion to mean anything")
        checks.expect(berlin.lat != munich.lat || berlin.lon != munich.lon,
                      "two IPs in the same country but different cities must not share a coordinate, got \(berlin.lat ?? 0),\(berlin.lon ?? 0) and \(munich.lat ?? 0),\(munich.lon ?? 0)")
        checks.expect(berlin.city != munich.city, "two different cities must carry different names")
        checks.expect(berlin6.lat != munich6.lat || berlin6.lon != munich6.lon,
                      "the same must hold over IPv6")
        checks.expect(abs((berlin.lat ?? 0) - 52.52) < 0.001 && abs((berlin.lon ?? 0) - 13.405) < 0.001,
                      "the city coordinate must be the city's own, got \(berlin.lat ?? 0),\(berlin.lon ?? 0)")

        // 5. An unknown city degrades to the country centroid, and says so.
        guard let unknownCity = cache.lookup("5.10.3.5") else {
            FileHandle.standardError.write(Data("ipgeo harness: FAIL: a row without a city must still resolve to its country\n".utf8))
            exit(1)
        }
        checks.expect(unknownCity.city == nil, "an unknown city must be reported as unknown, got \(unknownCity.city ?? "nil")")
        checks.expect(unknownCity.precision == .country && !unknownCity.isCityLevel,
                      "an unknown city must be labelled country level")
        checks.expect(unknownCity.countryCode == "FR" && unknownCity.country == "France",
                      "an unknown city must still name its country")
        checks.expect(abs((unknownCity.lat ?? 0) - 46.227638) < 0.001 && abs((unknownCity.lon ?? 0) - 2.213749) < 0.001,
                      "an unknown city must fall back to the country centroid, got \(unknownCity.lat ?? 0),\(unknownCity.lon ?? 0)")
        let unknownCity6 = cache.lookup("2001:202::9")
        checks.expect(unknownCity6?.precision == .country && unknownCity6?.city == nil,
                      "the country fallback must work over IPv6 too")
        // A country the canonical country table does not know: the code is
        // still honest, the centroid is simply absent rather than invented.
        let unknownCountry = cache.lookup("5.10.4.5")
        checks.expect(unknownCountry?.countryCode == "ZZ" && unknownCountry?.city == "Nowhere",
                      "a country code outside the canonical table must still be reported")
        checks.expect(unknownCountry?.country == nil, "an unknown country must not be given an invented name")
        // A hole between fixture ranges is not locatable.
        checks.expect(cache.lookup("6.0.0.1") == nil, "an address in a gap between ranges must not resolve")
        checks.expect(cache.lookup("240.0.0.1") == nil, "an address past the last range must not resolve")
        checks.expect(cache.lookup("2001:203::1") == nil, "an IPv6 address in a gap must not resolve")

        // 6. Damaged databases leave the working one intact.
        let indexPath = root + "/small/dbip-city.index"
        let originalSize = fileSize(indexPath)
        checks.expect(originalSize > 0, "the built index must exist on disk")

        func expectStillWorking(_ label: String) {
            let again = cache.lookup("5.10.0.7")
            checks.expect(again?.city == "Berlin" && again?.lat == berlin.lat,
                          "\(label) must leave the previously loaded database answering, got \(again as Any)")
            checks.expect(cache.lookup("2001:200::1")?.city == "Berlin",
                          "\(label) must leave IPv6 answering too")
            checks.expect(fileSize(indexPath) == originalSize, "\(label) must not replace the installed index")
            checks.expect(cache.status.hasDatabase, "\(label) must not clear the loaded database")
        }

        fetcher.failureMessage = "simulated network unreachable"
        loadSynchronously(cache, force: true)
        expectStillWorking("an unreachable source")
        checks.expect(cache.status.lastError != nil, "a failed refresh must record why")
        fetcher.failureMessage = nil

        fetcher.set(IPGeoCache.ipv4Source.url, to: path("garbage.csv"))
        loadSynchronously(cache, force: true)
        expectStillWorking("a garbage database")

        fetcher.set(IPGeoCache.ipv4Source.url, to: path("garbage.csv.gz"))
        loadSynchronously(cache, force: true)
        expectStillWorking("a database with a valid gzip header and garbage behind it")

        fetcher.set(IPGeoCache.ipv4Source.url, to: path("truncated.csv.gz"))
        loadSynchronously(cache, force: true)
        expectStillWorking("a truncated database")

        fetcher.set(IPGeoCache.ipv4Source.url, to: path("unsorted-ipv4.csv"))
        loadSynchronously(cache, force: true)
        expectStillWorking("an unsorted, overlapping database")

        fetcher.set(IPGeoCache.ipv4Source.url, to: path("big-ipv4.csv"))
        fetcher.set(IPGeoCache.countrySource.url, to: path("city-ipv4.csv"))
        loadSynchronously(cache, force: true)
        expectStillWorking("a country table that is not a country table")
        fetcher.set(IPGeoCache.countrySource.url, to: path("countries.csv"))

        // A file past the per-source byte ceiling is refused before it is
        // parsed, not after it has been read into memory.
        checks.expect(IPGeoCache.ipv4Source.maxBytes <= 128 * 1024 * 1024,
                      "the IPv4 source ceiling must stay bounded, is \(IPGeoCache.ipv4Source.maxBytes)")
        checks.expect(IPGeoCache.countrySource.maxBytes <= 4 * 1024 * 1024,
                      "the country table ceiling must stay small, is \(IPGeoCache.countrySource.maxBytes)")
        let oversized = root + "/oversized.csv"
        FileManager.default.createFile(atPath: oversized, contents: nil)
        if let handle = FileHandle(forWritingAtPath: oversized) {
            try? handle.truncate(atOffset: UInt64(IPGeoCache.countrySource.maxBytes + 1))
            try? handle.close()
        }
        fetcher.set(IPGeoCache.countrySource.url, to: oversized)
        loadSynchronously(cache, force: true)
        expectStillWorking("an oversized database")
        fetcher.set(IPGeoCache.countrySource.url, to: path("countries.csv"))

        // A corrupt index on disk must be rejected on open rather than mapped
        // and trusted.
        let corruptDirectory = root + "/corrupt"
        try? FileManager.default.createDirectory(atPath: corruptDirectory, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: corruptDirectory + "/dbip-city.index",
                                       contents: Data(repeating: 0x41, count: 4096))
        let corruptFetcher = FixtureFetcher([:])
        corruptFetcher.failureMessage = "offline"
        let corruptCache = makeCache(corruptDirectory, corruptFetcher)
        loadSynchronously(corruptCache)
        checks.expect(corruptCache.lookup("5.10.0.7") == nil, "a corrupt index must not answer")
        checks.expect(corruptCache.status.isLoaded, "a corrupt index must still complete loading")
        checks.expect(!corruptCache.status.hasDatabase, "a corrupt index must not be mapped as a database")

        // 7. The byte parser must agree with the system parser.
        var samples: [String] = ["::", "::1", "2001:db8::", "2001:db8::1", "::ffff:1.2.3.4", "::1.2.3.4",
                                 "fe80::1", "2a00:1450:4001:80e::200e", "2606:4700:4700::1111",
                                 "0:0:0:0:0:0:0:0", "1:2:3:4:5:6:7:8", "1::8", "1:2:3:4:5:6:1.2.3.4",
                                 "abcd:ef01:2345:6789:abcd:ef01:2345:6789", "::ffff:0:0", "1:2::7:8"]
        var generator = SystemRandomNumberGenerator()
        for _ in 0..<2000 {
            let groups = (0..<8).map { _ in String(UInt16.random(in: 0...UInt16.max, using: &generator), radix: 16) }
            samples.append(groups.joined(separator: ":"))
        }
        var agreements = 0
        for sample in samples {
            let mine = IPGeoCache.parseIPv6(sample)
            let system = IPBlocklistAddress.ipv6(sample)
            checks.expect(mine == system, "the address parser disagrees with inet_pton on \(sample): \(mine as Any) vs \(system as Any)")
            if mine == system { agreements += 1 }
        }
        checks.note("\(agreements) of \(samples.count) IPv6 spellings parse identically to inet_pton")
        for rejected in ["1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7", "::ffff:1.2.3", "1::2::3", "g::1", ":1:2:3:4:5:6:7"] {
            checks.expect(IPGeoCache.parseIPv6(rejected) == nil, "'\(rejected)' must be rejected, got \(IPGeoCache.parseIPv6(rejected) as Any)")
        }

        // 8. Loading must never block the caller, and ready must always fire.
        let slowFetcher = FixtureFetcher(smallMapping)
        slowFetcher.delay = 1.0
        let startedAt = Date()
        let slowCache = IPGeoCache(cacheDirectory: URL(fileURLWithPath: root + "/slow"),
                                   fetcher: slowFetcher.fetcher, startLoading: true)
        let constructionSeconds = Date().timeIntervalSince(startedAt)
        checks.expect(constructionSeconds < 0.1,
                      String(format: "construction must not wait on a download, took %.3fs", constructionSeconds))
        checks.expect(!slowCache.status.isLoaded || slowCache.status.hasDatabase,
                      "a cache that is still downloading must not claim to be loaded with nothing")
        let ready = DispatchSemaphore(value: 0)
        slowCache.onReady { ready.signal() }
        checks.expect(ready.wait(timeout: .now() + 60) == .success, "the ready callback must fire after a slow load")
        checks.expect(slowCache.lookup("5.10.1.7")?.city == "Munich", "a slow load must still produce a working database")
        let readyAgain = DispatchSemaphore(value: 0)
        slowCache.onReady { readyAgain.signal() }
        checks.expect(readyAgain.wait(timeout: .now() + 5) == .success, "onReady after loading must fire immediately")

        // A failing fetch with no cached index must still complete loading.
        let deadFetcher = FixtureFetcher([:])
        deadFetcher.failureMessage = "offline"
        let deadCache = makeCache(root + "/dead", deadFetcher)
        let deadReady = DispatchSemaphore(value: 0)
        deadCache.onReady { deadReady.signal() }
        loadSynchronously(deadCache)
        checks.expect(deadReady.wait(timeout: .now() + 5) == .success,
                      "the ready callback must fire even when no database could be loaded")
        checks.expect(deadCache.lookup("5.10.0.7") == nil, "a cache with no database must answer nil, not crash")

        // A cached, fresh index must be served without any fetch at all.
        let warmFetcher = FixtureFetcher(smallMapping)
        let warmCache = makeCache(root + "/small", warmFetcher)
        let openStart = Date()
        loadSynchronously(warmCache)
        let openSeconds = Date().timeIntervalSince(openStart)
        checks.expect(warmFetcher.count == 0, "a fresh cached index must be used without downloading anything, got \(warmFetcher.count) fetches")
        checks.expect(warmCache.lookup("5.10.0.7")?.city == "Berlin", "a cached index must answer after a restart")
        checks.note(String(format: "opening a cached index: %.4fs", openSeconds))

        // 9. Size, time and boundedness, on a database with the shape of the
        //    real one.
        let bigFetcher = FixtureFetcher([
            IPGeoCache.ipv4Source.url: path("big-ipv4.csv.gz"),
            IPGeoCache.ipv6Source.url: path("big-ipv6.csv.gz"),
            IPGeoCache.countrySource.url: path("countries.csv")
        ])
        let bigCache = makeCache(root + "/big", bigFetcher)
        let beforeBuild = footprint()
        let buildStart = Date()
        loadSynchronously(bigCache)
        let buildSeconds = Date().timeIntervalSince(buildStart)
        let afterBuild = footprint()
        let bigStatus = bigCache.status
        checks.expect(bigStatus.hasDatabase, "the large database must load, error=\(bigStatus.lastError ?? "none")")
        checks.expect(bigStatus.ipv4RangeCount >= 400_000, "every IPv4 range must load, got \(bigStatus.ipv4RangeCount)")
        checks.expect(bigStatus.ipv6RangeCount >= 400_000, "every IPv6 range must load, got \(bigStatus.ipv6RangeCount)")
        // 4000 city names in the IPv4 half and the same 4000 in the IPv6 half,
        // under a different country, so 8000 distinct places is the correct
        // deduplication of 800k rows.
        checks.expect(bigStatus.placeCount == 8_000,
                      "800k rows must deduplicate to 8000 places, got \(bigStatus.placeCount)")
        checks.expect(buildSeconds < 60, "building 800k ranges took \(buildSeconds)s, which is not a sane load time")
        checks.note(String(format: "built %d IPv4 + %d IPv6 ranges and %d cities in %.2fs, index %.1f MB, build footprint %.1f MB",
                           bigStatus.ipv4RangeCount, bigStatus.ipv6RangeCount, bigStatus.placeCount, buildSeconds,
                           Double(bigStatus.indexBytes) / 1048576, Double(afterBuild - beforeBuild) / 1048576))

        var located = 0
        let lookupStart = Date()
        for index in 0..<200_000 {
            let source = index % 400_000
            let text = "\(33 + source / 65536).\((source / 256) % 256).\(source % 256).\(index % 256)"
            if bigCache.lookup(text) != nil { located += 1 }
        }
        let lookupSeconds = Date().timeIntervalSince(lookupStart)
        checks.expect(located == 200_000, "every generated address must resolve, got \(located)")
        checks.expect(lookupSeconds < 20, "200k string lookups took \(lookupSeconds)s, which is not a sane lookup time")
        checks.note(String(format: "200000 IPv4 string lookups in %.3fs (%.0f lookups/s)", lookupSeconds, 200_000 / lookupSeconds))

        var located6 = 0
        let lookup6Start = Date()
        for index in 0..<200_000 {
            let source = index % 400_000
            let text = String(format: "%x:%x::%x", 8192 + source / 65536, source % 65536, index % 4096)
            if bigCache.lookup(text) != nil { located6 += 1 }
        }
        let lookup6Seconds = Date().timeIntervalSince(lookup6Start)
        checks.expect(located6 == 200_000, "every generated IPv6 address must resolve, got \(located6)")
        checks.note(String(format: "200000 IPv6 string lookups in %.3fs (%.0f lookups/s)", lookup6Seconds, 200_000 / lookup6Seconds))

        // The search itself must not allocate. Parsed input, no Entry building.
        let addresses: [UInt32] = (0..<100_000).map { index in
            let a = UInt32(33 + index / 65536), b = UInt32((index / 256) % 256), c = UInt32(index % 256)
            return (a << 24) | (b << 16) | (c << 8) | 7
        }
        var typedHits = 0
        let beforeTyped = mstats()
        for address in addresses where bigCache.placeIndex(ipv4: address) != nil { typedHits += 1 }
        let afterTyped = mstats()
        let growth = Int(afterTyped.bytes_used) - Int(beforeTyped.bytes_used)
        checks.expect(typedHits == 100_000, "the typed lookup must agree with the textual one, got \(typedHits)")
        checks.expect(growth < 64 * 1024, "100k typed lookups grew the heap by \(growth) bytes, so the search is allocating")

        // Cost must not scale with the database: the same probes against the
        // seven-row fixture and against 400k ranges.
        let smallStart = Date()
        for address in addresses { _ = cache.placeIndex(ipv4: address) }
        let smallSeconds = Date().timeIntervalSince(smallStart)
        let bigStart = Date()
        for address in addresses { _ = bigCache.placeIndex(ipv4: address) }
        let bigSeconds = Date().timeIntervalSince(bigStart)
        let ratio = smallSeconds > 0 ? bigSeconds / smallSeconds : 0
        checks.expect(ratio < 12, String(format: "a 50000x larger database cost %.1fx more per lookup, which is not a bounded search", ratio))
        checks.note(String(format: "100000 typed lookups: %.4fs over 7 ranges, %.4fs over %d ranges",
                           smallSeconds, bigSeconds, bigStatus.ipv4RangeCount))

        // Nothing on the lookup path fetched anything.
        checks.expect(bigFetcher.count == 3, "lookups must never fetch: \(bigFetcher.count) fetches after 400k lookups")
        for source in IPGeoCache.sources {
            checks.expect(source.url.hasPrefix("https://"), "every source must be HTTPS, got \(source.url)")
            checks.expect(!source.url.contains("?"), "a bulk database URL must not carry a query, got \(source.url)")
        }
        checks.expect(IPGeoCache.cacheLifetime >= 24 * 60 * 60,
                      "the cache lifetime must be days, not minutes, so the app is not re-downloading a database")
        checks.expect(!IPGeoCache.attribution.text.isEmpty && IPGeoCache.attribution.linkURL == "https://db-ip.com/",
                      "the DB-IP attribution required by CC BY 4.0 must be available to the UI")

        checks.finish("real sources")
    }
}
SWIFT

printf 'ipgeo harness: building from the real shared sources\n'
xcrun swiftc -O -sdk "$SDK" -target "$TARGET" -parse-as-library \
  -o "$TMP/run" \
  "$ROOT"/Sources/Shared/*.swift \
  "$TMP/verify.swift"

FIXTURES="$FIXTURES" "$TMP/run"

printf 'ipgeo verification: PASS\n'
