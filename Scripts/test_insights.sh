#!/usr/bin/env bash
# Deterministic Insights verification, compiled from the real helper and shared
# sources. Seeds a store in a temporary directory and asserts the read side:
# per-app grouping, co-occurrence counts, DNS-name joins, unresolved addresses,
# domain-scoped app-specific proposals, retention at 14 days and 1 year, a purge
# that removes the write-ahead log too, and query bounds.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-insights.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

@main
struct InsightsHarness {
    static var failures = 0

    static func check(_ condition: Bool, _ message: String) {
        if condition {
            print("insights harness: PASS: \(message)")
        } else {
            failures += 1
            FileHandle.standardError.write(Data("insights harness: FAIL: \(message)\n".utf8))
        }
    }

    static func equal<T: Equatable>(_ actual: T, _ expected: T, _ message: String) {
        check(actual == expected, "\(message) (expected \(expected), got \(actual))")
    }

    static func expectThrow(_ label: String, _ body: () throws -> Void) {
        do {
            try body()
            failures += 1
            FileHandle.standardError.write(Data("insights harness: FAIL: \(label) was accepted\n".utf8))
        } catch {
            print("insights harness: PASS: \(label) rejected: \(error.localizedDescription)")
        }
    }

    static func observation(app: String, bundle: String?, path: String, host: String, ip: String,
                            at date: Date, bytesIn: Int64 = 100, bytesOut: Int64 = 50) -> FlowObservation {
        let connection = Connection(pid: 501,
                                    processName: app,
                                    processPath: path,
                                    processBundleId: bundle,
                                    remoteHost: host,
                                    remoteIP: ip,
                                    remotePort: 443,
                                    direction: .outgoing,
                                    protocolName: "tcp",
                                    bytesIn: bytesIn,
                                    bytesOut: bytesOut)
        return FlowObservation(connection: connection, observedAt: date)
    }

    static func main() {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("freesnitch-insights-harness-\(UUID().uuidString)")
        let support = root.appendingPathComponent("Application Support")
        try! FileManager.default.createDirectory(at: support, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o755])
        let path = support.appendingPathComponent("Insights/insights.sqlite").path
        let store: InsightsStore
        do {
            store = try InsightsStore(path: path, expectedUID: getuid())
        } catch {
            FileHandle.standardError.write(Data("insights harness: FAIL: store did not open: \(error)\n".utf8))
            exit(1)
        }

        let now = Date()
        let segmentIP = "203.0.113.10"
        let cdnIP = "203.0.113.20"
        let bareIP = "203.0.113.77"

        try! store.recordDNSMappings([
            DNSMapping(domain: "api.segment.io", ip: segmentIP, observedAt: now.addingTimeInterval(-3600)),
            DNSMapping(domain: "cdn.example.com", ip: cdnIP, observedAt: now.addingTimeInterval(-3600))
        ])

        var seeded: [FlowObservation] = []
        for index in 0..<3 {
            seeded.append(observation(app: "Beeper", bundle: "com.beeper.app", path: "/Applications/Beeper.app",
                                      host: "", ip: segmentIP, at: now.addingTimeInterval(-Double(index) * 60)))
        }
        for index in 0..<2 {
            seeded.append(observation(app: "Beeper", bundle: "com.beeper.app", path: "/Applications/Beeper.app",
                                      host: "", ip: bareIP, at: now.addingTimeInterval(-Double(index) * 90)))
        }
        for index in 0..<2 {
            seeded.append(observation(app: "Slack", bundle: "com.slack.app", path: "/Applications/Slack.app",
                                      host: "", ip: segmentIP, at: now.addingTimeInterval(-Double(index) * 120)))
        }
        seeded.append(observation(app: "Notes", bundle: "com.apple.Notes", path: "/Applications/Notes.app",
                                  host: "", ip: segmentIP, at: now.addingTimeInterval(-150)))
        for index in 0..<4 {
            seeded.append(observation(app: "Notes", bundle: "com.apple.Notes", path: "/Applications/Notes.app",
                                      host: "cdn.example.com", ip: cdnIP, at: now.addingTimeInterval(-Double(index) * 30)))
        }
        // Old but still inside the 14 day raw window, so the retention boundary
        // has something to delete later.
        let oldEvent = observation(app: "Beeper", bundle: "com.beeper.app", path: "/Applications/Beeper.app",
                                   host: "", ip: segmentIP, at: now.addingTimeInterval(-13 * 24 * 60 * 60))
        seeded.append(oldEvent)
        try! store.record(seeded)

        let day: TimeInterval = 24 * 60 * 60

        // MARK: per-app grouping
        let appsReport = try! store.report(for: InsightsQuery(kind: .apps, since: now.addingTimeInterval(-day), limit: 50))
        equal(appsReport.source, .rawEvents, "a range inside 14 days is answered from raw events")
        equal(appsReport.apps.count, 3, "three apps are grouped")
        let byApp = Dictionary(uniqueKeysWithValues: appsReport.apps.map { ($0.appIdentity, $0) })
        equal(byApp["com.beeper.app"]?.connectionCount, 5, "Beeper connection count")
        equal(byApp["com.beeper.app"]?.destinationCount, 2, "Beeper distinct destinations")
        equal(byApp["com.beeper.app"]?.bytesIn, 500, "Beeper bytes in")
        equal(byApp["com.beeper.app"]?.bytesOut, 250, "Beeper bytes out")
        equal(byApp["com.slack.app"]?.connectionCount, 2, "Slack connection count")
        equal(byApp["com.apple.Notes"]?.connectionCount, 5, "Notes connection count")
        equal(byApp["com.beeper.app"]?.displayName, "Beeper", "app display name comes from the recorded process name")

        // MARK: destinations, correlation and DNS-name joins
        let beeper = try! store.report(for: InsightsQuery(kind: .destinations, appIdentity: "com.beeper.app",
                                                         since: now.addingTimeInterval(-day), limit: 50))
        equal(beeper.destinations.count, 2, "Beeper has two destinations")
        let segment = beeper.destinations.first { $0.destinationKey == segmentIP }
        equal(segment?.resolvedDomain, "api.segment.io", "the destination IP joins to the recorded DNS answer")
        equal(segment?.connectionCount, 3, "Beeper reached the named destination three times")
        equal(segment?.otherAppCount, 2, "two other apps also contacted the same destination")
        equal(segment?.correlationNote, "also contacted by 2 other apps", "the inline correlation note states co-occurrence")
        let bare = beeper.destinations.first { $0.destinationKey == bareIP }
        check(bare?.resolvedDomain == nil, "an address with no DNS answer keeps no invented name")
        equal(bare?.displayName, bareIP, "an unnamed destination shows the raw address")
        equal(bare?.otherAppCount, 0, "no other app reached the bare address")

        let notes = try! store.report(for: InsightsQuery(kind: .destinations, appIdentity: "com.apple.Notes",
                                                        since: now.addingTimeInterval(-day), limit: 50))
        let cdn = notes.destinations.first { $0.destinationKey == "cdn.example.com" }
        equal(cdn?.resolvedDomain, "cdn.example.com", "a hostname the app asked for is its own name")
        equal(cdn?.connectionCount, 4, "hostname destination count")

        // MARK: unresolved addresses
        let unresolved = try! store.report(for: InsightsQuery(kind: .unresolved, since: now.addingTimeInterval(-day), limit: 50))
        equal(unresolved.unresolved.count, 1, "exactly one address never appeared in a DNS answer")
        equal(unresolved.unresolved.first?.remoteIP, bareIP, "the bare address is the unresolved one")
        equal(unresolved.unresolved.first?.connectionCount, 2, "unresolved connection count")
        equal(unresolved.unresolved.first?.appCount, 1, "unresolved app count")
        equal(unresolved.unresolved.first?.appNames, ["Beeper"], "the unresolved row names the process")
        check(!unresolved.unresolved.contains { $0.remoteIP == segmentIP },
              "an address with a DNS answer is not reported as unresolved")

        // MARK: proposals
        let proposalsReport = try! store.report(for: InsightsQuery(kind: .proposals, since: now.addingTimeInterval(-day), limit: 50))
        let proposals = proposalsReport.proposals
        check(!proposals.isEmpty, "proposals are generated from what was observed")
        equal(proposals.first?.otherAppCount, 2, "proposals lead with the destination several apps reach")
        let namedIPs: Set<String> = [segmentIP, cdnIP]
        check(!proposals.contains { ($0.remoteIP.map(namedIPs.contains) ?? false) && !$0.isDomainScoped },
              "no proposal pins an address when a name is known")
        guard let beeperSegment = proposals.first(where: { $0.appIdentity == "com.beeper.app" && $0.domain == "api.segment.io" }) else {
            FileHandle.standardError.write(Data("insights harness: FAIL: no proposal for Beeper reaching api.segment.io\n".utf8))
            exit(1)
        }
        check(beeperSegment.isDomainScoped, "the Beeper proposal is domain-scoped")
        check(!beeperSegment.requiresExplicitIPChoice, "a named destination does not need an address-pinned choice")
        let rule = beeperSegment.rule()
        equal(rule.remoteHost, "api.segment.io", "the proposed rule targets the domain")
        check(rule.remoteIP == nil, "the proposed rule is not address-pinned")
        equal(rule.scope, .domain, "the proposed rule scope is the domain")
        equal(rule.action, .deny, "the proposal is a block proposal")
        equal(rule.processBundleId, "com.beeper.app", "the proposed rule is app-specific")
        equal(rule.processPath, "/Applications/Beeper.app", "the proposed rule carries the app path")
        let widened = beeperSegment.widenedRule()
        check(widened?.processBundleId == nil && widened?.processPath == nil, "widening drops the app, keeping the domain")
        equal(widened?.remoteHost, "api.segment.io", "the widened rule keeps the domain")

        guard let bareProposal = proposals.first(where: { $0.appIdentity == "com.beeper.app" && $0.remoteIP == bareIP }) else {
            FileHandle.standardError.write(Data("insights harness: FAIL: no proposal for the unnamed address\n".utf8))
            exit(1)
        }
        check(bareProposal.requiresExplicitIPChoice, "an unnamed destination requires an explicit address choice")
        let bareRule = bareProposal.rule()
        equal(bareRule.scope, .ip, "the unnamed proposal falls back to an address rule")
        equal(bareRule.remoteIP, bareIP, "the unnamed proposal pins the observed address")
        equal(bareRule.processBundleId, "com.beeper.app", "the unnamed proposal stays app-specific")
        check(bareProposal.widenedRule() == nil, "an address-pinned proposal cannot be widened silently")
        equal(beeperSegment.id, InsightsProposedRule(appIdentity: "com.beeper.app", appDisplayName: "Beeper",
                                                     processBundleId: "com.beeper.app", processPath: "/Applications/Beeper.app",
                                                     domain: "api.segment.io", remoteIP: segmentIP,
                                                     connectionCount: 3, otherAppCount: 2, lastSeen: nil).id,
              "proposal identifiers are stable across queries")

        // MARK: rollups answer ranges older than the raw window
        let rollup = try! store.report(for: InsightsQuery(kind: .apps, since: now.addingTimeInterval(-300 * day), limit: 50))
        equal(rollup.source, .dailyRollups, "a range older than 14 days is answered from daily rollups")
        let rollupApps = Dictionary(uniqueKeysWithValues: rollup.apps.map { ($0.appIdentity, $0) })
        equal(rollupApps["com.beeper.app"]?.connectionCount, 6, "rollups count every recorded connection, old event included")
        equal(rollupApps["com.beeper.app"]?.bytesIn, 600, "rollups carry bytes, not only counts")
        let rollupDestinations = try! store.report(for: InsightsQuery(kind: .destinations, appIdentity: "com.beeper.app",
                                                                     since: now.addingTimeInterval(-300 * day), limit: 50))
        let rollupSegment = rollupDestinations.destinations.first { $0.destinationKey == segmentIP }
        equal(rollupSegment?.otherAppCount, 2, "correlation also works on the rollup path")
        equal(rollupSegment?.resolvedDomain, "api.segment.io", "the DNS join also works on the rollup path")

        // MARK: query bounds
        expectThrow("a page size of zero") {
            _ = try store.report(for: InsightsQuery(kind: .apps, since: now.addingTimeInterval(-day), limit: 0))
        }
        expectThrow("a page size above the maximum") {
            _ = try store.report(for: InsightsQuery(kind: .apps, since: now.addingTimeInterval(-day),
                                                limit: InsightsLimits.maxQueryPageSize + 1))
        }
        expectThrow("a negative offset") {
            _ = try store.report(for: InsightsQuery(kind: .apps, since: now.addingTimeInterval(-day), limit: 10, offset: -1))
        }
        expectThrow("a range longer than a year") {
            _ = try store.report(for: InsightsQuery(kind: .apps, since: now.addingTimeInterval(-400 * day), limit: 10))
        }
        expectThrow("an inverted range") {
            _ = try store.report(for: InsightsQuery(kind: .apps, since: now, until: now.addingTimeInterval(-day), limit: 10))
        }
        expectThrow("a range ending in the future") {
            _ = try store.report(for: InsightsQuery(kind: .apps, since: now.addingTimeInterval(-day),
                                                until: now.addingTimeInterval(day), limit: 10))
        }
        expectThrow("a destinations query with no app") {
            _ = try store.report(for: InsightsQuery(kind: .destinations, since: now.addingTimeInterval(-day), limit: 10))
        }
        expectThrow("an oversized request payload") {
            try InsightsQuery(kind: .apps, since: now.addingTimeInterval(-day), limit: 10)
                .validate(payloadBytes: InsightsLimits.maxQueryRequestBytes + 1)
        }
        let maximumPage = try! store.report(for: InsightsQuery(kind: .apps, since: now.addingTimeInterval(-day),
                                                              limit: InsightsLimits.maxQueryPageSize))
        equal(maximumPage.apps.count, 3, "exactly the maximum page size is accepted")

        let firstPage = try! store.report(for: InsightsQuery(kind: .apps, since: now.addingTimeInterval(-day), limit: 1))
        equal(firstPage.apps.count, 1, "a page never returns more rows than the limit")
        check(firstPage.hasMore, "a truncated page reports that more exist")
        let lastPage = try! store.report(for: InsightsQuery(kind: .apps, since: now.addingTimeInterval(-day), limit: 1, offset: 2))
        equal(lastPage.apps.count, 1, "the final page returns its row")
        check(!lastPage.hasMore, "the final page reports no more rows")
        let encoded = try! FreeSnitchWireCodec.encode(firstPage)
        try! firstPage.validateBounds(payloadBytes: encoded.count)
        check(encoded.count <= InsightsLimits.maxReportBytes, "an encoded report stays inside the transport bound")
        expectThrow("an oversized encoded report") {
            try firstPage.validateBounds(payloadBytes: InsightsLimits.maxReportBytes + 1)
        }

        // MARK: retention
        func overview() -> InsightsOverview {
            let report = try! store.report(for: InsightsQuery(kind: .overview, since: Date().addingTimeInterval(-day), limit: 1))
            return report.overview!
        }
        equal(overview().rawObservationCount, 13, "every seeded event is stored")
        equal(overview().dnsMappingCount, 2, "both DNS answers are stored")

        try! store.prune(now: now.addingTimeInterval(2 * day))
        equal(overview().rawObservationCount, 12, "raw events older than 14 days are pruned")
        equal(overview().dnsMappingCount, 2,
              "DNS answers outlive their five minute TTL, otherwise every address would look unresolved")
        check(overview().rollupRowCount > 0, "rollups survive a raw-event prune")

        try! store.prune(now: now.addingTimeInterval(364 * day))
        equal(overview().rawObservationCount, 0, "raw events are gone well before the rollups are")
        check(overview().rollupRowCount > 0, "rollups are still kept one day short of a year")
        try! store.prune(now: now.addingTimeInterval(366 * day))
        equal(overview().rollupRowCount, 0, "rollups are pruned past one year")

        // MARK: purge, including the write-ahead log
        try! store.record([observation(app: "Beeper", bundle: "com.beeper.app", path: "/Applications/Beeper.app",
                                       host: "", ip: segmentIP, at: Date())])
        check(FileManager.default.fileExists(atPath: path + "-wal"), "a write-ahead log exists before the purge")
        func fileIdentity(_ file: String) -> (inode: UInt64, size: UInt64)? {
            guard let attributes = try? FileManager.default.attributesOfItem(atPath: file),
                  let inode = attributes[.systemFileNumber] as? UInt64,
                  let size = attributes[.size] as? UInt64 else { return nil }
            return (inode, size)
        }
        let walBefore = fileIdentity(path + "-wal")
        let shmBefore = fileIdentity(path + "-shm")
        let databaseBefore = fileIdentity(path)
        check((walBefore?.size ?? 0) > 0, "the write-ahead log holds data before the purge")
        try! store.purge()
        // Purge closes the database, unlinks all three files and reopens a clean
        // schema. The reopened store writes its schema straight into a fresh
        // write-ahead log, so the proof that the old log is gone is a new inode,
        // not an empty file.
        let walAfter = fileIdentity(path + "-wal")
        check(walAfter == nil || walAfter!.inode != walBefore!.inode,
              "the purge deletes the write-ahead log rather than leaving the old one")
        let shmAfter = fileIdentity(path + "-shm")
        check(shmAfter == nil || shmBefore == nil || shmAfter!.inode != shmBefore!.inode,
              "the purge deletes the shared-memory file rather than leaving the old one")
        let databaseAfter = fileIdentity(path)
        check(databaseAfter != nil && databaseAfter!.inode != databaseBefore!.inode,
              "the purge unlinks the database file instead of emptying it in place")
        check(FileManager.default.fileExists(atPath: path), "the store is usable again after a purge")
        let purged = overview()
        equal(purged.rawObservationCount, 0, "the purge removes every raw event")
        equal(purged.dnsMappingCount, 0, "the purge removes every DNS answer")
        equal(purged.rollupRowCount, 0, "the purge removes every rollup")
        check(purged.recordingEnabled, "recording returns to its default after a purge")
        try! store.record([observation(app: "Beeper", bundle: "com.beeper.app", path: "/Applications/Beeper.app",
                                       host: "", ip: segmentIP, at: Date())])
        equal(overview().rawObservationCount, 1, "recording works again after a purge")

        // MARK: the off switch
        try! store.setRecordingEnabled(false)
        try! store.record([observation(app: "Beeper", bundle: "com.beeper.app", path: "/Applications/Beeper.app",
                                       host: "", ip: segmentIP, at: Date())])
        equal(overview().rawObservationCount, 1, "nothing is recorded while the off switch is off")
        try! store.setRecordingEnabled(true)

        try? FileManager.default.removeItem(at: root)
        if failures > 0 {
            FileHandle.standardError.write(Data("insights harness: \(failures) failure(s)\n".utf8))
            exit(1)
        }
        print("insights harness: PASS: all checks")
    }
}
SWIFT

mkdir -p "$TMP/build"
xcrun swiftc -O \
  -sdk "$(xcrun --show-sdk-path)" \
  -target arm64-apple-macos13.0 \
  -parse-as-library \
  -o "$TMP/build/run" \
  $(ls "$ROOT"/Sources/Helper/*.swift | rg -v '/main.swift$') \
  "$ROOT"/Sources/Shared/*.swift \
  "$TMP/verify.swift"

"$TMP/build/run"
printf 'insights verification: PASS\n'
