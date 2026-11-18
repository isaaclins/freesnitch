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
                            at date: Date, port: Int = 443,
                            bytesIn: Int64 = 100, bytesOut: Int64 = 50) -> FlowObservation {
        let connection = Connection(pid: 501,
                                    processName: app,
                                    processPath: path,
                                    processBundleId: bundle,
                                    remoteHost: host,
                                    remoteIP: ip,
                                    remotePort: port,
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

        // MARK: the apps behind one shared destination (#435)
        let sharedRaw = try! store.report(for: InsightsQuery(kind: .apps, destinationKey: segmentIP,
                                                            since: now.addingTimeInterval(-day), limit: 50))
        equal(sharedRaw.apps.map(\.appIdentity), ["com.beeper.app", "com.slack.app", "com.apple.Notes"],
              "a shared address lists every app that reached it, busiest first")
        equal(sharedRaw.apps.map(\.connectionCount), [3, 2, 1], "each app keeps its own count for that address")
        equal(sharedRaw.apps.first?.processPath, "/Applications/Beeper.app", "the app behind a shared address carries its path")
        let bareRaw = try! store.report(for: InsightsQuery(kind: .apps, destinationKey: bareIP,
                                                          since: now.addingTimeInterval(-day), limit: 50))
        equal(bareRaw.apps.map(\.appIdentity), ["com.beeper.app"], "an address one app reached names only that app")
        let sharedRollup = try! store.report(for: InsightsQuery(kind: .apps, destinationKey: segmentIP,
                                                               since: now.addingTimeInterval(-300 * day), limit: 50))
        equal(sharedRollup.source, .dailyRollups, "the shared-address list past 14 days comes from rollups")
        equal(sharedRollup.apps.map(\.appIdentity), ["com.beeper.app", "com.slack.app", "com.apple.Notes"],
              "rollups name the apps behind a shared address too, not only a count")
        equal(sharedRollup.apps.first?.connectionCount, 4, "the rollup count for one app includes its old event")
        let injected = try! store.report(for: InsightsQuery(kind: .apps, destinationKey: "' OR 1=1 --",
                                                           since: now.addingTimeInterval(-day), limit: 50))
        check(injected.apps.isEmpty, "a destination key is bound, never spliced into the query")
        expectThrow("a destination key on a query other than apps") {
            _ = try store.report(for: InsightsQuery(kind: .destinations, appIdentity: "com.beeper.app",
                                                destinationKey: segmentIP, since: now.addingTimeInterval(-day), limit: 50))
        }
        expectThrow("an empty destination key") {
            _ = try store.report(for: InsightsQuery(kind: .apps, destinationKey: "", since: now.addingTimeInterval(-day), limit: 50))
        }

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

        // MARK: lookups through a resolver (#167)
        // A port-53 flow names what was looked up and carries the resolver's
        // address. It is a contact with the resolver, never with the name, and
        // a name shows the address it was last reached at, not a text maximum.
        let resolverIP = "46.243.231.30"
        let mailPath = "/System/Applications/Mail.app"
        try! store.record([
            observation(app: "Mail", bundle: "com.apple.mail", path: mailPath,
                        host: "github.com", ip: "20.26.156.215", at: now.addingTimeInterval(-300)),
            observation(app: "Mail", bundle: "com.apple.mail", path: mailPath,
                        host: "github.com", ip: "140.82.121.4", at: now.addingTimeInterval(-60)),
            observation(app: "Mail", bundle: "com.apple.mail", path: mailPath,
                        host: "github.com", ip: resolverIP, at: now.addingTimeInterval(-30), port: 53),
            observation(app: "Mail", bundle: "com.apple.mail", path: mailPath,
                        host: "formulae.brew.sh", ip: resolverIP, at: now.addingTimeInterval(-20), port: 53)
        ])
        let mail = try! store.report(for: InsightsQuery(kind: .destinations, appIdentity: "com.apple.mail",
                                                       since: now.addingTimeInterval(-day), limit: 50))
        let github = mail.destinations.first { $0.destinationKey == "github.com" }
        equal(github?.connectionCount, 2, "lookups of a name are not counted as contacts with it")
        equal(github?.remoteIP, "140.82.121.4", "a name shows the address it was most recently reached at")
        check(!mail.destinations.contains { $0.destinationKey == "formulae.brew.sh" },
              "a name that was only looked up is not listed as a destination")
        let resolver = mail.destinations.first { $0.destinationKey == resolverIP }
        equal(resolver?.connectionCount, 2, "the lookups are contacts with the resolver")
        let mailProposals = try! store.report(for: InsightsQuery(kind: .proposals, since: now.addingTimeInterval(-day), limit: 50))
        check(!mailProposals.proposals.contains { $0.remoteIP == resolverIP || $0.domain == "formulae.brew.sh" },
              "no block is proposed against the DNS server or a name that was only looked up")
        let longProposals = try! store.report(for: InsightsQuery(kind: .proposals, since: now.addingTimeInterval(-30 * day), limit: 50))
        check(longProposals.source == .dailyRollups, "a 30 day range is answered from the daily rollups")
        check(!longProposals.proposals.contains { $0.remoteIP == resolverIP || $0.domain == "formulae.brew.sh" || $0.domain == "github.com" && $0.connectionCount > 2 },
              "the daily rollups carry no lookups, so long ranges propose nothing against the DNS server either")

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

        // MARK: coverage by an existing rule (#316)
        // A proposal for an address must count as covered when an enabled rule
        // already covers that address the way the matcher would, so Insights
        // does not offer a rule that is already there.
        func addressProposal(_ ip: String) -> InsightsProposedRule {
            InsightsProposedRule(appIdentity: "com.beeper.app", appDisplayName: "Beeper",
                                 processBundleId: "com.beeper.app", processPath: "/Applications/Beeper.app",
                                 domain: nil, remoteIP: ip, connectionCount: 3, otherAppCount: 0, lastSeen: nil)
        }
        let expandedV6 = addressProposal("2001:0db8:0000:0000:0000:0000:0000:0070")
        check(expandedV6.isCovered(by: [Rule(processBundleId: "com.beeper.app", remoteIP: "2001:db8::70", action: .deny)]),
              "an IPv6 address rule covers a proposal for the same address spelled out in full")
        check(addressProposal("2001:db8::70").isCovered(by: [Rule(remoteIP: "2001:0db8::0070", action: .deny)]),
              "an IPv6 address rule covers a proposal for the same address spelled another way")
        check(addressProposal("203.0.113.70").isCovered(by: [Rule(processBundleId: "com.beeper.app", remoteIP: "203.0.113.0/24", action: .deny)]),
              "a range rule covers a proposal for an address inside it")
        check(expandedV6.isCovered(by: [Rule(remoteIP: "2001:db8::/32", action: .deny)]),
              "an IPv6 range rule covers a proposal for an address inside it")
        check(addressProposal("203.0.113.70").isCovered(by: [Rule(remoteIP: "203.0.113.*", action: .deny)]),
              "a wildcard address rule covers a proposal for an address it matches")
        check(addressProposal("203.0.113.70").isCovered(by: [Rule(remoteHost: "203.0.113.70", action: .deny)]),
              "an address in the hostname field covers a proposal for that address")
        check(expandedV6.isCovered(by: [Rule(remoteHost: "2001:db8::70", action: .deny)]),
              "an IPv6 address in the hostname field covers a proposal for that address in another spelling")
        check(addressProposal("198.51.100.9").isCovered(by: [Rule(remoteHost: "198.51.100.0/24", action: .deny)]),
              "a range in the hostname field covers a proposal for an address inside it")
        check(addressProposal("2001:db8::70").isCovered(by: [Rule(processBundleId: "com.beeper.app",
                                                                  remoteHost: "2001:db8::70", remoteIP: "2001:db8::70",
                                                                  action: .deny)]),
              "a rule Insights itself wrote for the address still covers it")
        check(!addressProposal("203.0.114.1").isCovered(by: [Rule(remoteIP: "203.0.113.0/24", action: .deny)]),
              "a range rule does not cover an address outside it")
        check(!addressProposal("2001:db8::71").isCovered(by: [Rule(remoteIP: "2001:db8::70", action: .deny)]),
              "an IPv6 address rule does not cover a different address")
        check(!addressProposal("203.0.113.70").isCovered(by: [Rule(remoteIP: "203.0.113.0/24", action: .deny, enabled: false)]),
              "a disabled rule covers nothing")
        check(!addressProposal("203.0.113.70").isCovered(by: [Rule(processBundleId: "com.other.app", remoteIP: "203.0.113.0/24", action: .deny)]),
              "a rule for another app does not cover this app's proposal")
        check(!addressProposal("203.0.113.70").isCovered(by: [Rule(remoteHost: "cdn.example.com", action: .deny)]),
              "a hostname rule does not cover an address proposal")
        check(!addressProposal("203.0.113.70").isCovered(by: [Rule(remoteHost: "203.0.113.70", remoteIP: "203.0.113.80", action: .deny)]),
              "a rule with its own address is compared by that address, not the hostname field")
        let domainProposal = InsightsProposedRule(appIdentity: "com.beeper.app", appDisplayName: "Beeper",
                                                  processBundleId: "com.beeper.app", processPath: nil,
                                                  domain: "api.example.com", remoteIP: nil, connectionCount: 1,
                                                  otherAppCount: 0, lastSeen: nil)
        check(domainProposal.isCovered(by: [Rule(remoteHost: "API.example.com", action: .deny)]),
              "a domain proposal is still covered by the same name in any case")
        check(!domainProposal.isCovered(by: [Rule(remoteIP: "203.0.113.0/24", action: .deny)]),
              "an address rule does not cover a domain proposal")

        // #331: a rule only covers a proposal when it would match every
        // outgoing connection the proposal stands for.
        let coverageNow = Date()
        check(!domainProposal.isCovered(by: [Rule(remoteHost: "api.example.com", remotePort: 443, action: .deny)], now: coverageNow),
              "a port-only rule does not cover a domain proposal")
        check(!addressProposal("203.0.113.70").isCovered(by: [Rule(remoteIP: "203.0.113.70", remotePort: 443, action: .deny)], now: coverageNow),
              "a port-only rule does not cover an address proposal")
        check(domainProposal.isCovered(by: [Rule(remoteHost: "api.example.com", remotePort: 0, action: .deny)], now: coverageNow),
              "port 0 means any port and still covers")
        check(!domainProposal.isCovered(by: [Rule(remoteHost: "api.example.com", direction: .incoming, action: .deny)], now: coverageNow),
              "an incoming-only rule does not cover an outgoing proposal")
        check(!addressProposal("203.0.113.70").isCovered(by: [Rule(remoteIP: "203.0.113.0/24", direction: .incoming, action: .deny)], now: coverageNow),
              "an incoming-only range rule does not cover an outgoing address proposal")
        check(domainProposal.isCovered(by: [Rule(remoteHost: "api.example.com", direction: .any, action: .deny)], now: coverageNow),
              "a rule for both directions covers an outgoing proposal")
        check(!domainProposal.isCovered(by: [Rule(remoteHost: "api.example.com", action: .deny,
                                                  expiresAt: coverageNow.addingTimeInterval(-60))], now: coverageNow),
              "an expired rule does not cover a proposal")
        check(domainProposal.isCovered(by: [Rule(remoteHost: "api.example.com", action: .deny,
                                                 expiresAt: coverageNow.addingTimeInterval(3600))], now: coverageNow),
              "a rule that has not expired yet still covers")
        check(domainProposal.isCovered(by: [Rule(remoteHost: "api.example.com", remotePort: 443, action: .deny),
                                            Rule(remoteHost: "api.example.com", action: .deny)], now: coverageNow),
              "a full rule next to a port-only rule still covers")

        // MARK: coverage by a wildcard or suffix hostname rule (#332)
        check(domainProposal.isCovered(by: [Rule(remoteHost: "*.example.com", action: .deny)]),
              "a wildcard hostname rule covers a domain proposal under it")
        check(domainProposal.isCovered(by: [Rule(remoteHost: ".example.com", action: .deny)]),
              "a suffix hostname rule covers a domain proposal under it")
        check(domainProposal.isCovered(by: [Rule(processBundleId: "com.beeper.app", remoteHost: "*.EXAMPLE.com", action: .deny)]),
              "a wildcard rule for this app covers the proposal in any case")
        let apexProposal = InsightsProposedRule(appIdentity: "com.beeper.app", appDisplayName: "Beeper",
                                                processBundleId: "com.beeper.app", processPath: nil,
                                                domain: "Example.com", remoteIP: nil, connectionCount: 1,
                                                otherAppCount: 0, lastSeen: nil)
        check(apexProposal.isCovered(by: [Rule(remoteHost: "*.example.com", action: .deny)]),
              "a wildcard rule covers the bare domain too, as the matcher does")
        check(!domainProposal.isCovered(by: [Rule(remoteHost: "*.other.com", action: .deny)]),
              "a wildcard rule for another domain does not cover the proposal")
        check(!domainProposal.isCovered(by: [Rule(remoteHost: "*.eu.api.example.com", action: .deny)]),
              "a wildcard rule for a deeper name does not cover the name above it")
        check(!domainProposal.isCovered(by: [Rule(remoteHost: "example.com", action: .deny)]),
              "a plain parent name does not cover a subdomain, as in the matcher")
        check(!domainProposal.isCovered(by: [Rule(remoteHost: "*.example.com", action: .deny, enabled: false)]),
              "a disabled wildcard rule covers nothing")
        check(!domainProposal.isCovered(by: [Rule(processBundleId: "com.other.app", remoteHost: "*.example.com", action: .deny)]),
              "a wildcard rule for another app does not cover this app's proposal")
        // The answer must agree with the matcher for every one of these.
        let probe = Connection(pid: 501, processName: "Beeper", processPath: "/Applications/Beeper.app",
                               processBundleId: "com.beeper.app", remoteHost: "api.example.com",
                               remoteIP: "203.0.113.5", remotePort: 443, direction: .outgoing)
        for pattern in ["*.example.com", ".example.com", "api.example.com", "example.com", "*.api.example.com", "*.eu.api.example.com", "*.other.com"] {
            let rule = Rule(remoteHost: pattern, action: .deny)
            equal(domainProposal.isCovered(by: [rule]), RuleMatcher().matches(rule: rule, connection: probe),
                  "coverage agrees with the matcher for \(pattern)")
        }

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
