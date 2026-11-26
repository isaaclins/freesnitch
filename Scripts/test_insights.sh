#!/usr/bin/env bash
# Deterministic Insights verification, compiled from the real helper and shared
# sources. Seeds a store in a temporary directory and asserts the read side:
# per-app grouping, co-occurrence counts, DNS-name joins, unresolved addresses,
# domain-scoped app-specific proposals, retention at 14 days and 1 year, the
# size ceiling on disk (#228), a purge
# that removes the write-ahead log too, and query bounds.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-insights.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation
import SQLite3

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
                            bytesIn: Int64 = 100, bytesOut: Int64 = 50,
                            decision: FlowDecision? = nil, version: String? = nil) -> FlowObservation {
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
        return FlowObservation(connection: connection, observedAt: date, processVersion: version, decision: decision)
    }

    static func rowStatus(_ row: InsightsDestinationSummary?) -> InsightsDecisionCounts.Status? {
        guard let row else { return nil }
        return row.decisions?.status(total: row.connectionCount)
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
        equal(sharedRaw.destinationKey, segmentIP, "a narrowed report echoes its destination, which the app uses to spot an older helper")
        check(appsReport.destinationKey == nil, "an unfiltered apps report carries no destination")
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

        // MARK: a failed read of the off switch (#267)
        // The store stays open while its settings query fails: another
        // connection takes the table away. The switch must come back as an
        // error, never as "on", and the report must fail rather than carry a
        // guessed state. Only a missing row means the default.
        func rawExec(_ sql: String) {
            var raw: OpaquePointer?
            defer { sqlite3_close(raw) }
            check(sqlite3_open(path, &raw) == SQLITE_OK && sqlite3_exec(raw, sql, nil, nil, nil) == SQLITE_OK,
                  "test setup ran: \(sql)")
        }
        try! store.setRecordingEnabled(false)
        rawExec("ALTER TABLE settings RENAME TO settings_unreadable;")
        expectThrow("a recording-setting read that fails") { _ = try store.recordingEnabled() }
        expectThrow("an overview whose recording setting cannot be read") {
            _ = try store.report(for: InsightsQuery(kind: .overview, since: Date().addingTimeInterval(-day), limit: 1))
        }
        expectThrow("an apps report whose recording setting cannot be read") {
            _ = try store.report(for: InsightsQuery(kind: .apps, since: Date().addingTimeInterval(-day), limit: 1))
        }
        rawExec("ALTER TABLE settings_unreadable RENAME TO settings;")
        check((try? store.recordingEnabled()) == false, "the switch reads off again once the setting can be read")
        rawExec("DELETE FROM settings WHERE key='recording_enabled';")
        check((try? store.recordingEnabled()) == true, "a missing setting means the documented default, on")
        check(overview().recordingEnabled, "the overview reports the default when the setting is missing")
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
        check(!domainProposal.isCovered(by: [Rule(remoteHost: "api.example.com", remotePort: 0, action: .deny)], now: coverageNow),
              "a port 0 rule matches nothing, so it does not cover (#218)")
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

        // MARK: lookups to a resolver stay out of the narrowed list (#435)
        // Recorded last so the counts above stay as they were. A lookup to a
        // resolver carries the name asked for; No Name and the rollups leave
        // it out, so the narrowed list does too.
        let sharedResolverIP = "198.51.100.53"
        try! store.record([
            observation(app: "Beeper", bundle: "com.beeper.app", path: "/Applications/Beeper.app",
                        host: "", ip: sharedResolverIP, at: Date().addingTimeInterval(-30)),
            observation(app: "Lookup Probe", bundle: "com.example.lookupprobe", path: "/Applications/Lookup Probe.app",
                        host: "lookup.example.net", ip: sharedResolverIP, at: Date().addingTimeInterval(-20), port: 53),
            // A lookup recorded without its name (one the resolver path could
            // not read) has the address as its host, and No Name counts it.
            observation(app: "Nameless Query", bundle: "com.example.namelessquery", path: "/Applications/Nameless Query.app",
                        host: sharedResolverIP, ip: sharedResolverIP, at: Date().addingTimeInterval(-10), port: 53)
        ])
        let resolverRow = try! store.report(for: InsightsQuery(kind: .unresolved, since: Date().addingTimeInterval(-day), limit: 50))
            .unresolved.first { $0.remoteIP == sharedResolverIP }
        let resolverApps = try! store.report(for: InsightsQuery(kind: .apps, destinationKey: sharedResolverIP, excludesLookups: true,
                                                               since: Date().addingTimeInterval(-day), limit: 50)).apps
        equal(Set(resolverApps.map(\.appIdentity)), ["com.beeper.app", "com.example.namelessquery"],
              "from No Name, a lookup that carried a name is left out and one without a name is listed, like the row counts them")
        equal(resolverApps.count, resolverRow?.appCount ?? -1, "the narrowed list agrees with the No Name row's app count")
        let withLookups = try! store.report(for: InsightsQuery(kind: .apps, destinationKey: sharedResolverIP,
                                                              since: Date().addingTimeInterval(-day), limit: 50)).apps
        equal(Set(withLookups.map(\.appIdentity)), ["com.beeper.app", "com.example.lookupprobe", "com.example.namelessquery"],
              "from the Apps tab, an app that only looked a name up there is listed, as its destinations count it")
        let probeDestinations = try! store.report(for: InsightsQuery(kind: .destinations, appIdentity: "com.example.lookupprobe",
                                                                    since: Date().addingTimeInterval(-day), limit: 50)).destinations
        equal((probeDestinations.first { $0.destinationKey == sharedResolverIP }?.otherAppCount ?? -2) + 1, withLookups.count,
              "the Apps tab's 'also contacted by' count matches the list its Show Apps opens")

        // MARK: what the filter did with each connection (#447)
        var decided: [FlowObservation] = []
        let spotify = (app: "Spotify", bundle: "com.spotify.client", path: "/Applications/Spotify.app")
        for index in 0..<4 {
            decided.append(observation(app: spotify.app, bundle: spotify.bundle, path: spotify.path,
                                       host: "apresolve.spotify.com", ip: "203.0.113.30",
                                       at: now.addingTimeInterval(-Double(index) * 10), decision: .allowed))
        }
        for index in 0..<3 {
            decided.append(observation(app: spotify.app, bundle: spotify.bundle, path: spotify.path,
                                       host: "analytics.spotify.com", ip: "203.0.113.31",
                                       at: now.addingTimeInterval(-Double(index) * 10), decision: .blocked))
        }
        // A rule that changed part way: two allowed, then one blocked.
        for (index, decision) in [FlowDecision.allowed, .allowed, .blocked].enumerated() {
            decided.append(observation(app: spotify.app, bundle: spotify.bundle, path: spotify.path,
                                       host: "ads.spotify.com", ip: "203.0.113.32",
                                       at: now.addingTimeInterval(-Double(index) * 10), decision: decision))
        }
        // Blocked next to connections that went through without a decision
        // (an alert that timed out): not "Blocked" (#447).
        for decision in [FlowDecision.blocked, .unfiltered] {
            decided.append(observation(app: spotify.app, bundle: spotify.bundle, path: spotify.path,
                                       host: "", ip: "192.0.2.92", at: now, decision: decision))
        }
        // Allowed next to a connection with no recorded decision: no label.
        for decision in [FlowDecision.allowed, nil] {
            decided.append(observation(app: spotify.app, bundle: spotify.bundle, path: spotify.path,
                                       host: "", ip: "192.0.2.93", at: now, decision: decision))
        }
        // Allowed next to one let through without a decision: not blocked,
        // but not all allowed either.
        for decision in [FlowDecision.allowed, .unfiltered] {
            decided.append(observation(app: spotify.app, bundle: spotify.bundle, path: spotify.path,
                                       host: "", ip: "192.0.2.94", at: now, decision: decision))
        }
        // Let through without a decision, and one recorded by an older
        // extension that sent no decision at all.
        decided.append(observation(app: spotify.app, bundle: spotify.bundle, path: spotify.path,
                                   host: "", ip: "192.0.2.90", at: now, decision: .unfiltered))
        decided.append(observation(app: spotify.app, bundle: spotify.bundle, path: spotify.path,
                                   host: "", ip: "192.0.2.91", at: now, decision: nil))
        try! store.record(decided)

        for (label, since) in [("raw events", now.addingTimeInterval(-day)), ("daily rollups", now.addingTimeInterval(-300 * day))] {
            let apps = try! store.report(for: InsightsQuery(kind: .apps, since: since, limit: 50))
            let spotifyApp = apps.apps.first { $0.appIdentity == spotify.bundle }
            equal(spotifyApp?.decisions, InsightsDecisionCounts(allowed: 8, blocked: 5, unfiltered: 3),
                  "\(label): the app row counts allowed, blocked and unfiltered connections")
            equal(spotifyApp?.blockedCount, 5, "\(label): the app row says how many were blocked")
            let destinations = try! store.report(for: InsightsQuery(kind: .destinations, appIdentity: spotify.bundle,
                                                                    since: since, limit: 50))
            let byKey = Dictionary(uniqueKeysWithValues: destinations.destinations.map { ($0.destinationKey, $0) })
            equal(rowStatus(byKey["apresolve.spotify.com"]), .allowed, "\(label): an all-allowed destination reads Allowed")
            equal(rowStatus(byKey["analytics.spotify.com"]), .blocked, "\(label): an all-blocked destination reads Blocked")
            equal(rowStatus(byKey["ads.spotify.com"]), .mixed(blocked: 1, of: 3),
                  "\(label): a destination with both reads as 1 of 3 blocked")
            equal(rowStatus(byKey["192.0.2.90"]), .unfiltered, "\(label): a connection let through without a decision reads Not filtered")
            equal(rowStatus(byKey["192.0.2.92"]), .mixed(blocked: 1, of: 2),
                  "\(label): blocked next to an unfiltered connection reads 1 of 2 blocked, not Blocked")
            equal(rowStatus(byKey["192.0.2.93"]), .unknown,
                  "\(label): allowed next to a connection with no decision gets no label, not Allowed")
            equal(rowStatus(byKey["192.0.2.94"]), .notBlocked,
                  "\(label): allowed next to an unfiltered connection reads Not blocked, not Allowed")
            equal(rowStatus(byKey["192.0.2.91"]), .unknown,
                  "\(label): a connection with no recorded decision is neither allowed nor blocked")
        }
        // Rows from before this change have no decision and must stay unknown.
        equal(appsReport.apps.first { $0.appIdentity == "com.beeper.app" }?.decisions,
              InsightsDecisionCounts(allowed: 0, blocked: 0, unfiltered: 0),
              "connections recorded without a decision are counted in none of the three")

        // The wire form: a decision survives the trip, and one this build
        // does not know reads as unknown instead of failing the batch.
        let blockedObservation = observation(app: "curl", bundle: nil, path: "/usr/bin/curl", host: "", ip: "192.0.2.5",
                                             at: now, decision: .blocked)
        let wire = try! FreeSnitchWireCodec.encode(FlowObservationBatch(observations: [blockedObservation]))
        let decoded = try! FreeSnitchWireCodec.decode(FlowObservationBatch.self, from: wire)
        equal(decoded.observations.first?.decision, .blocked, "the decision travels with the observation")
        let future = String(decoding: wire, as: UTF8.self).replacingOccurrences(of: "\"blocked\"", with: "\"quarantined\"")
        let futureBatch = try? FreeSnitchWireCodec.decode(FlowObservationBatch.self, from: Data(future.utf8))
        check(futureBatch != nil, "an unknown decision value does not fail the batch")
        check(futureBatch?.observations.first?.decision == nil, "an unknown decision value reads as unknown")

        // MARK: alerts the app let through without anyone answering (#447)
        // The extension only hears "allow" back, so it sends these as allowed.
        // The app relabels them on the way to the helper.
        let duplicate = observation(app: "Chrome", bundle: "com.google.Chrome", path: "/Applications/Chrome.app",
                                    host: "", ip: "192.0.2.60", at: now, decision: .allowed)
        let answered = observation(app: "Chrome", bundle: "com.google.Chrome", path: "/Applications/Chrome.app",
                                   host: "", ip: "192.0.2.61", at: now, decision: .allowed)
        let denied = observation(app: "Chrome", bundle: "com.google.Chrome", path: "/Applications/Chrome.app",
                                 host: "", ip: "192.0.2.62", at: now, decision: .blocked)
        var ledger = UnansweredAlertLedger()
        check(ledger.relabel(FlowObservationBatch(observations: [duplicate])) == nil,
              "with nothing noted, a batch is forwarded unchanged")
        ledger.note(duplicate.id)
        ledger.note(denied.id)
        let relabelled = ledger.relabel(FlowObservationBatch(observations: [duplicate, answered, denied]))
        equal(relabelled?.observations.map(\.decision), [.unfiltered, .allowed, .blocked],
              "only the flow let through without an answer becomes not filtered")
        check(ledger.relabel(FlowObservationBatch(observations: [duplicate])) == nil,
              "a noted flow is relabelled once")
        var withHits = UnansweredAlertLedger()
        withHits.note(answered.id)
        let hit = RuleHit(ruleID: UUID(), count: 3, lastMatchedAt: now)
        equal(withHits.relabel(FlowObservationBatch(observations: [answered], ruleHits: [hit]))?.ruleHits, [hit],
              "relabelling keeps the rule hits that travel in the same batch")
        try! store.record(relabelled!.observations)
        let chrome = try! store.report(for: InsightsQuery(kind: .destinations, appIdentity: "com.google.Chrome",
                                                          since: now.addingTimeInterval(-day), limit: 50))
        equal(rowStatus(chrome.destinations.first { $0.destinationKey == "192.0.2.60" }), .unfiltered,
              "a duplicate alert's flow reads Not filtered, not Allowed")
        let evicted = observation(app: "Chrome", bundle: nil, path: "/Applications/Chrome.app", host: "",
                                  ip: "192.0.2.63", at: now, decision: .allowed)
        let newest = observation(app: "Chrome", bundle: nil, path: "/Applications/Chrome.app", host: "",
                                 ip: "192.0.2.64", at: now, decision: .allowed)
        var bounded = UnansweredAlertLedger()
        bounded.note(evicted.id)
        for _ in 0..<(UnansweredAlertLedger.capacity - 1) { bounded.note(UUID()) }
        bounded.note(newest.id)
        check(bounded.relabel(FlowObservationBatch(observations: [evicted])) == nil,
              "the ledger stays bounded and forgets the oldest id")
        equal(bounded.relabel(FlowObservationBatch(observations: [newest]))?.observations.first?.decision, .unfiltered,
              "the newest id is still there after the oldest was dropped")
        let negative = try? JSONDecoder().decode(InsightsDecisionCounts.self,
                                                 from: Data(#"{"allowed":-3,"blocked":2,"unfiltered":-1}"#.utf8))
        equal(negative, InsightsDecisionCounts(allowed: 0, blocked: 2, unfiltered: 0),
              "negative counts from the wire read as zero")

        // MARK: the database has a ceiling on disk (#228)
        // A flood of connections to distinct destinations, all inside the
        // retention windows, against a small ceiling: the file must stay
        // under it, every batch must still be accepted, and what goes is the
        // oldest history, never the newest.
        func fileBytes(_ file: String) -> Int64 {
            var info = stat()
            return lstat(file, &info) == 0 ? Int64(info.st_size) : 0
        }
        func count(_ file: String, _ sql: String) -> Int {
            var handle: OpaquePointer?
            var statement: OpaquePointer?
            defer { sqlite3_finalize(statement); sqlite3_close(handle) }
            guard sqlite3_open_v2(file, &handle, SQLITE_OPEN_READONLY, nil) == SQLITE_OK,
                  sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK,
                  sqlite3_step(statement) == SQLITE_ROW else { return -1 }
            return Int(sqlite3_column_int64(statement, 0))
        }
        func floodBatch(_ index: Int, at date: Date, rows: Int = InsightsLimits.maxBatchCount,
                        path: String = "/Applications/Flood.app") -> [FlowObservation] {
            (0..<rows).map { row in
                observation(app: "Flood", bundle: "com.example.flood", path: path,
                            host: "host-\(index)-\(row).flood.example", ip: "198.51.\(index % 250).\(row % 250)",
                            at: date, decision: .allowed)
            }
        }
        let cappedSupport = root.appendingPathComponent("Capped Support")
        try! FileManager.default.createDirectory(at: cappedSupport, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o755])
        let cappedPath = cappedSupport.appendingPathComponent("Insights/insights.sqlite").path
        let ceiling: Int64 = 2 * 1024 * 1024
        do {
            let capped = try InsightsStore(path: cappedPath, expectedUID: getuid(), maxDatabaseBytes: ceiling)
            var refused = 0
            var largest: Int64 = 0
            let batches = 120
            for index in 0..<batches {
                // Oldest first, spread across the 14-day raw window.
                let at = now.addingTimeInterval(-13 * day + Double(index) * (13 * day / Double(batches)))
                do { try capped.record(floodBatch(index, at: at)) } catch { refused += 1 }
                largest = max(largest, fileBytes(cappedPath))
            }
            equal(refused, 0, "every batch is accepted while the ceiling is reached again and again")
            check(largest <= ceiling, "the database file never grows past its ceiling (largest \(largest) of \(ceiling) bytes)")
            let overview = try capped.report(for: InsightsQuery(kind: .overview, since: now.addingTimeInterval(-day))).overview
            check((overview?.rawObservationCount ?? 0) < batches * InsightsLimits.maxBatchCount,
                  "the oldest raw events were dropped to stay under the ceiling")
            check((overview?.rawObservationCount ?? 0) > 0, "recent raw events are kept")
            equal(count(cappedPath, "SELECT COUNT(*) FROM flow_observations WHERE remote_host LIKE 'host-\(batches - 1)-%';"),
                  InsightsLimits.maxBatchCount, "the newest batch is still in the history")
            check(overview.map { ($0.oldestObservation ?? now) > now.addingTimeInterval(-13 * day + 60) } ?? false,
                  "the oldest events are the ones that went")
            try capped.prune(now: now)
            check(fileBytes(cappedPath) <= ceiling, "maintenance leaves the file under its ceiling")
        } catch {
            check(false, "a store with a ceiling keeps recording: \(error)")
        }
        // Batches bigger than a tenth of the ceiling (long process paths make
        // each one about a sixth of it) reach the hard limit inside a write;
        // the store makes room and the batch still lands.
        let tightSupport = root.appendingPathComponent("Tight Support")
        try! FileManager.default.createDirectory(at: tightSupport, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o755])
        let tightPath = tightSupport.appendingPathComponent("Insights/insights.sqlite").path
        let tightCeiling: Int64 = 4 * 1024 * 1024
        let longPath = "/Applications/" + String(repeating: "Flood/", count: 400) + "Flood.app"
        do {
            let tight = try InsightsStore(path: tightPath, expectedUID: getuid(), maxDatabaseBytes: tightCeiling)
            var refused = 0
            for index in 0..<40 {
                do { try tight.record(floodBatch(index, at: now.addingTimeInterval(Double(index - 39) * 8 * 3600),
                                                 path: longPath)) }
                catch { refused += 1 }
            }
            equal(refused, 0, "a write that hits the hard limit makes room and lands")
            check(tight.fullRetryCount > 0, "the hard limit was actually reached and a write was retried after trimming")
            check(fileBytes(tightPath) <= tightCeiling, "the hard limit holds the file at its ceiling")
            equal(count(tightPath, "SELECT COUNT(*) FROM flow_observations WHERE remote_host LIKE 'host-39-%';"),
                  InsightsLimits.maxBatchCount, "the batch that hit the hard limit was recorded in full")
        } catch {
            check(false, "a store at its hard limit keeps recording: \(error)")
        }
        // A flood of DNS answers is trimmed oldest first like everything
        // else, and like raw events before the rollup of their own day: a
        // connection newer than every answer survives the flood that follows.
        // Everything is on one UTC day, where answers used to lose to the
        // connection's rollup and take the connection with them.
        let dnsSupport = root.appendingPathComponent("DNS Flood Support")
        try! FileManager.default.createDirectory(at: dnsSupport, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o755])
        let dnsPath = dnsSupport.appendingPathComponent("Insights/insights.sqlite").path
        do {
            let flooded = try InsightsStore(path: dnsPath, expectedUID: getuid(), maxDatabaseBytes: 1024 * 1024)
            let floodNow = Date()
            for index in 0..<60 {
                if index == 10 {
                    try flooded.record([observation(app: "Kept", bundle: "com.example.kept", path: "/Applications/Kept.app",
                                                    host: "kept.example", ip: "192.0.2.81", at: floodNow)])
                }
                let at = floodNow.addingTimeInterval(-Double(60 - index) / 10)
                try flooded.recordDNSMappings((0..<InsightsLimits.maxDNSMappingCount).map { row in
                    DNSMapping(domain: "random-\(index)-\(row).dns-flood.example", ip: "203.0.113.\(row % 250)",
                               observedAt: at, expiresAt: at.addingTimeInterval(300))
                })
            }
            check(fileBytes(dnsPath) <= 1024 * 1024, "a DNS flood stays under the ceiling")
            check(count(dnsPath, "SELECT COUNT(*) FROM dns_mappings WHERE domain LIKE 'random-0-%';") == 0,
                  "the DNS flood was trimmed")
            equal(count(dnsPath, "SELECT COUNT(*) FROM flow_observations WHERE remote_host = 'kept.example';"), 1,
                  "a connection newer than every DNS answer survives the flood")
        } catch {
            check(false, "a DNS flood is trimmed: \(error)")
        }
        // A store that grew past the ceiling before it existed stops growing
        // at once and is compacted under it by the next maintenance run.
        let grownSupport = root.appendingPathComponent("Grown Support")
        try! FileManager.default.createDirectory(at: grownSupport, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o755])
        let grownPath = grownSupport.appendingPathComponent("Insights/insights.sqlite").path
        do {
            do {
                let unbounded = try InsightsStore(path: grownPath, expectedUID: getuid())
                for index in 0..<40 {
                    try unbounded.record(floodBatch(index, at: now.addingTimeInterval(Double(index - 40) * 3600)))
                }
            }
            let grown = fileBytes(grownPath)
            let grownCeiling: Int64 = 1024 * 1024
            check(grown > grownCeiling, "the old store is larger than the new ceiling (\(grown) bytes)")
            let reopened = try InsightsStore(path: grownPath, expectedUID: getuid(), maxDatabaseBytes: grownCeiling)
            for index in 40..<60 {
                try reopened.record(floodBatch(index, at: now.addingTimeInterval(Double(index - 60) * 60)))
            }
            check(fileBytes(grownPath) <= grown, "the oversized store does not grow any further")
            try reopened.prune(now: now)
            check(fileBytes(grownPath) <= grownCeiling,
                  "maintenance compacts the oversized store under its ceiling (\(fileBytes(grownPath)) bytes)")
            try reopened.record(floodBatch(60, at: now))
            equal(count(grownPath, "SELECT COUNT(*) FROM flow_observations WHERE remote_host LIKE 'host-60-%';"),
                  InsightsLimits.maxBatchCount, "the compacted store keeps recording")
        } catch {
            check(false, "an oversized store opens, records and compacts: \(error)")
        }

        // When one UTC day alone fills the budget, the trim after a write
        // must not take the batch that was just written (#579). Every batch
        // here is on the same day, noon UTC yesterday, whatever time the
        // harness runs (today's noon can still be in the future).
        let oneDaySupport = root.appendingPathComponent("One Day Support")
        try! FileManager.default.createDirectory(at: oneDaySupport, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o755])
        let oneDayPath = oneDaySupport.appendingPathComponent("Insights/insights.sqlite").path
        do {
            var utc = Calendar(identifier: .gregorian)
            utc.timeZone = TimeZone(identifier: "UTC")!
            let noon = utc.date(bySettingHour: 12, minute: 0, second: 0, of: now.addingTimeInterval(-24 * 3600))!
            let oneDayCeiling: Int64 = 1024 * 1024
            let oneDay = try InsightsStore(path: oneDayPath, expectedUID: getuid(), maxDatabaseBytes: oneDayCeiling)
            var lost: [Int] = []
            for index in 0..<40 {
                try oneDay.record(floodBatch(index, at: noon.addingTimeInterval(Double(index))))
                if count(oneDayPath, "SELECT COUNT(*) FROM flow_observations WHERE remote_host LIKE 'host-\(index)-%';")
                    != InsightsLimits.maxBatchCount { lost.append(index) }
            }
            check(count(oneDayPath, "SELECT COUNT(*) FROM flow_observations WHERE remote_host LIKE 'host-0-%';") == 0,
                  "a store filled by one day was trimmed")
            equal(lost, [], "every batch written into a store filled by one day is kept by the trim that follows it")
            check(fileBytes(oneDayPath) <= oneDayCeiling, "a store filled by one day stays under its ceiling")
        } catch {
            check(false, "a store filled by one day keeps recording: \(error)")
        }

        // A DNS flood after a single batch, with nothing older to trim: the
        // answers newer than that batch still make room, so the store never
        // refuses every write at its ceiling.
        let lateDNSSupport = root.appendingPathComponent("Late DNS Support")
        try! FileManager.default.createDirectory(at: lateDNSSupport, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o755])
        let lateDNSPath = lateDNSSupport.appendingPathComponent("Insights/insights.sqlite").path
        do {
            let lateCeiling: Int64 = 512 * 1024
            let late = try InsightsStore(path: lateDNSPath, expectedUID: getuid(), maxDatabaseBytes: lateCeiling)
            let lateNow = Date()
            try late.record(floodBatch(0, at: lateNow.addingTimeInterval(-120)))
            var refused = 0
            for index in 0..<80 {
                let at = lateNow.addingTimeInterval(-Double(80 - index) / 10)
                do {
                    try late.recordDNSMappings((0..<InsightsLimits.maxDNSMappingCount).map { row in
                        DNSMapping(domain: "late-\(index)-\(row).dns-flood.example", ip: "203.0.113.\(row % 250)",
                                   observedAt: at, expiresAt: at.addingTimeInterval(300))
                    })
                } catch { refused += 1 }
            }
            equal(refused, 0, "a DNS flood after a single batch keeps landing")
            check(fileBytes(lateDNSPath) <= lateCeiling, "a DNS flood after a single batch stays under the ceiling")
            try late.record(floodBatch(1, at: lateNow))
            equal(count(lateDNSPath, "SELECT COUNT(*) FROM flow_observations WHERE remote_host LIKE 'host-1-%';"),
                  InsightsLimits.maxBatchCount, "a connection batch after that DNS flood is recorded")
        } catch {
            check(false, "a DNS flood after a single batch keeps recording: \(error)")
        }

        // A store from before #228 that is over the ceiling, has no free
        // pages and lacks the indexes this change adds must still open,
        // record and be compacted.
        let fullSupport = root.appendingPathComponent("Full Support")
        try! FileManager.default.createDirectory(at: fullSupport, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o755])
        let fullPath = fullSupport.appendingPathComponent("Insights/insights.sqlite").path
        do {
            do {
                let unbounded = try InsightsStore(path: fullPath, expectedUID: getuid())
                for index in 0..<30 {
                    try unbounded.record(floodBatch(index, at: now.addingTimeInterval(Double(index - 30) * 3600)))
                }
            }
            var raw: OpaquePointer?
            check(sqlite3_open(fullPath, &raw) == SQLITE_OK, "the pre-#228 store can be opened directly")
            check(sqlite3_exec(raw, """
                DROP INDEX IF EXISTS idx_insights_dns_observed_at;
                DROP INDEX IF EXISTS idx_insights_versioned_rollup_day;
                VACUUM;
                PRAGMA wal_checkpoint(TRUNCATE);
                """, nil, nil, nil) == SQLITE_OK, "the new indexes were removed and the free pages compacted away")
            sqlite3_close(raw)
            equal(count(fullPath, "PRAGMA freelist_count;"), 0, "the pre-#228 store has no free pages")
            let fullCeiling: Int64 = 1024 * 1024
            check(fileBytes(fullPath) > fullCeiling, "the pre-#228 store is over the new ceiling")
            let reopened = try InsightsStore(path: fullPath, expectedUID: getuid(), maxDatabaseBytes: fullCeiling)
            equal(count(fullPath, "SELECT COUNT(*) FROM sqlite_master WHERE name='idx_insights_dns_observed_at';"), 1,
                  "the full, oversized store opens and gains the new indexes")
            try reopened.record(floodBatch(90, at: now))
            equal(count(fullPath, "SELECT COUNT(*) FROM flow_observations WHERE remote_host LIKE 'host-90-%';"),
                  InsightsLimits.maxBatchCount, "the full, oversized store keeps recording")
            try reopened.prune(now: now)
            check(fileBytes(fullPath) <= fullCeiling, "the full, oversized store is compacted under its ceiling")
        } catch {
            check(false, "a full, oversized store from before #228 opens: \(error)")
        }

        // MARK: a store from before #447 gains the columns and keeps its rows unknown
        let legacySupport = root.appendingPathComponent("Legacy Support")
        try! FileManager.default.createDirectory(at: legacySupport.appendingPathComponent("Insights"),
                                                 withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        let legacyPath = legacySupport.appendingPathComponent("Insights/insights.sqlite").path
        var legacyDB: OpaquePointer?
        check(sqlite3_open(legacyPath, &legacyDB) == SQLITE_OK, "a pre-#447 store can be created")
        let legacySQL = """
            CREATE TABLE flow_observations (id TEXT PRIMARY KEY, observed_at REAL NOT NULL, pid INTEGER NOT NULL,
                process_bundle_id TEXT, process_path TEXT NOT NULL, process_name TEXT NOT NULL, process_version TEXT,
                remote_host TEXT NOT NULL, remote_ip TEXT NOT NULL, remote_port INTEGER NOT NULL, direction TEXT NOT NULL,
                protocol_name TEXT NOT NULL, bytes_in INTEGER, bytes_out INTEGER);
            CREATE TABLE daily_rollups (app_identity TEXT NOT NULL, destination_key TEXT NOT NULL, utc_day TEXT NOT NULL,
                connection_count INTEGER NOT NULL, bytes_in INTEGER NOT NULL DEFAULT 0, bytes_out INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(app_identity, destination_key, utc_day));
            INSERT INTO flow_observations VALUES ('\(UUID().uuidString)', \(now.timeIntervalSince1970 - 60), 501, 'com.old.app',
                '/Applications/Old.app', 'Old', NULL, '', '192.0.2.70', 443, 'outgoing', 'tcp', 10, 10);
            INSERT INTO daily_rollups VALUES ('com.old.app', '192.0.2.70', '2026-01-01', 7, 70, 70);
            """
        check(sqlite3_exec(legacyDB, legacySQL, nil, nil, nil) == SQLITE_OK, "the pre-#447 store was seeded")
        sqlite3_close(legacyDB)
        chmod(legacyPath, 0o600)
        do {
            let upgraded = try InsightsStore(path: legacyPath, expectedUID: getuid())
            try upgraded.record([observation(app: "Old", bundle: "com.old.app", path: "/Applications/Old.app",
                                             host: "", ip: "192.0.2.70", at: now, decision: .blocked)])
            let oldRows = try upgraded.report(for: InsightsQuery(kind: .destinations, appIdentity: "com.old.app",
                                                                 since: now.addingTimeInterval(-day), limit: 50))
            let oldRow = oldRows.destinations.first
            equal(oldRow?.connectionCount, 2, "the upgraded store keeps its old row and takes the new one")
            equal(oldRow?.decisions, InsightsDecisionCounts(allowed: 0, blocked: 1, unfiltered: 0),
                  "only the new connection counts as blocked; the old one stays unknown")
        } catch {
            check(false, "a pre-#447 store opens and upgrades: \(error)")
        }

        // MARK: Changed findings page past the first 50 (#231)
        let pagedSupport = root.appendingPathComponent("Paged Support")
        try! FileManager.default.createDirectory(at: pagedSupport.appendingPathComponent("Insights"),
                                                 withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        do {
            let paged = try InsightsStore(path: pagedSupport.appendingPathComponent("Insights/insights.sqlite").path,
                                          expectedUID: getuid())
            let pagedNow = Date()
            var seeded = [observation(app: "Updater", bundle: "com.example.updater",
                                      path: "/Applications/Updater.app",
                                      host: "old.example.com", ip: "192.0.2.1",
                                      at: pagedNow.addingTimeInterval(-7200), version: "1.0")]
            for index in 0..<60 {
                let at = pagedNow.addingTimeInterval(-3600 + Double(index))
                seeded.append(observation(app: "Updater", bundle: "com.example.updater",
                                          path: "/Applications/Updater.app",
                                          host: "new\(index).example.com", ip: "198.51.100.\(index + 1)",
                                          at: at, version: "2.0"))
            }
            try paged.record(seeded)
            let since = pagedNow.addingTimeInterval(-day)
            let first = try paged.report(for: InsightsQuery(kind: .findings, since: since, limit: 50))
            let second = try paged.report(for: InsightsQuery(kind: .findings, since: since, limit: 50, offset: 50))
            equal(first.findings.count, 50, "the first page of changed destinations holds 50")
            check(first.hasMore, "the first page says more changed destinations follow")
            equal(second.findings.count, 10, "the second page holds the remaining 10")
            check(!second.hasMore, "the second page is the last one")
            let firstKeys = Set(first.findings.map(\.destination))
            let secondKeys = Set(second.findings.map(\.destination))
            check(firstKeys.isDisjoint(with: secondKeys), "the second page returns different rows than the first")
            equal(firstKeys.union(secondKeys).count, 60, "every changed destination is reachable across the pages")
            let past = try paged.report(for: InsightsQuery(kind: .findings, since: since, limit: 50, offset: 100))
            check(past.findings.isEmpty && !past.hasMore, "a page past the end is empty")
        } catch {
            check(false, "changed findings can be paged: \(error)")
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
