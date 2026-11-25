import Foundation

/// The domains each app reached, written out of Insights as CSV or JSON so
/// they can be kept as an inventory or fed to a DNS filter elsewhere (#195).
///
/// Names come only from what Insights already holds: the DNS answers this Mac
/// saw. A destination that never had a name stays an address and is written
/// as one, never guessed.
public struct InsightsDomainExport: Sendable {
    public static let formatIdentifier = "freesnitch.insights-domains.v1"
    public static let csvHeader = ["app", "bundle_id", "path", "domain", "ip", "connections", "last_seen"]

    public struct App: Sendable {
        public let summary: InsightsAppSummary
        public let destinations: [InsightsDestinationSummary]

        public init(summary: InsightsAppSummary, destinations: [InsightsDestinationSummary]) {
            self.summary = summary
            self.destinations = destinations
        }
    }

    public let generatedAt: Date
    public let rangeStart: Date
    public let rangeEnd: Date
    public let source: InsightsDataSource
    /// False when the store had more than the export could page through, so a
    /// reader never takes a cut-off list for the whole picture.
    public let complete: Bool
    public let apps: [App]

    public init(generatedAt: Date, rangeStart: Date, rangeEnd: Date, source: InsightsDataSource,
                complete: Bool, apps: [App]) {
        self.generatedAt = generatedAt
        self.rangeStart = rangeStart
        self.rangeEnd = rangeEnd
        self.source = source
        self.complete = complete
        self.apps = apps
    }

    // MARK: Collecting

    public struct Failure: Error, Sendable {
        public let message: String
        public init(message: String) { self.message = message }
    }

    /// Pages through every app in the range and every destination of each,
    /// with one fixed range so every page describes the same window. `fetch`
    /// is the helper's Insights query; the harness passes the store itself.
    public static func collect(since: Date, until: Date, pageSize: Int,
                               fetch: (InsightsQuery) async -> (InsightsReport?, String?)) async
        -> Result<InsightsDomainExport, Failure> {
        var complete = true
        var source = InsightsDataSource.rawEvents

        func pages<Row>(_ kind: InsightsQueryKind, appIdentity: String?,
                        rows: (InsightsReport) -> [Row]) async -> Result<[Row], Failure> {
            var collected: [Row] = []
            var offset = 0
            while true {
                let request = InsightsQuery(kind: kind, appIdentity: appIdentity, since: since, until: until,
                                            limit: pageSize, offset: offset)
                let (report, error) = await fetch(request)
                guard let report else {
                    return .failure(Failure(message: error ?? String(localized: "The helper did not answer the Insights query.")))
                }
                if report.source == .dailyRollups { source = .dailyRollups }
                let page = rows(report)
                collected += page
                offset += page.count
                guard report.hasMore, !page.isEmpty else { return .success(collected) }
                guard offset <= InsightsLimits.maxQueryOffset else {
                    complete = false
                    return .success(collected)
                }
            }
        }

        let summaries: [InsightsAppSummary]
        switch await pages(.apps, appIdentity: nil, rows: \.apps) {
        case .success(let rows): summaries = rows
        case .failure(let failure): return .failure(failure)
        }
        var apps: [App] = []
        for summary in summaries {
            switch await pages(.destinations, appIdentity: summary.appIdentity, rows: \.destinations) {
            case .success(let rows): apps.append(App(summary: summary, destinations: rows))
            case .failure(let failure): return .failure(failure)
            }
        }
        return .success(InsightsDomainExport(generatedAt: Date(), rangeStart: since, rangeEnd: until,
                                             source: source, complete: complete, apps: apps))
    }

    // MARK: CSV

    /// One row per app and destination. `domain` is empty when no name was
    /// seen; `ip` is empty when the store kept only the name.
    public func csv() -> Data {
        var lines = [Self.csvHeader.joined(separator: ",")]
        for app in apps {
            for destination in app.destinations {
                let cells = [
                    app.summary.displayName,
                    app.summary.processBundleId ?? "",
                    app.summary.processPath ?? "",
                    destination.resolvedDomain ?? "",
                    destination.remoteIP ?? (destination.resolvedDomain == nil ? destination.destinationKey : ""),
                    String(destination.connectionCount),
                    destination.lastSeen.map(Self.timestamp) ?? ""
                ]
                lines.append(cells.map(Self.csvCell).joined(separator: ","))
            }
        }
        return Data((lines.joined(separator: "\r\n") + "\r\n").utf8)
    }

    /// RFC 4180 quoting, plus a leading apostrophe on text a spreadsheet would
    /// run as a formula. Process names come from whatever ran on the Mac, so a
    /// name like `=HYPERLINK(...)` must open as text. Valid domains, addresses
    /// and absolute paths never start with these characters.
    static func csvCell(_ value: String) -> String {
        var text = value
        if let first = text.unicodeScalars.first, "=+-@\t\r".unicodeScalars.contains(first) {
            text = "'" + text
        }
        let needsQuotes = text.contains(where: { $0 == "," || $0 == "\"" || $0 == "\n" || $0 == "\r" })
        guard needsQuotes else { return text }
        return "\"" + text.replacingOccurrences(of: "\"", with: "\"\"") + "\""
    }

    // MARK: JSON

    private struct Document: Encodable {
        let format: String
        let generatedAt: String
        let rangeStart: String
        let rangeEnd: String
        let source: String
        let complete: Bool
        let apps: [AppEntry]
    }

    private struct AppEntry: Encodable {
        let name: String
        let bundleId: String?
        let path: String?
        let domains: [DomainEntry]
        let addressesWithoutName: [AddressEntry]
    }

    private struct DomainEntry: Encodable {
        let domain: String
        /// Every address the name was reached at, so one name is one entry.
        let ips: [String]
        let connections: Int
        let lastSeen: String?
    }

    private struct AddressEntry: Encodable {
        let ip: String
        let connections: Int
        let lastSeen: String?
    }

    /// Grouped by app: the names it reached, then the addresses it reached
    /// without a name lookup, so a domain list can be read straight off
    /// `apps[].domains[].domain`.
    public func json() throws -> Data {
        let document = Document(
            format: Self.formatIdentifier,
            generatedAt: Self.timestamp(generatedAt),
            rangeStart: Self.timestamp(rangeStart),
            rangeEnd: Self.timestamp(rangeEnd),
            source: source.rawValue,
            complete: complete,
            apps: apps.map { app in
                AppEntry(
                    name: app.summary.displayName,
                    bundleId: app.summary.processBundleId,
                    path: app.summary.processPath,
                    domains: Self.domainEntries(app.destinations),
                    addressesWithoutName: app.destinations.compactMap { destination in
                        guard destination.resolvedDomain == nil else { return nil }
                        return AddressEntry(ip: destination.remoteIP ?? destination.destinationKey,
                                            connections: destination.connectionCount,
                                            lastSeen: destination.lastSeen.map(Self.timestamp))
                    })
            })
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(document)
    }

    /// One entry per name. The store can hold the same name more than once for
    /// an app (asked for by name, and reached at several mapped addresses), and
    /// an allowlist wants each name once.
    private static func domainEntries(_ destinations: [InsightsDestinationSummary]) -> [DomainEntry] {
        var order: [String] = []
        var merged: [String: (ips: [String], connections: Int, lastSeen: Date?)] = [:]
        for destination in destinations {
            guard let domain = destination.resolvedDomain else { continue }
            var entry = merged[domain] ?? (ips: [], connections: 0, lastSeen: nil)
            if merged[domain] == nil { order.append(domain) }
            if let ip = destination.remoteIP, !entry.ips.contains(ip) { entry.ips.append(ip) }
            entry.connections += destination.connectionCount
            if let seen = destination.lastSeen, entry.lastSeen.map({ seen > $0 }) ?? true { entry.lastSeen = seen }
            merged[domain] = entry
        }
        return order.map { domain in
            let entry = merged[domain]!
            return DomainEntry(domain: domain, ips: entry.ips, connections: entry.connections,
                               lastSeen: entry.lastSeen.map(timestamp))
        }
    }

    static func timestamp(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: date)
    }
}
