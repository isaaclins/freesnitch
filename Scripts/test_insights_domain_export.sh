#!/usr/bin/env bash
# The Insights domain export (#195), compiled from the real helper store and
# shared sources. Seeds a store the way the helper records it (DNS answers,
# then flows), exports through the same paging code the app runs, and checks
# what lands in the CSV and JSON files: every app across several pages, every
# destination of each, names only where a DNS answer was seen, addresses kept
# as addresses, and process names that cannot break the CSV or run as a
# spreadsheet formula.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-domain-export.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

@main
struct DomainExportHarness {
    static var failures = 0

    static func check(_ condition: Bool, _ message: String) {
        if condition {
            print("domain export harness: PASS: \(message)")
        } else {
            failures += 1
            FileHandle.standardError.write(Data("domain export harness: FAIL: \(message)\n".utf8))
        }
    }

    static func observation(app: String, bundle: String?, path: String, host: String, ip: String,
                            at date: Date) -> FlowObservation {
        let connection = Connection(pid: 501, processName: app, processPath: path, processBundleId: bundle,
                                    remoteHost: host, remoteIP: ip, remotePort: 443, direction: .outgoing,
                                    protocolName: "tcp", bytesIn: 100, bytesOut: 50)
        return FlowObservation(connection: connection, observedAt: date, decision: .allowed)
    }

    /// A minimal RFC 4180 reader, so the check reads the file the way a
    /// spreadsheet or a script would rather than splitting on commas.
    static func parseCSV(_ text: String) -> [[String]] {
        var rows: [[String]] = []
        var row: [String] = []
        var cell = ""
        var quoted = false
        var chars = Array(text)
        var i = 0
        while i < chars.count {
            let c = chars[i]
            if quoted {
                if c == "\"" {
                    if i + 1 < chars.count, chars[i + 1] == "\"" { cell.append("\""); i += 1 } else { quoted = false }
                } else { cell.append(c) }
            } else if c == "\"" {
                quoted = true
            } else if c == "," {
                row.append(cell); cell = ""
            } else if c == "\r\n" || c == "\n" {
                row.append(cell); cell = ""; rows.append(row); row = []
            } else {
                cell.append(c)
            }
            i += 1
        }
        if !cell.isEmpty || !row.isEmpty { row.append(cell); rows.append(row) }
        chars = []
        return rows
    }

    static func main() async {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("freesnitch-domain-export-\(UUID().uuidString)")
        let support = root.appendingPathComponent("Application Support")
        try! FileManager.default.createDirectory(at: support, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o755])
        defer { try? FileManager.default.removeItem(at: root) }
        let store: InsightsStore
        do {
            store = try InsightsStore(path: support.appendingPathComponent("Insights/insights.sqlite").path,
                                      expectedUID: getuid())
        } catch {
            FileHandle.standardError.write(Data("domain export harness: FAIL: store did not open: \(error)\n".utf8))
            exit(1)
        }

        let now = Date()
        // The reporter's case: Office talks to cloud names whose addresses
        // change, plus one address it reached without a lookup.
        try! store.recordDNSMappings([
            DNSMapping(domain: "login.microsoftonline.com", ip: "20.190.160.1", observedAt: now.addingTimeInterval(-600)),
            DNSMapping(domain: "outlook.office365.com", ip: "52.97.1.1", observedAt: now.addingTimeInterval(-600)),
            DNSMapping(domain: "d111.cloudfront.net", ip: "13.32.0.9", observedAt: now.addingTimeInterval(-600))
        ])
        var seeded: [FlowObservation] = []
        let outlook = "/Applications/Microsoft Outlook.app"
        seeded.append(observation(app: "Microsoft Outlook", bundle: "com.microsoft.Outlook", path: outlook,
                                  host: "", ip: "20.190.160.1", at: now.addingTimeInterval(-300)))
        seeded.append(observation(app: "Microsoft Outlook", bundle: "com.microsoft.Outlook", path: outlook,
                                  host: "", ip: "52.97.1.1", at: now.addingTimeInterval(-200)))
        seeded.append(observation(app: "Microsoft Outlook", bundle: "com.microsoft.Outlook", path: outlook,
                                  host: "", ip: "198.51.100.7", at: now.addingTimeInterval(-100)))
        // A process name meant to run as a formula, with a comma and a quote.
        seeded.append(observation(app: "=HYPERLINK(\"http://x\",\"y\")", bundle: nil, path: "/tmp/evil",
                                  host: "", ip: "13.32.0.9", at: now.addingTimeInterval(-90)))
        // Enough apps and destinations that a page size of 2 needs several
        // pages for both, the way a busy Mac does with the real page size.
        for index in 0..<5 {
            seeded.append(observation(app: "Tool \(index)", bundle: "dev.tool\(index)", path: "/usr/local/bin/tool\(index)",
                                      host: "", ip: "203.0.113.\(10 + index)", at: now.addingTimeInterval(-50)))
        }
        for index in 0..<5 {
            let ip = "198.18.0.\(index + 1)"
            try! store.recordDNSMappings([DNSMapping(domain: "s\(index).amazonaws.com", ip: ip,
                                                     observedAt: now.addingTimeInterval(-600))])
            seeded.append(observation(app: "Sync", bundle: "dev.sync", path: "/Applications/Sync.app",
                                      host: "", ip: ip, at: now.addingTimeInterval(-40)))
        }
        try! store.record(seeded)

        var queries: [InsightsQuery] = []
        let result = await InsightsDomainExport.collect(since: now.addingTimeInterval(-86_400), until: now,
                                                        pageSize: 2) { query in
            queries.append(query)
            do {
                try query.validate()
                return (try store.report(for: query), nil)
            } catch {
                return (nil, error.localizedDescription)
            }
        }
        guard case .success(let export) = result else {
            if case .failure(let failure) = result { check(false, "export collected: \(failure.message)") }
            exit(1)
        }

        check(export.apps.count == 8, "every app across pages is exported (got \(export.apps.count))")
        check(Set(queries.map(\.since)).count == 1 && Set(queries.map(\.until)).count == 1,
              "every page asks for the same range")
        check(queries.allSatisfy { $0.limit == 2 }, "every page uses the requested size")
        let sync = export.apps.first { $0.summary.appIdentity == "dev.sync" }
        check(sync?.destinations.count == 5, "every destination of one app across pages is exported")
        check(export.complete, "a store that fits is marked complete")

        // CSV
        let csvText = String(decoding: export.csv(), as: UTF8.self)
        let rows = parseCSV(csvText)
        check(rows.first == InsightsDomainExport.csvHeader, "CSV starts with the header row")
        check(rows.dropFirst().allSatisfy { $0.count == InsightsDomainExport.csvHeader.count },
              "every CSV row has every column, commas and quotes in names included")
        let outlookRows = rows.filter { $0.first == "Microsoft Outlook" }
        let outlookDomains = Set(outlookRows.map { $0[3] }.filter { !$0.isEmpty })
        check(outlookDomains == ["login.microsoftonline.com", "outlook.office365.com"],
              "Outlook's names come from the DNS answers (got \(outlookDomains))")
        let bare = outlookRows.first { $0[4] == "198.51.100.7" }
        check(bare != nil && bare?[3] == "", "an address without a lookup stays an address with no name")
        check(outlookRows.allSatisfy { $0[1] == "com.microsoft.Outlook" && $0[2] == outlook },
              "bundle id and path are on every row")
        check(outlookRows.allSatisfy { Int($0[5]) == 1 && !$0[6].isEmpty }, "connection count and last seen are written")
        let evil = rows.first { $0[2] == "/tmp/evil" }
        check(evil?[0] == "'=HYPERLINK(\"http://x\",\"y\")", "a formula-looking process name is written as text")
        check(evil?[3] == "d111.cloudfront.net", "the formula row keeps its domain")
        check(!csvText.contains("\n=") && !csvText.contains(",="), "no CSV cell starts with a formula")

        // JSON
        guard let object = try? JSONSerialization.jsonObject(with: try! export.json()) as? [String: Any],
              let apps = object["apps"] as? [[String: Any]] else {
            check(false, "JSON parses")
            exit(1)
        }
        check(object["format"] as? String == InsightsDomainExport.formatIdentifier, "JSON names its format")
        check(object["complete"] as? Bool == true, "JSON says the list is complete")
        check(apps.count == 8, "JSON has every app")
        let outlookJSON = apps.first { $0["bundleId"] as? String == "com.microsoft.Outlook" }
        let domains = (outlookJSON?["domains"] as? [[String: Any]])?.compactMap { $0["domain"] as? String } ?? []
        check(Set(domains) == ["login.microsoftonline.com", "outlook.office365.com"], "JSON groups the domains under the app")
        let addresses = (outlookJSON?["addressesWithoutName"] as? [[String: Any]])?.compactMap { $0["ip"] as? String } ?? []
        check(addresses == ["198.51.100.7"], "JSON keeps unnamed addresses apart from the domains")
        let allDomains = apps.flatMap { ($0["domains"] as? [[String: Any]] ?? []).compactMap { $0["domain"] as? String } }
        check(!allDomains.contains { $0.first?.isNumber == true && $0.contains(".") && Int($0.split(separator: ".").last ?? "") != nil },
              "no address is passed off as a domain")

        // A helper that fails mid-way fails the export instead of writing half.
        var calls = 0
        let broken = await InsightsDomainExport.collect(since: now.addingTimeInterval(-86_400), until: now,
                                                        pageSize: 2) { query in
            calls += 1
            if calls > 2 { return (nil, "helper gone") }
            return ((try? store.report(for: query)), nil)
        }
        if case .failure(let failure) = broken {
            check(failure.message == "helper gone", "a failed page fails the export with the helper's reason")
        } else {
            check(false, "a failed page fails the export")
        }

        if failures > 0 {
            FileHandle.standardError.write(Data("domain export harness: \(failures) failure(s)\n".utf8))
            exit(1)
        }
        print("domain export harness: PASS: all checks")
    }
}
SWIFT

mkdir -p "$TMP/build"
xcrun swiftc -O \
  -sdk "$(xcrun --show-sdk-path)" \
  -target arm64-apple-macos13.0 \
  -parse-as-library \
  -o "$TMP/build/run" \
  $(ls "$ROOT"/Sources/Helper/*.swift | grep -v '/main.swift$') \
  "$ROOT"/Sources/Shared/*.swift \
  "$TMP/verify.swift"

"$TMP/build/run"
printf 'insights domain export verification: PASS\n'
