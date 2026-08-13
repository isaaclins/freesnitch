#!/usr/bin/env bash
# First-contact and changed-after-update verification, compiled from the real
# shared models and helper Insights store. The classifier is memory-only; the
# store is used only to prepare evidence before classification.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-contact.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# The verdict callback may enqueue evidence, but it must not classify by
# opening the store or reading the filesystem itself.
FILTER="$ROOT/Sources/NetExt/FilterDataProvider.swift"
VERDICT_BODY="$(awk '/override func handleNewFlow\(/,/^    }$/' "$FILTER")"
if grep -Eiq 'InsightsStore|sqlite3_|Data\(contentsOf:|FileManager|readBundleMetadata' <<<"$VERDICT_BODY"; then
    echo "contact classification: FAIL: verdict path contains disk/store access" >&2
    exit 1
fi
printf 'contact classification: PASS: verdict path has no direct disk/store access\n'

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

@main
struct ContactHarness {
    static var failures = 0

    static func check(_ condition: Bool, _ message: String) {
        if condition {
            print("contact harness: PASS: \(message)")
        } else {
            failures += 1
            FileHandle.standardError.write(Data("contact harness: FAIL: \(message)\n".utf8))
        }
    }

    static func observation(app: String, bundle: String?, host: String, ip: String,
                            version: String? = nil, at date: Date) -> FlowObservation {
        let connection = Connection(pid: 501, processName: app,
                                    processPath: "/Applications/\(app).app/Contents/MacOS/\(app)",
                                    processBundleId: bundle, remoteHost: host, remoteIP: ip,
                                    remotePort: 443, direction: .outgoing)
        return FlowObservation(connection: connection, observedAt: date, processVersion: version)
    }

    static func main() {
        let now = Date()
        let app = "com.example.chat"
        let destination = "api.example.com"
        let otherDestination = "cdn.example.com"
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("freesnitch-contact-\(UUID().uuidString)")
        let support = root.appendingPathComponent("Application Support")
        try! FileManager.default.createDirectory(at: support, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o755])
        let store: InsightsStore
        do {
            store = try InsightsStore(path: support.appendingPathComponent("Insights/insights.sqlite").path,
                                      expectedUID: getuid())
        } catch {
            FileHandle.standardError.write(Data("contact harness: FAIL: store did not open: \(error)\n".utf8))
            exit(1)
        }

        // The contact set is prepared away from the verdict path.
        let known = observation(app: "Chat", bundle: app, host: destination, ip: "203.0.113.10", at: now.addingTimeInterval(-3600))
        let otherApp = observation(app: "Other", bundle: "com.example.other", host: destination, ip: "203.0.113.10", at: now.addingTimeInterval(-3500))
        try! store.record([known, otherApp])
        let snapshot = try! store.contactSnapshot(now: now)
        let classifier = InsightsContactClassifier(snapshot: snapshot, now: now)

        let unseen = observation(app: "Chat", bundle: app, host: otherDestination, ip: "203.0.113.20", at: now)
        let seen = observation(app: "Chat", bundle: app, host: destination, ip: "203.0.113.10", at: now)
        let sameDestinationOtherApp = observation(app: "New", bundle: "com.example.new", host: destination, ip: "203.0.113.10", at: now)
        check(classifier.decision(for: unseen) == .firstContact, "unseen app + destination is first contact")
        check(classifier.decision(for: seen) == .knownContact, "seen app + destination is known contact")
        check(classifier.decision(for: sameDestinationOtherApp) == .firstContact,
              "a destination seen by another app is first contact for this app")
        check(classifier.decision(for: seen) == .knownContact,
              "known contact has an explicit silent allow verdict")

        let stale = InsightsContactSnapshot(contacts: snapshot.contacts,
                                            preparedAt: now.addingTimeInterval(-InsightsLimits.maxContactSnapshotAge - 1))
        let malformed = InsightsContactSnapshot(contacts: [InsightsContact(appIdentity: app, destination: "not a destination")],
                                                preparedAt: now)
        check(!InsightsContactClassifier(snapshot: nil, now: now).isAvailable &&
              InsightsContactClassifier(snapshot: nil, now: now).decision(for: seen) == .askHistoryUnavailable,
              "unavailable history retains existing Alert ask semantics")
        check(InsightsContactClassifier(snapshot: stale, now: now).decision(for: seen) == .askHistoryUnavailable,
              "stale history retains existing Alert ask semantics")
        check(InsightsContactClassifier(snapshot: malformed, now: now).decision(for: seen) == .askHistoryUnavailable,
              "malformed history retains existing Alert ask semantics")

        // Version 1 is the baseline. Version 2 adds one destination and keeps
        // the old one. Unknown version metadata is never replaced by a guess.
        let v1Old = observation(app: "Chat", bundle: app, host: destination, ip: "203.0.113.10",
                                version: "1.0 (1)", at: now.addingTimeInterval(-7200))
        let v1Repeat = observation(app: "Chat", bundle: app, host: destination, ip: "203.0.113.10",
                                   version: "1.0 (1)", at: now.addingTimeInterval(-7000))
        let v2Old = observation(app: "Chat", bundle: app, host: destination, ip: "203.0.113.10",
                                version: "1.0 (2)", at: now.addingTimeInterval(-1800))
        let v2New = observation(app: "Chat", bundle: app, host: "new.example.com", ip: "203.0.113.30",
                                version: "1.0 (2)", at: now.addingTimeInterval(-1700))
        let unknownNew = observation(app: "Chat", bundle: app, host: "unknown.example.com", ip: "203.0.113.40",
                                     version: nil, at: now.addingTimeInterval(-1000))
        try! store.record([v1Old, v1Repeat, v2Old, v2New, unknownNew])
        let report = try! store.report(for: InsightsQuery(kind: .findings,
                                                          since: now.addingTimeInterval(-24 * 60 * 60),
                                                          limit: 50), now: now)
        let updateFinding = report.findings.first { $0.destination == "new.example.com" }
        check(updateFinding?.wording == "new after update", "version 2 new destination is a new-after-update finding")
        check(updateFinding?.oldVersion == "1.0 (1)" && updateFinding?.newVersion == "1.0 (2)",
              "finding includes both old and new app builds")
        check(updateFinding.map { abs($0.firstSeen.timeIntervalSince(v2New.observedAt)) < 0.001 && $0.connectionCount == 1 } ?? false,
              "finding includes first seen and connection count")
        check(!report.findings.contains { $0.destination == destination && $0.versionKnown },
              "a destination already present in version 1 is not flagged for version 2")
        let unknownFinding = report.findings.first { $0.destination == "unknown.example.com" }
        check(unknownFinding?.versionKnown == false && unknownFinding?.newVersion == nil &&
              unknownFinding?.versionLabel == "Unknown app version",
              "unknown app version is labelled unknown and never guessed")

        // Constructing a proposed rule is still only a proposal. Nothing in a
        // finding mutates the stored rules or creates an enforcement action.
        let proposal = updateFinding?.proposedRule()
        check(proposal != nil && proposal?.rule().action == .deny,
              "a finding may offer the existing human-accepted proposed-rule flow")
        check(proposal?.rule().groupName == "Insights",
              "a finding proposal is marked as an Insights proposal")
        check(report.findings.count > 0, "findings are first-class report rows")

        try? FileManager.default.removeItem(at: root)
        if failures > 0 {
            FileHandle.standardError.write(Data("contact harness: \(failures) failure(s)\n".utf8))
            exit(1)
        }
        print("contact harness: PASS: all checks")
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
printf 'contact classification: PASS\n'
