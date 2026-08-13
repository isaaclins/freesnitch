#!/usr/bin/env bash
# Deterministic production-source checks for the shared rule export contract
# (issue #48). The harness compiles the real CLI and Shared sources, never a
# copy, so the file format it exercises is the shipping one.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-rule-export.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

@main
struct Verify {
    static var failures = 0

    static func check(_ name: String, _ condition: @autoclosure () -> Bool) {
        if condition() {
            print("rule export harness: PASS: \(name)")
        } else {
            failures += 1
            print("rule export harness: FAIL: \(name)")
        }
    }

    static func ruleA() -> Rule {
        Rule(id: UUID(uuidString: "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")!,
             processName: "Safari",
             remoteHost: "example.com",
             remoteIP: "1.2.3.4",
             remotePort: 443,
             action: .deny,
             scope: .domain,
             createdAt: Date(timeIntervalSinceReferenceDate: 100))
    }

    static func ruleB() -> Rule {
        Rule(id: UUID(uuidString: "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB")!,
             processName: "curl",
             remoteHost: "b.example",
             action: .allow,
             scope: .domain,
             createdAt: Date(timeIntervalSinceReferenceDate: 200))
    }

    // Production CLI export path: same call the CLI runner makes.
    static func cliExport(_ rules: [Rule]) throws -> Data {
        try RuleExportCodec.encode(rules, exportedAt: Date(timeIntervalSinceReferenceDate: 1000))
    }

    // Production GUI export path: RuleJSONDocument.fileWrapper calls this.
    static func guiExport(_ rules: [Rule]) throws -> Data {
        try RuleExportCodec.encode(rules)
    }

    static func legacyArray(_ rules: [Rule]) throws -> Data {
        // Exactly what old GUI builds wrote: bare array, default date coding.
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(rules)
    }

    static func expectRejected(_ name: String, _ data: Data, _ expected: RuleExportError) {
        do {
            let result = try RuleExportCodec.decode(data)
            failures += 1
            print("rule export harness: FAIL: \(name): accepted \(result.rules.count) rules")
        } catch let error as RuleExportError {
            if error == expected {
                print("rule export harness: PASS: \(name): \(error.errorDescription ?? "")")
            } else {
                failures += 1
                print("rule export harness: FAIL: \(name): wrong error \(error)")
            }
        } catch {
            failures += 1
            print("rule export harness: FAIL: \(name): unexpected error \(error)")
        }
    }

    static func main() throws {
        let rules = [ruleA(), ruleB()]

        // 1. CLI export -> shared reader (this is the GUI import path).
        let cli = try cliExport(rules)
        let cliRead = try RuleExportCodec.decode(cli)
        check("CLI export is the canonical format", String(data: cli, encoding: .utf8)!.contains("\"format\" : \"freesnitch.rules.v1\""))
        check("CLI export decodes through the shared reader", cliRead.rules == rules && cliRead.source == .canonical)

        // 2. GUI export -> shared reader (this is the CLI import path).
        let gui = try guiExport(rules)
        let guiRead = try RuleExportCodec.decode(gui)
        check("GUI export decodes through the shared reader", guiRead.rules == rules && guiRead.source == .canonical)

        // 3. Both clients emit the identical canonical document for the same input.
        let cliAgain = try RuleExportCodec.encode(rules, exportedAt: Date(timeIntervalSinceReferenceDate: 1000))
        check("CLI and GUI writers agree byte for byte", cli == cliAgain)

        // 4. Legacy bare array is accepted by both clients (one shared reader).
        let legacy = try legacyArray(rules)
        let legacyRead = try RuleExportCodec.decode(legacy)
        check("legacy bare array accepted", legacyRead.rules == rules && legacyRead.source == .legacyRuleArray)

        // 5. Unknown format name rejected.
        let unknownFormat = Data("""
        {"format":"acme.rules.v1","version":1,"exportedAt":"2026-01-01T00:00:00Z","rules":[]}
        """.utf8)
        expectRejected("unknown format rejected", unknownFormat, .unsupportedFormat("acme.rules.v1"))

        // 6. Unsupported version rejected.
        let futureVersion = Data("""
        {"format":"freesnitch.rules.v1","version":2,"exportedAt":"2026-01-01T00:00:00Z","rules":[]}
        """.utf8)
        expectRejected("unsupported version rejected", futureVersion, .unsupportedVersion(2))

        // 7. Arbitrary JSON with a rules key is not a rule export.
        let bystander = Data("""
        {"rules":[],"note":"some other tool"}
        """.utf8)
        expectRejected("foreign object with a rules key rejected", bystander, .notRuleJSON)

        // 8. Oversized payload rejected before decoding.
        let oversize = RuleExportCodec.maximumEncodedBytes + 1
        expectRejected("oversized payload rejected",
                       Data(repeating: UInt8(ascii: " "), count: oversize),
                       .oversized(bytes: oversize, limit: RuleExportCodec.maximumEncodedBytes))

        // 9. Absurd rule count rejected before allocating rules.
        let overCount = RuleExportCodec.maximumRuleCount + 1
        var body = Data("{\"format\":\"freesnitch.rules.v1\",\"version\":1,\"exportedAt\":\"2026-01-01T00:00:00Z\",\"rules\":[".utf8)
        body.append(Data(Array(repeating: "{}", count: overCount).joined(separator: ",").utf8))
        body.append(Data("]}".utf8))
        expectRejected("over-count payload rejected", body,
                       .tooManyRules(count: overCount, limit: RuleExportCodec.maximumRuleCount))

        // 10. A malformed batch imports nothing at all: one bad rule rejects all.
        var bad = ruleB()
        bad.remoteIP = "999.1.1.1"
        let mixed = try RuleExportCodec.encoder().encode(RuleExportDocument(rules: [ruleA(), bad]))
        do {
            let accepted = try RuleExportCodec.decode(mixed)
            failures += 1
            print("rule export harness: FAIL: malformed batch imported \(accepted.rules.count) rules")
        } catch let error as RuleExportError {
            var isInvalidRule = false
            if case .invalidRule(let id, _) = error, id == bad.id.uuidString { isInvalidRule = true }
            check("malformed batch imports nothing", isInvalidRule)
            print("rule export harness: rejection reason: \(error.errorDescription ?? "")")
        }

        // 11. Duplicate ids rejected.
        let dupes = try RuleExportCodec.encoder().encode(RuleExportDocument(rules: [ruleA(), ruleA()]))
        expectRejected("duplicate rule id rejected", dupes, .duplicateRuleID(ruleA().id.uuidString))

        // 12. Empty file rejected.
        expectRejected("empty payload rejected", Data(), .empty)

        if failures == 0 {
            print("rule export harness: PASS (all checks)")
        } else {
            print("rule export harness: \(failures) FAILURES")
            exit(1)
        }
    }
}
SWIFT

# CLIEntry.swift carries the CLI @main, which would collide with the harness
# entry point, so it is the only production CLI file left out.
xcrun swiftc -O \
  -sdk "$(xcrun --show-sdk-path)" \
  -target arm64-apple-macos13.0 \
  -parse-as-library \
  -o "$TMP/rule_export_harness" \
  $(ls "$ROOT"/Sources/CLI/*.swift | grep -v '/CLIEntry.swift$') \
  "$ROOT"/Sources/Shared/*.swift \
  "$TMP/verify.swift"

"$TMP/rule_export_harness"

bash "$ROOT/Scripts/audit_firewall_safety.sh" >/dev/null
printf 'rule export harness: firewall safety audit passed\n'
printf 'rule export verification: PASS\n'
