#!/usr/bin/env bash
# Replays #257: the helper confirms a rule or mode change, then the snapshot
# read right after it fails (timeout or an older helper without the call).
# The command must still exit nonzero, but with a receipt of what was saved
# (rule ID, IDs, count, mode) and the snapshot failure kept apart, so a script
# does not retry and create a second rule. Built from the real CLI sources
# with a stand-in helper; nothing here talks to a real helper or extension.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-cli-commit-receipt.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/main.swift" <<'SWIFT'
import Foundation

final class StandInHelper: CLIPolicyHelper {
    var rules: [Rule]
    var mode: AppMode = .alert
    var snapshotError: CLIError?
    /// Fail every rule call after this many confirmed ones, like a helper
    /// that goes away in the middle of a multi-rule change.
    var dropAfterConfirmed: Int?
    private(set) var confirmed = 0
    private(set) var snapshotReads = 0

    init(rules: [Rule] = []) { self.rules = rules }

    private func gate() throws {
        if let limit = dropAfterConfirmed, confirmed >= limit {
            throw CLIError(.helperUnreachable, message: "The helper could not be reached.")
        }
    }

    func prepare(timeout: TimeInterval) async throws -> HelperStatus {
        HelperStatus(version: "test", running: true, pfctlActive: false, dnsProxyActive: false,
                     dnsProxyPort: 0, activeRules: rules.count, blockedToday: 0, mode: mode)
    }
    func setMode(_ mode: AppMode) async throws { try gate(); self.mode = mode; confirmed += 1 }
    func listRules(profile: String) async throws -> [Rule] { try gate(); return rules }
    func addRule(_ rule: Rule) async throws {
        try gate()
        rules.removeAll { $0.id == rule.id }
        rules.append(rule)
        confirmed += 1
    }
    func removeRule(_ id: UUID) async throws { try gate(); rules.removeAll { $0.id == id }; confirmed += 1 }
    func importRules(_ imported: [Rule]) async throws {
        try gate()
        for rule in imported { rules.removeAll { $0.id == rule.id }; rules.append(rule) }
        confirmed += 1
    }
    func authoritativeSnapshot() async throws -> SharedRuleBridge.Snapshot {
        snapshotReads += 1
        if let snapshotError { throw snapshotError }
        return SharedRuleBridge.Snapshot(mode: mode, rules: rules, generation: 42)
    }
}

var failures: [String] = []
func expect(_ ok: Bool, _ message: String) { if !ok { failures.append(message) } }

// What CLIHelperClient.perform reports when the helper does not answer in time.
let timeout = CLIError(.helperUnreachable, message: "The helper did not answer within 15 seconds.")
let unsupported = CLIError(.helperVersionMismatch, code: "authoritative_snapshot_unsupported",
                           message: "The helper does not support authoritative snapshots.")

func run(_ args: [String], _ helper: StandInHelper) async -> Result<CommandResult, CLIError> {
    do {
        let invocation = try CLIParser.parse(args + ["--json"])
        let runner = CLIRunner(invocation: invocation,
                               makePolicyHelper: { helper },
                               rememberMode: { _ in },
                               deliverSnapshot: { snapshot in ("ready", nil, snapshot.generation) })
        return .success(try await runner.run())
    } catch let error as CLIError {
        return .failure(error)
    } catch {
        fatalError("unexpected error \(error)")
    }
}

func json(_ result: CommandResult) -> [String: Any] {
    let data = try! CLIJSON.encode(result.data)
    return try! JSONSerialization.jsonObject(with: data) as! [String: Any]
}

func expectReceipt(_ outcome: Result<CommandResult, CLIError>, _ label: String, snapshotCode: String) -> [String: Any] {
    guard case .success(let result) = outcome else {
        if case .failure(let error) = outcome { failures.append("\(label): returned only the error \(error.code), no receipt") }
        return [:]
    }
    expect(result.exitCode != .success, "\(label): a failed snapshot must still exit nonzero")
    expect(result.error?.code == "snapshot_after_commit_failed", "\(label): error must say the change was saved, got \(result.error?.code ?? "none")")
    let data = json(result)
    let snapshot = data["snapshotError"] as? [String: Any]
    expect(snapshot?["code"] as? String == snapshotCode, "\(label): snapshotError must carry \(snapshotCode) separately")
    expect(data["extensionSync"] as? String == "not-checked", "\(label): extensionSync must say no snapshot was sent")
    expect(result.error?.remediation?.contains("Do not repeat the command") == true, "\(label): the remediation must say not to retry")
    expect(result.human.contains("Do not repeat the command") || result.human.contains("changed in the helper"),
           "\(label): the text output must say the change is saved")
    return data
}

func makeRule(_ host: String) -> Rule {
    Rule(processPath: "/Applications/Firefox.app/", remoteHost: host, action: .allow)
}

// Steps 1-4 of the issue: rules add, then the snapshot read times out.
for (label, error) in [("timeout", timeout), ("unsupported", unsupported)] {
    let helper = StandInHelper()
    helper.snapshotError = error
    let data = expectReceipt(await run(["rules", "add", "--process-path", "/Applications/Firefox.app/",
                                        "--host", "example.com", "--action", "allow"], helper),
                             "rules add (\(label))", snapshotCode: error.code)
    let ruleID = (data["rule"] as? [String: Any])?["id"] as? String
    expect(helper.rules.count == 1, "rules add (\(label)): the helper must hold the one saved rule")
    expect(ruleID != nil && ruleID == helper.rules.first?.id.uuidString,
           "rules add (\(label)): the receipt must name the saved rule's ID")
}

// mode
do {
    let helper = StandInHelper()
    helper.snapshotError = timeout
    let data = expectReceipt(await run(["mode", "silent-deny"], helper), "mode", snapshotCode: "helper_unreachable")
    expect(helper.mode == .silentDeny, "mode: the helper must hold the new mode")
    expect(data["mode"] as? String == "silent-deny", "mode: the receipt must name the mode that was set")
    expect(data["ruleCount"] == nil, "mode: no rule count may be invented without a snapshot")
}

// rules disable / rm: succeeded IDs survive the snapshot failure.
do {
    let a = makeRule("a.example"), b = makeRule("b.example")
    let helper = StandInHelper(rules: [a, b])
    helper.snapshotError = timeout
    let data = expectReceipt(await run(["rules", "disable", a.id.uuidString, b.id.uuidString], helper),
                             "rules disable", snapshotCode: "helper_unreachable")
    expect((data["succeeded"] as? [String])?.count == 2, "rules disable: both changed IDs must be in the receipt")
    expect(helper.rules.allSatisfy { !$0.enabled }, "rules disable: the helper must hold both changes")

    let removed = expectReceipt(await run(["rules", "rm", a.id.uuidString, "--yes"], helper),
                                "rules rm", snapshotCode: "helper_unreachable")
    expect((removed["succeeded"] as? [String]) == [a.id.uuidString], "rules rm: the removed ID must be in the receipt")
}

// rules import
do {
    let imported = [makeRule("c.example"), makeRule("d.example")]
    let file = URL(fileURLWithPath: CommandLine.arguments[1]).appendingPathComponent("import.json")
    try! RuleExportCodec.encode(imported).write(to: file)
    let helper = StandInHelper()
    helper.snapshotError = unsupported
    let data = expectReceipt(await run(["rules", "import", file.path], helper),
                             "rules import", snapshotCode: "authoritative_snapshot_unsupported")
    expect(data["imported"] as? Int == 2, "rules import: the receipt must carry the count")
    expect(Set((data["ids"] as? [String]) ?? []) == Set(imported.map(\.id.uuidString)), "rules import: the receipt must carry the IDs")
}

// Nothing changed yet: an unreachable helper is still the plain error.
do {
    let rule = makeRule("h.example")
    let helper = StandInHelper(rules: [rule])
    helper.dropAfterConfirmed = 0
    if case .failure(let error) = await run(["rules", "rm", rule.id.uuidString, "--yes"], helper) {
        expect(error.exitCode == .helperUnreachable, "unchanged: the helper error must be returned as is")
    } else { failures.append("unchanged: a failure before any change must not look like a saved change") }
    expect(helper.snapshotReads == 0, "unchanged: no snapshot is read when nothing changed")
}

// The normal path is unchanged.
do {
    let helper = StandInHelper()
    guard case .success(let result) = await run(["rules", "add", "--process-path", "/Applications/Firefox.app/",
                                                 "--host", "example.com", "--action", "allow"], helper) else {
        fatalError("rules add must succeed with a working snapshot")
    }
    let data = json(result)
    expect(result.exitCode == .success && result.error == nil, "success: rules add must still exit 0")
    expect(data["snapshotError"] == nil, "success: no snapshotError on a good snapshot")
    expect(data["generation"] as? Int == 42 && data["extensionSync"] as? String == "ready", "success: generation and sync state kept")
}

guard failures.isEmpty else {
    failures.forEach { FileHandle.standardError.write(Data("cli commit receipt: FAIL: \($0)\n".utf8)) }
    exit(1)
}
print("cli commit receipt: PASS")
SWIFT

# shellcheck disable=SC2046
xcrun swiftc -o "$TMP/run" \
  $(ls "$ROOT"/Sources/CLI/*.swift | grep -v '/CLIEntry.swift$') \
  "$ROOT"/Sources/Shared/*.swift "$TMP/main.swift"
"$TMP/run" "$TMP"
