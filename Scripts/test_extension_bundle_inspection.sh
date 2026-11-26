#!/usr/bin/env bash
# Replays #256: the bundled CLI decides whether this app build embeds the
# network extension by listing Contents/Library/SystemExtensions. A folder
# that exists but cannot be listed used to read as "no extension", so doctor
# called a firewall build monitor-only and marked approval and filter
# configuration OK. Builds the real CLI sources, lists a scratch folder in each
# state (missing, empty, with an extension, unreadable) and feeds the result
# to doctor's real extension findings. Nothing here talks to a helper.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-extension-bundle.XXXXXX")"
trap 'chmod -R u+rwx "$TMP" 2>/dev/null || true; rm -rf "$TMP"' EXIT

if [ "$(id -u)" = "0" ]; then
  echo "extension bundle inspection: run this as a normal user; root can list an unreadable folder" >&2
  exit 1
fi

cat > "$TMP/check.swift" <<'SWIFT'
import Foundation

@main
struct Check {
    static func main() {
        var failures: [String] = []
        func expect(_ ok: Bool, _ message: String) { if !ok { failures.append(message) } }
        let fm = FileManager.default
        let work = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)

        let missing = work.appendingPathComponent("missing/Contents/Library/SystemExtensions", isDirectory: true)
        expect(EmbeddedExtensionPresence.inspect(missing) == .absent, "a missing SystemExtensions folder must read as a monitor-only build")

        let empty = work.appendingPathComponent("empty/Contents/Library/SystemExtensions", isDirectory: true)
        try! fm.createDirectory(at: empty, withIntermediateDirectories: true)
        expect(EmbeddedExtensionPresence.inspect(empty) == .absent, "an empty SystemExtensions folder must read as a monitor-only build")

        let firewall = work.appendingPathComponent("firewall/Contents/Library/SystemExtensions", isDirectory: true)
        try! fm.createDirectory(at: firewall.appendingPathComponent("com.isaaclins.freesnitch.netext.systemextension"), withIntermediateDirectories: true)
        expect(EmbeddedExtensionPresence.inspect(firewall) == .present, "a SystemExtensions folder with a .systemextension must read as a firewall build")

        let locked = work.appendingPathComponent("locked/Contents/Library/SystemExtensions", isDirectory: true)
        try! fm.createDirectory(at: locked.appendingPathComponent("com.isaaclins.freesnitch.netext.systemextension"), withIntermediateDirectories: true)
        try! fm.setAttributes([.posixPermissions: 0o000], ofItemAtPath: locked.path)
        let lockedPresence = EmbeddedExtensionPresence.inspect(locked)
        try! fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: locked.path)
        guard case .unreadable(let error) = lockedPresence else {
            failures.append("an unreadable SystemExtensions folder must not read as \(lockedPresence)")
            report(failures); return
        }
        expect(error.contains(locked.path), "the unreadable outcome must name the folder, got: \(error)")
        expect(error.contains("Permission denied"), "the unreadable outcome must carry the underlying error, got: \(error)")

        // Doctor's real findings for each outcome.
        let runner: CLIRunner
        do { runner = CLIRunner(invocation: try CLIParser.parse(["doctor"])) } catch { fatalError("doctor must parse: \(error)") }
        func findings(_ inspection: ExtensionInspection) -> [String: DoctorFinding] {
            var list: [DoctorFinding] = []
            runner.appendExtensionFindings(findings: &list, inspection: inspection)
            return Dictionary(list.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        }
        func inspection(approval: String, filter: String, error: String? = nil) -> ExtensionInspection {
            let snapshot = SnapshotReport(state: "unknown", mode: nil, ruleCount: nil, updatedAt: nil, generation: nil, message: nil)
            let report = ExtensionReport(identifier: AppConstants.bundleIdNetExt, approval: approval, running: "unknown",
                                         filterConfiguration: filter, filterEnabled: "unknown", snapshot: snapshot, message: nil)
            return ExtensionInspection(report: report, approvalState: approval, filterConfigurationState: filter,
                                       filterEnabledState: "unknown", snapshotState: "unknown", runningState: "unknown",
                                       bundleInspectionError: error)
        }

        let unreadable = findings(inspection(approval: "unknown", filter: "unknown", error: error))
        for id in ["extension_approval", "filter_configuration", "extension_running", "filter_snapshot"] {
            guard let finding = unreadable[id] else { failures.append("doctor must still report \(id) when the bundle is unreadable"); continue }
            expect(finding.state == "unknown", "\(id) must be unknown when the bundle is unreadable, got \(finding.state)")
            expect(!finding.message.contains("monitor-only"), "\(id) must not call an unreadable bundle monitor-only: \(finding.message)")
        }
        expect(unreadable["extension_approval"]?.message.contains("Permission denied") == true,
               "doctor must show the underlying error, got: \(unreadable["extension_approval"]?.message ?? "nothing")")

        let monitorOnly = findings(inspection(approval: "not-in-build", filter: "not-in-build"))
        expect(monitorOnly["extension_approval"]?.state == "ok" && monitorOnly["extension_approval"]?.message.contains("monitor-only") == true,
               "a real monitor-only build must still be reported as such")
        expect(monitorOnly["filter_configuration"]?.state == "ok", "a real monitor-only build keeps its filter configuration OK")

        report(failures)
    }

    static func report(_ failures: [String]) {
        if failures.isEmpty { print("extension bundle inspection: PASS"); return }
        for failure in failures { print("extension bundle inspection: FAIL: \(failure)") }
        exit(1)
    }
}
SWIFT

# shellcheck disable=SC2046
xcrun swiftc -parse-as-library -o "$TMP/run" \
  $(ls "$ROOT"/Sources/CLI/*.swift | grep -v '/CLIEntry.swift$') \
  "$ROOT"/Sources/Shared/*.swift "$TMP/check.swift"
mkdir -p "$TMP/work"
"$TMP/run" "$TMP/work"
