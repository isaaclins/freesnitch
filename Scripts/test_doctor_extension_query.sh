#!/usr/bin/env bash
# Replays #255: when `systemextensionsctl list` fails and prints nothing about
# FreeSnitch, doctor must say approval is unknown because the query failed,
# not that the extension is unapproved. Only a listing that succeeded can show
# the extension is missing. Built from the real CLI and shared sources; nothing
# here runs systemextensionsctl or talks to a helper.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-doctor-extension.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/check.swift" <<'SWIFT'
import Foundation

@main
struct Check {
    static func main() {
        var failures: [String] = []
        func expect(_ ok: Bool, _ message: String) { if !ok { failures.append(message) } }
        let runner: CLIRunner
        do { runner = CLIRunner(invocation: try CLIParser.parse(["doctor"])) } catch { fatalError("doctor must parse: \(error)") }
        func doctor(_ observation: SystemExtensionObservation) -> DoctorFinding? {
            let inspection = ExtensionInspection(
                report: ExtensionReport(identifier: AppConstants.bundleIdNetExt, approval: observation.state, running: "unknown",
                                        filterConfiguration: "unknown", filterEnabled: "unknown",
                                        snapshot: SnapshotReport(state: "unknown", mode: nil, ruleCount: nil, updatedAt: nil, generation: nil, message: nil),
                                        message: observation.detail),
                approvalState: observation.state, approvalDetail: observation.detail,
                filterConfigurationState: "unknown", filterEnabledState: "unknown",
                snapshotState: "unknown", runningState: "unknown")
            var findings: [DoctorFinding] = []
            runner.appendExtensionFindings(findings: &findings, inspection: inspection)
            return findings.first { $0.id == "extension_approval" }
        }

        // The failure from the issue: the query exits nonzero with no FreeSnitch line.
        for (text, status) in [("", Int32(1)), ("systemextensionsctl: XPC error\n", Int32(64)), ("0 extension(s)\n", Int32(1))] {
            let observed = SystemExtensionProbe.parse(text, exitStatus: status)
            expect(observed.state == "unknown", "exit \(status) with no FreeSnitch line reads as \(observed.state), not unknown")
            expect(observed.detail.contains("query failed") && observed.detail.contains("exit status \(status)"),
                   "exit \(status) detail does not say the query failed: \(observed.detail)")
            let finding = doctor(observed)
            expect(finding?.state == "unknown", "doctor finding for exit \(status) is \(finding?.state ?? "missing"), not unknown")
            expect(finding?.exitCode == nil, "doctor sets an exit code for a failed query (exit \(status))")
            expect(finding?.message.contains("query failed") == true, "doctor does not explain the failed query: \(finding?.message ?? "")")
            expect(finding?.action.lowercased().contains("approve") != true, "doctor tells the user to approve after a failed query: \(finding?.action ?? "")")
        }

        // A listing that succeeded and has no FreeSnitch line still proves it is missing.
        let missing = SystemExtensionProbe.parse("0 extension(s)\n", exitStatus: 0)
        expect(missing.state == "not-approved", "a successful listing without FreeSnitch reads as \(missing.state)")
        let missingFinding = doctor(missing)
        expect(missingFinding?.state == "problem" && missingFinding?.exitCode == CLIExitCode.extensionNotApproved.rawValue,
               "doctor no longer reports a missing extension from a successful listing")

        // A FreeSnitch record still counts even when the exit status is nonzero.
        let id = AppConstants.bundleIdNetExt
        let active = SystemExtensionProbe.parse("*\t*\tTEAM\t\(id) (1.0/1)\tFreeSnitch\t[activated enabled]\n", exitStatus: 1)
        expect(active.state == "approved", "an activated FreeSnitch record with exit 1 reads as \(active.state)")
        let waiting = SystemExtensionProbe.parse("\t\tTEAM\t\(id) (1.0/1)\tFreeSnitch\t[activated waiting for user approval]\n", exitStatus: 0)
        expect(waiting.state == "not-approved", "a FreeSnitch record waiting for approval reads as \(waiting.state)")

        if failures.isEmpty {
            print("doctor extension query: PASS")
        } else {
            failures.forEach { print("doctor extension query: FAIL: \($0)") }
            exit(1)
        }
    }
}
SWIFT

# shellcheck disable=SC2046
xcrun swiftc -parse-as-library -o "$TMP/run" \
  $(ls "$ROOT"/Sources/CLI/*.swift | grep -v '/CLIEntry.swift$') \
  "$ROOT"/Sources/Shared/*.swift "$TMP/check.swift"
"$TMP/run"
