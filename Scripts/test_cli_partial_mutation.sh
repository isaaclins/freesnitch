#!/usr/bin/env bash
# Replays #258: `freesnitch rules disable A B` where the helper changes A and
# then stops answering before B. The command must still say that A changed,
# list B (and anything after it) as failed with a reason, and exit nonzero.
# Built from the real CLI and shared sources with a scripted helper in place
# of the real one; nothing here talks to a helper.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-cli-partial.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/check.swift" <<'SWIFT'
import Foundation

@main
struct Check {
    static func main() async {
        var failures: [String] = []
        func expect(_ ok: Bool, _ message: String) { if !ok { failures.append(message) } }
        let a = UUID(), b = UUID(), c = UUID()
        let gone = CLIError(.helperUnreachable, message: "The helper connection was interrupted.",
                            remediation: "Run `freesnitch doctor`.")
        let ready: (state: String, message: String?, generation: UInt64?) = ("not-checked", "not sent", nil)

        // A changes, then the helper disconnects on B (the issue's steps), with C still to go.
        var asked: [UUID] = []
        do {
            let outcome = try await RuleMutationBatch.run([a, b, c]) { id in
                asked.append(id)
                if id == a { return nil }
                throw gone
            }
            expect(asked == [a, b], "the batch must stop asking once the helper is gone, asked \(asked)")
            expect(outcome.succeeded == [a], "A changed and must be reported as succeeded")
            expect(outcome.failed.map(\.id) == [b, c], "B and C must be listed as failed")
            expect(outcome.failed.first?.message.hasPrefix("Result unknown:") == true, "B's result is unknown, the reason must say so")
            expect(outcome.failed.first?.message.contains(gone.message) == true, "B's reason must carry the helper error")
            expect(outcome.failed.last?.message.hasPrefix("Not attempted:") == true, "C was never tried, the reason must say so")

            let result = RuleMutationBatch.result(operation: "disable", pastTense: "Disabled", ids: [a, b, c],
                                                  outcome: outcome, sync: ready)
            expect(result.exitCode == .helperUnreachable, "the exit status must be nonzero and name the cause, got \(result.exitCode)")
            expect(result.error?.code == "rule_mutation_interrupted", "the error code must say the batch was interrupted")
            expect(result.human.contains("Disabled 1 of 3 rules."), "the terminal text must say A changed: \(result.human)")
            expect(result.human.contains(b.uuidString) && result.human.contains(c.uuidString), "the terminal text must list B and C")

            // The JSON a script reads: ok false, nonzero exit, and data still holding the IDs.
            let envelope = CLIEnvelope<AnyEncodable>.failure(command: "rules disable", error: result.error!, data: result.data)
            let json = try JSONSerialization.jsonObject(with: CLIJSON.encode(envelope)) as! [String: Any]
            let data = json["data"] as? [String: Any]
            expect(json["ok"] as? Bool == false, "JSON ok must be false")
            expect(json["exitCode"] as? Int == 66, "JSON exitCode must be 66")
            expect((data?["succeeded"] as? [String]) == [a.uuidString], "JSON data.succeeded must hold A")
            expect(((data?["failed"] as? [[String: Any]]) ?? []).compactMap { $0["id"] as? String } == [b.uuidString, c.uuidString],
                   "JSON data.failed must hold B and C")
        } catch {
            failures.append("a disconnect after a success must not be thrown, got \(error)")
        }

        // A helper of another build after a success: same handling, its own exit code.
        do {
            let mismatch = CLIError(.helperVersionMismatch, message: "Helper is another build.")
            let outcome = try await RuleMutationBatch.run([a, b]) { id in
                if id == a { return nil }
                throw mismatch
            }
            let result = RuleMutationBatch.result(operation: "remove", pastTense: "Removed", ids: [a, b], outcome: outcome, sync: ready)
            expect(outcome.succeeded == [a] && result.exitCode == .helperVersionMismatch, "a version mismatch after a success must keep A and exit 67")
        } catch {
            failures.append("a version mismatch after a success must not be thrown, got \(error)")
        }

        // Nothing changed yet: the helper error is the whole answer, as before.
        do {
            _ = try await RuleMutationBatch.run([a, b]) { _ in throw gone }
            failures.append("a disconnect before anything changed must be thrown")
        } catch let error as CLIError {
            expect(error.exitCode == .helperUnreachable, "the thrown error must stay helper_unreachable")
        } catch {
            failures.append("unexpected error \(error)")
        }

        // A refusal for one ID is not a disconnect: the rest are still tried.
        do {
            asked = []
            let outcome = try await RuleMutationBatch.run([a, b, c]) { id in
                asked.append(id)
                if id == b { throw CLIError(.operationFailed, message: "refused") }
                return id == c ? "rule not found" : nil
            }
            expect(asked == [a, b, c], "a per-rule refusal must not stop the batch")
            expect(outcome.succeeded == [a] && outcome.failed.map(\.id) == [b, c], "per-rule refusals must be listed")
            let result = RuleMutationBatch.result(operation: "enable", pastTense: "Enabled", ids: [a, b, c], outcome: outcome,
                                                  sync: ("ready", nil, 4))
            expect(result.exitCode == .operationFailed && result.error?.code == "rule_mutation_partial_failure",
                   "per-rule refusals keep the partial failure exit 72")
        } catch {
            failures.append("per-rule refusals must not throw, got \(error)")
        }

        // Every ID changed but the snapshot read failed: still nonzero, IDs kept.
        let all = RuleMutationOutcome(succeeded: [a, b], failed: [], interruption: nil)
        let snapshotFailed = RuleMutationBatch.result(operation: "remove", pastTense: "Removed", ids: [a, b], outcome: all,
                                                      sync: ("not-checked", "snapshot unreadable", nil), syncError: gone)
        expect(snapshotFailed.exitCode == .helperUnreachable, "a failed snapshot read after the changes must exit nonzero")
        expect(snapshotFailed.human.contains("Removed 2 of 2 rules."), "a failed snapshot read must still report the changes")

        let clean = RuleMutationBatch.result(operation: "remove", pastTense: "Removed", ids: [a, b], outcome: all, sync: ("ready", nil, 7))
        expect(clean.exitCode == .success && clean.error == nil, "a clean batch must exit 0")

        // The extension sync step, as CLIRunner runs it after the batch.
        var reads = 0
        func read() async throws -> Int { reads += 1; return 1 }
        func deliver(_: Int) async -> (state: String, message: String?, generation: UInt64?) { ("ready", nil, 9) }
        let interrupted = RuleMutationOutcome(succeeded: [a], failed: [RuleMutationFailure(id: b, message: "x")], interruption: gone)
        let skipped = await RuleMutationBatch.sync(after: interrupted, readSnapshot: read, deliver: deliver)
        expect(reads == 0 && skipped.sync.state == "not-checked" && skipped.error == nil,
               "after an interruption the snapshot must not be read again")
        let none = await RuleMutationBatch.sync(after: RuleMutationOutcome(), readSnapshot: read, deliver: deliver)
        expect(reads == 0 && none.sync.state == "not-needed", "nothing changed: no snapshot is needed")
        let delivered = await RuleMutationBatch.sync(after: all, readSnapshot: read, deliver: deliver)
        expect(reads == 1 && delivered.sync.state == "ready" && delivered.sync.generation == 9 && delivered.error == nil,
               "after a clean batch the snapshot must be read and delivered")
        let unreadable = await RuleMutationBatch.sync(after: all, readSnapshot: { () async throws -> Int in throw gone }, deliver: deliver)
        expect(unreadable.error?.exitCode == .helperUnreachable && unreadable.sync.state == "not-checked",
               "a failed snapshot read must be returned, not thrown")
        let afterUnreadable = RuleMutationBatch.result(operation: "remove", pastTense: "Removed", ids: [a, b], outcome: all,
                                                       sync: unreadable.sync, syncError: unreadable.error)
        expect(afterUnreadable.exitCode == .helperUnreachable && afterUnreadable.human.contains("Removed 2 of 2 rules."),
               "a failed snapshot read must exit nonzero and still report the changes")

        guard failures.isEmpty else {
            failures.forEach { FileHandle.standardError.write(Data("cli partial mutation: FAIL: \($0)\n".utf8)) }
            exit(1)
        }
        print("cli partial mutation: PASS")
    }
}
SWIFT

# shellcheck disable=SC2046
xcrun swiftc -parse-as-library -o "$TMP/run" \
  $(ls "$ROOT"/Sources/CLI/*.swift | grep -v '/CLIEntry.swift$') \
  "$ROOT"/Sources/Shared/*.swift "$TMP/check.swift"
"$TMP/run"
