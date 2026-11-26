import Foundation

/// What happened to each ID of a multi-rule command (`rules enable`,
/// `disable`, `rm`). The helper is asked once per ID, so it can stop answering
/// halfway through; the IDs it already changed must still reach the caller.
struct RuleMutationOutcome {
    var succeeded: [UUID] = []
    var failed: [RuleMutationFailure] = []
    /// Set when the helper stopped answering (or turned out to be another
    /// build) after at least one ID had already changed. Every ID from the one
    /// that hit it onwards is in `failed`.
    var interruption: CLIError?
}

enum RuleMutationBatch {
    /// Errors that mean the helper can no longer be asked anything, so asking
    /// it about the next ID would only repeat the same failure.
    static func stopsTheBatch(_ error: CLIError) -> Bool {
        error.exitCode == .helperUnreachable || error.exitCode == .helperVersionMismatch
    }

    /// Runs `apply` for each ID in order. `apply` returns nil when the helper
    /// changed the rule, or a reason when it refused that one ID.
    ///
    /// If the helper stops answering before anything changed, that error is
    /// thrown as before: nothing changed, and the error is the whole story.
    /// If it stops after something changed, the batch ends there and the
    /// outcome keeps the changed IDs, the ID whose result is unknown, and the
    /// IDs that were never tried.
    static func run(_ ids: [UUID], apply: (UUID) async throws -> String?) async throws -> RuleMutationOutcome {
        var outcome = RuleMutationOutcome()
        for (index, id) in ids.enumerated() {
            do {
                if let reason = try await apply(id) {
                    outcome.failed.append(RuleMutationFailure(id: id, message: reason))
                } else {
                    outcome.succeeded.append(id)
                }
            } catch let error as CLIError {
                guard stopsTheBatch(error) else {
                    outcome.failed.append(RuleMutationFailure(id: id, message: error.message))
                    continue
                }
                guard !outcome.succeeded.isEmpty else { throw error }
                outcome.interruption = error
                outcome.failed.append(RuleMutationFailure(
                    id: id,
                    message: "Result unknown: \(error.message) Run `freesnitch rules show \(id.uuidString)` to see whether this rule changed."))
                for rest in ids[(index + 1)...] {
                    outcome.failed.append(RuleMutationFailure(
                        id: rest,
                        message: "Not attempted: the helper could not be used any more before this rule was reached."))
                }
                break
            }
        }
        return outcome
    }

    /// Hands the helper's new rules to the extension after the batch. A
    /// failure here must not hide which rules already changed, so it is
    /// returned next to them instead of thrown. Nothing is read when nothing
    /// changed, or when the helper already stopped answering.
    static func sync<Snapshot>(after outcome: RuleMutationOutcome,
                               readSnapshot: () async throws -> Snapshot,
                               deliver: (Snapshot) async -> (state: String, message: String?, generation: UInt64?))
        async -> (sync: (state: String, message: String?, generation: UInt64?), error: CLIError?) {
        guard !outcome.succeeded.isEmpty else { return (("not-needed", nil, nil), nil) }
        guard outcome.interruption == nil else {
            return (("not-checked", "The helper could not be used any more, so the changed rules were not sent to the network extension from here. Rerun the command for the failed IDs once the helper answers again.", nil), nil)
        }
        do {
            let snapshot = try await readSnapshot()
            return (await deliver(snapshot), nil)
        } catch let error as CLIError {
            return (("not-checked", "The rules changed in the helper, but their snapshot could not be read for the network extension: \(error.message)", nil), error)
        } catch {
            let wrapped = CLIError(.operationFailed, message: "The rules changed in the helper, but their snapshot could not be read: \(error.localizedDescription)")
            return (("not-checked", wrapped.message, nil), wrapped)
        }
    }

    /// The command's answer. `sync` is "not-needed" when nothing changed;
    /// `syncError` is set when reading the snapshot failed.
    static func result(operation: String,
                       pastTense: String,
                       ids: [UUID],
                       outcome: RuleMutationOutcome,
                       sync: (state: String, message: String?, generation: UInt64?),
                       syncError: CLIError? = nil) -> CommandResult {
        let report = RuleMutationReport(operation: operation,
                                        requested: ids,
                                        succeeded: outcome.succeeded,
                                        failed: outcome.failed,
                                        generation: sync.generation,
                                        extensionSync: sync.state,
                                        extensionMessage: sync.message)
        let failureText = outcome.failed.isEmpty ? "" : "\nFailures: " + outcome.failed.map { "\($0.id): \($0.message)" }.joined(separator: "; ")
        let warning = sync.message.map { "\nWarning: \($0)" } ?? ""
        let human = "\(pastTense) \(outcome.succeeded.count) of \(ids.count) rules.\(failureText)\nExtension synchronization: \(sync.state)\(sync.generation.map { " (generation \($0))" } ?? "").\(warning)"

        let error: CLIError?
        if let stop = outcome.interruption {
            error = CLIError(stop.exitCode,
                             code: "rule_mutation_interrupted",
                             message: "The command stopped after \(outcome.succeeded.count) of \(ids.count) rules were changed: \(stop.message)",
                             remediation: (stop.remediation.map { $0 + " " } ?? "") + "Once the helper works again, rerun the command for the IDs listed as failed.")
        } else if !outcome.failed.isEmpty {
            error = CLIError(.operationFailed,
                             code: "rule_mutation_partial_failure",
                             message: operation == "remove" ? "One or more rule removals failed." : "One or more rule mutations failed.",
                             remediation: "Review the failed IDs in the response and rerun the operation after fixing the helper error.")
        } else {
            error = syncError
        }
        return CommandResult(data: report, human: human, exitCode: error?.exitCode ?? .success, error: error)
    }
}
