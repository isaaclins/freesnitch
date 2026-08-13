#!/usr/bin/env bash
# Deterministic production-source checks for the helper-owned policy snapshot.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AUDIT="$ROOT/Scripts/audit_firewall_safety.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-authoritative-policy.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

run_audit() {
  local root="$1"
  bash "$root/Scripts/audit_firewall_safety.sh" 2>&1
}

compile_snapshot_harness() {
  local dir="$TMP/snapshot"
  local source="$dir/main.swift"
  local binary="$dir/snapshot_harness"
  mkdir -p "$dir"
  cat > "$source" <<'SWIFT'
import Foundation

func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else {
        FileHandle.standardError.write(Data(("authoritative policy harness: FAIL: " + message + "\n").utf8))
        exit(1)
    }
}

let baseDate = Date(timeIntervalSinceReferenceDate: 100)
let ruleA = Rule(id: UUID(uuidString: "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")!,
                 remoteHost: "a.example", action: .deny, scope: .domain)
let ruleB = Rule(id: UUID(uuidString: "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB")!,
                 remoteHost: "b.example", action: .deny, scope: .domain)
let snapshotA = SharedRuleBridge.Snapshot(mode: .alert,
                                          rules: [ruleA],
                                          updatedAt: baseDate,
                                          generation: 10)
let snapshotB = SharedRuleBridge.Snapshot(mode: .silentDeny,
                                          rules: [ruleA, ruleB],
                                          updatedAt: baseDate,
                                          generation: 11)
let conflicting = SharedRuleBridge.Snapshot(mode: .silentDeny,
                                            rules: [ruleA],
                                            updatedAt: baseDate,
                                            generation: 11)
let identical = SharedRuleBridge.Snapshot(mode: snapshotB.mode,
                                          rules: snapshotB.rules,
                                          updatedAt: baseDate.addingTimeInterval(1),
                                          generation: snapshotB.generation)

var gate = SharedRuleBridge.LiveSnapshotGate()
expect(gate.apply(snapshotB) == .accepted, "newer snapshot B was not accepted")
print("authoritative policy harness: newer B accepted")
expect(gate.apply(snapshotA) == .rejectedOlder(currentGeneration: 11), "older snapshot A was accepted after B")
print("authoritative policy harness: older A rejected")
expect(gate.apply(conflicting) == .rejectedConflict(currentGeneration: 11), "equal-generation different rules were accepted")
print("authoritative policy harness: equal-generation conflict rejected")
expect(gate.apply(identical) == .idempotent, "equal-generation identical policy was not accepted idempotently")
print("authoritative policy harness: equal-generation identical accepted")
SWIFT

  swiftc \
    "$ROOT/Sources/Shared/Models.swift" \
    "$ROOT/Sources/Shared/WireCodec.swift" \
    "$ROOT/Sources/Shared/SharedRuleBridge.swift" \
    "$source" \
    -o "$binary"
  "$binary"
}

compile_rule_store_harness() {
  local dir="$TMP/rule_store"
  local source="$dir/main.swift"
  local binary="$dir/rule_store_harness"
  local db="$TMP/sequence.sqlite"
  mkdir -p "$dir"
  cat > "$source" <<'SWIFT'
import Foundation

func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else {
        FileHandle.standardError.write(Data(("rule store sequencing harness: FAIL: " + message + "\n").utf8))
        exit(1)
    }
}

let path = CommandLine.arguments[1]
let rule = Rule(id: UUID(uuidString: "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC")!,
                remoteHost: "cli-added.example", action: .deny, scope: .domain)
var store: RuleStore? = try RuleStore(path: path)
let before = store!.policyState()
let cliState = try store!.mutatePolicy { draft in
    draft.rules.append(rule)
}
let cliSnapshot = SharedRuleBridge.Snapshot(mode: cliState.mode,
                                             rules: cliState.rules,
                                             updatedAt: Date(timeIntervalSinceReferenceDate: 200),
                                             generation: cliState.generation)
let guiState = store!.policyState()
let guiSnapshot = SharedRuleBridge.Snapshot(mode: guiState.mode,
                                             rules: guiState.rules,
                                             updatedAt: Date(timeIntervalSinceReferenceDate: 201),
                                             generation: guiState.generation)
expect(cliSnapshot.rules.contains { $0.id == rule.id }, "CLI-style returned snapshot lost the mutation")
expect(guiSnapshot.rules.contains { $0.id == rule.id }, "GUI external refresh lost the CLI mutation")
expect(before.generation <= cliSnapshot.generation, "generation decreased during CLI mutation")
expect(cliSnapshot.generation <= guiSnapshot.generation, "generation decreased during GUI refresh")
store = nil
let reopened = try RuleStore(path: path)
let reopenedState = reopened.policyState()
expect(reopenedState.rules.contains { $0.id == rule.id }, "reopened store lost the committed mutation")
expect(guiSnapshot.generation <= reopenedState.generation, "generation decreased after reopening the store")
print("rule store sequencing harness: CLI generation \(cliSnapshot.generation), GUI refresh generation \(guiSnapshot.generation), reopened generation \(reopenedState.generation)")
SWIFT

  swiftc \
    "$ROOT/Sources/Shared/Models.swift" \
    "$ROOT/Sources/Shared/RuleStore.swift" \
    "$ROOT/Sources/Shared/SharedRuleBridge.swift" \
    "$ROOT/Sources/Shared/WireCodec.swift" \
    "$source" \
    -lsqlite3 \
    -o "$binary"
  "$binary" "$db"
}

printf 'authoritative policy audit: clean tree\n'
run_audit "$ROOT"
printf 'authoritative policy audit clean: passed\n'

compile_snapshot_harness
printf 'authoritative policy harness: GUI cached rules are not a sendable snapshot\n'

compile_rule_store_harness

copy_audit_tree() {
  local target="$1"
  mkdir -p "$target"
  cp -R "$ROOT/Sources" "$target/"
  cp -R "$ROOT/Scripts" "$target/"
  cp "$ROOT/project.yml" "$ROOT/project-netext.yml" "$target/"
}

mutate_and_expect_failure() {
  local label="$1"
  local file="$2"
  local old="$3"
  local new="$4"
  local tree="$TMP/$label"
  copy_audit_tree "$tree"
  python3 - "$tree/$file" "$old" "$new" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
old = sys.argv[2]
new = sys.argv[3]
text = path.read_text()
if old not in text:
    raise SystemExit(f"mutation target not found: {path}")
path.write_text(text.replace(old, new))
PY

  local output
  if output="$(run_audit "$tree")"; then
    printf 'authoritative policy audit mutation %s: UNEXPECTED PASS\n' "$label" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
  local reason
  reason="$(printf '%s\n' "$output" | grep -m1 'FIREWALL SAFETY AUDIT FAILED:' || true)"
  printf 'authoritative policy audit mutation %s: failed as expected: %s\n' "$label" "${reason#*: }"
}

mutate_and_expect_failure \
  gui-stale-cache \
  Sources/GUI/ViewModels/AppState.swift \
  'helper.authoritativeSnapshot { [weak self] snapshot, error in' \
  'SharedRuleBridge.Snapshot(mode: mode, rules: rules); helper.authoritativeSnapshot { [weak self] snapshot, error in'

mutate_and_expect_failure \
  cli-cached-sync \
  Sources/CLI/CLIRunner.swift \
  'try await helper.authoritativeSnapshot()' \
  'try await helper.listRules()'

mutate_and_expect_failure \
  extension-no-generation-gate \
  Sources/NetExt/FilterDataProvider.swift \
  'if let current, received.generation < current.generation {' \
  'if let current, false {'

printf 'authoritative policy audit: restored tree\n'
run_audit "$ROOT"
printf 'authoritative policy audit restored: passed\n'
printf 'authoritative policy verification: PASS\n'
