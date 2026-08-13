#!/usr/bin/env bash
# Production-source checks for the shared rule transport boundary.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AUDIT="$ROOT/Scripts/audit_firewall_safety.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-rule-transport.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
  printf 'rule transport verification: FAIL: %s\n' "$*" >&2
  exit 1
}

run_audit() {
  local root="$1"
  bash "$root/Scripts/audit_firewall_safety.sh" 2>&1
}

compile_harness() {
  local dir="$TMP/harness"
  local source="$dir/main.swift"
  local binary="$dir/rule_transport_harness"
  mkdir -p "$dir"
  cat > "$source" <<'SWIFT'
import Foundation

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data(("rule transport harness: FAIL: " + message + "\n").utf8))
    exit(1)
}

func pass(_ message: String) {
    print("rule transport harness: PASS: \(message)")
}

func expectOversized(_ label: String,
                     maximum: Int,
                     validate: (Data) throws -> Void) {
    let payload = Data(repeating: 0, count: maximum + 1)
    do {
        try validate(payload)
        fail("\(label) accepted a payload one byte over its limit")
    } catch let error as RuleTransportBoundary.ValidationError {
        guard case .oversized(_, let actualBytes, let maximumBytes) = error,
              actualBytes == maximum + 1,
              maximumBytes == maximum else {
            fail("\(label) returned the wrong oversized error: \(error.localizedDescription)")
        }
        pass("\(label) rejected before JSON decode: \(error.localizedDescription)")
    } catch {
        fail("\(label) returned an unexpected error: \(error.localizedDescription)")
    }
}

func expectTooManyRules(_ rules: [Rule]) {
    do {
        try RuleTransportBoundary.validate(rules: rules)
        fail("maximum decoded rule count plus one was accepted")
    } catch let error as RuleTransportBoundary.ValidationError {
        guard case .tooManyRules(let actualCount, let maximumCount) = error,
              actualCount == RuleTransportBoundary.maximumDecodedRuleCount + 1,
              maximumCount == RuleTransportBoundary.maximumDecodedRuleCount else {
            fail("wrong too-many-rules error: \(error.localizedDescription)")
        }
        pass("maximum decoded rule count plus one rejected: \(error.localizedDescription)")
    } catch {
        fail("too-many-rules validation returned an unexpected error: \(error.localizedDescription)")
    }
}

func expectFieldTooLong(_ field: String, rule: Rule) {
    do {
        try RuleTransportBoundary.validate(rule: rule)
        fail("oversized field \(field) was accepted")
    } catch let error as RuleTransportBoundary.ValidationError {
        guard case .fieldTooLong(let actualField, _, _) = error,
              actualField == field else {
            fail("wrong field error for \(field): \(error.localizedDescription)")
        }
        pass("oversized field \(field) rejected: \(error.localizedDescription)")
    } catch {
        fail("field \(field) returned an unexpected error: \(error.localizedDescription)")
    }
}

let minimal = Rule(id: UUID(uuidString: "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")!)
expectOversized("snapshot byte limit", maximum: RuleTransportBoundary.maximumEncodedSnapshotBytes) {
    try RuleTransportBoundary.validateSnapshotBytes($0)
}
expectOversized("rule-batch byte limit", maximum: RuleTransportBoundary.maximumEncodedRuleBatchBytes) {
    try RuleTransportBoundary.validateRuleBatchBytes($0)
}
expectOversized("single-rule byte limit", maximum: RuleTransportBoundary.maximumEncodedSingleRuleBytes) {
    try RuleTransportBoundary.validateSingleRuleBytes($0)
}

let maximumRules = Array(repeating: minimal, count: RuleTransportBoundary.maximumDecodedRuleCount)
try! RuleTransportBoundary.validate(rules: maximumRules)
pass("exactly maximum decoded rule count accepted by validation: \(maximumRules.count)")
expectTooManyRules(maximumRules + [minimal])

let fieldCases: [(String, Rule)] = [
    ("processBundleId", Rule(processBundleId: String(repeating: "x", count: RuleTransportBoundary.maximumProcessBundleIDBytes + 1))),
    ("processPath", Rule(processPath: String(repeating: "x", count: RuleTransportBoundary.maximumProcessPathBytes + 1))),
    ("processName", Rule(processName: String(repeating: "x", count: RuleTransportBoundary.maximumProcessNameBytes + 1))),
    ("remoteHost", Rule(remoteHost: String(repeating: "x", count: RuleTransportBoundary.maximumRemoteHostBytes + 1))),
    ("remoteIP", Rule(remoteIP: String(repeating: "x", count: RuleTransportBoundary.maximumRemoteIPBytes + 1))),
    ("profile", Rule(profile: String(repeating: "x", count: RuleTransportBoundary.maximumProfileBytes + 1))),
    ("groupName", Rule(groupName: String(repeating: "x", count: RuleTransportBoundary.maximumGroupNameBytes + 1))),
    ("notes", Rule(notes: String(repeating: "x", count: RuleTransportBoundary.maximumNotesBytes + 1)))
]
for (field, rule) in fieldCases {
    expectFieldTooLong(field, rule: rule)
}

let valid = Rule(processBundleId: "com.example.App",
                 processPath: "/Applications/App.app",
                 processName: "App",
                 remoteHost: "*.example.com",
                 remoteIP: "2001:db8::/32",
                 remotePort: 443,
                 profile: "default",
                 groupName: "example",
                 notes: "valid")
try! RuleTransportBoundary.validate(rule: valid)
pass("valid bounded fields and address syntax accepted")

let ordinaryRules = Array(repeating: valid, count: 217)
let ordinaryData = try! RuleTransportBoundary.encodeRuleBatch(ordinaryRules)
try! RuleTransportBoundary.validateRuleBatchBytes(ordinaryData)
let ordinaryDecoded = try! FreeSnitchWireCodec.decode([Rule].self, from: ordinaryData)
try! RuleTransportBoundary.validate(rules: ordinaryDecoded)
pass("ordinary 217-rule current scale accepted: \(ordinaryData.count) bytes")

let snapshot = SharedRuleBridge.Snapshot(mode: .alert, rules: ordinaryRules)
let snapshotData = try! RuleTransportBoundary.encodeSnapshot(snapshot)
let decodedSnapshot = try! SharedRuleBridge.decode(snapshotData)
try! RuleTransportBoundary.validate(snapshot: decodedSnapshot)
let bootData = try! SharedRuleBridge.encodeBootSnapshot(snapshot)
_ = try! SharedRuleBridge.decodeBootSnapshot(bootData)
pass("live and boot snapshots reuse the shared limits")
SWIFT

  swiftc \
    "$ROOT/Sources/Shared/Models.swift" \
    "$ROOT/Sources/Shared/WireCodec.swift" \
    "$ROOT/Sources/Shared/PFHostValidator.swift" \
    "$ROOT/Sources/Shared/RuleMatcher.swift" \
    "$ROOT/Sources/Shared/RuleTransport.swift" \
    "$ROOT/Sources/Shared/SharedRuleBridge.swift" \
    "$source" \
    -o "$binary"
  "$binary"
}

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
  local occurrence="${5:-1}"
  local tree="$TMP/$label"
  copy_audit_tree "$tree"
  python3 - "$tree/$file" "$old" "$new" "$occurrence" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
old = sys.argv[2].replace("\\n", "\n")
new = sys.argv[3].replace("\\n", "\n")
occurrence = int(sys.argv[4]) if len(sys.argv) > 4 else 1
text = path.read_text()
starts = []
search_from = 0
while True:
    index = text.find(old, search_from)
    if index < 0:
        break
    starts.append(index)
    search_from = index + len(old)
if len(starts) < occurrence:
    raise SystemExit(f"mutation target is not found enough times in {path}: {len(starts)} matches")
index = starts[occurrence - 1]
path.write_text(text[:index] + new + text[index + len(old):])
PY

  local output
  if output="$(run_audit "$tree")"; then
    printf 'rule transport audit mutation %s: UNEXPECTED PASS\n%s\n' "$label" "$output" >&2
    exit 1
  fi
  printf 'rule transport audit mutation %s: expected failure\n%s\n' "$label" "$output"
}

printf 'rule transport audit: clean tree\n'
run_audit "$ROOT"
printf 'rule transport audit clean: passed\n'

compile_harness

mutate_and_expect_failure \
  netext-live-predecode-gate \
  Sources/NetExt/FilterDataProvider.swift \
  'try RuleTransportBoundary.validateSnapshotBytes(data)' \
  'try RuleTransportBoundary.validateSnapshotBytes(Data())'

mutate_and_expect_failure \
  helper-reload-predecode-gate \
  Sources/Helper/HelperService.swift \
  'func reloadRules(rulesJSON: Data, reply: @escaping (Bool, String?) -> Void) {\n        do {\n            try RuleTransportBoundary.validateRuleBatchBytes(rulesJSON)' \
  'func reloadRules(rulesJSON: Data, reply: @escaping (Bool, String?) -> Void) {\n        do {\n            try RuleTransportBoundary.validateRuleBatchBytes(Data())'

mutate_and_expect_failure \
  helper-replace-predecode-gate \
  Sources/Helper/HelperService.swift \
  'func replaceRules(rulesJSON: Data, reply: @escaping (Bool, String?) -> Void) {\n        do {\n            try RuleTransportBoundary.validateRuleBatchBytes(rulesJSON)' \
  'func replaceRules(rulesJSON: Data, reply: @escaping (Bool, String?) -> Void) {\n        do {\n            try RuleTransportBoundary.validateRuleBatchBytes(Data())'

mutate_and_expect_failure \
  helper-add-predecode-gate \
  Sources/Helper/HelperService.swift \
  'try RuleTransportBoundary.validateSingleRuleBytes(ruleJSON)' \
  'try RuleTransportBoundary.validateSingleRuleBytes(Data())'

printf 'rule transport audit: restored tree\n'
run_audit "$ROOT"
printf 'rule transport audit restored: passed\n'
printf 'rule transport verification: PASS\n'
