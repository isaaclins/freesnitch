#!/usr/bin/env bash
# Deterministic production-source checks for the helper session epoch (#70).
#
# After an update or a helper restart the extension kept comparing the policy
# generation alone, rejected the restarted helper forever, and left the Mac
# unfiltered until a reboot. These checks pin the ordering that fixes it, from
# the real sources, plus the audit gates that must not regress.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-snapshot-epoch.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

run_audit() {
  local root="$1"
  bash "$root/Scripts/audit_firewall_safety.sh" 2>&1
}

compile_epoch_harness() {
  local dir="$TMP/epoch"
  local source="$dir/main.swift"
  local binary="$dir/epoch_harness"
  local db="$TMP/epoch.sqlite"
  mkdir -p "$dir"
  cat > "$source" <<'SWIFT'
import Foundation

func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else {
        FileHandle.standardError.write(Data(("snapshot epoch harness: FAIL: " + message + "\n").utf8))
        exit(1)
    }
}

let baseDate = Date(timeIntervalSinceReferenceDate: 100)
let ruleA = Rule(id: UUID(uuidString: "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")!,
                 remoteHost: "a.example", action: .deny, scope: .domain)
let ruleB = Rule(id: UUID(uuidString: "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB")!,
                 remoteHost: "b.example", action: .deny, scope: .domain)

func snapshot(mode: AppMode = .alert,
              rules: [Rule] = [ruleA],
              generation: UInt64,
              epoch: UInt64) -> SharedRuleBridge.Snapshot {
    SharedRuleBridge.Snapshot(mode: mode, rules: rules, updatedAt: baseDate,
                              generation: generation, epoch: epoch)
}

// 1. A restarted helper opens a new session. Its generation may be lower, or
//    zero because the machine in #70 had no policy_generation row at all, and
//    it is still the authority on policy.
var restarted = SharedRuleBridge.LiveSnapshotGate(current: snapshot(generation: 8, epoch: 1))
expect(restarted.apply(snapshot(mode: .silentDeny, rules: [ruleA, ruleB], generation: 0, epoch: 2)) == .accepted,
       "a restarted helper (new session, generation reset to 0) was rejected")
expect(restarted.current?.epoch == 2 && restarted.current?.generation == 0,
       "the restarted helper's policy did not become the current policy")
print("snapshot epoch harness: restarted helper at generation 0 accepted over generation 8")

// 2. Inside one session a lower generation is still a rollback, which is the
//    case the guard was written for.
var sameSession = SharedRuleBridge.LiveSnapshotGate(current: snapshot(generation: 5, epoch: 2))
expect(sameSession.apply(snapshot(generation: 4, epoch: 2)) == .rejectedOlder(currentGeneration: 5),
       "a lower generation within one helper session was accepted")
expect(sameSession.current?.generation == 5, "a rejected rollback still replaced the current policy")
print("snapshot epoch harness: lower generation within one session rejected")

// 3. The split-brain check is unchanged: equal generation, different content.
var splitBrain = SharedRuleBridge.LiveSnapshotGate(current: snapshot(generation: 5, epoch: 2))
expect(splitBrain.apply(snapshot(rules: [ruleA, ruleB], generation: 5, epoch: 2)) == .rejectedConflict(currentGeneration: 5),
       "equal generation with different content was accepted")
expect(splitBrain.apply(snapshot(generation: 5, epoch: 2)) == .idempotent,
       "equal generation with identical content was not accepted idempotently")
print("snapshot epoch harness: equal-generation split brain still rejected")

// 4. The upgrade path: an extension holding a generation learned from a
//    pre-epoch helper converges with the first epoch-aware helper. No reboot,
//    no manual step.
let preEpoch = snapshot(generation: 8, epoch: PolicyEpoch.unknown)
var upgrading = SharedRuleBridge.LiveSnapshotGate(current: preEpoch)
expect(upgrading.apply(snapshot(generation: 0, epoch: PolicyEpoch.first)) == .accepted,
       "an extension holding a pre-epoch generation did not converge with a new helper")
print("snapshot epoch harness: pre-epoch generation 8 converges with session 1 generation 0")

// 4b. A pre-epoch payload really does decode as the unknown epoch, so the
//     convergence above is what happens on the wire, not only in memory.
let encoded = try SharedRuleBridge.encode(snapshot(generation: 8, epoch: 4))
var object = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
expect(object["epoch"] != nil, "the encoded snapshot carries no epoch field")
object.removeValue(forKey: "epoch")
let legacy = try SharedRuleBridge.decode(try JSONSerialization.data(withJSONObject: object))
expect(legacy.epoch == PolicyEpoch.unknown, "a snapshot without an epoch field did not decode as the unknown epoch")
expect(legacy.generation == 8, "removing the epoch field changed the decoded generation")
print("snapshot epoch harness: a pre-epoch wire payload decodes as the unknown epoch")

// 5. An older session is a stale client and stays rejected, however high its
//    generation is. This is ordering, not trust: it only ever refuses more.
var older = SharedRuleBridge.LiveSnapshotGate(current: snapshot(generation: 2, epoch: 3))
expect(older.apply(snapshot(generation: 99, epoch: 2)) == .rejectedOlderSession(currentEpoch: 3),
       "a snapshot from an older helper session was accepted")
expect(older.current?.generation == 2, "an older session's snapshot replaced the current policy")
print("snapshot epoch harness: older session rejected even at a higher generation")

// 6. No rejection may need a reboot, and every rejection must say so.
let rejection = SharedRuleBridge.SnapshotStatus.invalid("rejected", generation: 5, epoch: 2, rejection: .olderGeneration)
expect(rejection.needsFilterRestart, "an ordering rejection is not marked as recoverable by restarting the filter")
expect(!SharedRuleBridge.SnapshotStatus.ready(for: snapshot(generation: 1, epoch: 1)).needsFilterRestart,
       "an accepted snapshot asks for a filter restart")
expect(!SharedRuleBridge.SnapshotStatus.unavailable("no ipc").needsFilterRestart,
       "an unavailable extension asks for a filter restart")
let remediation = SharedRuleBridge.snapshotRejectionRemediation.lowercased()
expect(remediation.contains("restarting the mac is not required"),
       "the rejection remediation does not rule out a reboot")
expect(!SharedRuleBridge.snapshotRecoveryExhaustedRemediation.lowercased().contains("restart your mac"),
       "the exhausted-recovery remediation tells the user to reboot")

var recovery = FilterRestartRecovery()
let now = Date(timeIntervalSinceReferenceDate: 0)
expect(recovery.decide(for: rejection, now: now) == .restartFilter, "a rejection did not trigger a filter restart")
expect(recovery.decide(for: rejection, now: now.addingTimeInterval(1)) == .waitForCooldown,
       "a second rejection restarted the filter inside the cooldown")
var later = now
for attempt in 2...FilterRestartRecovery.maximumAttempts {
    later = later.addingTimeInterval(FilterRestartRecovery.cooldown + 1)
    expect(recovery.decide(for: rejection, now: later) == .restartFilter, "restart attempt \(attempt) was not made")
}
later = later.addingTimeInterval(FilterRestartRecovery.cooldown + 1)
expect(recovery.decide(for: rejection, now: later) == .exhausted, "filter restarts are not bounded")
recovery.noteHealthy()
expect(recovery.decide(for: rejection, now: later) == .restartFilter,
       "an accepted snapshot did not return the recovery budget")
expect(recovery.decide(for: .ready(for: snapshot(generation: 1, epoch: 1)), now: later) == .notNeeded,
       "a ready snapshot asked for a restart")
print("snapshot epoch harness: rejection is bounded, spaced, and never asks for a reboot")

// 7. The store: the generation is durable across a helper restart, and every
//    restart opens a strictly newer session.
let path = CommandLine.arguments[1]
var store: RuleStore? = try RuleStore(path: path)
expect(store!.getSetting(RuleStore.policyGenerationSettingKey) == nil,
       "a fresh database already has a policy generation row")
let firstSession = store!.beginPolicySession()
expect(firstSession.epoch == PolicyEpoch.first, "the first helper session is not epoch 1")
expect(firstSession.persisted, "the first helper session could not be persisted")
expect(store!.getSetting(RuleStore.policyGenerationSettingKey) == "0",
       "opening a session did not make the missing policy generation row durable")
_ = try store!.mutatePolicy { $0.rules.append(ruleA) }
let mutated = try store!.mutatePolicy { $0.rules.append(ruleB) }
expect(mutated.generation == 2, "two mutations did not advance the generation to 2")
expect(mutated.epoch == PolicyEpoch.first, "a policy state does not carry its session epoch")

// A helper restart: same database, new process.
store = nil
let restartedStore = try RuleStore(path: path)
expect(restartedStore.policyState().generation == 2,
       "the generation did not survive a helper restart")
let secondSession = restartedStore.beginPolicySession()
expect(secondSession.epoch == PolicyEpoch.first + 1, "a helper restart did not open a strictly newer session")
expect(restartedStore.policyState().generation == 2,
       "opening a new session rewound the persisted generation")
expect(restartedStore.policyState().epoch == secondSession.epoch,
       "the restarted helper publishes the previous session's epoch")

// And the extension accepts that restarted helper even at the reported
// generation 0, which is the exact shape of #70.
var afterRestart = SharedRuleBridge.LiveSnapshotGate(current: snapshot(generation: 8, epoch: firstSession.epoch))
let published = snapshot(generation: restartedStore.policyState().generation, epoch: secondSession.epoch)
expect(afterRestart.apply(published) == .accepted, "the restarted helper's real snapshot was rejected")
print("snapshot epoch harness: generation 2 survived the restart, session \(firstSession.epoch) to \(secondSession.epoch)")

// A store that never opened a session claims no authority.
let observer = try RuleStore(path: path)
expect(observer.policyState().epoch == PolicyEpoch.unknown,
       "a store that never opened a helper session claims a session epoch")
print("snapshot epoch harness: PASS")
SWIFT

  # Compile the whole Shared module rather than a hand-listed subset, so
  # adding a file there cannot silently break this gate.
  swiftc \
    "$ROOT"/Sources/Shared/*.swift \
    "$source" \
    -lsqlite3 \
    -o "$binary"
  "$binary" "$db"
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
    printf 'snapshot epoch audit mutation %s: UNEXPECTED PASS\n' "$label" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
  local reason
  reason="$(printf '%s\n' "$output" | grep -m1 'FIREWALL SAFETY AUDIT FAILED:' || true)"
  [[ -n "$reason" ]] || { printf 'snapshot epoch audit mutation %s: audit failed without a reason\n' "$label" >&2; exit 1; }
  printf 'snapshot epoch audit mutation %s: failed as expected: %s\n' "$label" "${reason#*: }"
}

printf 'snapshot epoch audit: clean tree\n'
run_audit "$ROOT" >/dev/null
printf 'snapshot epoch audit clean: passed\n'

compile_epoch_harness

# The properties above must stay enforced by the static gate as well, so a
# future edit cannot quietly restore the reboot-only state.
mutate_and_expect_failure \
  gate-ignores-session \
  Sources/Shared/SharedRuleBridge.swift \
  'switch SnapshotAuthority.compare(received: received, against: current) {' \
  'switch SnapshotAuthority.sameSession {'

mutate_and_expect_failure \
  extension-unscoped-generation \
  Sources/NetExt/FilterDataProvider.swift \
  'if authority == .sameSession {' \
  'if true {'

mutate_and_expect_failure \
  extension-ignores-older-session \
  Sources/NetExt/FilterDataProvider.swift \
  'if let current, authority == .olderSession {' \
  'if let current, false {'

mutate_and_expect_failure \
  helper-reuses-session \
  Sources/Helper/HelperService.swift \
  'let session = self.store.beginPolicySession()' \
  'let session = RuleStore.PolicySession(epoch: PolicyEpoch.first, generation: 0, persisted: true)'

mutate_and_expect_failure \
  store-forgets-generation \
  Sources/Shared/RuleStore.swift \
  'try persistPolicyGenerationLocked(atLeast: generation)' \
  'try {}()'

mutate_and_expect_failure \
  clock-derived-epoch \
  Sources/Shared/PolicyEpoch.swift \
  'return stored == UInt64.max ? UInt64.max : stored + 1' \
  'return UInt64(Date().timeIntervalSince1970)'

mutate_and_expect_failure \
  app-ignores-rejection \
  Sources/GUI/App/SystemExtensionManager.swift \
  'recoverFromSnapshotRejection(snapshotStatus)' \
  '_ = snapshotStatus'

mutate_and_expect_failure \
  recovery-unbounded \
  Sources/Shared/SnapshotRecovery.swift \
  'guard attempts < Self.maximumAttempts else { return .exhausted }' \
  'if false { return .exhausted }'

printf 'snapshot epoch audit: restored tree\n'
run_audit "$ROOT" >/dev/null
printf 'snapshot epoch audit restored: passed\n'
printf 'snapshot epoch verification: PASS\n'
