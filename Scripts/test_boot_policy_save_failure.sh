#!/usr/bin/env bash
# Replays #213 from the real sources: a boot-policy save fails after the user
# removed a deny rule, and the filter restarts before another save succeeds.
#
# Before the fix the failed snapshot was dropped and the extension loaded the
# older saved policy at its next start, so the removed deny rule came back.
# The checks below run that sequence against the real shared queue and
# live-policy watermark types, with the extension's start-up check mirrored in
# the harness (the extension itself cannot run here), then prove the audit
# catches each part of the fix being taken out. The app's retry scheduling
# needs NEFilterManager and is not exercised here.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-boot-save.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

compile_harness() {
  local dir="$TMP/harness"
  mkdir -p "$dir"
  cat > "$dir/main.swift" <<'SWIFT'
import Foundation

func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else {
        FileHandle.standardError.write(Data(("boot save harness: FAIL: " + message + "\n").utf8))
        exit(1)
    }
}

let watermarkURL = URL(fileURLWithPath: CommandLine.arguments[1])
    .appendingPathComponent(SharedRuleBridge.LivePolicyWatermark.fileName)
let saved = Date(timeIntervalSinceNow: -60)
let denyTracker = Rule(id: UUID(uuidString: "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")!,
                       remoteHost: "tracker.example", action: .deny, scope: .domain)

func snapshot(_ rules: [Rule], generation: UInt64, epoch: UInt64 = 3) -> SharedRuleBridge.Snapshot {
    SharedRuleBridge.Snapshot(mode: .alert, rules: rules, updatedAt: saved,
                              generation: generation, epoch: epoch)
}

/// What the extension does at start with the saved preferences: the same
/// decode and watermark check FilterDataProvider.loadBootSnapshot runs.
func extensionStart(saved data: Data) -> SharedRuleBridge.Snapshot? {
    let decoded = try! SharedRuleBridge.decodeBootSnapshot(data)
    if let mark = SharedRuleBridge.LivePolicyWatermark.read(from: watermarkURL), mark.supersedes(decoded) {
        return nil // fails open until the app sends the current rules
    }
    return SharedRuleBridge.applyingBootPolicySafety(decoded)
}

/// The extension accepting a live snapshot from the app.
func encoded(_ s: SharedRuleBridge.Snapshot) -> Data {
    try! SharedRuleBridge.encodeBootSnapshot(s)
}

func extensionAcceptsLive(_ s: SharedRuleBridge.Snapshot) throws {
    try SharedRuleBridge.LivePolicyWatermark(s).write(to: watermarkURL)
}

// 1. A saved boot policy holds a deny rule, and the extension enforces it.
let withDeny = snapshot([denyTracker], generation: 7)
var preferences = try SharedRuleBridge.encodeBootSnapshot(withDeny)
try extensionAcceptsLive(withDeny)
expect(extensionStart(saved: preferences)?.rules == [denyTracker],
       "the matching saved policy did not load")

// 2. The user deletes the rule; the running extension accepts it live.
let withoutDeny = snapshot([], generation: 8)
try extensionAcceptsLive(withoutDeny)

// 3. The app queues the new policy, takes it, and the save fails.
var queue = SharedRuleBridge.NewestWriteWinsQueue()
queue.enqueue(try SharedRuleBridge.encodeBootSnapshot(withoutDeny))
let attempt = queue.takeNewest()!
// (save fails: `preferences` keeps the old policy)
expect(queue.requeueFailed(attempt), "the failed snapshot was not put back for a retry")
expect(queue.hasPending, "nothing is pending after a failed save, so nothing will retry it")
print("boot save harness: failed save keeps the current policy queued for a retry")

// 4. The filter restarts before another save succeeds.
let atRestart = extensionStart(saved: preferences)
expect(atRestart == nil,
       "the extension loaded the older saved policy and re-enforces the deny rule the user removed")
print("boot save harness: restart after a failed save refuses the older saved policy and fails open")

// 5. The retry succeeds and the next start converges on the current rules.
let retry = queue.takeNewest()!
preferences = retry.data
let afterRetry = extensionStart(saved: preferences)
expect(afterRetry != nil && afterRetry!.rules.isEmpty && afterRetry!.generation == 8,
       "after a successful retry the current policy did not load")
print("boot save harness: the retried save loads at the next start")

// 6. A newer policy that arrived during the failed save wins over the retry.
var racing = SharedRuleBridge.NewestWriteWinsQueue()
racing.enqueue(try SharedRuleBridge.encodeBootSnapshot(withDeny))
let first = racing.takeNewest()!
let newer = try SharedRuleBridge.encodeBootSnapshot(withoutDeny)
racing.enqueue(newer)
expect(!racing.requeueFailed(first), "a failed older save replaced a newer queued policy")
expect(racing.takeNewest()?.data == newer, "the newer queued policy was lost")
print("boot save harness: a newer policy queued during the failed save wins")

// 6b. The filter is turned on, off or removed while a save is in flight. When
//     that save then fails, it must not come back: a retried old snapshot
//     could otherwise enable the filter or rewrite a removed configuration.
var cancelled = SharedRuleBridge.NewestWriteWinsQueue()
cancelled.enqueue(encoded(withDeny))
let inFlight = cancelled.takeNewest()!
cancelled.invalidateAll()
expect(!cancelled.requeueFailed(inFlight), "a save in flight during cancellation was requeued after it failed")
expect(!cancelled.hasPending, "cancellation left a snapshot queued")
print("boot save harness: cancelling drops the in-flight save too")

// 6c. Snapshot A waits for a retry; the newer B cannot be saved at all (over
//     the boot policy size limit). A must not be saved in B's place, and an A
//     save finishing late must not count as the newest one (it would clear
//     the warning). The app invalidates the queue on an encode failure.
var tooBig = SharedRuleBridge.NewestWriteWinsQueue()
tooBig.enqueue(encoded(withDeny))
let retainedA = tooBig.takeNewest()!
expect(tooBig.requeueFailed(retainedA), "A was not kept for a retry")
let hugeRules = (0..<(SharedRuleBridge.maximumBootSnapshotRuleCount + 1)).map {
    Rule(id: UUID(), remoteHost: "h\($0).example", action: .deny, scope: .domain)
}
expect((try? SharedRuleBridge.encodeBootSnapshot(snapshot(hugeRules, generation: 20))) == nil,
       "a policy over the boot limit encoded, so this case does not test anything")
tooBig.invalidateAll()
expect(!tooBig.hasPending, "the older snapshot stayed queued after a newer one could not be encoded")
expect(tooBig.hasNewerWork(since: retainedA.generation),
       "a late save of the older snapshot would count as the newest and clear the warning")
print("boot save harness: an unsaveable newer policy is never replaced by an older retry")

// 6d. Retries are spaced, bounded, and start over after a newer policy.
var schedule = SharedRuleBridge.RetrySchedule()
expect(schedule.nextDelay() == 5 && schedule.nextDelay() == 30 && schedule.nextDelay() == 120,
       "the retry delays are not 5, 30, 120 seconds")
expect(schedule.nextDelay() == nil, "retries continue after the last delay")
schedule.reset()
expect(schedule.nextDelay() == 5, "a newer policy does not restart the retries")
print("boot save harness: retries are 5 s, 30 s, 120 s, then stop until something changes")

// 7. A restarted helper opens a new session at a lower generation. Its saved
//    policy outranks the old session's, and an older session's is refused.
try extensionAcceptsLive(snapshot([], generation: 0, epoch: 4))
expect(extensionStart(saved: encoded(snapshot([], generation: 0, epoch: 4))) != nil,
       "the new helper session's saved policy was refused")
expect(extensionStart(saved: encoded(snapshot([denyTracker], generation: 9, epoch: 3))) == nil,
       "an older helper session's saved policy loaded over the newer live one")
print("boot save harness: ordering is (session, generation), as for live snapshots")

// 8. A helper restart opens a new session for the same rules. If the re-save
//    of that session does not land, the older saved policy with identical
//    content is still current and loads.
try extensionAcceptsLive(snapshot([denyTracker], generation: 10, epoch: 7))
expect(extensionStart(saved: encoded(snapshot([denyTracker], generation: 10, epoch: 6))) != nil,
       "an older saved policy with the same rules was refused after a helper restart")
//    A record written before the digest existed decides by order alone.
try SharedRuleBridge.LivePolicyWatermark(epoch: 7, generation: 10).write(to: watermarkURL)
expect(extensionStart(saved: encoded(snapshot([denyTracker], generation: 10, epoch: 6))) == nil,
       "a record without a content digest did not refuse an older saved policy")
var usedRule = denyTracker
usedRule.hitCount = 42
usedRule.lastUsedAt = saved
try extensionAcceptsLive(snapshot([usedRule], generation: 10, epoch: 8))
expect(extensionStart(saved: encoded(snapshot([denyTracker], generation: 10, epoch: 7))) != nil,
       "rules that differ only in usage counters were treated as a different policy")
print("boot save harness: identical rules from an older session still load")

// 9. No record, or an unreadable one, never refuses anything: the saved
//    policy loads exactly as before this change.
try FileManager.default.removeItem(at: watermarkURL)
expect(extensionStart(saved: encoded(withDeny)) != nil,
       "a missing watermark refused the saved policy")
try Data("not json".utf8).write(to: watermarkURL)
expect(extensionStart(saved: encoded(withDeny)) != nil,
       "an unreadable watermark refused the saved policy")
print("boot save harness: a missing or unreadable watermark changes nothing")
SWIFT
  swiftc "$ROOT"/Sources/Shared/*.swift "$dir/main.swift" -lsqlite3 -o "$dir/harness"
  mkdir -p "$TMP/container"
  "$dir/harness" "$TMP/container"
}

copy_audit_tree() {
  local target="$1"
  mkdir -p "$target"
  cp -R "$ROOT/Sources" "$ROOT/Scripts" "$target/"
  cp "$ROOT/project.yml" "$ROOT/project-netext.yml" "$target/"
}

mutate_and_expect_failure() {
  local label="$1" file="$2" old="$3" new="$4"
  local tree="$TMP/$label"
  copy_audit_tree "$tree"
  python3 - "$tree/$file" "$old" "$new" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
if sys.argv[2] not in text:
    raise SystemExit(f"mutation target not found: {path}")
path.write_text(text.replace(sys.argv[2], sys.argv[3]))
PY
  if bash "$tree/Scripts/audit_firewall_safety.sh" >/dev/null 2>&1; then
    printf 'boot save audit: FAIL: mutation %s was not caught\n' "$label" >&2
    exit 1
  fi
  printf 'boot save audit: mutation %s caught\n' "$label"
}

compile_harness
bash "$ROOT/Scripts/audit_firewall_safety.sh" >/dev/null
printf 'boot save audit: passed on the real tree\n'

mutate_and_expect_failure drop-failed-save \
  Sources/GUI/App/SystemExtensionManager.swift \
  'self.persistenceQueue.requeueFailed(pending)' 'false'
mutate_and_expect_failure load-stale-boot-policy \
  Sources/NetExt/FilterDataProvider.swift \
  'watermark.supersedes(decoded)' 'false'
mutate_and_expect_failure enable-keeps-retained-save \
  Sources/GUI/App/SystemExtensionManager.swift \
  $'cancelPendingPersistence()\n        enableFilterRequested = true' 'enableFilterRequested = true'
mutate_and_expect_failure encode-failure-keeps-older \
  Sources/GUI/App/SystemExtensionManager.swift \
  $'cancelPendingPersistence()\n            recordPersistenceFailure("encode", error: error)' 'recordPersistenceFailure("encode", error: error)'
mutate_and_expect_failure removal-keeps-banner \
  Sources/GUI/App/SystemExtensionManager.swift \
  'DispatchQueue.main.async { self.state?.clearFilterPersistenceFailure() }' ''
mutate_and_expect_failure no-config-keeps-banner \
  Sources/GUI/App/SystemExtensionManager.swift \
  $'// warning no longer applies (#311).\n                    self.state?.clearFilterPersistenceFailure()' '// removed'
mutate_and_expect_failure stop-drops-record \
  Sources/NetExt/FilterDataProvider.swift \
  'watermarkQueue.sync {}' ''
mutate_and_expect_failure forget-live-policy \
  Sources/NetExt/FilterDataProvider.swift \
  'if decision == .accepted { recordLiveWatermark(accepted) }' ''

printf 'boot policy save failure verification: PASS\n'
