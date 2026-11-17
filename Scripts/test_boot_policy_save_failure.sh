#!/usr/bin/env bash
# Replays #213 from the real sources: a boot-policy save fails after the user
# removed a deny rule, and the filter restarts before another save succeeds.
#
# Before the fix the failed snapshot was dropped and the extension loaded the
# older saved policy at its next start, so the removed deny rule came back.
# The checks below run that sequence against the real shared queue and
# live-policy watermark types, with the extension's start-up check mirrored in
# the harness (the extension itself cannot run here), then prove the audit
# catches each part of the fix being taken out. The app's save cycle runs as
# BootPolicySaveCycle with the system's answers played by the harness (#310).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-boot-save.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

compile_harness() {
  local root="${1:-$ROOT}" dir="$TMP/harness${2:-}"
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

// 6c-2. The same over-limit policy is enforced live, so turning the filter on
//     goes ahead (#320). The app queues a removal in its place: the save takes
//     the older saved policy out of the preferences, and the next start fails
//     open until the app sends the live rules again, instead of enforcing the
//     older policy's deny rules.
tooBig.enqueue(SharedRuleBridge.bootSnapshotRemoval)
expect(tooBig.hasPending, "turning the filter on would wait forever: nothing is queued to save")
let removal = tooBig.takeNewest()!
expect(removal.data == SharedRuleBridge.bootSnapshotRemoval && removal.data != encoded(withDeny),
       "the removal cannot be told apart from a real saved policy")
var vendorConfiguration: [String: Any] = [SharedRuleBridge.bootSnapshotVendorConfigurationKey: encoded(withDeny)]
// What the app's save cycle does with a removal (mirrored here: the cycle
// needs NEFilterManager; the audit checks and mutations guard the real code):
vendorConfiguration.removeValue(forKey: SharedRuleBridge.bootSnapshotVendorConfigurationKey)
// What the extension does at start when the key is missing:
let savedAtStart = vendorConfiguration[SharedRuleBridge.bootSnapshotVendorConfigurationKey] as? Data
expect(savedAtStart.flatMap(extensionStart(saved:)) == nil,
       "after a removal the next start still enforces the older saved policy")
// A failed removal save is retried like any other.
expect(tooBig.requeueFailed(removal) && tooBig.takeNewest()?.data == SharedRuleBridge.bootSnapshotRemoval,
       "a failed removal save is not retried")
print("boot save harness: an over-limit policy turns on live and removes the older saved policy")

// 6c-3. The banner only tells the user to remove rules when the count or the
//     size is why the policy can't be kept (#341). Each cause is classified
//     from the real encoder's error.
func problem(_ s: SharedRuleBridge.Snapshot) -> SharedRuleBridge.BootSnapshotProblem? {
    do { _ = try SharedRuleBridge.encodeBootSnapshot(s); return nil }
    catch { return SharedRuleBridge.BootSnapshotProblem(error, ruleCount: s.rules.count) }
}
expect(problem(snapshot(hugeRules, generation: 21))
           == .tooManyRules(count: hugeRules.count, maximum: SharedRuleBridge.maximumBootSnapshotRuleCount),
       "a policy over the rule count is not reported as too many rules")
let longNotes = String(repeating: "n", count: RuleTransportBoundary.maximumNotesBytes)
let bulkyRules = (0..<100).map {
    Rule(id: UUID(), remoteHost: "b\($0).example", action: .deny, scope: .domain, notes: longNotes)
}
expect(bulkyRules.count <= SharedRuleBridge.maximumBootSnapshotRuleCount, "the size case is over the rule count")
if case .tooLarge(_, let maximum)? = problem(snapshot(bulkyRules, generation: 22)) {
    expect(maximum == RuleTransportBoundary.maximumEncodedBootSnapshotBytes, "the size limit reported is not the boot limit")
} else {
    expect(false, "a policy over the boot size limit with fewer rules than the count limit is not reported as too large")
}
let future = SharedRuleBridge.Snapshot(mode: .alert, rules: [denyTracker], updatedAt: Date(timeIntervalSinceNow: 3600),
                                       generation: 23, epoch: 3)
expect(problem(future) == .datedInFuture, "a policy dated after the clock is not reported as dated in the future")
expect(problem(snapshot([denyTracker], generation: 24)) == nil, "a small policy dated now does not encode")
expect(SharedRuleBridge.BootSnapshotProblem(NSError(domain: "Other", code: 2), ruleCount: 1) == .other,
       "an unrelated error is reported as a size or count problem")
expect(SharedRuleBridge.BootSnapshotProblem(NSError(domain: "SharedRuleBridge", code: 1), ruleCount: 1) == .other,
       "another boot snapshot error (such as an unsupported version) is reported as a size, count or date problem")
print("boot save harness: each reason a policy can't be kept for the next start is told apart")

// 6d. Retries are spaced, bounded, and start over after a newer policy.
var schedule = SharedRuleBridge.RetrySchedule()
expect(schedule.nextDelay() == 5 && schedule.nextDelay() == 30 && schedule.nextDelay() == 120,
       "the retry delays are not 5, 30, 120 seconds")
expect(schedule.nextDelay() == nil, "retries continue after the last delay")
schedule.reset()
expect(schedule.nextDelay() == 5, "a newer policy does not restart the retries")
print("boot save harness: retries are 5 s, 30 s, 120 s, then stop until something changes")

// 6e. A snapshot that arrived while the preferences were loading is the one
//     the cycle takes. When its save fails and is put back, it is not newer
//     work: the spaced retry (or, after the last one, the single give-up
//     message) owns it, and no extra immediate cycle starts. Measuring from
//     the load instead would start one (#312).
var midLoad = SharedRuleBridge.NewestWriteWinsQueue()
midLoad.enqueue(encoded(withDeny))
let generationAtLoad = midLoad.generation
midLoad.enqueue(encoded(withoutDeny)) // arrives during loadFromPreferences
let takenMidLoad = midLoad.takeNewest()!
expect(midLoad.requeueFailed(takenMidLoad), "the snapshot taken after the load was not kept for a retry")
expect(!midLoad.hasNewerWork(since: takenMidLoad.generation),
       "a requeued snapshot counts as newer work and starts an extra save cycle")
expect(midLoad.hasNewerWork(since: generationAtLoad),
       "this case does not reproduce the cycle measured from the load")
print("boot save harness: a failed save taken mid-load is retried once, not twice")

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

// 10. #321: with the filter off, a failed boot-policy save is only logged,
//     and turning it on (in the app or in System Settings) saves the current
//     rules again, after which a failure warns as before.
var off = FilterOffState()
expect(off.saveFailureShowsBanner, "a failed save while the filter is on does not warn")
off.turnedOff(turnOnPending: false)                      // turned off in the app
expect(!off.saveFailureShowsBanner, "a failed save while the filter is off still raises the banner")
expect(off.observed(configured: true, enabled: false, fromOutside: false) == .clearBanner,
       "a save cycle that finds the filter off keeps an old banner up")
expect(!off.saveFailureShowsBanner, "a rule change while off brings the banner back")
off.turnedOn()                                           // turned on in the app
expect(off.saveFailureShowsBanner, "a failed save after turning the filter on is hidden")
//     Off and on in System Settings, seen only through the change notification.
expect(off.observed(configured: true, enabled: false, fromOutside: true) == .clearBanner,
       "turning the filter off in System Settings keeps the banner up")
expect(!off.saveFailureShowsBanner, "a failed save after turning off in System Settings warns")
expect(off.observed(configured: true, enabled: true, fromOutside: true) == .saveCurrentRules,
       "turning the filter on in System Settings does not save the current rules again")
expect(off.saveFailureShowsBanner, "a failed save after turning on in System Settings is hidden")
expect(off.observed(configured: true, enabled: true, fromOutside: true) == .none,
       "an unrelated change while on saves again for nothing")
//     The app's own save cycle is already saving: it never asks for another.
off.turnedOff(turnOnPending: false)
expect(off.observed(configured: true, enabled: true, fromOutside: false) == .none,
       "a save cycle that finds the filter on asks for a second save")
//     A turn-off that finishes after a turn-on was asked for does not win.
off.turnedOn()
expect(!off.turnedOff(turnOnPending: true),
       "a late turn-off reports the firewall as not filtering while a turn-on is pending (#335)")
expect(off.saveFailureShowsBanner, "a late turn-off overrode the turn-on asked for after it")
//     #335: a turn-off or removal with nothing pending says the firewall is
//     not filtering, whatever macOS answers about the extension afterwards.
expect(off.turnedOff(turnOnPending: false),
       "a finished turn-off or removal leaves the firewall shown as filtering")
off.turnedOn()
//     No configuration at all counts as off.
expect(off.observed(configured: false, enabled: true, fromOutside: true) == .clearBanner,
       "a removed filter configuration is not treated as off")
//     #348: at launch the app reads the filter state once. Before that read
//     it assumes on, so a failure then warns; finding the filter left off
//     takes the banner down, and finding it on asks for no extra save.
var launch = FilterOffState()
expect(launch.saveFailureShowsBanner, "a failure before the launch read is hidden")
expect(launch.observed(configured: true, enabled: false, fromOutside: true) == .clearBanner,
       "finding the filter left off at launch keeps an early banner up")
expect(!launch.saveFailureShowsBanner, "a failed save after finding the filter off at launch warns")
var launchOn = FilterOffState()
expect(launchOn.observed(configured: true, enabled: true, fromOutside: true) == .none,
       "finding the filter on at launch saves the rules a second time")
print("boot save harness: with the filter off a failed save is logged, and turning it on saves again")

// 11. The app's save cycle around NEFilterManager (#310). The harness plays
//     the system's answers (load failed, configuration exists, save failed)
//     and checks each decision BootPolicySaveCycle makes.
typealias Cycle = SharedRuleBridge.BootPolicySaveCycle
let policyA = encoded(withDeny)
let policyB = encoded(withoutDeny)

func savePlan(_ decision: Cycle.AfterLoad, _ message: String) -> Cycle.Save {
    guard case .save(let plan) = decision else {
        expect(false, message + " (got \(decision))")
        fatalError()
    }
    return plan
}

// 11a. Load failure: the snapshot stays queued and a spaced retry follows.
var loadFails = Cycle()
loadFails.enqueue(policyB)
let loadAt = loadFails.begin()!
expect(loadFails.begin() == nil, "a second cycle started while one was loading")
expect(loadFails.afterLoad(loadAt, loadFailed: true, configurationExists: true, hasSavedPolicy: true)
       == .loadFailed(failActivation: false, next: .retry(after: 5)),
       "a failed load did not schedule the first retry")
expect(loadFails.queue.hasPending && !loadFails.inFlight, "a failed load dropped the snapshot or stayed in flight")
let retriedAt = loadFails.begin()!
let retried = savePlan(loadFails.afterLoad(retriedAt, loadFailed: false, configurationExists: true, hasSavedPolicy: true),
                       "the retry after a failed load did not save")
expect(retried.pending?.data == policyB && !retried.enable, "the retry saved the wrong snapshot or enabled the filter")
let loadSaved = loadFails.afterSave(retried, saveFailed: false)
expect(loadSaved.clearWarning && loadSaved.savedPolicy && loadSaved.next == .none && !loadSaved.runAgainNow,
       "a successful retry did not clear the warning, or kept going")
//      A newer policy queued during the failed load runs now, not on the retry clock.
var loadRaced = Cycle()
loadRaced.enqueue(policyA)
let racedAt = loadRaced.begin()!
loadRaced.enqueue(policyB)
expect(loadRaced.afterLoad(racedAt, loadFailed: true, configurationExists: true, hasSavedPolicy: true)
       == .loadFailed(failActivation: false, next: .now),
       "a newer policy queued during a failed load waited for the retry delay")
//      A failed load while turning the filter on fails visibly, ends the
//      enable request and keeps the snapshot for a retry that only saves (#345).
var enableLoadFails = Cycle()
enableLoadFails.requestEnable()
enableLoadFails.enqueue(policyB)
let enableLoadAt = enableLoadFails.begin()!
expect(enableLoadFails.afterLoad(enableLoadAt, loadFailed: true, configurationExists: true, hasSavedPolicy: true)
       == .loadFailed(failActivation: true, next: .retry(after: 5)),
       "a failed load during activation was not reported, or its snapshot was not retried")
expect(!enableLoadFails.enableRequested, "a failed load during activation kept the enable request, so the retry would turn the filter on")
let enableLoadRetryAt = enableLoadFails.begin()!
let enableLoadRetry = savePlan(enableLoadFails.afterLoad(enableLoadRetryAt, loadFailed: false, configurationExists: true, hasSavedPolicy: true),
                               "the retry after a failed activation load did not save")
expect(enableLoadRetry.pending?.data == policyB && !enableLoadRetry.enable,
       "the retry after a failed activation load saved the wrong snapshot or turned the filter on")
//      #345: rules over the limit, so the queued save is the removal of the
//      older saved policy. A failed activation load keeps it, and the retry
//      removes the older policy without turning the filter on.
var enableLoadRemoval = Cycle()
enableLoadRemoval.requestEnable()
enableLoadRemoval.queueRemoval()
let enableRemovalAt = enableLoadRemoval.begin()!
expect(enableLoadRemoval.afterLoad(enableRemovalAt, loadFailed: true, configurationExists: true, hasSavedPolicy: true)
       == .loadFailed(failActivation: true, next: .retry(after: 5)),
       "a failed load while turning the filter on dropped the queued removal of the older saved policy")
let removalRetryAt = enableLoadRemoval.begin()!
let removalRetry = savePlan(enableLoadRemoval.afterLoad(removalRetryAt, loadFailed: false, configurationExists: true, hasSavedPolicy: true),
                            "the retried removal did not save")
expect(removalRetry.removesSavedPolicy && !removalRetry.enable,
       "the retried removal did not remove the older saved policy, or turned the filter on")
expect(enableLoadRemoval.afterSave(removalRetry, saveFailed: false).removedSavedPolicy,
       "the retried removal did not take the older saved policy out")
//      With no configuration (the first turn-on failed), the retry saves nothing.
var enableLoadNoConfig = Cycle()
enableLoadNoConfig.requestEnable()
enableLoadNoConfig.enqueue(policyB)
let noConfigLoadAt = enableLoadNoConfig.begin()!
_ = enableLoadNoConfig.afterLoad(noConfigLoadAt, loadFailed: true, configurationExists: false, hasSavedPolicy: false)
let noConfigRetryAt = enableLoadNoConfig.begin()!
expect(enableLoadNoConfig.afterLoad(noConfigRetryAt, loadFailed: false, configurationExists: false, hasSavedPolicy: false)
       == .stop(.noConfiguration), "the retry after a failed first turn-on created a filter configuration")
print("boot save harness: cycle: a failed load keeps the snapshot and retries; during activation it fails visibly and retries without turning on")

// 11b. Save failure: the snapshot is put back and retried on the schedule;
//      a newer policy queued during the save wins and runs at once.
var saveFails = Cycle()
saveFails.enqueue(policyB)
let saveAt = saveFails.begin()!
let failing = savePlan(saveFails.afterLoad(saveAt, loadFailed: false, configurationExists: true, hasSavedPolicy: true),
                       "the first save did not run")
let failed = saveFails.afterSave(failing, saveFailed: true)
expect(failed.next == .retry(after: 5) && failed.reportFailure && !failed.runAgainNow && !failed.clearWarning && !failed.failActivation,
       "a failed save was not kept for a spaced retry")
expect(saveFails.queue.hasPending, "a failed save left nothing to retry")
var saveRaced = Cycle()
saveRaced.enqueue(policyA)
let saveRacedAt = saveRaced.begin()!
let olderSave = savePlan(saveRaced.afterLoad(saveRacedAt, loadFailed: false, configurationExists: true, hasSavedPolicy: true),
                         "the older save did not run")
saveRaced.enqueue(policyB)
let olderFailed = saveRaced.afterSave(olderSave, saveFailed: true)
expect(olderFailed.next == .none && olderFailed.runAgainNow, "a newer policy queued during a failed save did not run next")
let newerAt = saveRaced.begin()!
let newerSave = savePlan(saveRaced.afterLoad(newerAt, loadFailed: false, configurationExists: true, hasSavedPolicy: true),
                         "the newer save did not run")
expect(newerSave.pending?.data == policyB, "the failed older snapshot was saved instead of the newer one")
//      An older save that succeeds late does not clear the warning.
var lateOlder = Cycle()
lateOlder.enqueue(policyA)
let lateAt = lateOlder.begin()!
let lateSave = savePlan(lateOlder.afterLoad(lateAt, loadFailed: false, configurationExists: true, hasSavedPolicy: true),
                        "the older save did not run")
lateOlder.enqueue(policyB)
let lateDone = lateOlder.afterSave(lateSave, saveFailed: false)
expect(lateDone.savedPolicy && !lateDone.clearWarning && lateDone.runAgainNow,
       "an older save finishing late cleared the warning or did not save the newer policy next")
//      A failed save while turning the filter on fails visibly and keeps
//      what it was saving for a retry that only saves (#345).
var enableSaveFails = Cycle()
enableSaveFails.requestEnable()
enableSaveFails.queueRemoval()
let enableSaveAt = enableSaveFails.begin()!
let enabling = savePlan(enableSaveFails.afterLoad(enableSaveAt, loadFailed: false, configurationExists: true, hasSavedPolicy: true),
                        "activation did not save")
expect(enabling.enable && enabling.removesSavedPolicy, "activation did not enable the filter and remove the older policy")
let enableFailed = enableSaveFails.afterSave(enabling, saveFailed: true)
expect(enableFailed.failActivation && !enableFailed.activated, "a failed activation save was not reported")
expect(enableFailed.next == .retry(after: 5) && enableSaveFails.queue.hasPending,
       "a failed save while turning the filter on dropped the queued removal of the older saved policy")
let enableSaveRetryAt = enableSaveFails.begin()!
let enableSaveRetry = savePlan(enableSaveFails.afterLoad(enableSaveRetryAt, loadFailed: false, configurationExists: true, hasSavedPolicy: true),
                               "the retry after a failed activation save did not run")
expect(enableSaveRetry.removesSavedPolicy && !enableSaveRetry.enable,
       "the retry after a failed activation save turned the filter on or did not remove the older policy")
print("boot save harness: cycle: a failed save is retried, newer work wins, only the newest save clears the warning")

// 11c. Cancel during load: turned off or removed while loading saves nothing.
var cancelLoad = Cycle()
cancelLoad.enqueue(policyA)
let cancelLoadAt = cancelLoad.begin()!
cancelLoad.cancel()
expect(cancelLoad.afterLoad(cancelLoadAt, loadFailed: false, configurationExists: true, hasSavedPolicy: true)
       == .stop(.cancelledDuringLoad), "a save ran after the filter was turned off during the load")
expect(!cancelLoad.inFlight && cancelLoad.begin() == nil, "a cancelled cycle left work behind")
//      A failed load after a cancel does not schedule a retry of nothing.
var cancelLoadFails = Cycle()
cancelLoadFails.enqueue(policyA)
let cancelLoadFailsAt = cancelLoadFails.begin()!
cancelLoadFails.cancel()
expect(cancelLoadFails.afterLoad(cancelLoadFailsAt, loadFailed: true, configurationExists: true, hasSavedPolicy: true)
       == .cancelledLoadFailed(next: .none), "a load failure after the filter was turned off raised a warning or retried")
expect(!cancelLoadFails.queue.hasPending, "a cancelled snapshot came back after a failed load")
//      Turned on during a load that then fails: no warning, no failed
//      activation; the activation goes on with the helper's fresh answer.
var enableLoadCancelled = Cycle()
enableLoadCancelled.enqueue(policyA)
let enableCancelAt = enableLoadCancelled.begin()!
enableLoadCancelled.requestEnable()
expect(enableLoadCancelled.afterLoad(enableCancelAt, loadFailed: true, configurationExists: true, hasSavedPolicy: true)
       == .cancelledLoadFailed(next: .now), "a stale load failure failed an activation that had not run yet")
expect(enableLoadCancelled.enableRequested, "the activation was dropped by a stale load failure")
print("boot save harness: cycle: turning the filter off or removing it during the load saves nothing")

// 11d. Cancel during save: the save in flight fails and is not put back.
var cancelSave = Cycle()
cancelSave.enqueue(policyA)
let cancelSaveAt = cancelSave.begin()!
let cancelling = savePlan(cancelSave.afterLoad(cancelSaveAt, loadFailed: false, configurationExists: true, hasSavedPolicy: true),
                          "the save did not run")
cancelSave.cancel()
let cancelledSave = cancelSave.afterSave(cancelling, saveFailed: true)
expect(cancelledSave.next == .none && !cancelledSave.reportFailure && !cancelSave.queue.hasPending && cancelSave.begin() == nil,
       "a save in flight when the filter was turned off came back as a retry or raised the warning")
//      ...and if it succeeds late, it does not count as the newest save.
var cancelSaveOk = Cycle()
cancelSaveOk.enqueue(policyA)
let cancelSaveOkAt = cancelSaveOk.begin()!
let cancellingOk = savePlan(cancelSaveOk.afterLoad(cancelSaveOkAt, loadFailed: false, configurationExists: true, hasSavedPolicy: true),
                            "the save did not run")
cancelSaveOk.cancel()
expect(!cancelSaveOk.afterSave(cancellingOk, saveFailed: false).clearWarning,
       "a save cancelled in flight cleared the warning")
print("boot save harness: cycle: a save cancelled in flight is never retried or counted as current")

// 11e. Enable without a fresh snapshot: a snapshot kept for a retry is never
//      what activation saves; only the helper's fresh answer may enable.
var staleEnable = Cycle()
staleEnable.enqueue(policyA)
let staleAt = staleEnable.begin()!
expect(staleEnable.afterSave(savePlan(staleEnable.afterLoad(staleAt, loadFailed: false, configurationExists: true, hasSavedPolicy: true),
                                      "the save did not run"), saveFailed: true).next == .retry(after: 5),
       "setup: the failed save was not kept")
staleEnable.requestEnable()
expect(!staleEnable.queue.hasPending && staleEnable.begin() == nil,
       "turning the filter on kept the retried snapshot, which would then be saved and enabled")
//      Turned on while a cycle is loading: that cycle stops, the fresh answer starts the next.
var enableDuringLoad = Cycle()
enableDuringLoad.enqueue(policyA)
let enableDuringAt = enableDuringLoad.begin()!
enableDuringLoad.requestEnable()
expect(enableDuringLoad.afterLoad(enableDuringAt, loadFailed: false, configurationExists: true, hasSavedPolicy: true)
       == .stop(.enableWithoutFreshSnapshot), "the filter was enabled with the snapshot queued before activation")
enableDuringLoad.enqueue(policyB)
let freshAt = enableDuringLoad.begin()!
let fresh = savePlan(enableDuringLoad.afterLoad(freshAt, loadFailed: false, configurationExists: true, hasSavedPolicy: true),
                     "the fresh answer did not enable the filter")
expect(fresh.enable && fresh.pending?.data == policyB, "activation saved something other than the fresh answer")
expect(enableDuringLoad.afterSave(fresh, saveFailed: false).activated, "a successful activation did not turn the filter on")
//      The helper gave nothing while turning on, with nothing in flight: give up visibly.
var noAnswer = Cycle()
noAnswer.requestEnable()
expect(noAnswer.begin() == nil, "an enable request without a snapshot started a save")
expect(noAnswer.abandonEnableIfIdle() && !noAnswer.enableRequested, "a missing helper answer did not fail activation")
//      Turned on, then off before the helper answered: the answer saves the
//      rules but does not turn the filter back on (#309).
var onThenOff = Cycle()
onThenOff.requestEnable()
onThenOff.cancel()
onThenOff.dropEnableRequest()
onThenOff.enqueue(policyB)
let onThenOffAt = onThenOff.begin()!
let onThenOffSave = savePlan(onThenOff.afterLoad(onThenOffAt, loadFailed: false, configurationExists: true, hasSavedPolicy: true),
                             "the helper's answer after the filter was turned off did not save")
expect(!onThenOffSave.enable, "the helper's answer turned the filter back on after the user turned it off")
print("boot save harness: cycle: turning the filter on only ever saves the helper's fresh answer")

// 11f. No configuration: a boot-policy save never creates one.
var noConfig = Cycle()
noConfig.enqueue(policyA)
let noConfigAt = noConfig.begin()!
expect(noConfig.afterLoad(noConfigAt, loadFailed: false, configurationExists: false, hasSavedPolicy: false)
       == .stop(.noConfiguration), "a boot-policy save would create a filter configuration that was not there")
expect(!noConfig.queue.hasPending, "the snapshot stayed queued for a configuration that does not exist")
print("boot save harness: cycle: a save never creates a missing filter configuration")

// 11g. Retries used up: three spaced retries, then it stops until something
//      changes; a newer policy starts the retries over.
var exhausted = Cycle()
exhausted.enqueue(policyB)
var seen: [Cycle.Next] = []
for _ in 0..<4 {
    let at = exhausted.begin()!
    let plan = savePlan(exhausted.afterLoad(at, loadFailed: false, configurationExists: true, hasSavedPolicy: true),
                        "a retry did not save")
    seen.append(exhausted.afterSave(plan, saveFailed: true).next)
}
expect(seen == [.retry(after: 5), .retry(after: 30), .retry(after: 120), .retriesUsedUp],
       "retries were not 5 s, 30 s, 120 s and then stopped: \(seen)")
exhausted.enqueue(policyA)
let restartAt = exhausted.begin()!
let restart = savePlan(exhausted.afterLoad(restartAt, loadFailed: false, configurationExists: true, hasSavedPolicy: true),
                       "the newer policy did not save")
expect(exhausted.afterSave(restart, saveFailed: true).next == .retry(after: 5), "a newer policy did not restart the retries")
print("boot save harness: cycle: retries stop after three and start over with a newer policy")

// 11h. Over the boot policy limit (#320): the newest policy cannot be kept
//      for the next start, but it is enforced live. The older snapshot kept
//      for a retry is dropped, the saved policy is removed instead, and
//      turning the filter on goes ahead.
var unencodable = Cycle()
unencodable.enqueue(policyA)
let unencodableAt = unencodable.begin()!
let olderInFlight = savePlan(unencodable.afterLoad(unencodableAt, loadFailed: false, configurationExists: true, hasSavedPolicy: true),
                             "the save did not run")
unencodable.queueRemoval()
let olderLate = unencodable.afterSave(olderInFlight, saveFailed: false)
expect(!olderLate.clearWarning, "after a newer policy could not be kept, an older save finishing late cleared the warning")
expect(olderLate.runAgainNow, "the removal queued during the older save does not run next")
let removalAt = unencodable.begin()!
let removing = savePlan(unencodable.afterLoad(removalAt, loadFailed: false, configurationExists: true, hasSavedPolicy: true),
                        "the removal did not run")
expect(removing.removesSavedPolicy && removing.hadSavedPolicy && removing.pending?.data != policyA,
       "the older snapshot was saved in place of the removal")
let removed = unencodable.afterSave(removing, saveFailed: false)
expect(removed.removedSavedPolicy && !removed.savedPolicy && !removed.clearWarning,
       "removing the saved policy cleared the can't-keep-for-restart warning")
//      An older save in flight that fails after the over-limit edit is
//      not put back and raises no warning: the removal replaces it.
var olderFailsLate = Cycle()
olderFailsLate.enqueue(policyA)
let olderFailsAt = olderFailsLate.begin()!
let olderFailing = savePlan(olderFailsLate.afterLoad(olderFailsAt, loadFailed: false, configurationExists: true, hasSavedPolicy: true),
                            "the save did not run")
olderFailsLate.queueRemoval()
let olderFailedLate = olderFailsLate.afterSave(olderFailing, saveFailed: true)
expect(!olderFailedLate.reportFailure && olderFailedLate.next == .none,
       "an older save that failed after the over-limit edit raised the warning or was retried")
//      A failed removal is retried like any other save.
var removalFails = Cycle()
removalFails.queueRemoval()
let removalFailsAt = removalFails.begin()!
let failingRemoval = savePlan(removalFails.afterLoad(removalFailsAt, loadFailed: false, configurationExists: true, hasSavedPolicy: true),
                              "the removal did not run")
expect(removalFails.afterSave(failingRemoval, saveFailed: true).next == .retry(after: 5), "a failed removal is not retried")
//      Turning the filter on over the limit goes ahead with the removal.
var enableOverLimit = Cycle()
enableOverLimit.requestEnable()
enableOverLimit.queueRemoval()
expect(enableOverLimit.enableRequested, "a policy over the limit stopped the filter from being turned on")
let enableOverLimitAt = enableOverLimit.begin()!
let enablingRemoval = savePlan(enableOverLimit.afterLoad(enableOverLimitAt, loadFailed: false, configurationExists: false, hasSavedPolicy: false),
                               "turning the filter on over the limit saved nothing")
expect(enablingRemoval.enable && enablingRemoval.removesSavedPolicy, "turning the filter on over the limit did not enable it")
expect(enableOverLimit.afterSave(enablingRemoval, saveFailed: false).activated, "turning the filter on over the limit did not activate it")
//      Nothing saved to remove and not turning on: the preferences are not
//      rewritten unchanged on every rule edit over the limit.
var nothingSaved = Cycle()
nothingSaved.queueRemoval()
let nothingSavedAt = nothingSaved.begin()!
expect(nothingSaved.afterLoad(nothingSavedAt, loadFailed: false, configurationExists: true, hasSavedPolicy: false)
       == .nothingToRemove(next: .none), "a removal with nothing saved rewrote the preferences")
expect(!nothingSaved.inFlight && !nothingSaved.queue.hasPending, "a removal with nothing saved left work behind")
print("boot save harness: cycle: over the limit the saved policy is removed, never replaced by an older one, and turning on goes ahead")

// 11i. A snapshot that arrived while the preferences were loading is the one
//      the cycle takes. When its save fails and is put back, the spaced retry
//      owns it; no extra immediate cycle starts (#312).
var midLoadCycle = Cycle()
midLoadCycle.enqueue(policyA)
let midLoadAt = midLoadCycle.begin()!
midLoadCycle.enqueue(policyB)
let midLoadSave = savePlan(midLoadCycle.afterLoad(midLoadAt, loadFailed: false, configurationExists: true, hasSavedPolicy: true),
                           "the save did not run")
let midLoadFailed = midLoadCycle.afterSave(midLoadSave, saveFailed: true)
expect(midLoadFailed.next == .retry(after: 5) && !midLoadFailed.runAgainNow,
       "a failed save taken mid-load started an extra cycle besides its retry")
print("boot save harness: cycle: a failed save taken mid-load is retried once, not twice")
SWIFT
  swiftc "$root"/Sources/Shared/*.swift "$dir/main.swift" -lsqlite3 -o "$dir/harness"
  rm -rf "$TMP/container" && mkdir -p "$TMP/container"
  "$dir/harness" "$TMP/container"
}

# Take one decision out of the save cycle and prove the harness notices.
mutate_cycle_and_expect_harness_failure() {
  local label="$1" old="$2" new="$3"
  local tree="$TMP/cycle-$label"
  mkdir -p "$tree" && cp -R "$ROOT/Sources" "$tree/"
  python3 - "$tree/Sources/Shared/BootPolicySaveCycle.swift" "$old" "$new" <<'PY2'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
if sys.argv[2] not in text:
    raise SystemExit(f"mutation target not found: {sys.argv[2]!r}")
path.write_text(text.replace(sys.argv[2], sys.argv[3], 1))
PY2
  local out
  if out="$(compile_harness "$tree" "-$label" 2>&1)"; then
    printf 'boot save harness: FAIL: cycle mutation %s was not caught\n' "$label" >&2
    exit 1
  fi
  # Caught means a harness check failed, not that the mutation broke the build.
  if ! grep -q '^boot save harness: FAIL: ' <<<"$out"; then
    printf 'boot save harness: FAIL: cycle mutation %s did not compile, so it tests nothing\n%s\n' "$label" "$out" >&2
    exit 1
  fi
  printf 'boot save harness: cycle mutation %s caught\n' "$label"
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
  Sources/Shared/BootPolicySaveCycle.swift \
  'queue.requeueFailed(pending)' 'false'
mutate_and_expect_failure load-stale-boot-policy \
  Sources/NetExt/FilterDataProvider.swift \
  'watermark.supersedes(decoded)' 'false'
mutate_and_expect_failure enable-bypasses-cycle \
  Sources/GUI/App/SystemExtensionManager.swift \
  'persistenceCycle.requestEnable()' ''
mutate_and_expect_failure encode-failure-keeps-older \
  Sources/GUI/App/SystemExtensionManager.swift \
  'persistenceCycle.queueRemoval()' ''
mutate_and_expect_failure retry-not-scheduled \
  Sources/GUI/App/SystemExtensionManager.swift \
  'self.carryOut(result.next, removal: removesBootSnapshot)' ''
mutate_and_expect_failure extra-cycle-after-requeue \
  Sources/Shared/BootPolicySaveCycle.swift \
  'hasNewerWork(since: attempted)' 'hasNewerWork(since: save.load.generation)'
mutate_and_expect_failure banner-always-says-remove-rules \
  Sources/GUI/Views/HelperBanner.swift \
  'sends them again.",' 'sends them again. Remove some rules to keep them across restarts.",'
mutate_and_expect_failure clock-skew-says-remove-rules \
  Sources/GUI/App/SystemExtensionManager.swift \
  'for example with the next rule change."' 'for example with the next rule change. Remove some rules."'
mutate_and_expect_failure other-failure-says-remove-rules \
  Sources/GUI/App/SystemExtensionManager.swift \
  'could not be saved for the next start: \(error.sentence)"' 'could not be saved for the next start. Remove some rules."'
mutate_and_expect_failure reason-ignores-cause \
  Sources/GUI/App/SystemExtensionManager.swift \
  'Self.unsavableReason(SharedRuleBridge.BootSnapshotProblem(error, ruleCount: snapshot.rules.count),' 'Self.unsavableReason(.other,'
mutate_and_expect_failure over-limit-keeps-older-saved-policy \
  Sources/Shared/BootPolicySaveCycle.swift \
  'queue.enqueue(SharedRuleBridge.bootSnapshotRemoval)' ''
mutate_and_expect_failure over-limit-stops-activation \
  Sources/GUI/App/SystemExtensionManager.swift \
  'recordPersistenceFailure("encode", error: error, unsavable: reason, writeLog: firstTime)' $'recordPersistenceFailure("encode", error: error, unsavable: reason, writeLog: firstTime)\n            if persistenceCycle.abandonEnableIfIdle() { fail("filter snapshot could not be saved") }'
mutate_and_expect_failure removal-clears-unsavable-banner \
  Sources/GUI/App/SystemExtensionManager.swift \
  $'// can be kept is saved.\n                                let reason' $'// can be kept is saved.\n                                self.state?.clearFilterPersistenceFailure()\n                                let reason'
mutate_and_expect_failure cancelled-save-reports \
  Sources/GUI/App/SystemExtensionManager.swift \
  'if result.reportFailure {' 'if true {'
mutate_and_expect_failure over-limit-logs-every-edit \
  Sources/GUI/App/SystemExtensionManager.swift \
  'unsavable: reason, writeLog: firstTime)' 'unsavable: reason)'
mutate_and_expect_failure over-limit-log-keyed-on-count \
  Sources/GUI/App/SystemExtensionManager.swift \
  'let firstTime = !unsavableLogged' 'let firstTime = state?.filterPersistenceUnsavable != reason'
mutate_and_expect_failure over-limit-banner-without-filter \
  Sources/GUI/App/SystemExtensionManager.swift \
  'if filterConfigurationActive || persistenceCycle.enableRequested {' 'if true {'
mutate_and_expect_failure failed-load-drops-reason \
  Sources/GUI/App/SystemExtensionManager.swift \
  'unsavable: self.unsavableLogged ? self.state?.filterPersistenceUnsavable : nil' 'unsavable: nil'
mutate_and_expect_failure failed-removal-drops-reason \
  Sources/GUI/App/SystemExtensionManager.swift \
  'unsavable: removesBootSnapshot ? self.state?.filterPersistenceUnsavable : nil' 'unsavable: nil'
mutate_and_expect_failure removal-giveup-generic-message \
  Sources/GUI/App/SystemExtensionManager.swift \
  'let message = removal' 'let message = state?.filterPersistenceUnsavable != nil'
mutate_and_expect_failure removal-giveup-logs-without-filter \
  Sources/GUI/App/SystemExtensionManager.swift \
  'if removal && state?.filterPersistenceUnsavable == nil {' 'if false {'
mutate_and_expect_failure removal-retry-not-flagged \
  Sources/GUI/App/SystemExtensionManager.swift \
  'self.carryOut(result.next, removal: removesBootSnapshot)' 'self.carryOut(result.next, removal: false)'
mutate_and_expect_failure removal-load-failure-banner \
  Sources/GUI/App/SystemExtensionManager.swift \
  'let removalQueued = self.persistenceCycle.queue.peekNewest == SharedRuleBridge.bootSnapshotRemoval' 'let removalQueued = false'
mutate_and_expect_failure banner-claims-rules-in-use \
  Sources/GUI/Views/HelperBanner.swift \
  'liveRulesReady ? "The filter is using them now." : nil' '"The filter is using them now."'
mutate_and_expect_failure removal-keeps-banner \
  Sources/GUI/App/SystemExtensionManager.swift \
  $'no longer applies (#311).\n                                self.state?.clearFilterPersistenceFailure()' 'no longer applies (#311).'
mutate_and_expect_failure no-config-keeps-banner \
  Sources/GUI/App/SystemExtensionManager.swift \
  $'// warning no longer applies (#311).\n                    self.state?.clearFilterPersistenceFailure()' '// removed'
mutate_and_expect_failure off-save-shows-banner \
  Sources/GUI/App/SystemExtensionManager.swift \
  'if !filterOff.saveFailureShowsBanner {' 'if false {'
mutate_and_expect_failure off-branch-falls-through \
  Sources/GUI/App/SystemExtensionManager.swift \
  $'offDetail)\n            }\n            return' 'offDetail)\n            }'
mutate_and_expect_failure off-not-noticed \
  Sources/GUI/App/SystemExtensionManager.swift \
  'self.apply(self.filterOff.observed(configured: true, enabled: mgr.isEnabled,' 'self.apply(self.filterOff.observed(configured: true, enabled: true,'
mutate_and_expect_failure enable-stays-off \
  Sources/GUI/App/SystemExtensionManager.swift \
  $'persistenceCycle.requestEnable()\n        filterOff.turnedOn()' 'persistenceCycle.requestEnable()'
mutate_and_expect_failure late-off-overrides-on \
  Sources/GUI/App/SystemExtensionManager.swift \
  $'self.filterConfigurationActive = true\n                                self.filterOff.turnedOn()' 'self.filterConfigurationActive = true'
mutate_and_expect_failure off-ignores-pending-on \
  Sources/GUI/App/SystemExtensionManager.swift \
  'self.filterOff.turnedOff(turnOnPending: self.persistenceCycle.enableRequested)' 'self.filterOff.turnedOff(turnOnPending: false)'
mutate_and_expect_failure settings-change-ignored \
  Sources/GUI/App/SystemExtensionManager.swift \
  'forName: .NEFilterConfigurationDidChange' 'forName: .init("unused")'
mutate_and_expect_failure launch-off-not-read \
  Sources/GUI/App/SystemExtensionManager.swift \
  'if hasEmbeddedExtension { refreshFilterOffState() }' ''
mutate_and_expect_failure settings-on-keeps-old-rules \
  Sources/GUI/App/SystemExtensionManager.swift \
  $'turning it on in the app does.\n            state?.syncSharedRules()' 'turning it on in the app does.'
mutate_and_expect_failure settings-off-keeps-banner \
  Sources/GUI/App/SystemExtensionManager.swift \
  $'while it is off.\n            state?.clearFilterPersistenceFailure()' 'while it is off.'
mutate_and_expect_failure failed-enable-save-keeps-enable-in-memory \
  Sources/GUI/App/SystemExtensionManager.swift \
  'mgr.isEnabled = loadedEnabled' ''
mutate_and_expect_failure failed-enable-save-keeps-configuration-in-memory \
  Sources/GUI/App/SystemExtensionManager.swift \
  'mgr.providerConfiguration = loadedConfiguration' ''
mutate_and_expect_failure failed-enable-save-keeps-name-in-memory \
  Sources/GUI/App/SystemExtensionManager.swift \
  'mgr.localizedDescription = loadedDescription' ''
mutate_and_expect_failure stop-drops-record \
  Sources/NetExt/FilterDataProvider.swift \
  'watermarkQueue.sync {}' ''
mutate_and_expect_failure forget-live-policy \
  Sources/NetExt/FilterDataProvider.swift \
  'if decision == .accepted { recordLiveWatermark(accepted) }' ''

mutate_cycle_and_expect_harness_failure keep-retry-on-enable \
  $'cancel()\n            enableRequested = true' 'enableRequested = true'
mutate_cycle_and_expect_harness_failure keep-older-on-encode-failure \
  $'cancel()\n            queue.enqueue(SharedRuleBridge.bootSnapshotRemoval)' 'queue.enqueue(SharedRuleBridge.bootSnapshotRemoval)'
mutate_cycle_and_expect_harness_failure removal-clears-warning \
  $'retry.reset()\n                    result.removedSavedPolicy = true' $'retry.reset()\n                    result.removedSavedPolicy = true\n                    result.clearWarning = true'
mutate_cycle_and_expect_harness_failure rewrite-nothing-to-remove \
  'if removes && !hasSavedPolicy && !enable {' 'if false {'
mutate_cycle_and_expect_harness_failure extra-cycle-after-requeue \
  'queue.hasNewerWork(since: attempted)' 'queue.hasNewerWork(since: save.load.generation)'
mutate_cycle_and_expect_harness_failure cancelled-load-raises-warning \
  'if cancellations != load.cancellations {' 'if false {'
mutate_cycle_and_expect_harness_failure cancelled-save-raises-warning \
  'result.reportFailure = cancellations == save.load.cancellations' 'result.reportFailure = true'
mutate_cycle_and_expect_harness_failure no-load-retry \
  'return .loadFailed(failActivation: failActivation, next: nextRetry())' 'return .loadFailed(failActivation: failActivation, next: .none)'
mutate_cycle_and_expect_harness_failure save-after-cancel-during-load \
  'if !enable && pending == nil {' 'if false {'
mutate_cycle_and_expect_harness_failure create-missing-configuration \
  'if !enable && !configurationExists {' 'if false {'
mutate_cycle_and_expect_harness_failure enable-with-stale-snapshot \
  'if enable && !queue.hasPending {' 'if false {'
mutate_cycle_and_expect_harness_failure older-save-clears-warning \
  'if !queue.hasNewerWork(since: pending.generation) {' 'if true {'
mutate_cycle_and_expect_harness_failure drop-failed-activation-save \
  'if let pending = save.pending, queue.requeueFailed(pending) {' 'if !save.enable, let pending = save.pending, queue.requeueFailed(pending) {'
mutate_cycle_and_expect_harness_failure drop-failed-activation-load \
  $'let failActivation = enableRequested\n                enableRequested = false' $'let failActivation = enableRequested\n                if enableRequested { enableRequested = false; queue.discardThrough(generationAtLoad); return .loadFailed(failActivation: true, next: .none) }'
mutate_cycle_and_expect_harness_failure failed-activation-load-keeps-request \
  $'let failActivation = enableRequested\n                enableRequested = false' 'let failActivation = enableRequested'
mutate_cycle_and_expect_harness_failure failed-activation-save-unreported \
  'result.failActivation = save.enable' 'result.failActivation = false'
mutate_cycle_and_expect_harness_failure off-keeps-enable \
  $'public mutating func dropEnableRequest() {\n            enableRequested = false' 'public mutating func dropEnableRequest() {'
mutate_cycle_and_expect_harness_failure endless-retries \
  'guard let delay = retry.nextDelay() else { return .retriesUsedUp }' 'let delay = retry.nextDelay() ?? 120'

printf 'boot policy save failure verification: PASS\n'
