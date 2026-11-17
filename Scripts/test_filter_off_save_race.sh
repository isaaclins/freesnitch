#!/usr/bin/env bash
# Replays #309: the user turns the filter off while a boot-policy save cycle
# that was started to turn it on is loading or saving the shared
# NEFilterManager preferences.
#
# NEFilterManager needs the app's entitlement, so the harness stands in a fake
# with the same shape: one shared object, an asynchronous load that copies the
# stored preferences into it, and an asynchronous save that stores it. Every
# callback is delivered by hand, in the order the issue describes, so nothing
# depends on timing. The sequences run through the real FilterPreferencesLine.
# The audit checks that the app routes every NEFilterManager writer through
# that line, and each part of the fix is taken out once to prove it is caught.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-filter-off.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

compile_harness() {
  local dir="$TMP/harness"
  mkdir -p "$dir"
  cat > "$dir/main.swift" <<'SWIFT'
import Foundation

func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else {
        FileHandle.standardError.write(Data(("filter off harness: FAIL: " + message + "\n").utf8))
        exit(1)
    }
}

/// The shape of NEFilterManager.shared(): one object, callbacks later.
final class FakeFilterManager {
    var storedEnabled = false
    var isEnabled = false
    var callbacks: [(String, () -> Void)] = []
    func loadFromPreferences(_ name: String, _ done: @escaping () -> Void) {
        callbacks.append(("\(name) load", { self.isEnabled = self.storedEnabled; done() }))
    }
    func saveToPreferences(_ name: String, _ done: @escaping () -> Void) {
        let value = isEnabled // the object is written as it is at the call
        callbacks.append(("\(name) save", { self.storedEnabled = value; done() }))
    }
    /// Delivers the waiting callback with this label.
    func deliver(_ name: String) {
        guard let index = callbacks.firstIndex(where: { $0.0 == name }) else {
            expect(false, "no \(name) callback is waiting (have: \(callbacks.map(\.0)))")
            return
        }
        callbacks.remove(at: index).1()
    }
    func deliverAll() { while !callbacks.isEmpty { callbacks.removeFirst().1() } }
}

/// The save cycle the app starts for "turn on with the helper's policy".
func enablingSave(_ mgr: FakeFilterManager, done: @escaping () -> Void) {
    mgr.loadFromPreferences("save") {
        mgr.isEnabled = true
        mgr.saveToPreferences("save") { done() }
    }
}

/// What disableFilter does.
func turnOff(_ mgr: FakeFilterManager, done: @escaping () -> Void) {
    mgr.loadFromPreferences("off") {
        mgr.isEnabled = false
        mgr.saveToPreferences("off") { done() }
    }
}

// 1. Without the line: the save cycle has loaded and set isEnabled = true;
//    the off loads and saves; the cycle's own save lands last. That is the
//    interleaving #309 describes, and the filter ends up on.
do {
    let racing = FakeFilterManager()
    enablingSave(racing) {}
    turnOff(racing) {}
    racing.deliver("off load")
    racing.deliver("save load")
    racing.deliver("off save")
    racing.deliver("save save")
    expect(racing.storedEnabled, "the unserialized race did not reproduce, so this test proves nothing")
    print("filter off harness: without serialization the save turns the filter back on (reproduced)")
}

// 2. With the line, the same requests in the same order: the off waits for
//    the save cycle and is saved last.
do {
    let mgr = FakeFilterManager()
    let line = FilterPreferencesLine()
    line.run { done in enablingSave(mgr, done: done) }
    line.run { done in turnOff(mgr, done: done) }
    expect(mgr.callbacks.map(\.0) == ["save load"], "the off started while the save cycle was still loading")
    mgr.deliver("save load")
    expect(mgr.callbacks.map(\.0) == ["save save"], "the off started while the save cycle was saving")
    mgr.deliverAll()
    expect(!mgr.storedEnabled, "the filter is on after the user turned it off last")
    expect(!line.isBusy, "the line is still busy after both sequences finished")
    print("filter off harness: turning off during a save cycle ends with the filter off")
}

// 3. The off is asked for first and a save cycle after it: the cycle loads
//    what the off saved, so it never sees a stale enabled state.
do {
    let mgr = FakeFilterManager()
    mgr.storedEnabled = true
    let line = FilterPreferencesLine()
    var seenByCycle: Bool?
    line.run { done in turnOff(mgr, done: done) }
    line.run { done in
        mgr.loadFromPreferences("plain") {
            seenByCycle = mgr.isEnabled
            mgr.saveToPreferences("plain") { done() }
        }
    }
    mgr.deliverAll()
    expect(seenByCycle == false, "a later save cycle loaded before the off was saved")
    expect(!mgr.storedEnabled, "a plain policy save after the off turned the filter on")
    print("filter off harness: a save asked for after the off loads the off")
}

// 4. #318: what the enabling save's completion reports. The app's counter
//    and the real FilterSaveCompletion, driven through the same callbacks.
do {
    struct App { var turnOffs = 0; var enableRequested = false; var reported: [FilterSaveCompletion] = [] }
    func run(_ name: String, saveFails: Bool = false, between: (inout App, FakeFilterManager, FilterPreferencesLine) -> Void,
             expected: [FilterSaveCompletion], storedEnabled: Bool) {
        let mgr = FakeFilterManager()
        let line = FilterPreferencesLine()
        var app = App()
        app.enableRequested = true
        line.run { done in
            let atLoad = app.turnOffs
            let enabling = app.enableRequested
            app.enableRequested = false
            mgr.loadFromPreferences("save") {
                mgr.isEnabled = true
                mgr.saveToPreferences("save") {
                    done()
                    app.reported.append(FilterSaveCompletion.decide(
                        enabling: enabling, turnOffsAtLoad: atLoad, turnOffsNow: app.turnOffs,
                        enableRequestedNow: app.enableRequested, saveFailed: saveFails))
                }
            }
        }
        between(&app, mgr, line)
        mgr.deliverAll()
        expect(app.reported == expected, "\(name): reported \(app.reported), expected \(expected)")
        expect(mgr.storedEnabled == storedEnabled, "\(name): stored isEnabled \(mgr.storedEnabled)")
    }
    let turnOff: (inout App, FakeFilterManager, FilterPreferencesLine) -> Void = { app, mgr, line in
        app.turnOffs &+= 1   // disableFilter / removeFilterConfiguration
        app.enableRequested = false
        line.run { done in turnOff(mgr, done: done) }
    }
    run("nothing overtakes", between: { _, _, _ in }, expected: [.active], storedEnabled: true)
    run("save fails", saveFails: true, between: { _, _, _ in }, expected: [.failed], storedEnabled: true)
    run("off while loading", between: turnOff, expected: [.stayedOff], storedEnabled: false)
    run("off while saving", between: { app, mgr, line in
        mgr.deliver("save load")
        turnOff(&app, mgr, line)
    }, expected: [.stayedOff], storedEnabled: false)
    run("off, then the save fails", saveFails: true, between: turnOff, expected: [.stayedOff], storedEnabled: false)
    run("off then on again", between: { app, mgr, line in
        turnOff(&app, mgr, line)
        app.enableRequested = true // enableFilter: the next cycle reports
    }, expected: [.awaitReenable], storedEnabled: false)
    expect(FilterSaveCompletion.decide(enabling: false, turnOffsAtLoad: 0, turnOffsNow: 1,
                                       enableRequestedNow: false, saveFailed: false) == .none,
           "a plain policy save reported something about the filter")
    print("filter off harness: an enabling save overtaken by a turn-off reports the filter off, not active")
}

// 5. #361: the filter is turned on in System Settings, the app turns it on
//    with the current rules, and the user turns it off or removes it there
//    again before that save cycle loads. The real save cycle and the real
//    turn-on rule, driven through the fake manager.
do {
    typealias Cycle = SharedRuleBridge.BootPolicySaveCycle
    struct Outcome { var decision: Cycle.AfterLoad; var storedEnabled: Bool; var storedConfigured: Bool }
    /// What System Settings holds besides isEnabled.
    final class Settings { var configured = true }
    func run(fromSettings: Bool, guarded: Bool = true,
             userAction: (FakeFilterManager, Settings) -> Void) -> Outcome {
        let mgr = FakeFilterManager()
        mgr.storedEnabled = true            // turned on in System Settings
        let settings = Settings()
        var cycle = Cycle()
        cycle.requestEnable()               // enableFilter(fromSettings:)
        cycle.enqueue(Data("rules".utf8))   // the helper's current rules
        guard let load = cycle.begin() else { expect(false, "no cycle started"); exit(1) }
        var decision: Cycle.AfterLoad?
        mgr.loadFromPreferences("save") {
            let configured = settings.configured
            if guarded && cycle.enableRequested
                && !FilterOffState.turnOnStands(fromSettings: fromSettings, configured: configured,
                                                enabled: mgr.isEnabled) {
                cycle.dropEnableRequest()
            }
            let decided = cycle.afterLoad(load, loadFailed: false, configurationExists: configured,
                                          hasSavedPolicy: configured)
            decision = decided
            guard case .save(let save) = decided else { return }
            if save.enable { mgr.isEnabled = true }
            settings.configured = true      // saving writes the configuration
            mgr.saveToPreferences("save") {}
        }
        userAction(mgr, settings)           // before the cycle's load lands
        mgr.deliverAll()
        return Outcome(decision: decision!, storedEnabled: mgr.storedEnabled,
                       storedConfigured: settings.configured)
    }
    let turnOffThere: (FakeFilterManager, Settings) -> Void = { mgr, _ in mgr.storedEnabled = false }
    let removeThere: (FakeFilterManager, Settings) -> Void = { mgr, settings in
        mgr.storedEnabled = false
        settings.configured = false
    }

    // Without the rule the bug reproduces: the save turns it back on.
    let unguarded = run(fromSettings: true, guarded: false, userAction: turnOffThere)
    expect(unguarded.storedEnabled, "the off-again race did not reproduce, so this test proves nothing")

    let off = run(fromSettings: true, userAction: turnOffThere)
    expect(!off.storedEnabled, "turned off again in System Settings, the app's save turned the filter back on")
    if case .save(let save) = off.decision {
        expect(!save.enable, "the cycle still counts as turning the filter on")
    } else { expect(false, "the current rules were not saved for the next turn-on: \(off.decision)") }

    let removed = run(fromSettings: true, userAction: removeThere)
    expect(removed.decision == .stop(.noConfiguration), "removed in System Settings, the cycle went on: \(removed.decision)")
    expect(!removed.storedConfigured && !removed.storedEnabled, "a filter removed in System Settings was recreated")

    let stays = run(fromSettings: true, userAction: { _, _ in })
    expect(stays.storedEnabled, "a turn-on in System Settings that nobody undid was dropped")
    if case .save(let save) = stays.decision { expect(save.enable, "the turn-on save does not report active") }
    else { expect(false, "the turn-on did not save: \(stays.decision)") }

    // Activation at launch turns the filter on even if it was off.
    let activation = run(fromSettings: false, userAction: turnOffThere)
    expect(activation.storedEnabled, "activation no longer turns the filter on")
    print("filter off harness: turned on and off again in System Settings, what is set there wins")
}

// 6. #382: the filter is turned on in System Settings, so the app asks the
//    helper for the current rules to turn it on. The user turns it off (or
//    removes it) there again before the helper answers, and the helper then
//    gives no rules. The app reads System Settings only after giving up, as
//    the change notice is skipped while a turn-on is pending. The real save
//    cycle and the real off-state rules, step by step.
do {
    typealias Cycle = SharedRuleBridge.BootPolicySaveCycle
    enum Shown: Equatable { case notFiltering, failed }
    func run(_ name: String, guarded: Bool = true, readFails: Bool = false,
             userAction: (FakeFilterManager, inout Bool) -> Void) -> Shown {
        let mgr = FakeFilterManager()
        var configured = true
        var off = FilterOffState()
        var cycle = Cycle()
        // Shown as not filtering: off in System Settings.
        _ = off.observed(configured: true, enabled: false, fromOutside: true)
        // Turned on there: the change notice asks for the current rules.
        mgr.storedEnabled = true
        let change = off.observed(configured: true, enabled: true, fromOutside: true)
        expect(change == .saveCurrentRules, "\(name): turning it on in System Settings did not start a turn-on")
        cycle.requestEnable()
        off.turnedOn()
        // Turned off there again: the notice is skipped while the turn-on is pending.
        userAction(mgr, &configured)
        expect(cycle.enableRequested, "\(name): the turn-on was dropped before the helper answered")
        // The helper gives no rules.
        expect(cycle.abandonEnableIfIdle(), "\(name): no rules did not give up the turn-on")
        // Before #382 the app reported a failed turn-on right here, without
        // reading System Settings again, even though the off-state still
        // counts the filter as on.
        guard guarded else {
            expect(!off.isOff, "\(name): the app already knew the filter was off")
            return .failed
        }
        var shown: Shown?
        mgr.loadFromPreferences("read") {
            if FilterOffState.abandonedTurnOnFailed(fromSettings: true, readFailed: readFails,
                                                     configured: configured, enabled: mgr.isEnabled) {
                shown = .failed
                return
            }
            expect(off.observed(configured: configured, enabled: mgr.isEnabled, fromOutside: true) == .clearBanner,
                   "\(name): the filter off in System Settings did not count as off")
            shown = .notFiltering
        }
        mgr.deliverAll()
        expect(!off.isOff || shown == .notFiltering, "\(name): off but not shown as not filtering")
        return shown!
    }
    let turnOffThere: (FakeFilterManager, inout Bool) -> Void = { mgr, _ in mgr.storedEnabled = false }
    let removeThere: (FakeFilterManager, inout Bool) -> Void = { mgr, configured in
        mgr.storedEnabled = false
        configured = false
    }
    let leaveOn: (FakeFilterManager, inout Bool) -> Void = { _, _ in }

    // Without the read the app can't know: it still counts the filter as on.
    expect(run("unguarded", guarded: false, userAction: turnOffThere) == .failed,
           "the failed turn-on did not reproduce, so this test proves nothing")
    expect(run("off again", userAction: turnOffThere) == .notFiltering,
           "turned off again in System Settings, the app said the turn-on failed")
    expect(run("removed", userAction: removeThere) == .notFiltering,
           "removed in System Settings, the app said the turn-on failed")
    expect(run("still on", userAction: leaveOn) == .failed,
           "still on in System Settings with no rules, the app did not say the turn-on failed")
    expect(run("read fails", readFails: true, userAction: turnOffThere) == .failed,
           "a failed read of System Settings hid the failed turn-on")
    expect(FilterOffState.abandonedTurnOnFailed(fromSettings: false, readFailed: false, configured: false, enabled: false),
           "a turn-on by activation that got no rules no longer counts as failed")
    print("filter off harness: turned on and off again in System Settings with no rules, the app says not filtering")
}

// 7. A sequence that finishes with an error still lets the next one run, and
//    calling done twice does not skip anyone.
do {
    let line = FilterPreferencesLine()
    var order: [Int] = []
    var firstDone: (() -> Void)?
    line.run { done in order.append(1); firstDone = done }
    line.run { done in order.append(2); done() }
    line.run { done in order.append(3); done() }
    expect(order == [1], "a queued sequence ran before the first finished")
    firstDone?()
    firstDone?()
    expect(order == [1, 2, 3], "the queue stalled or ran out of order: \(order)")
    expect(!line.isBusy, "the line is busy with nothing left to run")
    print("filter off harness: sequences run one at a time, in order, and never stall")
}
SWIFT
  swiftc "$ROOT"/Sources/Shared/*.swift "$dir/main.swift" -lsqlite3 -o "$dir/harness"
  "$dir/harness"
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
path.write_text(text.replace(sys.argv[2], sys.argv[3], 1))
PY
  if bash "$tree/Scripts/audit_firewall_safety.sh" >/dev/null 2>&1; then
    printf 'filter off audit: FAIL: mutation %s was not caught\n' "$label" >&2
    exit 1
  fi
  printf 'filter off audit: mutation %s caught\n' "$label"
}

compile_harness
bash "$ROOT/Scripts/audit_firewall_safety.sh" >/dev/null
printf 'filter off audit: passed on the real tree\n'

SEM=Sources/GUI/App/SystemExtensionManager.swift
mutate_and_expect_failure disable-unserialized "$SEM" \
  $'        // then sees what it wrote and the off is saved last (#309).\n        filterPreferences.run { [weak self] done in' \
  $'        // then sees what it wrote and the off is saved last (#309).\n        do { let done = {}'
mutate_and_expect_failure save-cycle-unserialized "$SEM" \
  'filterPreferences.run { [weak self] done in
            guard let self else { done(); return }
            self.persistenceCycleDone = done' \
  'do { let done = {}
            self.persistenceCycleDone = done'
mutate_and_expect_failure disable-keeps-enable-request "$SEM" \
  $'cancelPendingPersistence()\n        // Turning the filter on and then off before the helper answered must\n        // not let that answer turn it back on.\n        persistenceCycle.dropEnableRequest()' \
  'cancelPendingPersistence()'
mutate_and_expect_failure restart-reenables-off-filter "$SEM" \
  'guard mgr.isEnabled else {' 'guard true else {'
mutate_and_expect_failure writer-outside-line "$SEM" \
  '    private func recordFilterDiagnostic(state: String, detail: String) {' \
  $'    private func sneakyEnable() { NEFilterManager.shared().isEnabled = true }\n\n    private func recordFilterDiagnostic(state: String, detail: String) {'
mutate_and_expect_failure restart-run-directly "$SEM" \
  'restartFilterProvider()
        }' \
  'runFilterRestart(done: {})
        }'
mutate_and_expect_failure remove-unserialized "$SEM" \
  $'        persistenceCycle.dropEnableRequest()\n        filterPreferences.run { [weak self] done in' \
  $'        persistenceCycle.dropEnableRequest()\n        do { let done = {}'

mutate_and_expect_failure overtaken-enable-reports-active "$SEM" \
  'if completion == .active {
                                self.filterConfigurationActive = true' \
  'if shouldEnable {
                                self.filterConfigurationActive = true'
mutate_and_expect_failure overtaken-not-checked "$SEM" \
  'turnOffsNow: self.filterTurnOffs,' 'turnOffsNow: turnOffsAtLoad,'
mutate_and_expect_failure overtaken-status-kept "$SEM" \
  'if completion == .stayedOff {' 'if false {'
mutate_and_expect_failure disable-not-counted "$SEM" \
  $'        persistenceCycle.dropEnableRequest()\n        filterTurnOffs &+= 1\n        // A save cycle' \
  $'        persistenceCycle.dropEnableRequest()\n        // A save cycle'
mutate_and_expect_failure remove-not-counted "$SEM" \
  $'        cancelPendingPersistence()\n        filterTurnOffs &+= 1\n        persistenceCycle.dropEnableRequest()\n        filterPreferences.run' \
  $'        cancelPendingPersistence()\n        persistenceCycle.dropEnableRequest()\n        filterPreferences.run'
mutate_and_expect_failure removal-keeps-active-status "$SEM" \
  $'no longer applies (#311).\n                                self.state?.clearFilterPersistenceFailure()\n                                // A turn-on asked for meanwhile waits behind this\n                                // and decides the state, not this late answer.\n                                if self.filterOff.turnedOff(turnOnPending: self.persistenceCycle.enableRequested) {\n                                    self.showNotFiltering()\n                                }' \
  $'no longer applies (#311).\n                                self.state?.clearFilterPersistenceFailure()\n                                // A turn-on asked for meanwhile waits behind this\n                                // and decides the state, not this late answer.\n                                self.filterOff.turnedOff(turnOnPending: self.persistenceCycle.enableRequested)'
mutate_and_expect_failure disable-keeps-active-status "$SEM" \
  $'these rules; turning it on saves the current ones again.\n                                self.state?.clearFilterPersistenceFailure()\n                                // A turn-on asked for meanwhile waits behind this\n                                // and decides the state, not this late answer.\n                                if self.filterOff.turnedOff(turnOnPending: self.persistenceCycle.enableRequested) {\n                                    self.showNotFiltering()\n                                }' \
  $'these rules; turning it on saves the current ones again.\n                                self.state?.clearFilterPersistenceFailure()\n                                // A turn-on asked for meanwhile waits behind this\n                                // and decides the state, not this late answer.\n                                self.filterOff.turnedOff(turnOnPending: self.persistenceCycle.enableRequested)'
mutate_and_expect_failure not-filtering-keeps-status "$SEM" \
  'if status != .unsupported { status = .idle }' ''
mutate_and_expect_failure outside-off-keeps-active-status "$SEM" \
  'if filterConfigurationActive && !persistenceCycle.enableRequested {
                showNotFiltering()
            }' ''
mutate_and_expect_failure outside-off-hides-approval "$SEM" \
  'if filterConfigurationActive && !persistenceCycle.enableRequested {' 'if true {'
mutate_and_expect_failure outside-on-stays-not-filtering "$SEM" \
  $'            if hasEmbeddedExtension && status != .needsApproval && status != .activating {\n                enableFilter(fromSettings: true)' \
  $'            if hasEmbeddedExtension {\n                state?.syncSharedRules()'
mutate_and_expect_failure outside-on-skips-rules "$SEM" \
  $'            } else {\n                state?.syncSharedRules()\n            }' \
  $'            } else {\n            }'
mutate_and_expect_failure outside-removal-keeps-active-status "$SEM" \
  'if self.filterConfigurationActive && !self.persistenceCycle.enableRequested { self.showNotFiltering() }' ''
mutate_and_expect_failure settings-turn-on-overrides-off "$SEM" \
  $'                    self.persistenceCycle.dropEnableRequest()\n                }\n                let decision' \
  $'                }\n                let decision'
mutate_and_expect_failure settings-turn-on-not-checked "$SEM" \
  'fromSettings: self.turnOnFromSettings,' 'fromSettings: false,'
mutate_and_expect_failure settings-turn-on-skips-approval "$SEM" \
  'if hasEmbeddedExtension && status != .needsApproval && status != .activating {' 'if hasEmbeddedExtension {'
mutate_and_expect_failure settings-turn-on-not-marked "$SEM" \
  'enableFilter(fromSettings: true)' 'enableFilter()'
mutate_and_expect_failure abandoned-settings-turn-on-fails "$SEM" \
  'if turnOnFromSettings {
                reportAbandonedSettingsTurnOn(message)' \
  'if false {
                reportAbandonedSettingsTurnOn(message)'
mutate_and_expect_failure abandoned-settings-read-failure-hidden "$SEM" \
  'readFailed: error != nil,' 'readFailed: false,'
mutate_and_expect_failure abandoned-settings-keeps-status "$SEM" \
  $'else { return }\n                    self.showNotFiltering()' \
  $'else { return }'
mutate_and_expect_failure abandoned-settings-hides-approval "$SEM" \
  'guard self.status != .needsApproval && self.status != .activating else { return }
                    self.showNotFiltering()' \
  'self.showNotFiltering()'
mutate_and_expect_failure abandoned-settings-overrides-newer-turn-on "$SEM" \
  $'                    // A newer turn-on reports the state itself.\n                    guard !self.persistenceCycle.enableRequested else { return }\n' \
  $'                    // A newer turn-on reports the state itself.\n'
mutate_and_expect_failure abandoned-settings-read-unserialized "$SEM" \
  $'        turnOnFromSettings = false\n        filterPreferences.run { [weak self] done in' \
  $'        turnOnFromSettings = false\n        do { let done = {}'
printf 'filter off vs boot-policy save verification: PASS\n'
