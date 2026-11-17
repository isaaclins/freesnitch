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

// 4. A sequence that finishes with an error still lets the next one run, and
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
  $'        filterPreferences.run { done in\n            let mgr = NEFilterManager.shared()\n            mgr.loadFromPreferences { [weak self] error in\n                DispatchQueue.main.async {\n                    guard let self else { done(); return }\n                    guard error == nil' \
  $'        do { let done = {}\n            let mgr = NEFilterManager.shared()\n            mgr.loadFromPreferences { [weak self] error in\n                DispatchQueue.main.async {\n                    guard let self else { done(); return }\n                    guard error == nil'
mutate_and_expect_failure save-cycle-unserialized "$SEM" \
  'filterPreferences.run { [weak self] done in
            guard let self else { done(); return }
            self.persistenceCycleDone = done' \
  'do { let done = {}
            self.persistenceCycleDone = done'
mutate_and_expect_failure disable-keeps-enable-request "$SEM" \
  $'cancelPendingPersistence()\n        // Turning the filter on and then off before the helper answered must\n        // not let that answer turn it back on.\n        enableFilterRequested = false' \
  'cancelPendingPersistence()'
mutate_and_expect_failure restart-reenables-off-filter "$SEM" \
  'guard mgr.isEnabled else {' 'guard true else {'
mutate_and_expect_failure remove-unserialized "$SEM" \
  $'        enableFilterRequested = false\n        filterPreferences.run { done in' \
  $'        enableFilterRequested = false\n        do { let done = {}'

printf 'filter off vs boot-policy save verification: PASS\n'
