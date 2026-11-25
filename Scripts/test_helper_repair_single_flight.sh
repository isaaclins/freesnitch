#!/usr/bin/env bash
# Regression harness for overlapping Repair Helper attempts (issue #216).
#
# The repair guard checked a flag that nothing ever set, so a second click on
# Repair Helper while the first attempt was still prompting, registering or
# waiting for the helper started another registration or privileged kickstart.
# This compiles the real HelperRepairGate.swift, replays the clicks of each
# repair path, and checks that HelperClient and the banner use the gate.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-repair-gate.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/main.swift" <<'SWIFT'
import Foundation

var failures = 0
func expect(_ ok: Bool, _ what: String) {
    if ok { print("ok   \(what)") } else { print("FAIL \(what)"); failures += 1 }
}

// Mirrors HelperClient.repairHelperInternal: a click either starts an attempt
// (state goes to .inProgress) or does nothing.
var gate = HelperRepairGate()
var state = HelperRepairState.idle
var started = 0
func click() {
    guard gate.begin(state: state) else { return }
    started += 1
    state = .inProgress
}

// Kickstart path: two clicks before the authorization prompt is answered.
click(); click()
expect(started == 1, "a second click during the authorization prompt starts nothing")
expect(gate.isHeld, "polling stays paused while the prompt is open")
// The user cancels the prompt.
gate.release(); state = .idle
click()
expect(started == 2, "after a cancelled prompt Repair Helper works again")

// The kickstart succeeds; the gate is held through the 1.5 s settle delay.
click()
expect(started == 2, "a click during the post-kickstart settle delay starts nothing")
gate.release(); state = .idle

// Registration path: register() returned, the helper hasn't reconnected yet.
click()
gate.release()            // registerAbsentService releases to resume polling
expect(!gate.isHeld, "polling resumes while waiting for the registered helper")
click()
expect(started == 3, "a click while waiting for the registered helper to reconnect starts nothing")
// The confirmation timer gives up and asks for the manual step.
state = .manualRequired("run the kickstart command")
click()
expect(started == 4, "after a reported failure Repair Helper can be tried again")

// A failure on the privileged side releases the gate with the message.
gate.release(); state = .manualRequired("restart failed")
click()
expect(started == 5, "after a failed restart Repair Helper can be tried again")

exit(failures == 0 ? 0 : 1)
SWIFT

xcrun swiftc -o "$TMP/gate" "$ROOT/Sources/GUI/App/HelperRepairGate.swift" "$TMP/main.swift"
"$TMP/gate"

client="$ROOT/Sources/GUI/App/HelperClient.swift"
banner="$ROOT/Sources/GUI/Views/HelperBanner.swift"
card="$ROOT/Sources/GUI/Views/NoticeCard.swift"
fail() { echo "FAIL $1"; exit 1; }

grep -q 'guard !DemoMode.isOn, repairGate.begin(state: repairState) else { return }' "$client" \
  || fail "repairHelperInternal starts through the gate"
grep -q 'isRepairing' "$client" && fail "the old never-set isRepairing flag is gone"
grep -q 'guard let self, !self.repairGate.isHeld else { return }' "$client" \
  || fail "polling pauses while a repair holds the gate"
# Every repairState that ends an attempt releases the gate first.
grep -c 'repairGate.release()' "$client" | grep -qx 4 \
  || fail "the four exits of a repair attempt release the gate"
grep -q 'state.helper.repairHelper()' "$banner" || fail "the banner still offers Repair Helper"
[ "$(grep -c 'state.helper.repairHelper()' "$banner")" = 1 ] \
  || fail "every Repair Helper button goes through BannerAction.repair"
grep -q 'title: String(localized: "Repairing…"), isEnabled: false' "$banner" \
  || fail "a running repair shows a disabled Repairing… button"
grep -q 'actionEnabled: info.action?.isEnabled ?? true' "$banner" || fail "the banner passes the enabled state on"
grep -q '.disabled(!actionEnabled)' "$card" || fail "the notice card disables its button"
echo "ok   source checks"
