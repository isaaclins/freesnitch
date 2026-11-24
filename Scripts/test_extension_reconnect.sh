#!/usr/bin/env bash
# The app must connect to the network extension again after the link drops
# (#212).
#
# Restarting the filter to clear a rejected snapshot (#70) can replace the
# extension process. The app only registered its connection on the first
# turn-on, so after such a restart rule changes never reached the extension
# and alerts never appeared until the app was relaunched. This checks the
# retry policy from the real source, and the wiring in the real sources:
# the restart registers again, a dropped link is reported and acted on, and a
# stale answer can't undo a newer link. Each wiring check is also run against
# a copy with the fix taken out, so a check that can no longer fail is caught.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-reconnect.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# 1. The retry policy, compiled from the production source.
cat > "$TMP/main.swift" <<'SWIFT'
import Foundation

func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else {
        FileHandle.standardError.write(Data(("extension reconnect harness: FAIL: " + message + "\n").utf8))
        exit(1)
    }
}

// The filter restart replaced the extension process; the new one is not
// listening yet for the first few attempts.
var reconnect = ExtensionReconnect()
expect(reconnect.linkLost() == .retry(after: ExtensionReconnect.delays[0]), "a lost link was not retried")
// The interruption and the failed registration both report the same loss.
expect(reconnect.linkLost() == .alreadyScheduled, "one loss scheduled two attempts")
reconnect.attemptStarted()
expect(reconnect.linkLost() == .retry(after: ExtensionReconnect.delays[1]), "a failed attempt was not retried")
reconnect.attemptStarted()
reconnect.policyDelivered()
expect(reconnect.attempts == 0, "a link that delivered the rules again did not return the budget")
expect(reconnect.linkLost() == .retry(after: ExtensionReconnect.delays[0]),
       "a later drop did not start again from the shortest wait")
print("extension reconnect harness: a dropped link is retried until the extension takes it")

// An extension that never takes the connection: bounded, spaced, and said once.
var stuck = ExtensionReconnect()
var waited: TimeInterval = 0
var previous: TimeInterval = 0
for attempt in 0..<ExtensionReconnect.delays.count {
    guard case .retry(let delay) = stuck.linkLost() else {
        expect(false, "attempt \(attempt + 1) was not scheduled")
        break
    }
    expect(delay >= previous, "the wait got shorter between attempts")
    previous = delay
    waited += delay
    stuck.attemptStarted()
}
expect(stuck.linkLost() == .exhausted, "reconnect attempts are not bounded")
expect(stuck.hasGivenUp, "a used-up budget is not reported as given up")
expect(stuck.linkLost() == .gaveUp, "giving up was reported more than once")
expect(waited >= 60 && waited <= 180, "the attempts cover \(waited) s, not a provider that takes a while to start")
stuck.reset()
expect(stuck.linkLost() == .retry(after: ExtensionReconnect.delays[0]),
       "turning the filter on again did not allow new attempts")
// An extension that takes the registration and drops it again before any
// rules arrive must not be reconnected forever.
var flapping = ExtensionReconnect()
var flaps = 0
while case .retry = flapping.linkLost() {
    flapping.attemptStarted()  // registered, accepted, and dropped again
    flaps += 1
    expect(flaps <= ExtensionReconnect.delays.count, "an accept-then-drop extension is reconnected without end")
}
print("extension reconnect harness: an extension that keeps dropping the link is given up on after \(flaps) attempts")
print("extension reconnect harness: attempts are bounded and spaced (\(Int(waited)) s in all)")

// A reset drops an attempt that was still scheduled, so the next loss is
// not swallowed as already scheduled.
var turnedOff = ExtensionReconnect()
_ = turnedOff.linkLost()
turnedOff.reset()
expect(!turnedOff.scheduled, "a reset left an attempt marked as scheduled")
expect(turnedOff.linkLost() == .retry(after: ExtensionReconnect.delays[0]),
       "a loss after a reset was ignored")
print("extension reconnect harness: a reset never leaves a loss unanswered")
SWIFT
swiftc -O -o "$TMP/harness" "$ROOT/Sources/Shared/ExtensionReconnect.swift" "$TMP/main.swift"
"$TMP/harness"

# 2. The wiring, read from the sources.
function_body() {
  awk -v start="$2" '
    index($0, start) > 0 && !seen { seen = 1; active = 1; depth = 0; opened = 0 }
    active {
      print
      opens = gsub(/\{/, "{"); closes = gsub(/\}/, "}")
      if (opens > 0) opened = 1
      depth += opens - closes
      if (opened && depth == 0) exit
    }
  ' "$1"
}

check_wiring() {
  local root="$1"
  local sem="$root/Sources/GUI/App/SystemExtensionManager.swift"
  local ipc="$root/Sources/Shared/IPCConnection.swift"
  local restart register lost show
  restart="$(function_body "$sem" 'private func runFilterRestart(')"
  register="$(function_body "$ipc" 'public func register(')"
  lost="$(function_body "$sem" 'private func extensionLinkLost(')"
  show="$(function_body "$sem" 'private func showNotFiltering(')"
  local reg_app record
  reg_app="$(function_body "$sem" 'private func registerIPC(')"
  record="$(function_body "$sem" 'private func recordSnapshotStatus(')"

  # The restart registers again, since the old link may reach a process that
  # is gone. Resending the rules alone went over the dead link.
  grep -Fq 'self.registerIPC()' <<<"$restart" || { echo "the filter restart does not register with the extension again"; return 1; }
  # Both ways the app-side link ends are reported.
  [[ "$(grep -c 'onAppConnectionLost?()' <<<"$register")" -ge 2 ]] \
    || { echo "a dropped or invalidated link is not reported to the app"; return 1; }
  grep -Fq 'clearCurrentConnection(newConnection) == true' <<<"$register" \
    || { echo "a replaced connection reports a lost link"; return 1; }
  grep -Fq 'previous?.invalidate()' <<<"$register" \
    || { echo "registering again leaves the old connection open"; return 1; }
  # The app acts on it while the filter is on.
  grep -Fq 'IPCConnection.shared.onAppConnectionLost = {' "$sem" \
    || { echo "the app does not listen for a dropped link"; return 1; }
  grep -Fq 'self?.extensionLinkLost()' "$sem" \
    || { echo "a dropped link does not lead to a new registration"; return 1; }
  grep -Fq 'self.registerIPC()' <<<"$lost" || { echo "a lost link is never registered again"; return 1; }
  grep -Fq 'filterConfigurationActive' <<<"$lost" || { echo "reconnecting does not stop when the filter is off"; return 1; }
  # A failed registration retries, and a stale answer is ignored.
  grep -Fq 'self.extensionLinkLost()' <<<"$reg_app" || { echo "a failed registration is not retried"; return 1; }
  grep -Fq 'registration == self.ipcRegistration' <<<"$reg_app" \
    || { echo "a stale registration answer can overwrite a newer link"; return 1; }
  # The budget comes back only once the extension accepted the rules.
  # A new extension can answer "ready" at registration from its saved boot
  # rules, so only the answer to rules the app sent may return the budget.
  # Otherwise an extension that drops the link once live rules arrive is
  # reconnected forever.
  local healthy
  healthy="$(awk '/if delivered \{/{f=1} f{print} f&&/^            \}/{exit}' <<<"$record")"
  grep -Fq 'ipcReconnect.policyDelivered()' <<<"$healthy" \
    || { echo "the reconnect budget comes back without rules having been delivered, or never"; return 1; }
  # The same goes for the #70 restart limit: a "ready" from saved boot rules
  # after a restart must not hand it back, or a refusal the restart can't
  # clear restarts the filter without end.
  grep -Fq 'snapshotRecovery.noteHealthy()' <<<"$healthy" \
    || { echo "the filter restart limit comes back without rules having been delivered"; return 1; }
  [[ "$(grep -c 'noteHealthy()' "$sem")" -eq 1 ]] \
    || { echo "the filter restart limit is handed back somewhere other than after delivered rules"; return 1; }
  # Once the attempts are used up, it says so where the user sees it, and
  # sending the rules again starts a new round instead of failing.
  grep -Fq 'state?.recordFilterRecovery(String(localized: "FreeSnitch lost its connection' <<<"$lost" \
    || { echo "giving up on the extension is not shown in the banner"; return 1; }
  grep -Fq 'if delivered, ipcReconnect.hasGivenUp, filterConfigurationActive,' <<<"$record" \
    || { echo "sending the rules again after giving up does not reconnect"; return 1; }
  [[ "$(grep -c 'policyDelivered()' "$sem")" -eq 1 ]] \
    || { echo "the reconnect budget is returned somewhere other than after delivered rules"; return 1; }
  grep -Fq 'self.recordSnapshotStatus(remoteStatus, delivered: false)' <<<"$reg_app" \
    || { echo "a registration answer counts as delivered rules, so an accept-then-drop extension is reconnected forever"; return 1; }
  grep -Fq 'self?.recordSnapshotStatus(snapshotStatus, delivered: true)' "$sem" \
    || { echo "the answer to delivered rules does not return the reconnect budget"; return 1; }
  # An interrupted connection is closed, not left open.
  grep -Fq 'newConnection?.invalidate()' <<<"$register" \
    || { echo "an interrupted connection is left open"; return 1; }
  # Turning the filter off stops the attempts.
  grep -Fq 'ipcReconnect.reset()' <<<"$show" || { echo "turning the filter off leaves reconnect attempts running"; return 1; }
  return 0
}

check_wiring "$ROOT" || { echo "extension reconnect: FAIL"; exit 1; }
echo "extension reconnect: wiring present in the sources"

mutate_and_expect_failure() {
  local name="$1" file="$2" from="$3" to="$4"
  local copy="$TMP/mut-$name"
  mkdir -p "$copy/Sources/GUI/App" "$copy/Sources/Shared"
  cp "$ROOT/Sources/GUI/App/SystemExtensionManager.swift" "$copy/Sources/GUI/App/"
  cp "$ROOT/Sources/Shared/IPCConnection.swift" "$copy/Sources/Shared/"
  python3 - "$copy/$file" "$from" "$to" <<'PY'
import sys
path, old, new = sys.argv[1:]
text = open(path).read()
if old not in text:
    sys.exit("mutation text not found: " + old)
open(path, "w").write(text.replace(old, new, 1))
PY
  if check_wiring "$copy" >/dev/null; then
    echo "extension reconnect: FAIL: the checks pass with '$name' taken out"
    exit 1
  fi
  echo "extension reconnect: '$name' taken out is caught"
}

mutate_and_expect_failure restart-only-resends Sources/GUI/App/SystemExtensionManager.swift \
  $'                                // authoritative path.\n                                self.ipcReconnect.reset()\n                                self.registerIPC()' \
  $'                                // authoritative path.\n                                self.state?.syncSharedRules()'
mutate_and_expect_failure interruption-silent Sources/Shared/IPCConnection.swift \
  $'            // is closed; its invalidation no longer counts as a second loss.\n            if self?.clearCurrentConnection(newConnection) == true { self?.onAppConnectionLost?() }' \
  '            self?.clearCurrentConnection(newConnection)'
mutate_and_expect_failure old-connection-kept Sources/Shared/IPCConnection.swift \
  'previous?.invalidate()' '_ = previous'
mutate_and_expect_failure no-listener Sources/GUI/App/SystemExtensionManager.swift \
  'IPCConnection.shared.onAppConnectionLost = {' 'let _unused: () -> Void = {'
mutate_and_expect_failure failure-not-retried Sources/GUI/App/SystemExtensionManager.swift \
  $'                } else {\n                    self.extensionLinkLost()\n                }' '                }'
mutate_and_expect_failure stale-answer-wins Sources/GUI/App/SystemExtensionManager.swift \
  $'guard let self, registration == self.ipcRegistration else { return }\n                if ok {' \
  $'guard let self else { return }\n                if ok {'
mutate_and_expect_failure budget-never-returned Sources/GUI/App/SystemExtensionManager.swift \
  '                ipcReconnect.policyDelivered()' ''
mutate_and_expect_failure healthy-on-any-ready Sources/GUI/App/SystemExtensionManager.swift \
  $'        if snapshotStatus.isReady {\n' $'        if snapshotStatus.isReady {\n            snapshotRecovery.noteHealthy()\n'
mutate_and_expect_failure restart-limit-never-returned Sources/GUI/App/SystemExtensionManager.swift \
  '                snapshotRecovery.noteHealthy()' ''
mutate_and_expect_failure give-up-only-logged Sources/GUI/App/SystemExtensionManager.swift \
  'state?.recordFilterRecovery(String(localized: "FreeSnitch lost its connection' 'state?.appendLog(level: "error", message: String(localized: "FreeSnitch lost its connection'
mutate_and_expect_failure resend-after-give-up-fails Sources/GUI/App/SystemExtensionManager.swift \
  'if delivered, ipcReconnect.hasGivenUp, filterConfigurationActive,' 'if false, ipcReconnect.hasGivenUp, filterConfigurationActive,'
mutate_and_expect_failure registration-counts-as-delivery Sources/GUI/App/SystemExtensionManager.swift \
  'self.recordSnapshotStatus(remoteStatus, delivered: false)' 'self.recordSnapshotStatus(remoteStatus, delivered: true)'
mutate_and_expect_failure interrupted-left-open Sources/Shared/IPCConnection.swift \
  '            newConnection?.invalidate()' ''
mutate_and_expect_failure off-keeps-retrying Sources/GUI/App/SystemExtensionManager.swift \
  $'        ipcRegistration &+= 1\n        ipcReconnect.reset()' '        ipcRegistration &+= 1'

echo "extension reconnect verification: PASS"
