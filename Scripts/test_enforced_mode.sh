#!/usr/bin/env bash
# The mode the app shows is the mode that is enforced (issue #452).
#
# FreeSnitch stores two modes: a global one and each profile's own. What the
# helper enforces (DNS proxy, extension snapshot, status) is the ACTIVE
# profile's. The mode can change four ways: the mode picker (menu bar,
# Settings), the Profiles page, `freesnitch mode`, and an automatic switch when
# the network changes. The harness below drives each of them through the
# shipping Sources/Shared code and checks, after each, that what the helper
# reports and what the Profiles page reads are the enforced mode, and that the
# change tells the open app to refresh. Static checks pin the GUI wiring that
# cannot run without a helper.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-enforced-mode.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
  printf 'enforced mode verification: FAIL: %s\n' "$*" >&2
  exit 1
}

pass() {
  printf 'enforced mode verification: PASS: %s\n' "$*"
}

HELPER="$ROOT/Sources/Helper/HelperService.swift"
APPSTATE="$ROOT/Sources/GUI/ViewModels/AppState.swift"
CLIENT="$ROOT/Sources/GUI/App/HelperClient.swift"
INSIGHTS="$ROOT/Sources/GUI/Views/InsightsView.swift"
MENUBAR="$ROOT/Sources/GUI/App/MenubarController.swift"
POPOVER="$ROOT/Sources/GUI/Views/MenubarPopover.swift"

# Returns the body of one Swift function, from its signature to the next
# top-level declaration at the same indentation.
function_body() {
  awk -v sig="$2" '
    index($0, sig) { on = 1 }
    on && /^    (func|private func|public func|@objc|\/\/\/|var|private var|@discardableResult)/ && !index($0, sig) && seen { exit }
    on { print; seen = 1 }
  ' "$1"
}

# 1. Everything the helper reports or enforces is read from the active profile.
status_body="$(function_body "$HELPER" 'func getStatus(')"
[[ -n "$status_body" ]] || fail "getStatus not found in HelperService.swift"
grep -Fq 'authoritativePolicyState()' <<<"$status_body" \
  || fail "the helper status no longer reads the enforced (active profile) policy"
grep -Fq 'store.policyState()' "$HELPER" \
  && fail "the helper reads the global policy mode somewhere; only the active profile's mode is enforced"
for fn in 'private func authoritativePolicyState(' 'private func authoritativeSnapshot(' 'private func republishActivePolicy('; do
  function_body "$HELPER" "$fn" | grep -Fq 'store.activePolicyState()' \
    || fail "$fn does not read store.activePolicyState()"
done
pass "status, snapshot and republish all read the active profile's mode"

# 2. A mode set through the helper (the mode picker and `freesnitch mode`) tells
#    every open app to refresh, so its Profiles page follows too.
setmode_body="$(function_body "$HELPER" 'func setMode(rawValue')"
grep -Fq 'draft.activeProfileMode = m' <<<"$setmode_body" \
  || fail "the helper's setMode no longer writes the active profile's mode"
grep -Fq 'profilePolicyChangedLogMessage' <<<"$setmode_body" \
  || fail "the helper's setMode does not tell open apps to refresh"
grep -Fq 'ProfileClient.shared.refresh()' "$CLIENT" \
  || fail "the app no longer refreshes its Profiles page when the helper says the policy changed"
pass "a mode change through the helper refreshes the app's mode and its Profiles page"

# 3. The status ping goes through the tested decision (replayed in the harness
#    below), and the app does not start out claiming Silent Allow.
adopt_body="$(function_body "$APPSTATE" 'func adoptHelperStatus(')"
grep -Fq 'EnforcedModeSync.decide(' <<<"$adopt_body" \
  || fail "adoptHelperStatus no longer uses EnforcedModeSync"
grep -Fq 'if sync.fetchSnapshot { syncSharedRules() }' <<<"$adopt_body" \
  || fail "adoptHelperStatus no longer fetches the snapshot when the decision says so"
grep -Fq 'fetchInFlight: snapshotFetchInFlight' <<<"$adopt_body" \
  || fail "adoptHelperStatus no longer tells the decision that a fetch is running"
sync_body="$(function_body "$APPSTATE" 'func syncSharedRules(')"
grep -Fq 'if message != self.lastSnapshotFailure {' <<<"$sync_body" \
  || fail "a snapshot failure is logged again on every retry"
grep -Fq 'self?.state?.adoptHelperStatus(mode: status.mode, generation: status.policyGeneration)' "$CLIENT" \
  || fail "the status ping no longer hands the helper's mode and generation to the app"
grep -Eq '@Published var mode: AppMode = \.silentAllow$' "$APPSTATE" \
  && fail "the app starts out showing Silent Allow instead of the last mode the helper reported"
pass "the status ping goes through EnforcedModeSync, and the app starts from the last known mode"

# 4. Insights and the menu bar read that one value.
grep -Fq 'switch state.mode' "$INSIGHTS" || fail "Insights' banner no longer reads state.mode"
grep -Fq 'state.mode == .alert' "$MENUBAR" || fail "the menu bar's mode menu no longer reads state.mode"
grep -Fq 'ModeButton(mode: state.mode' "$POPOVER" || fail "the menu bar popover no longer reads state.mode"
pass "Insights and the menu bar read the mode the helper reported"

# 5. Drive every way of changing the mode through the shipping store code.
HARNESS_DIR="$TMP/harness"
mkdir -p "$HARNESS_DIR"
cat > "$HARNESS_DIR/main.swift" <<'SWIFT'
import Foundation

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data(("enforced mode harness: FAIL: " + message + "\n").utf8))
    exit(1)
}

func pass(_ message: String) {
    print("enforced mode harness: PASS: \(message)")
}

final class FixedGatewayProvider: GatewayMACProviding, @unchecked Sendable {
    private let lock = NSLock()
    private var value: String?
    init(_ value: String?) { self.value = value }
    func set(_ newValue: String?) { lock.lock(); value = newValue; lock.unlock() }
    func currentGatewayMAC() -> String? { lock.lock(); defer { lock.unlock() }; return value }
}

let store = try RuleStore(path: CommandLine.arguments[1])
let provider = FixedGatewayProvider("aa:bb:cc:dd:ee:01")
let coordinator = ProfileCoordinator(store: store, watcher: GatewayMACWatcher(provider: provider))
let service = ProfileCommandService(store: store, coordinator: coordinator)
var refreshes = 0
service.onPolicyChanged = { _ in refreshes += 1 }

/// What the helper does for `setMode` (the mode picker and `freesnitch mode`).
func helperSetMode(_ mode: AppMode) throws {
    _ = try store.mutateActivePolicy { draft in
        draft.mode = mode
        draft.activeProfileMode = mode
    }
}

/// What the helper enforces and reports (status, snapshot, DNS proxy).
func enforced() -> AppMode { store.activePolicyState().mode }

/// What the Profiles page shows for the active profile.
func profilesPage() throws -> AppMode {
    let snapshot = try service.execute(.snapshot)
    guard let active = snapshot.profiles.first(where: { $0.name == snapshot.activeProfile }) else {
        fail("the profile snapshot has no active profile")
    }
    return active.mode
}

func check(_ expected: AppMode, after how: String) throws {
    let enforcedMode = enforced()
    guard enforcedMode == expected else {
        fail("after \(how) the helper enforces \(enforcedMode.rawValue), expected \(expected.rawValue)")
    }
    let shown = try profilesPage()
    guard shown == enforcedMode else {
        fail("after \(how) the Profiles page shows \(shown.rawValue) while \(enforcedMode.rawValue) is enforced")
    }
    pass("after \(how): enforced and shown are both \(expected.rawValue)")
}

guard enforced() == .silentAllow else { fail("a fresh install does not start in Silent Allow") }

// The mode picker and `freesnitch mode`.
try helperSetMode(.alert)
try check(.alert, after: "the mode picker or `freesnitch mode` set Alert")
try helperSetMode(.silentDeny)
try check(.silentDeny, after: "the mode picker or `freesnitch mode` set Silent Deny")

// The Profiles page changes only the profile's mode. The global mode is left
// behind, which is exactly the split #452 is about: nothing may report it.
var active = store.allProfiles().first { $0.isActive }!
active.mode = .alert
let before = refreshes
_ = try service.execute(.updateProfile(active))
try check(.alert, after: "the Profiles page set the active profile to Alert")
guard store.policyState().mode == .silentDeny else {
    fail("the Profiles page also wrote the global mode; this test no longer covers the split")
}
guard refreshes > before else { fail("a Profiles page mode change did not tell the app to refresh") }
pass("the Profiles page change left the global mode behind, and the helper still reports the profile's")

// A switch by hand to a profile with another mode.
_ = try store.createProfile(name: "office", mode: .silentDeny, icon: "building.2")
let beforeSwitch = refreshes
_ = try service.execute(.setActiveProfile(name: "office"))
try check(.silentDeny, after: "switching to a Silent Deny profile by hand")
guard refreshes > beforeSwitch else { fail("a profile switch did not tell the app to refresh") }

// An automatic switch when the network changes.
_ = try coordinator.bindNetwork(gatewayMAC: "aa:bb:cc:dd:ee:02", toProfile: "default")
let beforeAuto = refreshes
guard try coordinator.handleGatewayMACChange("aa:bb:cc:dd:ee:02") != nil else {
    fail("the automatic switch did not happen")
}
try check(.alert, after: "an automatic switch to the Alert profile")
guard refreshes > beforeAuto else { fail("an automatic switch did not tell the app to refresh") }

// The mode picker after a switch lands in the profile now active.
try helperSetMode(.silentAllow)
try check(.silentAllow, after: "the mode picker set Silent Allow after the automatic switch")
guard store.allProfiles().first(where: { $0.name == "office" })?.mode == .silentDeny else {
    fail("a mode change reached a profile that is not active")
}
pass("a mode change only touches the active profile")

// MARK: - the app's side of a status ping (#452)

// Replays the report: the helper enforces Alert and answers every status ping,
// but fetching the full snapshot fails. The app must show Alert at once and
// keep asking for the snapshot, because the extension enforces the snapshot.
struct App {
    var shown: AppMode = .silentAllow
    var snapshotGeneration: UInt64? = nil
    var inFlight = false
    var fetches = 0
    /// One status ping. A fetch it starts answers before the next ping,
    /// unless `answersBeforeNextPing` is false (a slow helper).
    mutating func ping(mode: AppMode, generation: UInt64?, fetchWorks: Bool, answersBeforeNextPing: Bool = true) {
        let sync = EnforcedModeSync.decide(statusMode: mode, statusGeneration: generation,
                                           shownMode: shown, snapshotGeneration: snapshotGeneration,
                                           fetchInFlight: inFlight)
        if let m = sync.showMode { shown = m }
        guard sync.fetchSnapshot else { return }
        fetches += 1
        inFlight = true
        if answersBeforeNextPing { answer(mode: mode, generation: generation, works: fetchWorks) }
    }
    mutating func answer(mode: AppMode, generation: UInt64?, works: Bool) {
        inFlight = false
        if works { shown = mode; snapshotGeneration = generation }
    }
}

var app = App()
app.ping(mode: .alert, generation: 7, fetchWorks: false)
guard app.shown == .alert else { fail("with the snapshot failing, the app still shows \(app.shown.rawValue) while Alert is enforced") }
app.ping(mode: .alert, generation: 7, fetchWorks: false)
app.ping(mode: .alert, generation: 7, fetchWorks: false)
guard app.fetches == 3 else { fail("a failed snapshot fetch was retried \(app.fetches - 1) times over two more pings, expected 2") }
pass("a failing snapshot fetch: Alert is shown at once and the fetch is retried on every ping")
app.ping(mode: .alert, generation: 7, fetchWorks: true)
app.ping(mode: .alert, generation: 7, fetchWorks: true)
guard app.fetches == 4, app.snapshotGeneration == 7 else { fail("the app kept fetching after it held the current snapshot") }
pass("once the current snapshot arrived, pings stop fetching it")

// A rule change or profile switch raises the generation without changing the
// mode; the app must still fetch, or the extension keeps the old rules.
app.ping(mode: .alert, generation: 8, fetchWorks: true)
guard app.fetches == 5, app.snapshotGeneration == 8 else { fail("a new generation with the same mode did not fetch the snapshot") }
pass("a new policy generation with the same mode still fetches the snapshot")

// A slow helper: the fetch takes longer than one ping. The next ping must not
// start a second fetch, which would drop the first one's answer.
var slow = App()
slow.ping(mode: .silentDeny, generation: 3, fetchWorks: true, answersBeforeNextPing: false)
guard slow.shown == .silentDeny else { fail("a slow snapshot kept the app from showing the enforced mode") }
slow.ping(mode: .silentDeny, generation: 3, fetchWorks: true, answersBeforeNextPing: false)
slow.ping(mode: .silentDeny, generation: 3, fetchWorks: true, answersBeforeNextPing: false)
guard slow.fetches == 1 else { fail("pings started \(slow.fetches) fetches while the first was still running") }
slow.answer(mode: .silentDeny, generation: 3, works: true)
slow.ping(mode: .silentDeny, generation: 3, fetchWorks: true)
guard slow.fetches == 1, slow.snapshotGeneration == 3 else { fail("the slow fetch's answer was not kept") }
pass("a slow snapshot fetch is left to finish, and its answer is kept")

// A helper that sends no generation: only a mode change fetches.
var old = App(shown: .alert, snapshotGeneration: nil)
old.ping(mode: .alert, generation: nil, fetchWorks: true)
guard old.fetches == 0 else { fail("a helper without generations was asked for a snapshot on every ping") }
old.ping(mode: .silentDeny, generation: nil, fetchWorks: false)
guard old.shown == .silentDeny, old.fetches == 1 else { fail("a mode change from a helper without generations was not shown or fetched") }
pass("a helper without generations: only a mode change fetches, and it is shown at once")

print("enforced mode harness: all checks passed")
SWIFT

swiftc "$ROOT"/Sources/Shared/*.swift "$ROOT/Sources/GUI/ViewModels/EnforcedModeSync.swift" "$HARNESS_DIR/main.swift" -lsqlite3 -o "$HARNESS_DIR/enforced_mode_harness"
"$HARNESS_DIR/enforced_mode_harness" "$TMP/enforced-mode.sqlite"

printf 'enforced mode verification: PASS\n'
