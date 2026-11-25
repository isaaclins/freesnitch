#!/usr/bin/env bash
# Production-source checks for real network profiles (issue #31).
#
# The harness is compiled from the shipping Sources/Shared code, never from a
# copy, so profile CRUD, rule layering, blocklist selection, gateway MAC
# handling, switch visibility and undo are exercised as they ship. Static
# checks cover the invariants that are about ABSENCE: no SSID API, no
# CoreLocation, and no way to touch an established flow.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-profiles.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
  printf 'profiles verification: FAIL: %s\n' "$*" >&2
  exit 1
}

pass() {
  printf 'profiles verification: PASS: %s\n' "$*"
}

PROFILE_SOURCES=(
  "$ROOT/Sources/Shared/ProfileCoordinator.swift"
  "$ROOT/Sources/Shared/ProfileCommand.swift"
  "$ROOT/Sources/Shared/ProfileValidation.swift"
  "$ROOT/Sources/Shared/GatewayMACWatcher.swift"
  "$ROOT/Sources/Shared/RuleStore.swift"
  "$ROOT/Sources/GUI/ViewModels/ProfileClient.swift"
  "$ROOT/Sources/GUI/Views/ProfilesSettings.swift"
)

for file in "${PROFILE_SOURCES[@]}"; do
  [[ -f "$file" ]] || fail "missing $file"
done

# 1. Nothing in the profile feature may read a wireless network name or ask for
#    a location. Both are refused at the source level, not merely unused.
for symbol in CoreLocation CLLocationManager CLLocation CWWiFiClient CWInterface SSID kCWSSID NEHotspot requestWhenInUseAuthorization requestAlwaysAuthorization locationServicesEnabled; do
  for file in "${PROFILE_SOURCES[@]}"; do
    if grep -Fq -- "$symbol" "$file"; then
      fail "$file references $symbol; profiles must identify a network by gateway MAC only"
    fi
  done
done
pass "no SSID, Wi-Fi or CoreLocation symbol appears in any profile source"

if ! grep -Fq 'NSLocationWhenInUseUsageDescription' "$ROOT/project.yml"; then
  printf 'profiles verification: note: the app declares no location usage string\n'
fi
if grep -Fq 'NSLocationAlwaysUsageDescription' "$ROOT/project.yml"; then
  fail "the app spec requests always-on location, which profiles must never need"
fi

# 2. A profile switch may never reach an established flow. No profile source is
#    allowed to speak the flow-control vocabulary at all.
for symbol in NEFilterFlow dropFlow resumeFlow pauseFlow terminateFlow closeFlow handleInboundData handleOutboundData; do
  for file in "${PROFILE_SOURCES[@]}"; do
    if grep -Fq -- "$symbol" "$file"; then
      fail "$file references $symbol; a profile switch must only affect new flows"
    fi
  done
done
pass "no profile source can enumerate, drop or close a live flow"

# 3. The rule editor must offer Applies to, defaulting to Always.
grep -Fq 'RuleAppliesToPicker' "$ROOT/Sources/GUI/Views/RulesManager.swift" \
  || fail "the rule editor no longer offers the Applies to control"
grep -Fq 'appliesTo = Profile.alwaysName' "$ROOT/Sources/GUI/Views/RulesManager.swift" \
  || fail "new rules no longer default to Always"
grep -Fq 'profile: String = Profile.alwaysName' "$ROOT/Sources/Shared/Models.swift" \
  || fail "the Rule model no longer defaults to the Always layer"
pass "new rules default to Always and the editor exposes Applies to"

# 4. The active profile is always visible in the menu bar surface.
grep -Fq 'profileChip' "$ROOT/Sources/GUI/Views/MenubarPopover.swift" \
  || fail "the menu bar no longer shows the active profile"
grep -Fq 'ProfileSwitchBanner' "$ROOT/Sources/GUI/Views/MenubarPopover.swift" \
  || fail "the menu bar no longer shows the switch notice with undo"
pass "the menu bar shows the active profile and the undoable switch notice"

# 5. No regex anywhere in the profile feature.
for symbol in NSRegularExpression 'Regex<' range\(of: options:\ .regularExpression; do
  for file in "${PROFILE_SOURCES[@]}"; do
    if grep -Fq -- "$symbol" "$file"; then
      fail "$file uses $symbol; regex is out of scope for matching"
    fi
  done
done
pass "no regex is used by any profile source"

compile_harness() {
  local dir="$TMP/harness"
  local source="$dir/main.swift"
  local binary="$dir/profiles_harness"
  mkdir -p "$dir"
  cat > "$source" <<'SWIFT'
import Foundation
import SQLite3

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data(("profiles harness: FAIL: " + message + "\n").utf8))
    exit(1)
}

func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else { fail(message) }
}

func pass(_ message: String) {
    print("profiles harness: PASS: \(message)")
}

func expectThrows(_ message: String, _ body: () throws -> Void) {
    do {
        try body()
        fail("expected a rejection: \(message)")
    } catch {
        print("profiles harness: PASS: rejected \(message): \(error.localizedDescription)")
    }
}

final class FixedGatewayProvider: GatewayMACProviding, @unchecked Sendable {
    private let lock = NSLock()
    private var value: String?
    init(_ value: String?) { self.value = value }
    func set(_ newValue: String?) {
        lock.lock(); self.value = newValue; lock.unlock()
    }
    func currentGatewayMAC() -> String? {
        lock.lock(); defer { lock.unlock() }
        return value
    }
}

let databasePath = CommandLine.arguments[1]
let store = try RuleStore(path: databasePath)

// MARK: - gateway MAC normalization and rejection

let acceptedForms = [
    "AA:BB:CC:DD:EE:01",
    "aa-bb-cc-dd-ee-01",
    "aabb.ccdd.ee01",
    "AABBCCDDEE01",
    "  aa:bb:cc:dd:ee:01  "
]
for form in acceptedForms {
    guard let canonical = GatewayMAC.normalized(form) else {
        fail("gateway MAC form was rejected: \(form)")
    }
    expect(canonical == "aa:bb:cc:dd:ee:01", "gateway MAC \(form) normalized to \(canonical)")
}
pass("every accepted gateway MAC spelling normalizes to one canonical value")

let rejectedForms = [
    "",
    "aa:bb:cc:dd:ee",
    "aa:bb:cc:dd:ee:zz",
    "aa:bb:cc:dd:ee:01:02",
    "ff:ff:ff:ff:ff:ff",
    "00:00:00:00:00:00",
    "01:00:5e:00:00:01",
    "11:22:33:44:55:66",
    "aa:bb-cc:dd:ee:01",
    String(repeating: "a", count: GatewayMAC.maximumInputBytes + 1),
    "my home wifi"
]
for form in rejectedForms {
    expect(GatewayMAC.normalized(form) == nil, "malformed gateway MAC accepted: \(form)")
}
pass("malformed, oversized, broadcast, zero and multicast gateway MACs are all rejected")

// MARK: - CRUD

let seeded = store.allProfiles().map(\.name).sorted()
expect(seeded == ["default", "home", "lockdown", "public-wifi"], "unexpected seeded profiles: \(seeded)")
expect(store.activeProfileName() == "default", "the seeded active profile is not default")

let office = try store.createProfile(name: "Office", mode: .alert, icon: "building.2")
expect(store.profile(named: "office") != nil, "profile lookup is case sensitive")
expectThrows("a duplicate profile name") { _ = try store.createProfile(name: "office") }
expectThrows("the reserved name always") { _ = try store.createProfile(name: "Always") }
expectThrows("an empty profile name") { _ = try store.createProfile(name: "   ") }
expectThrows("deleting the default profile") { _ = try store.deleteProfile(name: "default") }

var renamed = office
renamed.name = "Office HQ"
renamed.mode = .silentDeny
let updated = try store.updateProfile(renamed)
expect(updated.name == "Office HQ" && updated.mode == .silentDeny, "profile update did not persist")
pass("profile create, read, update and delete guards behave")

// MARK: - layering

let alwaysRule = Rule(processName: "Slack", remoteHost: "slack.com", action: .allow, profile: Profile.alwaysName)
let officeRule = Rule(processName: "Printer", remoteHost: "printer.example", action: .allow, profile: "Office HQ")
let homeRule = Rule(processName: "NAS", remoteHost: "nas.example", action: .allow, profile: "home")
_ = try store.mutatePolicy { draft in draft.rules.append(contentsOf: [alwaysRule, officeRule, homeRule]) }

let officeLayer = try store.layeredRules(profileName: "Office HQ")
expect(officeLayer.contains { $0.id == alwaysRule.id }, "the profile layer lost the Always rules")
expect(officeLayer.contains { $0.id == officeRule.id }, "the profile layer lost its own rules")
expect(!officeLayer.contains { $0.id == homeRule.id }, "one profile can see another profile's rules")
pass("exactly two rule layers apply: Always plus the selected profile")

let officePolicy = try store.profilePolicy(named: "Office HQ")
expect(officePolicy.allowLayerCount == 2, "a profile with its own rules reports \(officePolicy.allowLayerCount) allow layers")
let lockdownPolicy = try store.profilePolicy(named: "lockdown")
expect(lockdownPolicy.allowLayerCount == 1, "a profile without its own rules reports more than one allow layer")
for profile in store.allProfiles() {
    let policy = try store.profilePolicy(named: profile.name)
    expect(policy.allowLayerCount <= 2, "profile \(profile.name) exceeded two allow layers")
}
pass("no profile can ever produce a third allow layer")

// A fresh profile inherits Always immediately, by reference and not by copy.
let fresh = try store.createProfile(name: "Cafe", mode: .alert)
let freshOwn = (try! store.allRules(profile: fresh.name))
let freshLayer = try store.layeredRules(profileName: fresh.name)
let alwaysRules = (try! store.allRules(profile: Profile.alwaysName))
expect(freshOwn.isEmpty, "creating a profile copied \(freshOwn.count) rules into it")
expect(freshLayer.map(\.id).sorted(by: { $0.uuidString < $1.uuidString })
        == alwaysRules.map(\.id).sorted(by: { $0.uuidString < $1.uuidString }),
       "a fresh profile does not inherit exactly the Always rules")
pass("a fresh profile inherits every Always rule immediately, without copying one")

// MARK: - deny layer stacking

var stacked: Set<UUID> = []
for index in 0..<40 {
    let list = try store.addCustomBlocklist(name: "Stacked \(index)",
                                            url: "https://lists.example/\(index).txt",
                                            profileName: "Office HQ")
    stacked.insert(list.id)
}
let officeSelection = try store.selectedBlocklistIDs(profileName: "Office HQ")
expect(stacked.isSubset(of: officeSelection), "deny layers did not stack without limit")
expect(officeSelection.count >= 40, "only \(officeSelection.count) deny layers were retained")
let cafeSelection = try store.selectedBlocklistIDs(profileName: fresh.name)
expect(cafeSelection.isDisjoint(with: stacked), "a blocklist selected in one profile leaked into another")
pass("deny layers stack without limit and stay per profile: \(officeSelection.count) selected")

// MARK: - custom blocklist URL validation

expectThrows("a plain HTTP blocklist URL") {
    _ = try store.addCustomBlocklist(name: "Insecure", url: "http://lists.example/hosts.txt")
}
expectThrows("a localhost fixture without explicit test injection") {
    _ = try store.addCustomBlocklist(name: "Fixture", url: "http://localhost:8080/hosts.txt")
}
expectThrows("a malformed blocklist URL") {
    _ = try store.addCustomBlocklist(name: "Broken", url: "not a url")
}
expectThrows("a blocklist URL carrying credentials") {
    _ = try store.addCustomBlocklist(name: "Creds", url: "https://user:secret@lists.example/hosts.txt")
}
expectThrows("an oversized blocklist URL") {
    _ = try store.addCustomBlocklist(name: "Huge",
                                     url: "https://lists.example/" + String(repeating: "a", count: BlocklistURLValidator.maximumBytes))
}
expectThrows("a duplicate blocklist name") {
    _ = try store.addCustomBlocklist(name: "Stacked 0", url: "https://lists.example/other.txt")
}
let injected = try store.addCustomBlocklist(name: "Injected fixture",
                                            url: "http://localhost:8080/hosts.txt",
                                            profileName: nil,
                                            allowLocalhostHTTPForInjectedTest: true)
expect(injected.url.hasPrefix("http://localhost"), "the injected fixture was not stored")
pass("custom blocklist URLs are HTTPS only, with localhost allowed solely for injected test fixtures")

// MARK: - coordinator: switching, visibility, undo, network binding

let provider = FixedGatewayProvider("aa:bb:cc:dd:ee:01")
let coordinator = ProfileCoordinator(store: store, watcher: GatewayMACWatcher(provider: provider))
var observedSwitches: [ProfileCoordinator.SwitchResult] = []
coordinator.onSwitch = { observedSwitches.append($0) }

_ = try coordinator.activate(profileName: "home", reason: .user)
let switchToOffice = try coordinator.activate(profileName: "Office HQ", reason: .user)
expect(switchToOffice.notice.activeProfile == "Office HQ", "the notice names the wrong active profile")
expect(switchToOffice.notice.pausedProfile == "home", "the notice does not name the paused profile")
expect(switchToOffice.notice.activeRuleCount == switchToOffice.policy.activeRuleCount,
       "the notice rule count disagrees with the applied policy")
expect(switchToOffice.notice.pausedRuleCount == 1, "the notice paused \(switchToOffice.notice.pausedRuleCount) rules, expected the one home rule")
expect(switchToOffice.notice.canUndo, "a switch was not offered as undoable")
expect(switchToOffice.notice.message.contains("paused"), "the notice message does not report paused rules")
expect(observedSwitches.count == 2, "the switch observer was not called for every switch")

let undone = try coordinator.undoLastSwitch()
expect(undone?.notice.activeProfile == "home", "undo did not restore the previous profile")
expect(coordinator.activeProfileName == "home", "undo did not change the active profile")
expect(!coordinator.canUndo, "undo stayed available after it was used")
let secondUndo = try coordinator.undoLastSwitch()
expect(secondUndo == nil, "a second undo invented a switch")
pass("a switch is visible, names active and paused rule counts, and is undoable exactly once")

// An unbound network never selects a profile.
let before = coordinator.activeProfileName
let unboundSwitch = try coordinator.handleGatewayMACChange("de:ad:be:ef:00:02")
expect(unboundSwitch == nil, "an unbound gateway triggered an automatic switch")
expect(coordinator.activeProfileName == before, "an unbound gateway changed the active profile")
pass("an unknown network never switches profile")

// Only an explicit user action creates a binding.
provider.set("12:34:56:78:9a:bc")
_ = try coordinator.activate(profileName: "Office HQ", reason: .user)
_ = try coordinator.bindCurrentNetwork(toProfile: "Office HQ")
_ = try coordinator.activate(profileName: "home", reason: .user)
let networkSwitch = try coordinator.handleGatewayMACChange("12-34-56-78-9A-BC")
expect(networkSwitch?.notice.activeProfile == "Office HQ", "returning to a bound network did not switch back")
expect(networkSwitch?.reason == .network, "a network switch was not labelled as one")
expect(coordinator.canUndo, "an automatic switch was not reversible")
expect(store.allNetworkBindings().count == 1, "observing networks created bindings on its own")
pass("automatic switching happens only for a binding the user created, and stays reversible")

// MARK: - established connections survive a switch

let established = Connection(pid: 4242,
                             processName: "ssh",
                             processPath: "/usr/bin/ssh",
                             remoteHost: "shell.example",
                             remoteIP: "203.0.113.9",
                             remotePort: 22,
                             status: .established)
try store.recordConnection(established)
_ = try coordinator.activate(profileName: "lockdown", reason: .user)
let survivors = store.recentConnections(limit: 50).filter { $0.id == established.id }
expect(survivors.count == 1, "a profile switch removed an established connection record")
expect(survivors[0].status == .established, "a profile switch changed an established connection's status")
pass("switching to the strictest profile leaves an established connection untouched")

// The switch changes only what future flows are judged against.
let matcher = RuleMatcher()
let lockdownPolicyAfter = try store.activeProfilePolicy()
let newFlow = Connection(pid: 99, processName: "curl", processPath: "/usr/bin/curl",
                         remoteHost: "unknown.example", remoteIP: "203.0.113.10", status: .pending)
let verdict = matcher.decision(for: newFlow,
                               rules: lockdownPolicyAfter.rules,
                               defaultMode: lockdownPolicyAfter.profile.mode)
expect(verdict == .deny, "the lockdown profile did not apply its strictness to a NEW flow")
pass("a new flow is judged by the newly active profile's strictness")

// MARK: - command service round trip

let service = ProfileCommandService(store: store, coordinator: coordinator)
var blocklistRefreshes = 0
service.onBlocklistsChanged = { blocklistRefreshes += 1 }
let snapshotData = service.handle(requestData: try ProfileTransportBoundary.encodeRequest(.snapshot))
expect(snapshotData.1 == nil, "the snapshot command reported an error: \(snapshotData.1 ?? "")")
let decoded = try ProfileTransportBoundary.decodeResponse(snapshotData.0)
expect(decoded.activeProfile == coordinator.activeProfileName, "the snapshot disagrees about the active profile")
expect(decoded.profiles.count == store.allProfiles().count, "the snapshot lost profiles")
let failure = service.handle(requestData: try ProfileTransportBoundary.encodeRequest(.setActiveProfile(name: "nowhere")))
expect(failure.1 != nil && failure.0.isEmpty, "an unknown profile was accepted by the command service")
let selectCommand = ProfileCommand.setBlocklistEnabled(blocklistID: stacked.first!,
                                                       profileName: coordinator.activeProfileName,
                                                       enabled: true)
_ = service.handle(requestData: try ProfileTransportBoundary.encodeRequest(selectCommand))
expect(blocklistRefreshes >= 1, "selecting a blocklist did not ask the helper to refresh its deny set")
expectThrows("an oversized profile request") {
    try ProfileTransportBoundary.validateRequestBytes(Data(repeating: 0, count: ProfileTransportBoundary.maximumRequestBytes + 1))
}
pass("the profile command surface is bounded, refuses unknown profiles and refreshes deny sets")

// MARK: - a profile change is a new policy generation (#438)
//
// The extension enforces (session, generation) order and refuses a snapshot
// that repeats its current generation with different rules or mode. Every
// profile change that alters the enforced policy must therefore advance the
// generation, or the helper republishes new content under the old number and
// the extension stops filtering ("split-brain snapshot").

func liveSnapshot() -> SharedRuleBridge.Snapshot {
    let state = (try! store.activePolicyState())
    return SharedRuleBridge.Snapshot(mode: state.mode, rules: state.rules,
                                     generation: state.generation, epoch: state.epoch)
}

func expectExtensionAccepts(_ what: String, _ change: () throws -> Void) throws {
    var gate = SharedRuleBridge.LiveSnapshotGate(current: liveSnapshot())
    let before = liveSnapshot()
    try change()
    let after = liveSnapshot()
    let decision = gate.apply(after)
    if after.mode != before.mode || after.rules != before.rules {
        expect(after.generation > before.generation,
               "\(what) changed the enforced policy but kept generation \(after.generation)")
        expect(decision == .accepted, "\(what): the extension answered \(decision) instead of accepting the new policy")
    } else {
        expect(decision == .accepted || decision == .idempotent,
               "\(what): the extension answered \(decision) for an unchanged policy")
    }
}

_ = store.beginPolicySession()
_ = try store.createProfile(name: "strict-438", mode: .silentDeny, icon: "lock")
_ = try store.mutatePolicy { draft in
    draft.rules.append(Rule(processPath: "/Applications/Only438.app/Contents/MacOS/Only438",
                            action: .deny, profile: "strict-438"))
}
try expectExtensionAccepts("switching the active profile") {
    _ = try coordinator.activate(profileName: "strict-438")
}
try expectExtensionAccepts("changing the active profile's mode") {
    _ = try store.setProfileMode(name: "strict-438", mode: .alert)
}
try expectExtensionAccepts("renaming the active profile") {
    var renamed = store.profile(named: "strict-438")!
    renamed.name = "strict-438b"
    _ = try store.updateProfile(renamed)
}
try expectExtensionAccepts("deleting the active profile") {
    _ = try store.deleteProfile(name: "strict-438b")
}
try expectExtensionAccepts("switching back through the command service") {
    _ = service.handle(requestData: try ProfileTransportBoundary.encodeRequest(.setActiveProfile(name: "lockdown")))
}
pass("every profile change that alters the enforced policy advances its generation, so the extension accepts it")

// MARK: - watcher reports changes once

let watchProvider = FixedGatewayProvider("aa:bb:cc:dd:ee:01")
let watcher = GatewayMACWatcher(provider: watchProvider)
var observed: [String?] = []
watcher.onChange = { observed.append($0); return true }
_ = watcher.refresh()
_ = watcher.refresh()
watchProvider.set("12:34:56:78:9a:bc")
_ = watcher.refresh()
watchProvider.set("not a mac")
_ = watcher.refresh()
expect(observed == ["aa:bb:cc:dd:ee:01", "12:34:56:78:9a:bc", nil],
       "the gateway watcher reported \(observed) instead of one event per real change")
pass("the gateway watcher reports one event per change and drops malformed readings")

// A poll that comes in while a change is being handled (the timer and a
// refresh from the app at once) must not hand the same change over twice.
let nestedProvider = FixedGatewayProvider("aa:bb:cc:dd:ee:02")
let nestedWatcher = GatewayMACWatcher(provider: nestedProvider)
var nestedDeliveries = 0
nestedWatcher.onChange = { _ in
    nestedDeliveries += 1
    if nestedDeliveries == 1 { _ = nestedWatcher.refresh() }
    return true
}
_ = nestedWatcher.refresh()
_ = nestedWatcher.refresh()
expect(nestedDeliveries == 1, "one gateway change was handled \(nestedDeliveries) times")
pass("a gateway change is handled once even when two polls overlap")

// Dropping a pending change (the user picked a profile) only drops the change
// for that gateway: a newer gateway seen meanwhile is still delivered.
let scopedProvider = FixedGatewayProvider("aa:bb:cc:dd:ee:0a")
let scopedWatcher = GatewayMACWatcher(provider: scopedProvider)
var scopedSeen: [String?] = []
scopedWatcher.onChange = { mac in
    scopedSeen.append(mac)
    return mac == "aa:bb:cc:dd:ee:0b"
}
_ = scopedWatcher.refresh()            // A fails, stays undelivered
scopedProvider.set("aa:bb:cc:dd:ee:0b")
scopedWatcher.dropUndeliveredChange(for: "aa:bb:cc:dd:ee:0b")
scopedProvider.set("aa:bb:cc:dd:ee:0a")
scopedWatcher.dropUndeliveredChange(for: "aa:bb:cc:dd:ee:0b") // not A's gateway: A stays owed
_ = scopedWatcher.refresh()
expect(scopedSeen == ["aa:bb:cc:dd:ee:0a", "aa:bb:cc:dd:ee:0a"],
       "a drop for another gateway lost the pending change: \(scopedSeen)")
scopedWatcher.dropUndeliveredChange(for: "aa:bb:cc:dd:ee:0a")
_ = scopedWatcher.refresh()
expect(scopedSeen.count == 2, "a dropped change was delivered again")
scopedProvider.set("aa:bb:cc:dd:ee:0b")
_ = scopedWatcher.refresh()
expect(scopedSeen.last! == "aa:bb:cc:dd:ee:0b", "a newer gateway after a drop was not delivered")
pass("dropping a pending change only drops it for its own gateway")

// MARK: - a failed automatic switch is retried and visible (#269)

// Replays the issue: the user bound a gateway to public-wifi, the gateway
// appears, and the profile write fails because another connection holds the
// database's write lock. Before the fix the watcher had already recorded the
// MAC, the coordinator dropped the error, and no later poll tried again.
let retryPath = databasePath + ".retry"
let retryStore = try RuleStore(path: retryPath)
_ = try retryStore.createProfile(name: "office")
// public-wifi is one of the profiles every store starts with.
let retryProvider = FixedGatewayProvider("aa:bb:cc:dd:ee:01")
// The queue never runs, so the timer never polls: every poll is a refresh()
// below, and the coordinator's own wiring is what handles it.
let retryQueue = DispatchQueue(label: "profiles-harness.retry")
retryQueue.suspend()
let retryWatcher = GatewayMACWatcher(provider: retryProvider, queue: retryQueue)
let retryCoordinator = ProfileCoordinator(store: retryStore, watcher: retryWatcher)
let retryService = ProfileCommandService(store: retryStore, coordinator: retryCoordinator)
var pendingEvents: [PendingNetworkSwitch?] = []
retryCoordinator.onPendingNetworkSwitchChanged = { pendingEvents.append($0) }
var retrySwitches = 0
let serviceSwitch = retryCoordinator.onSwitch
retryCoordinator.onSwitch = { serviceSwitch?($0); retrySwitches += 1 }
_ = try retryCoordinator.bindNetwork(gatewayMAC: "12:34:56:78:9a:bc", toProfile: "public-wifi")
_ = try retryCoordinator.bindNetwork(gatewayMAC: "12:34:56:78:9a:bd", toProfile: "office")
retryCoordinator.startWatchingNetworks(every: 5)
_ = retryWatcher.refresh()
let startingProfile = retryCoordinator.activeProfileName
expect(startingProfile == Profile.defaultName, "the unbound starting gateway switched profile")

var writeLock: OpaquePointer?
func holdWriteLock() {
    expect(sqlite3_open(retryPath, &writeLock) == SQLITE_OK, "could not open a second connection")
    expect(sqlite3_exec(writeLock, "BEGIN IMMEDIATE;", nil, nil, nil) == SQLITE_OK,
           "could not take the write lock")
}
func releaseWriteLock() {
    sqlite3_exec(writeLock, "ROLLBACK;", nil, nil, nil)
    sqlite3_close(writeLock)
    writeLock = nil
}

holdWriteLock()
retryProvider.set("12:34:56:78:9a:bc")
_ = retryWatcher.refresh()
expect(retryCoordinator.activeProfileName == startingProfile, "the profile changed although its write failed")
expect(retryCoordinator.pendingNetworkSwitch?.profileName == "public-wifi",
       "a failed automatic switch left nothing pending: \(String(describing: retryCoordinator.pendingNetworkSwitch))")
expect(retryCoordinator.pendingNetworkSwitch?.gatewayMAC == "12:34:56:78:9a:bc", "the pending switch names the wrong gateway")
expect(!(retryCoordinator.pendingNetworkSwitch?.problem.isEmpty ?? true), "the pending switch does not say what failed")
let sentenceReason = RuleStore.StoreError.profileNotFound("public-wifi").localizedDescription
expect(sentenceReason.hasSuffix("."), "the sample store error no longer ends in a period: \(sentenceReason)")
let trimmed = PendingNetworkSwitch(gatewayMAC: "12:34:56:78:9a:bc", profileName: "public-wifi", problem: sentenceReason)
expect(!trimmed.problem.hasSuffix(".") && sentenceReason.hasPrefix(trimmed.problem),
       "a store error's closing period stays in the reason and doubles up mid-sentence: \(trimmed.problem)")
let failingSnapshot = try retryService.snapshot()
expect(failingSnapshot.pendingNetworkSwitch?.profileName == "public-wifi",
       "the Profiles screen is not told that the automatic switch failed")
let roundTrip = try ProfileTransportBoundary.decodeResponse(ProfileTransportBoundary.encodeResponse(failingSnapshot))
expect(roundTrip.pendingNetworkSwitch == failingSnapshot.pendingNetworkSwitch,
       "the pending switch does not survive the trip to the app")
_ = retryWatcher.refresh()
_ = retryWatcher.refresh()
expect(pendingEvents.count == 1, "the same failure was reported \(pendingEvents.count) times instead of once")
expect(retrySwitches == 0, "a failed switch was announced as a switch")
pass("a failed automatic switch is kept pending, shown to the app, and reported once")

releaseWriteLock()
_ = retryWatcher.refresh()
expect(retryCoordinator.activeProfileName == "public-wifi",
       "the bound profile was not applied once the write could succeed, while the gateway stayed the same")
expect(retryCoordinator.pendingNetworkSwitch == nil, "the pending switch stayed after it succeeded")
expect(pendingEvents.count == 2 && pendingEvents.last! == nil, "the app was not told the failure cleared")
expect(retrySwitches == 1, "the retried switch was not announced exactly once")
_ = retryWatcher.refresh()
expect(retrySwitches == 1, "a later poll switched again after the retry succeeded")
pass("the next poll on the same gateway retries the switch until the bound profile is active")

// #519: a binding that can't be read is not a binding that is gone. Replayed
// by renaming the bindings table from another connection, so the store's own
// lookup really fails while public-wifi is still owed to this gateway.
_ = try retryCoordinator.activate(profileName: Profile.defaultName, reason: .user)
holdWriteLock()
retryProvider.set("12:34:56:78:9a:bd")
_ = retryWatcher.refresh()
retryProvider.set("12:34:56:78:9a:bc")
_ = retryWatcher.refresh()
expect(retryCoordinator.pendingNetworkSwitch?.profileName == "public-wifi", "the switch did not fail under the write lock")
releaseWriteLock()
func renameBindings(_ from: String, _ to: String) {
    var other: OpaquePointer?
    expect(sqlite3_open(retryPath, &other) == SQLITE_OK, "could not open a second connection")
    expect(sqlite3_exec(other, "ALTER TABLE \(from) RENAME TO \(to);", nil, nil, nil) == SQLITE_OK,
           "could not rename the bindings table")
    sqlite3_close(other)
}
renameBindings("profile_network_bindings", "bindings_hidden")
let eventsBeforeLookupFailure = pendingEvents.count
_ = retryWatcher.refresh()
_ = retryWatcher.refresh()
expect(retryCoordinator.activeProfileName == Profile.defaultName, "a failed binding lookup switched profile")
expect(retryCoordinator.pendingNetworkSwitch?.profileName == "public-wifi",
       "a failed binding lookup dropped the pending switch: \(String(describing: retryCoordinator.pendingNetworkSwitch))")
expect(pendingEvents.count == eventsBeforeLookupFailure + 1,
       "the lookup failure was reported \(pendingEvents.count - eventsBeforeLookupFailure) times instead of once")
renameBindings("bindings_hidden", "profile_network_bindings")
_ = retryWatcher.refresh()
expect(retryCoordinator.activeProfileName == "public-wifi", "the switch was not retried once the binding could be read")
expect(retryCoordinator.pendingNetworkSwitch == nil, "the pending switch stayed after it succeeded")
pass("a binding that can't be read keeps the switch pending and retried, it is not taken as removed")

// A binding really removed while its switch is failing ends the retry.
_ = try retryCoordinator.activate(profileName: Profile.defaultName, reason: .user)
holdWriteLock()
retryProvider.set("12:34:56:78:9a:bd")
_ = retryWatcher.refresh()
retryProvider.set("12:34:56:78:9a:bc")
_ = retryWatcher.refresh()
expect(retryCoordinator.pendingNetworkSwitch?.profileName == "public-wifi", "the switch did not fail under the write lock")
expect(sqlite3_exec(writeLock, "DELETE FROM profile_network_bindings WHERE gateway_mac='12:34:56:78:9a:bc';", nil, nil, nil) == SQLITE_OK,
       "could not remove the binding")
sqlite3_exec(writeLock, "COMMIT;", nil, nil, nil)
sqlite3_close(writeLock)
writeLock = nil
_ = retryWatcher.refresh()
expect(retryCoordinator.pendingNetworkSwitch == nil, "a removed binding left its switch pending")
expect(retryCoordinator.activeProfileName == Profile.defaultName, "a removed binding still switched profile")
_ = retryWatcher.refresh()
expect(retryCoordinator.activeProfileName == Profile.defaultName, "a later poll switched for a removed binding")
_ = try retryCoordinator.bindNetwork(gatewayMAC: "12:34:56:78:9a:bc", toProfile: "public-wifi")
pass("a binding removed while its switch is failing ends the retry")

// The user's own choice in the meantime wins over the retry.
holdWriteLock()
retryProvider.set("12:34:56:78:9a:bd")
_ = retryWatcher.refresh()
expect(retryCoordinator.pendingNetworkSwitch?.profileName == "office", "the second failure was not kept pending")
releaseWriteLock()
_ = try retryCoordinator.activate(profileName: Profile.defaultName, reason: .user)
expect(retryCoordinator.pendingNetworkSwitch == nil, "a manual switch left the old automatic one pending")
_ = retryWatcher.refresh()
expect(retryCoordinator.activeProfileName == Profile.defaultName, "a retry overrode the profile the user picked")
pass("a profile the user picks while a switch is pending is not overridden by the retry")

// A retry the watcher had already lined up before that pick, arriving only
// now: the late delivery for the same gateway must not undo the pick.
expect(retryCoordinator.applyObservedGatewayMAC("12:34:56:78:9a:bd"), "a late delivery for a settled gateway was not taken as handled")
expect(retryCoordinator.activeProfileName == Profile.defaultName, "a late retry overrode the profile the user picked")
expect(retryCoordinator.pendingNetworkSwitch == nil, "a late retry brought the pending switch back")
// A different network right after a pick is a real change and still switches.
expect(retryCoordinator.applyObservedGatewayMAC("12:34:56:78:9a:bc"), "a new bound gateway after a pick was not handled")
expect(retryCoordinator.activeProfileName == "public-wifi", "a new network right after a manual pick did not switch")
_ = try retryCoordinator.activate(profileName: Profile.defaultName, reason: .user)
// Through the watcher: it reaches the gateway the user just picked on (no
// switch), then moves on to the next network (switch).
retryProvider.set("12:34:56:78:9a:bc")
_ = retryWatcher.refresh()
expect(retryCoordinator.activeProfileName == Profile.defaultName, "the gateway the user picked on switched anyway")
retryProvider.set("12:34:56:78:9a:bd")
_ = retryWatcher.refresh()
expect(retryCoordinator.activeProfileName == "office", "the watcher did not switch for the next real gateway change")
_ = try retryCoordinator.activate(profileName: Profile.defaultName, reason: .user)
pass("a late retry for the gateway the user picked on does nothing, a new gateway still switches")

// A pick that arrives while an automatic switch has read its binding but not
// applied it yet: switches take turns, so the pick lands last and stands.
_ = try retryCoordinator.activate(profileName: Profile.defaultName, reason: .user)
retryProvider.set("12:34:56:78:9a:bd")
_ = retryWatcher.refresh()
_ = try retryCoordinator.activate(profileName: Profile.defaultName, reason: .user)
let pickDone = DispatchSemaphore(value: 0)
let pickStarted = DispatchSemaphore(value: 0)
retryCoordinator.networkSwitchHookForTesting = {
    retryCoordinator.networkSwitchHookForTesting = nil
    DispatchQueue.global().async {
        pickStarted.signal()
        _ = try? retryCoordinator.activate(profileName: "lockdown", reason: .user)
        pickDone.signal()
    }
    pickStarted.wait()
    // The pick must wait for this switch, not finish inside it.
    expect(pickDone.wait(timeout: .now() + 0.2) == .timedOut, "a manual pick ran in the middle of a network switch")
}
retryProvider.set("12:34:56:78:9a:bc")
_ = retryWatcher.refresh()
pickDone.wait()
expect(retryCoordinator.activeProfileName == "lockdown",
       "an automatic switch landed after the user's pick: \(retryCoordinator.activeProfileName)")
_ = retryWatcher.refresh()
expect(retryCoordinator.activeProfileName == "lockdown", "a later poll overrode the user's pick")
pass("a manual pick made during an automatic switch is applied after it and stands")
retryCoordinator.stopWatchingNetworks()

// A gateway that cannot be read says why instead of looking like no gateway.
struct BrokenGatewayProvider: GatewayMACProviding {
    func currentGatewayMAC() -> String? { nil }
    func readGatewayMAC() throws -> String? { throw GatewayMACReadError.exitStatus(tool: "route", status: 1) }
}
let brokenWatcher = GatewayMACWatcher(provider: BrokenGatewayProvider(), queue: retryQueue)
let brokenCoordinator = ProfileCoordinator(store: retryStore, watcher: brokenWatcher)
expect(brokenCoordinator.refreshGatewayMAC() == nil, "a failed read produced a gateway MAC")
expect(brokenCoordinator.gatewayReadProblem?.contains("route") == true,
       "a failed gateway read gave no reason: \(String(describing: brokenCoordinator.gatewayReadProblem))")
let brokenSnapshot = try ProfileCommandService(store: retryStore, coordinator: brokenCoordinator).snapshot()
expect(brokenSnapshot.gatewayReadProblem != nil, "the Profiles screen is not told why there is no gateway")
expect(retryWatcher.lastReadProblem == nil, "a successful read reported a problem")
pass("a failed gateway read carries its reason to the Profiles screen")

// Real `route -n get -inet default` output on macOS. Offline it exits 0, says
// "not in table" on stderr and prints nothing here; a full-tunnel VPN route has
// an interface and no gateway line. Both are no gateway, not a read failure.
let routeWithGateway = """
   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en1
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
"""
let routeThroughTunnel = """
   route to: default
destination: default
       mask: default
  interface: utun4
      flags: <UP,DONE,CLONING,STATIC>
"""
expect(SystemGatewayMACProvider.gatewayAddress(in: routeWithGateway) == "192.168.1.1",
       "the gateway was not read from route's output")
expect(SystemGatewayMACProvider.gatewayAddress(in: routeThroughTunnel) == nil, "a tunnel route produced a gateway")
expect(SystemGatewayMACProvider.gatewayAddress(in: "") == nil, "offline output produced a gateway")
expect(SystemGatewayMACProvider.gatewayAddress(in: "    gateway: fe80::1%en0") == nil, "an IPv6 gateway was taken for IPv4")
pass("offline and tunnel routes read as no gateway, a normal route gives its gateway")

// Real `arp -n <gateway>` output: a known gateway, and one not in the table
// (just after joining, or a tunnel gateway), which arp reports and exits 1 on.
expect(SystemGatewayMACProvider.gatewayMAC(inARPOutput: "? (192.168.1.1) at f0:b0:14:23:20:75 on en1 ifscope [ethernet]")
       == "f0:b0:14:23:20:75", "the gateway MAC was not read from arp's output")
expect(SystemGatewayMACProvider.gatewayMAC(inARPOutput: "192.0.2.77 (192.0.2.77) -- no entry") == nil,
       "arp's no-entry answer produced a MAC")
expect(SystemGatewayMACProvider.gatewayMAC(inARPOutput: "? (192.168.1.1) at (incomplete) on en1 ifscope [ethernet]") == nil,
       "an incomplete arp entry produced a MAC")
let noEntry = GatewayMACReadError.noMACForGateway("10.8.0.1").localizedDescription
expect(noEntry.contains("10.8.0.1") && !noEntry.contains("status"),
       "a gateway missing from the ARP table is not said in plain words: \(noEntry)")
pass("arp's answer gives the gateway MAC, and a missing entry is said in plain words")

print("profiles harness: all checks passed")
SWIFT

  swiftc \
    "$ROOT"/Sources/Shared/*.swift \
    "$source" \
    -lsqlite3 \
    -o "$binary"
  "$binary" "$TMP/profiles.sqlite"
}

printf 'profiles verification: firewall safety audit\n'
bash "$ROOT/Scripts/audit_firewall_safety.sh" >/dev/null
pass "the firewall safety audit still passes with profiles in the tree"

compile_harness

printf 'profiles verification: PASS\n'
