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
for rule in [alwaysRule, officeRule, homeRule] { try store.upsertRule(rule) }

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
let freshOwn = store.allRules(profile: fresh.name)
let freshLayer = try store.layeredRules(profileName: fresh.name)
let alwaysRules = store.allRules(profile: Profile.alwaysName)
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

// MARK: - watcher reports changes once

let watchProvider = FixedGatewayProvider("aa:bb:cc:dd:ee:01")
let watcher = GatewayMACWatcher(provider: watchProvider)
var observed: [String?] = []
watcher.onChange = { observed.append($0) }
_ = watcher.refresh()
_ = watcher.refresh()
watchProvider.set("12:34:56:78:9a:bc")
_ = watcher.refresh()
watchProvider.set("not a mac")
_ = watcher.refresh()
expect(observed == ["aa:bb:cc:dd:ee:01", "12:34:56:78:9a:bc", nil],
       "the gateway watcher reported \(observed) instead of one event per real change")
pass("the gateway watcher reports one event per change and drops malformed readings")

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
