#!/usr/bin/env bash
# Live monitor tree verification (issue #62).
#
# The harness is compiled from the shipping Sources/GUI/Views/MonitorTree.swift
# and Sources/Shared, never from a copy, so the grouping, ordering, rollup and
# bounding properties are proven on the code that runs.
#
# What is proven here:
#   * ordering is by arrival and by nothing else: identical trees from shuffled
#     input, and no movement when traffic counts change
#   * rollups on a parent row equal the sum of every connection of that app,
#     including destinations that were bounded out of a row
#   * output is bounded per app and per snapshot, and says how much it hid
#   * a row's rule target round-trips through a drafted Rule, so a decision
#     made on a row is recognised as that row's decision afterwards
#   * compute for a few thousand connections is measured and printed
#
# Static checks cover the invariants that are about ABSENCE: the grouping model
# has no view layer, no ordering path may consult traffic, and no decision may
# be enforced from GUI state.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-monitor-tree.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

MODEL="$ROOT/Sources/GUI/Views/MonitorTree.swift"
CONTROLLER="$ROOT/Sources/GUI/Views/MonitorTreeController.swift"
ROWS="$ROOT/Sources/GUI/Views/MonitorTreeRows.swift"
MONITOR="$ROOT/Sources/GUI/Views/NetworkMonitor.swift"

fail() {
  printf 'monitor tree verification: FAIL: %s\n' "$*" >&2
  exit 1
}

pass() {
  printf 'monitor tree verification: PASS: %s\n' "$*"
}

for file in "$MODEL" "$CONTROLLER" "$ROWS" "$MONITOR"; do
  [[ -f "$file" ]] || fail "missing $file"
done

# 1. The grouping model must stay a plain value transformation. A view import
#    here would mean grouping could be done on the render path again.
model_imports="$(grep -E '^import ' "$MODEL" | sort | tr '\n' ' ' | sed 's/ $//')"
[[ "$model_imports" == "import Foundation" ]] \
  || fail "the grouping model imports more than Foundation ($model_imports); grouping must stay off the view layer"
for symbol in NSImage 'AppState\.' 'HelperClient(' '@MainActor' ': View'; do
  if grep -nE "$symbol" "$MODEL" >/dev/null; then
    fail "the grouping model uses $symbol; grouping must stay off the view layer"
  fi
done
pass "the grouping model has no view layer and no reference to app or helper state"

# 2. Ordering may never consult traffic. Sorting rows by bytes is what moves a
#    row out from under the pointer between press and release.
if grep -nE 'sorted[^\n]*(traffic|bytes|total)' "$MODEL" >/dev/null; then
  fail "the grouping model sorts by traffic"
fi
if grep -nE 'sorted[^\n]*(traffic|bytes|total)' "$ROWS" >/dev/null; then
  fail "the monitor rows sort by traffic"
fi
pass "no row ordering path sorts by traffic"

# 3. A decision must travel the existing rule ingest path and come back from
#    the helper, never be applied from cached GUI state.
grep -Fq "state.helper.addRule(rule)" "$CONTROLLER" \
  || fail "the monitor does not send decisions through the existing HelperClient.addRule ingest path"
grep -Fq "state.refreshRules()" "$CONTROLLER" \
  || fail "the monitor does not re-read the helper snapshot after a decision"
grep -Fq "state.helper.removeRule(id: rule.id)" "$CONTROLLER" \
  || fail "a decision made in the monitor cannot be taken back through the helper"
for symbol in PreparedRuleSet RuleMatcher setEnforcementEnabled SharedRuleBridge; do
  if grep -Fq "$symbol" "$CONTROLLER" || grep -Fq "$symbol" "$ROWS"; then
    fail "the monitor evaluates or publishes policy itself via $symbol"
  fi
done
pass "decisions go through the helper ingest path and nothing is enforced from GUI state"

# 4. A decision must be explicit. The only callers of the apply path are the
#    row's own controls, never a tap on the row.
if grep -nE 'onTapGesture[^\n]*(apply|decide)' "$ROWS" "$MONITOR" >/dev/null; then
  fail "a decision can be triggered by tapping a row"
fi
pass "no row tap can make a decision"

cat > "$TMP/main.swift" <<'SWIFT'
import Foundation

var failures = 0

func check(_ condition: Bool, _ message: String) {
    if condition {
        print("monitor tree harness: PASS: \(message)")
    } else {
        failures += 1
        FileHandle.standardError.write(Data("monitor tree harness: FAIL: \(message)\n".utf8))
    }
}

func equal<T: Equatable>(_ actual: T, _ expected: T, _ message: String) {
    check(actual == expected, "\(message) (expected \(expected), got \(actual))")
}

/// Deterministic shuffle, so a failure is reproducible.
struct LCG {
    var state: UInt64
    mutating func next(_ bound: Int) -> Int {
        state = state &* 6364136223846793005 &+ 1442695040888963407
        return Int((state >> 33) % UInt64(bound))
    }
}

func shuffled<T>(_ items: [T], seed: UInt64) -> [T] {
    var rng = LCG(state: seed)
    var copy = items
    var index = copy.count - 1
    while index > 0 {
        let swap = rng.next(index + 1)
        copy.swapAt(index, swap)
        index -= 1
    }
    return copy
}

func connection(app: String,
                bundle: String?,
                host: String,
                ip: String,
                bytesIn: Int64 = 100,
                bytesOut: Int64 = 50,
                port: Int = 443) -> Connection {
    Connection(pid: 501,
               processName: app,
               processPath: "/Applications/\(app).app/Contents/MacOS/\(app)",
               processBundleId: bundle,
               remoteHost: host,
               remoteIP: ip,
               remotePort: port,
               direction: .outgoing,
               status: .allowed,
               protocolName: "tcp",
               bytesIn: bytesIn,
               bytesOut: bytesOut)
}

// MARK: - Grouping and rollups

let base: [Connection] = [
    connection(app: "Beeper", bundle: "com.beeper.app", host: "api.beeper.com", ip: "203.0.113.10", bytesIn: 10, bytesOut: 5),
    connection(app: "Beeper", bundle: "com.beeper.app", host: "api.beeper.com", ip: "203.0.113.10", bytesIn: 20, bytesOut: 7),
    connection(app: "Beeper", bundle: "com.beeper.app", host: "api.segment.io", ip: "203.0.113.20", bytesIn: 1, bytesOut: 2),
    connection(app: "Beeper", bundle: "com.beeper.app", host: "", ip: "203.0.113.77", bytesIn: 4, bytesOut: 8),
    connection(app: "Safari", bundle: "com.apple.Safari", host: "apple.com", ip: "203.0.113.30", bytesIn: 1000, bytesOut: 2000),
    connection(app: "Safari", bundle: "com.apple.Safari", host: "icloud.com", ip: "203.0.113.31", bytesIn: 3, bytesOut: 4)
]

let first = MonitorTreeBuilder.build(connections: base, order: MonitorRowOrder())
equal(first.snapshot.apps.count, 2, "two apps are grouped from six connections")

guard let beeper = first.snapshot.apps.first(where: { $0.name == "Beeper" }),
      let safari = first.snapshot.apps.first(where: { $0.name == "Safari" }) else {
    FileHandle.standardError.write(Data("monitor tree harness: FAIL: both apps missing\n".utf8))
    exit(1)
}

equal(beeper.connectionCount, 4, "the Beeper row counts every one of its connections")
equal(beeper.destinationCount, 3, "the Beeper row counts its distinct destinations")
equal(beeper.traffic.bytesIn, 35, "the Beeper row rolls up received bytes")
equal(beeper.traffic.bytesOut, 22, "the Beeper row rolls up sent bytes")
equal(beeper.traffic.total, 57, "the Beeper row totals sent plus received")
equal(safari.traffic.total, 3007, "the Safari row totals sent plus received")

let beeperDestinationTotal = beeper.destinations.reduce(Int64(0)) { $0 + $1.traffic.total }
equal(beeperDestinationTotal, beeper.traffic.total, "an app total equals the sum of its destination rows")

if let apiRow = beeper.destinations.first(where: { $0.label == "api.beeper.com" }) {
    equal(apiRow.connectionCount, 2, "two flows to one domain collapse into one destination row")
    equal(apiRow.traffic.bytesIn, 30, "the destination row rolls up received bytes")
    equal(apiRow.traffic.bytesOut, 12, "the destination row rolls up sent bytes")
    equal(apiRow.remoteHost, "api.beeper.com", "a named destination keeps its domain for a rule")
    check(apiRow.remoteIP == "203.0.113.10", "a named destination also remembers the address it used")
} else {
    check(false, "api.beeper.com has a destination row")
}

if let bareRow = beeper.destinations.first(where: { $0.label == "203.0.113.77" }) {
    check(bareRow.remoteHost == nil, "a destination with no DNS answer offers no domain to a rule")
    equal(bareRow.remoteIP, "203.0.113.77", "a destination with no DNS answer offers its address to a rule")
} else {
    check(false, "an address with no DNS answer has a destination row")
}

// The same domain under two apps is two rows with two independent decisions.
let shared = base + [connection(app: "Safari", bundle: "com.apple.Safari", host: "api.segment.io", ip: "203.0.113.20")]
let sharedTree = MonitorTreeBuilder.build(connections: shared, order: MonitorRowOrder())
let segmentRows = sharedTree.snapshot.apps.flatMap { $0.destinations }.filter { $0.label == "api.segment.io" }
equal(segmentRows.count, 2, "one domain contacted by two apps is two independent rows")
equal(Set(segmentRows.map(\.id)).count, 2, "those two rows have distinct identities")

// MARK: - Ordering

// A fresh ledger ranks by sorted key, so the tree does not depend on the order
// the helper happened to deliver connections in.
let shuffledOnce = MonitorTreeBuilder.build(connections: shuffled(base, seed: 0xDEADBEEF), order: MonitorRowOrder())
let shuffledTwice = MonitorTreeBuilder.build(connections: shuffled(base, seed: 0x0BADF00D), order: MonitorRowOrder())
equal(shuffledOnce.snapshot.apps.map(\.id), first.snapshot.apps.map(\.id),
      "shuffled input produces the same app order")
equal(shuffledTwice.snapshot.apps.map(\.id), first.snapshot.apps.map(\.id),
      "a second shuffle produces the same app order")
equal(shuffledOnce.snapshot.apps.flatMap { $0.destinations.map(\.id) },
      first.snapshot.apps.flatMap { $0.destinations.map(\.id) },
      "shuffled input produces the same destination order")

// Traffic may not move a row. This is the click-safety property: the row under
// the pointer when the button went down is the row the decision lands on.
let reweighted = shuffled(base, seed: 7).map { connection -> Connection in
    var copy = connection
    copy.bytesIn = connection.bytesIn * 1000 + 1
    copy.bytesOut = 5_000_000 - connection.bytesOut * 999
    return copy
}
let second = MonitorTreeBuilder.build(connections: reweighted, order: first.order)
equal(second.snapshot.apps.map(\.id), first.snapshot.apps.map(\.id),
      "changed traffic counts do not reorder app rows")
equal(second.snapshot.apps.flatMap { $0.destinations.map(\.id) },
      first.snapshot.apps.flatMap { $0.destinations.map(\.id) },
      "changed traffic counts do not reorder destination rows")
check(second.snapshot.apps.first(where: { $0.name == "Beeper" })?.traffic.total != beeper.traffic.total,
      "the rebuild really did change the traffic it did not reorder for")

// A new app arrives at the end, and everything already on screen stays put.
let withNewcomer = base + [connection(app: "Aardvark", bundle: "com.aardvark.app", host: "aardvark.example", ip: "203.0.113.44")]
let third = MonitorTreeBuilder.build(connections: withNewcomer, order: second.order)
equal(Array(third.snapshot.apps.map(\.id).prefix(first.snapshot.apps.count)), first.snapshot.apps.map(\.id),
      "an arriving app does not push existing rows around")
equal(third.snapshot.apps.last?.name, "Aardvark", "an arriving app is appended, alphabetically early name and all")

// A new destination under an existing app is appended under that app too.
let withNewDestination = withNewcomer + [connection(app: "Beeper", bundle: "com.beeper.app", host: "aaa.beeper.com", ip: "203.0.113.99")]
let fourth = MonitorTreeBuilder.build(connections: withNewDestination, order: third.order)
if let beeperAfter = fourth.snapshot.apps.first(where: { $0.name == "Beeper" }) {
    equal(Array(beeperAfter.destinations.map(\.label).prefix(3)), beeper.destinations.map(\.label),
          "existing destination rows keep their position when a new one arrives")
    equal(beeperAfter.destinations.last?.label, "aaa.beeper.com", "a new destination is appended")
} else {
    check(false, "Beeper is still present after a new destination arrives")
}

// MARK: - Bounds

var flood: [Connection] = []
let floodDestinations = MonitorTreeLimits.trackedDestinationsPerApp + 40
for index in 0..<floodDestinations {
    flood.append(connection(app: "Scanner",
                            bundle: "com.scanner.app",
                            host: "",
                            ip: "198.51.100.\(index % 250)-\(index)",
                            bytesIn: 2,
                            bytesOut: 3))
}
let bounded = MonitorTreeBuilder.build(connections: flood, order: MonitorRowOrder())
guard let scanner = bounded.snapshot.apps.first else {
    FileHandle.standardError.write(Data("monitor tree harness: FAIL: the flooded app is missing\n".utf8))
    exit(1)
}
equal(scanner.destinations.count, MonitorTreeLimits.maxDestinationsPerApp,
      "destination rows per app are bounded")
equal(scanner.destinationCount, MonitorTreeLimits.trackedDestinationsPerApp,
      "tracked destinations per app are bounded")
equal(scanner.ungroupedConnectionCount, 40,
      "connections past the tracking bound are counted rather than dropped silently")
equal(scanner.hiddenDestinationCount,
      MonitorTreeLimits.trackedDestinationsPerApp - MonitorTreeLimits.maxDestinationsPerApp,
      "the row says how many tracked destinations it did not show")
equal(scanner.connectionCount, floodDestinations, "the app row counts every connection it saw")
equal(scanner.traffic.total, Int64(floodDestinations) * 5,
      "the app rollup includes traffic from destinations that were bounded out of a row")

var manyApps: [Connection] = []
for index in 0..<(MonitorTreeLimits.maxApps + 25) {
    manyApps.append(connection(app: String(format: "App%04d", index),
                               bundle: String(format: "com.example.app%04d", index),
                               host: "example.com",
                               ip: "203.0.113.1"))
}
let boundedApps = MonitorTreeBuilder.build(connections: manyApps, order: MonitorRowOrder())
equal(boundedApps.snapshot.apps.count, MonitorTreeLimits.maxApps, "app rows are bounded")
equal(boundedApps.snapshot.hiddenAppCount, 25, "the snapshot says how many apps it did not show")

// MARK: - Rule targets

guard let appTarget = MonitorRuleTarget.app(beeper) else {
    FileHandle.standardError.write(Data("monitor tree harness: FAIL: no app target\n".utf8))
    exit(1)
}
let domainRow = beeper.destinations.first { $0.label == "api.beeper.com" }!
let addressRow = beeper.destinations.first { $0.label == "203.0.113.77" }!
let domainTarget = MonitorRuleTarget.destination(domainRow, in: beeper)!
let addressTarget = MonitorRuleTarget.destination(addressRow, in: beeper)!

check(appTarget != domainTarget, "an app row and one of its destinations are different targets")
check(domainTarget != addressTarget, "two destinations of one app are different targets")
check(appTarget.isAddressable && domainTarget.isAddressable && addressTarget.isAddressable,
      "app, domain and address rows can all be named by a rule")

let denyDomain = MonitorRuleDraft.rule(for: domainTarget, processName: "Beeper", action: .deny,
                                       profile: "default", existing: nil)!
equal(denyDomain.action, .deny, "the drafted rule carries the action the user pressed")
equal(denyDomain.scope, .domain, "a named destination drafts a domain rule")
equal(denyDomain.remoteHost, "api.beeper.com", "the drafted rule names the destination")
check(denyDomain.remoteIP == nil, "a domain rule does not also pin an address")
check(denyDomain.remotePort == nil, "a row decision is not narrowed to one port")
equal(denyDomain.profile, "default", "the drafted rule lands in the active profile")
equal(MonitorRuleTarget.of(denyDomain), domainTarget, "a drafted rule is recognised as that row's decision")

let allowAddress = MonitorRuleDraft.rule(for: addressTarget, processName: "Beeper", action: .allow,
                                         profile: "default", existing: nil)!
equal(allowAddress.scope, .ip, "an unnamed destination drafts an address rule")
equal(allowAddress.remoteIP, "203.0.113.77", "the address rule names the address")
check(allowAddress.remoteHost == nil, "the address rule leaves the domain field empty")
equal(MonitorRuleTarget.of(allowAddress), addressTarget, "a drafted address rule round-trips to its row")

let allowApp = MonitorRuleDraft.rule(for: appTarget, processName: "Beeper", action: .allow,
                                     profile: "default", existing: nil)!
equal(allowApp.scope, .process, "an app row drafts a process rule")
equal(MonitorRuleTarget.of(allowApp), appTarget, "a drafted app rule round-trips to its row")

let flipped = MonitorRuleDraft.rule(for: domainTarget, processName: "Beeper", action: .allow,
                                    profile: "default", existing: denyDomain)!
equal(flipped.id, denyDomain.id, "changing your mind edits the same rule instead of stacking a second one")
equal(flipped.action, .allow, "changing your mind changes the action")
check(flipped.enabled, "changing your mind re-enables a rule that was switched off")

// A reverse-DNS name is a query, not a destination; the helper rejects it, so
// the row must not offer a control that could not work.
let reverse = Connection(pid: 1, processName: "Beeper",
                         processPath: "/Applications/Beeper.app/Contents/MacOS/Beeper",
                         processBundleId: "com.beeper.app",
                         remoteHost: "10.113.0.203.in-addr.arpa", remoteIP: "203.0.113.10")
let reverseTree = MonitorTreeBuilder.build(connections: [reverse], order: MonitorRowOrder())
let reverseApp = reverseTree.snapshot.apps[0]
let reverseTarget = MonitorRuleTarget.destination(reverseApp.destinations[0], in: reverseApp)!
check(!reverseTarget.isAddressable, "a reverse-DNS name is not offered as a destination a rule can name")
check(MonitorRuleDraft.rule(for: reverseTarget, processName: "Beeper", action: .deny,
                            profile: "default", existing: nil) == nil,
      "no rule is drafted for a destination the helper would refuse")

// MARK: - Decision index

let otherProfile = Rule(processBundleId: "com.beeper.app", processPath: nil, processName: "Beeper",
                        remoteHost: "api.beeper.com", action: .allow, scope: .domain, profile: "work")
let wildcard = Rule(processBundleId: "com.beeper.app", processPath: nil, processName: "Beeper",
                    remoteHost: "*.beeper.com", action: .allow, scope: .domain, profile: "default")
let portScoped = Rule(processBundleId: "com.beeper.app", processPath: nil, processName: "Beeper",
                      remoteHost: "api.beeper.com", remotePort: 8443, action: .allow, scope: .domain, profile: "default")
let always = Rule(processBundleId: "com.apple.Safari", processPath: "/Applications/Safari.app/Contents/MacOS/Safari",
                  processName: "Safari", action: .deny, scope: .process, profile: Profile.alwaysName)

let index = MonitorDecisionIndex(rules: [denyDomain, otherProfile, wildcard, portScoped, always], profile: "default")
equal(index.rule(for: domainTarget)?.id, denyDomain.id, "a row shows the rule that was made on that row")
equal(index.rule(for: appTarget)?.id, nil, "a destination rule is not shown as the app row's decision")
equal(index.rule(for: MonitorRuleTarget.app(safari))?.id, always.id,
      "a rule in the always layer is shown on the row it addresses")
let workOnly = MonitorDecisionIndex(rules: [otherProfile], profile: "default")
check(workOnly.rule(for: domainTarget) == nil, "a rule belonging to another profile is not shown as in force")
check(MonitorRuleTarget.of(wildcard) == nil, "a wildcard rule is broader than one row and is not claimed by one")
check(MonitorRuleTarget.of(portScoped) == nil, "a port-scoped rule is narrower than one row and is not claimed by one")

// MARK: - Bounded compute, measured

var load: [Connection] = []
let loadApps = 40
let loadDestinations = 100
for appIndex in 0..<loadApps {
    for destinationIndex in 0..<loadDestinations {
        load.append(connection(app: String(format: "Load%03d", appIndex),
                               bundle: String(format: "com.load.app%03d", appIndex),
                               host: "host\(destinationIndex).load\(appIndex).example",
                               ip: "198.51.100.\(destinationIndex % 250)",
                               bytesIn: Int64(destinationIndex),
                               bytesOut: Int64(appIndex)))
    }
}
let loadShuffled = shuffled(load, seed: 0xC0FFEE)
var order = MonitorRowOrder()
var elapsed: [Double] = []
for round in 0..<5 {
    let started = Date()
    let build = MonitorTreeBuilder.build(connections: loadShuffled, order: order, revision: UInt64(round))
    elapsed.append(Date().timeIntervalSince(started) * 1000)
    order = build.order
    if round == 0 {
        equal(build.snapshot.apps.count, loadApps, "every app in the load is grouped")
        equal(build.snapshot.destinationCount, loadApps * loadDestinations, "every destination in the load is grouped")
        let rolled = build.snapshot.apps.reduce(Int64(0)) { $0 + $1.traffic.total }
        let expected = load.reduce(Int64(0)) { $0 + $1.bytesIn + $1.bytesOut }
        equal(rolled, expected, "the load's rollups add up to every byte that went in")
    }
}
let worst = elapsed.max() ?? 0
let mean = elapsed.reduce(0, +) / Double(elapsed.count)
print(String(format: "monitor tree harness: TIMING: %d connections, %d apps, %d destinations: mean %.1f ms, worst %.1f ms over %d rebuilds",
             load.count, loadApps, loadApps * loadDestinations, mean, worst, elapsed.count))
check(worst < 750, String(format: "grouping %d connections stays bounded (worst %.1f ms, budget 750 ms)", load.count, worst))

// The ordering ledger may not grow without bound as rows come and go.
var churnOrder = MonitorRowOrder()
for round in 0..<40 {
    var churn: [Connection] = []
    for index in 0..<400 {
        churn.append(connection(app: "Churn",
                                bundle: "com.churn.app",
                                host: "r\(round)-h\(index).churn.example",
                                ip: "198.51.100.7"))
    }
    churnOrder = MonitorTreeBuilder.build(connections: churn, order: churnOrder).order
}
check(churnOrder.trackedKeyCount <= MonitorTreeLimits.orderLedgerCapacity + 401,
      "the ordering ledger stays bounded across churn (tracked \(churnOrder.trackedKeyCount))")

if failures > 0 {
    FileHandle.standardError.write(Data("monitor tree harness: \(failures) failure(s)\n".utf8))
    exit(1)
}
print("monitor tree harness: PASS: all checks")
SWIFT

printf 'monitor tree verification: compiling the shipping grouping model\n'
swiftc -O \
  -sdk "$(xcrun --show-sdk-path)" \
  -target arm64-apple-macos13.0 \
  "$ROOT"/Sources/Shared/*.swift \
  "$MODEL" \
  "$TMP/main.swift" \
  -lsqlite3 \
  -o "$TMP/monitor_tree_harness"

"$TMP/monitor_tree_harness"

printf 'monitor tree verification: PASS\n'
