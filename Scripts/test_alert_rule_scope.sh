#!/bin/bash
# Regression harness for #64 and #223.
#
# A remembered alert decision for a destination with no host name must produce
# a rule that matches ONLY that address. The failure this guards against is
# silent: both destination tests in PreparedRule.matches are `if let`, so a rule
# carrying an empty host and no address loses both tests and degrades into
# "this process, any destination". An allow then grants far more than the user
# approved, and it looks like an ordinary per-destination rule in the UI.
#
# Compiled from the real Sources/Shared, so it fails if the matcher's treatment
# of an empty destination ever changes too.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/main.swift" <<'SWIFT'
import Foundation

var failures = 0
func check(_ condition: Bool, _ what: String) {
    if condition {
        print("alert rule scope: PASS: \(what)")
    } else {
        print("alert rule scope: FAIL: \(what)")
        failures += 1
    }
}

func connection(host: String, ip: String, process: String = "/Applications/Demo.app/Contents/MacOS/Demo") -> Connection {
    Connection(pid: 501,
               processName: "Demo",
               processPath: process,
               processBundleId: "com.example.demo",
               remoteHost: host,
               remoteIP: ip,
               remotePort: 443,
               direction: .outgoing)
}

// The destination the user actually approved, and an unrelated one.
let approved = connection(host: "", ip: "203.0.113.10")
let unrelated = connection(host: "", ip: "198.51.100.77")

// The rule AppState.resolveAlert builds today for an address-only destination.
let fixed = Rule(processBundleId: approved.processBundleId,
                 processPath: approved.processPath,
                 processName: approved.processName,
                 remoteHost: nil,
                 remoteIP: approved.remoteIP,
                 remotePort: approved.remotePort,
                 direction: approved.direction,
                 action: .allow,
                 scope: .ip,
                 priority: 100)

let matcher = RuleMatcher()
check(matcher.matches(rule: fixed, connection: approved),
      "a remembered address-only decision matches the address it approved")
check(!matcher.matches(rule: fixed, connection: unrelated),
      "a remembered address-only decision does NOT match a different destination")
check(matcher.decision(for: approved, rules: [fixed], defaultMode: .alert) == .allow,
      "the approved destination is allowed by the remembered rule")
check(matcher.decision(for: unrelated, rules: [fixed], defaultMode: .alert) != .allow,
      "an unrelated destination is NOT allowed by the remembered rule")

// The exact shape of the bug: empty host, no address, address scope.
let broken = Rule(processBundleId: approved.processBundleId,
                  processPath: approved.processPath,
                  processName: approved.processName,
                  remoteHost: "",
                  remoteIP: nil,
                  remotePort: nil,
                  direction: approved.direction,
                  action: .allow,
                  scope: .ip,
                  priority: 100)
check(matcher.matches(rule: broken, connection: unrelated),
      "a rule with an empty destination really does match everything, which is why it must never be stored")

// And the guard that stops it being created at all.
let source = try String(contentsOfFile: CommandLine.arguments[1], encoding: .utf8)
check(source.contains("scopedIP = ruleIP") && source.contains("remoteIP: scopedIP"),
      "AppState carries the remote address into the remembered rule")
check(source.contains("hasDestination"),
      "AppState refuses to store a remembered rule with an empty destination")

// #223: "This address and port" needs both. A flow macOS reports with port 0
// (ICMP, or no port known) must not get it, because the rule it saved had no
// port and so covered the address on every port.
func flow(ip: String, port: Int) -> Connection {
    Connection(pid: 501, processName: "Demo",
               processPath: "/Applications/Demo.app/Contents/MacOS/Demo",
               processBundleId: "com.example.demo",
               remoteHost: "", remoteIP: ip, remotePort: port, direction: .outgoing)
}
check(flow(ip: "203.0.113.10", port: 443).canPinAddressAndPort,
      "an address with a real port can be remembered as address and port")
check(!flow(ip: "203.0.113.10", port: 0).canPinAddressAndPort,
      "an address with port 0 is NOT offered as address and port")
check(!flow(ip: "", port: 443).canPinAddressAndPort,
      "a port without an address is NOT offered as address and port")
check(!flow(ip: "0.0.0.0", port: 443).canPinAddressAndPort && !flow(ip: "::", port: 443).canPinAddressAndPort,
      "the unspecified address is NOT offered as address and port")

// What the old code saved for that alert: the address with no port. It denies
// the address on a port the alert never showed, which is the bug.
let portZero = flow(ip: "203.0.113.10", port: 0)
let wideDeny = Rule(processBundleId: portZero.processBundleId,
                    processPath: portZero.processPath,
                    processName: portZero.processName,
                    remoteIP: portZero.remoteIP,
                    remotePort: nil,
                    direction: .outgoing, action: .deny, scope: .ip, priority: 100)
check(matcher.decision(for: flow(ip: "203.0.113.10", port: 443), rules: [wideDeny], defaultMode: .alert) == .deny,
      "a remembered address rule with no port really does deny every port, which is why port 0 must never produce one")

// The rule AppState builds when the pair is real is pinned to that port.
let pinned = Rule(processBundleId: approved.processBundleId,
                  processPath: approved.processPath,
                  processName: approved.processName,
                  remoteIP: approved.remoteIP,
                  remotePort: approved.remotePort,
                  direction: .outgoing, action: .deny, scope: .ip, priority: 100)
check(matcher.decision(for: approved, rules: [pinned], defaultMode: .alert) == .deny,
      "an address-and-port deny blocks the port it was made for")
check(matcher.decision(for: flow(ip: approved.remoteIP, port: 8443), rules: [pinned], defaultMode: .alert) != .deny,
      "an address-and-port deny does NOT block the same address on another port")

check(source.contains("effectiveScope == .thisAddressAndPort && !alert.connection.canPinAddressAndPort"),
      "AppState remembers nothing for address and port when the pair is not real")
check(!source.contains("remotePort > 0 ? alert.connection.remotePort : nil"),
      "AppState no longer saves an address-and-port answer without its port")
let view = try String(contentsOfFile: CommandLine.arguments[2], encoding: .utf8)
check(view.contains("ForEach(availableScopes)") && view.contains("alert.connection.canPinAddressAndPort"),
      "the alert only offers address and port when the connection has both")

if failures > 0 {
    print("alert rule scope verification: FAILED (\(failures))")
    exit(1)
}
print("alert rule scope verification: PASS")
SWIFT

SHARED=()
while IFS= read -r file; do SHARED+=("$file"); done < <(find "$ROOT/Sources/Shared" -name '*.swift' | sort)

xcrun swiftc -O \
    -sdk "$(xcrun --show-sdk-path)" \
    -target arm64-apple-macos13.0 \
    -o "$WORK/harness" \
    "$WORK/main.swift" "${SHARED[@]}" \
    -lsqlite3

"$WORK/harness" "$ROOT/Sources/GUI/ViewModels/AppState.swift" "$ROOT/Sources/GUI/Views/ConnectionAlert.swift"
