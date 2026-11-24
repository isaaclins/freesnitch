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
check(remembered(approved, .thisHost).map { $0.remoteIP == approved.remoteIP } == true,
      "the remembered rule carries the remote address")
check(remembered(connection(host: "", ip: ""), .thisHost) == nil,
      "a remembered rule with an empty destination is never stored")

// #223: "This address and port" needs both. A flow macOS reports with port 0
// (ICMP, or no port known) must not get it, because the rule it saved had no
// port and so covered the address on every port.
func flow(ip: String, port: Int) -> Connection {
    Connection(pid: 501, processName: "Demo",
               processPath: "/Applications/Demo.app/Contents/MacOS/Demo",
               processBundleId: "com.example.demo",
               remoteHost: "", remoteIP: ip, remotePort: port, direction: .outgoing)
}
// `rememberedRule` is what AppState.resolveAlert stores, so these run the real
// rule building rather than a copy of it.
func remembered(_ c: Connection, _ scope: AlertRememberScope, allow: Bool = false) -> Rule? {
    c.rememberedRule(scope: scope, allow: allow, profile: Profile.alwaysName, expiresAt: nil)
}

let withPort = flow(ip: "203.0.113.10", port: 443)
let portZero = flow(ip: "203.0.113.10", port: 0)
check(withPort.availableRememberScopes == [.anywhere, .thisHost, .thisAddressAndPort],
      "an address with a real port is offered all three scopes")
check(portZero.availableRememberScopes == [.anywhere, .thisHost],
      "an address with port 0 is NOT offered address and port")
check(!flow(ip: "203.0.113.10", port: 70000).availableRememberScopes.contains(.thisAddressAndPort),
      "a port outside 1...65535 is NOT offered address and port")
check(!flow(ip: "", port: 443).availableRememberScopes.contains(.thisAddressAndPort),
      "a port without an address is NOT offered address and port")
check(["0.0.0.0", "::", "::0", "0:0:0:0:0:0:0:0"].allSatisfy { !flow(ip: $0, port: 443).availableRememberScopes.contains(.thisAddressAndPort) },
      "the unspecified address, in any spelling, is NOT offered address and port")

// Port 0: no rule at all, where the old code saved the address with no port.
check(remembered(portZero, .thisAddressAndPort) == nil,
      "answering address and port for an alert with port 0 remembers nothing")
check(remembered(portZero, .thisAddressAndPort, allow: true) == nil,
      "the same holds for an allow")
let wideDeny = Rule(processBundleId: withPort.processBundleId,
                    processPath: withPort.processPath,
                    processName: withPort.processName,
                    remoteIP: withPort.remoteIP,
                    remotePort: nil,
                    direction: .outgoing, action: .deny, scope: .ip, priority: 100)
check(matcher.decision(for: withPort, rules: [wideDeny], defaultMode: .alert) == .deny,
      "a remembered address rule with no port really does deny every port, which is why port 0 must never produce one")
// A host-named flow with port 0 and an address: address and port has nothing
// to pin either, and it must not widen to the host.
let namedPortZero = Connection(pid: 501, processName: "Demo",
                               processPath: "/Applications/Demo.app/Contents/MacOS/Demo",
                               processBundleId: "com.example.demo",
                               remoteHost: "example.com", remoteIP: "203.0.113.10", remotePort: 0, direction: .outgoing)
check(remembered(namedPortZero, .thisAddressAndPort) == nil,
      "a named flow with port 0 does not widen address and port to the host")

// With a real pair, the rule is pinned to that address and port.
if let pinnedDeny = remembered(withPort, .thisAddressAndPort) {
    check(pinnedDeny.remoteIP == "203.0.113.10" && pinnedDeny.remotePort == 443 && pinnedDeny.remoteHost == nil,
          "an address-and-port answer stores that address and port")
    check(matcher.decision(for: withPort, rules: [pinnedDeny], defaultMode: .alert) == .deny,
          "an address-and-port deny blocks the port it was made for")
    check(matcher.decision(for: flow(ip: "203.0.113.10", port: 8443), rules: [pinnedDeny], defaultMode: .alert) != .deny,
          "an address-and-port deny does NOT block the same address on another port")
    check(matcher.decision(for: flow(ip: "203.0.113.11", port: 443), rules: [pinnedDeny], defaultMode: .alert) != .deny,
          "an address-and-port deny does NOT block another address on the same port")
} else {
    check(false, "an address with a real port produces an address-and-port rule")
}

// The other scopes keep their meaning.
check(remembered(portZero, .thisHost).map { $0.remoteIP == "203.0.113.10" && $0.remotePort == nil && $0.scope == .ip } == true,
      "This host for an address-only flow stores that address")
check(remembered(namedPortZero, .thisHost).map { $0.remoteHost == "example.com" && $0.remoteIP == nil && $0.scope == .domain } == true,
      "This host for a named flow stores the name")
check(remembered(withPort, .anywhere).map { $0.remoteHost == nil && $0.remoteIP == nil && $0.scope == .process } == true,
      "Anywhere stores the app with no destination")
let noApp = Connection(pid: 1, processName: "", processPath: "", remoteHost: "", remoteIP: "203.0.113.10", remotePort: 443, direction: .outgoing)
check(remembered(noApp, .anywhere).map { $0.remoteIP == "203.0.113.10" } == true,
      "Anywhere without an app identity narrows to the host")
check(remembered(flow(ip: "0.0.0.0", port: 443), .thisHost) == nil && remembered(flow(ip: "::", port: 443), .thisHost) == nil,
      "an unspecified destination remembers nothing")

// The GUI is wired to it: AppState stores what rememberedRule returns and the
// dialog offers only availableRememberScopes.
check(source.contains("alert.connection.rememberedRule(scope: scope"),
      "AppState stores the rule rememberedRule builds")
let view = try String(contentsOfFile: CommandLine.arguments[2], encoding: .utf8)
check(view.contains("ForEach(availableScopes)") && view.contains("alert.connection.availableRememberScopes")
        && view.contains("scope: effectiveScope"),
      "the alert only offers and answers with the scopes the connection can have")

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
