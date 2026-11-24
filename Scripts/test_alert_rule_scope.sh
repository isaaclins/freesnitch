#!/bin/bash
# Regression harness for #64 and #224.
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

// #224: the extension reports an address-only flow with the address in BOTH
// fields. "This host" must store an address rule, and that rule must keep
// matching the address when a later flow to it carries a name.
func rememberedThisHost(_ c: Connection, action: RuleAction) -> Rule {
    let (host, ip) = c.rememberedHostDestination
    return Rule(processBundleId: c.processBundleId,
                processPath: c.processPath,
                processName: c.processName,
                remoteHost: host,
                remoteIP: ip,
                direction: c.direction,
                action: action,
                scope: host == nil ? .ip : .domain,
                priority: 100)
}
let numericFlow = connection(host: "203.0.113.10", ip: "203.0.113.10")
let numericDeny = rememberedThisHost(numericFlow, action: .deny)
check(numericDeny.remoteHost == nil && numericDeny.remoteIP == "203.0.113.10" && numericDeny.scope == .ip,
      "This host on an address-only flow stores an address rule (#224)")
let namedLater = connection(host: "api.example.com", ip: "203.0.113.10")
check(matcher.decision(for: namedLater, rules: [numericDeny], defaultMode: .silentAllow) == .deny,
      "the remembered address deny still blocks that address when a later flow carries a name (#224)")
check(matcher.decision(for: connection(host: "api.example.com", ip: "198.51.100.77"), rules: [numericDeny], defaultMode: .silentAllow) == .allow,
      "the remembered address deny does not block the same name at another address")
let v6Deny = rememberedThisHost(connection(host: "2001:db8::10", ip: "2001:db8::10"), action: .deny)
check(v6Deny.remoteHost == nil && v6Deny.remoteIP == "2001:db8::10" && v6Deny.scope == .ip,
      "an IPv6 address-only flow also stores an address rule")
let named = rememberedThisHost(connection(host: "api.example.com", ip: "203.0.113.10"), action: .allow)
check(named.remoteHost == "api.example.com" && named.remoteIP == nil && named.scope == .domain,
      "a flow with a real name still stores a host rule")
check(!matcher.matches(rule: named, connection: connection(host: "other.example.com", ip: "203.0.113.10")),
      "a host rule does not widen to every name sharing that address")
let ipOnlyIP = rememberedThisHost(connection(host: "", ip: "203.0.113.10"), action: .allow)
check(ipOnlyIP.remoteHost == nil && ipOnlyIP.remoteIP == "203.0.113.10",
      "a flow with an empty name still stores its address")
check(source.contains("rememberedHostDestination"),
      "AppState picks the remembered destination with the shared helper")

// And the guard that stops it being created at all.
let source = try String(contentsOfFile: CommandLine.arguments[1], encoding: .utf8)
check(source.contains("scopedIP = ruleIP") && source.contains("remoteIP: scopedIP"),
      "AppState carries the remote address into the remembered rule")
check(source.contains("hasDestination"),
      "AppState refuses to store a remembered rule with an empty destination")

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

"$WORK/harness" "$ROOT/Sources/GUI/ViewModels/AppState.swift"
