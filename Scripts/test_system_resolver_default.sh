#!/usr/bin/env bash
# Name lookups keep working while FreeSnitch sets itself up (issue #422).
#
# Every app's name lookup leaves the Mac through one process, the system
# resolver mDNSResponder. Right after setup the network extension holds the
# first live policy: Alert mode and no rules. Before the fix that policy asked
# about the resolver's first lookup and paused it until someone answered, so
# DNS stopped for the whole Mac. In Silent deny it dropped them outright.
#
# Compiled from the real shared sources and run through the prepared verdict
# path the extension uses.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-system-resolver.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

@main
struct Verify {
    static var failures = 0
    static let matcher = RuleMatcher()

    static func check(_ ok: Bool, _ label: String) {
        if ok {
            print("system resolver harness: PASS: \(label)")
        } else {
            failures += 1
            print("system resolver harness: FAIL: \(label)")
        }
    }

    static func flow(path: String, ip: String = "192.168.1.1", port: Int = 53,
                     host: String = "", direction: RuleDirection = .outgoing) -> Connection {
        Connection(pid: 321, processName: (path as NSString).lastPathComponent, processPath: path,
                   remoteHost: host, remoteIP: ip, remotePort: port, direction: direction)
    }

    static func verdict(_ c: Connection, _ rules: [Rule], _ mode: AppMode) -> RuleAction {
        matcher.decision(for: c, prepared: PreparedRuleSet(rules: rules), defaultMode: mode)
    }

    static func main() {
        let resolver = "/usr/sbin/mDNSResponder"
        let lookup = flow(path: resolver)

        // The first live policy after setup: Alert mode, nothing decided yet.
        check(verdict(lookup, [], .alert) == .allow,
              "a fresh install in Alert mode lets the system resolver's lookup through instead of pausing it")
        check(verdict(lookup, [], .silentDeny) == .allow,
              "Silent deny with no rule for the resolver does not cut DNS for the whole Mac")
        check(verdict(lookup, [], .silentAllow) == .allow, "Silent allow is unchanged")
        check(verdict(flow(path: resolver, ip: "1.1.1.1", port: 853), [], .alert) == .allow,
              "encrypted DNS from the resolver (DNS over TLS) is let through too")
        check(verdict(flow(path: resolver, ip: "1.1.1.1", port: 443), [], .alert) == .allow,
              "encrypted DNS from the resolver (DNS over HTTPS profile) is let through too")

        // What the user decided still wins.
        let denyResolver = Rule(processPath: resolver, direction: .outgoing, action: .deny, scope: .process)
        check(verdict(lookup, [denyResolver], .alert) == .deny, "a deny rule the user wrote for the resolver still blocks it")
        let askResolver = Rule(processPath: resolver, direction: .outgoing, action: .ask, scope: .process)
        check(verdict(lookup, [askResolver], .silentAllow) == .ask, "an ask rule the user wrote for the resolver still asks")
        let legacyReverse = Rule(processName: "mDNSResponder", remoteHost: "11.176.156.17.in-addr.arpa", action: .deny)
        check(verdict(flow(path: resolver, host: "11.176.156.17.in-addr.arpa"), [legacyReverse], .alert) == .deny,
              "an older deny rule for one reverse lookup still applies")

        // Nothing else gets the default allow.
        check(verdict(flow(path: "/usr/bin/dig"), [], .alert) == .ask,
              "an app that talks to a DNS server itself is still asked about")
        check(verdict(flow(path: "/usr/bin/dig"), [], .silentDeny) == .deny,
              "an app that talks to a DNS server itself is still blocked in Silent deny")
        check(verdict(flow(path: "/tmp/x/mDNSResponder"), [], .alert) == .ask,
              "a copy named mDNSResponder outside the system volume is treated like any other app")
        check(verdict(flow(path: "/usr/sbin/mDNSResponderHelper"), [], .alert) == .ask,
              "a different system tool whose name starts the same is not the resolver")
        check(verdict(flow(path: resolver, direction: .incoming), [], .alert) == .ask,
              "incoming connections to the resolver keep the normal default")

        if failures == 0 {
            print("system resolver harness: PASS (all checks)")
        } else {
            print("system resolver harness: \(failures) FAILURES")
            exit(1)
        }
    }
}
SWIFT

xcrun swiftc -O -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos13.0 -parse-as-library \
  -o "$TMP/run" "$ROOT"/Sources/Shared/*.swift "$TMP/verify.swift"
"$TMP/run"
