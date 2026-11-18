#!/usr/bin/env bash
# Name lookups keep working while FreeSnitch sets itself up (issue #422).
#
# Every app's name lookup leaves the Mac through one process, the system
# resolver mDNSResponder. Right after setup the network extension holds the
# first live policy: Alert mode and no rules. Before the fix that policy asked
# about the resolver's first lookup and paused it until someone answered, so
# DNS stopped for the whole Mac. In Silent deny it dropped them outright.
#
# Compiled from the real shared sources and the extension's signature check,
# and run through the prepared verdict path the extension uses. The default
# allow needs both the system path and Apple's signature; every other process
# keeps the default mode on port 53 too, so DNS stays a channel FreeSnitch
# can ask about and block for apps (#30).
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

    /// The extension vouches for the signature only after its check passed;
    /// `signed` stands for that check's answer.
    static func verdict(_ c: Connection, _ rules: [Rule], _ mode: AppMode, signed: Bool = true) -> RuleAction {
        matcher.explainedDecision(for: c, prepared: PreparedRuleSet(rules: rules), defaultMode: mode,
                                  systemResolverSigned: signed).action
    }

    static func staticCodePasses(_ path: String, _ requirementText: String) -> Bool {
        var code: SecStaticCode?
        var requirement: SecRequirement?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code,
              SecRequirementCreateWithString(requirementText as CFString, [], &requirement) == errSecSuccess,
              let requirement else { return false }
        return SecStaticCodeCheckValidity(code, [], requirement) == errSecSuccess
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

        // Path AND signature (#30): neither alone gets the default allow.
        check(verdict(lookup, [], .alert, signed: false) == .ask,
              "the resolver's path without a passed signature check is asked about like any app")
        check(verdict(lookup, [], .silentDeny, signed: false) == .deny,
              "the resolver's path without a passed signature check is blocked in Silent deny like any app")
        check(verdict(flow(path: "/tmp/x/mDNSResponder"), [], .alert, signed: true) == .ask,
              "Apple's signed resolver copied anywhere else is asked about like any app")
        check(verdict(flow(path: "/usr/bin/dig"), [], .silentDeny, signed: true) == .deny,
              "another process gets nothing from the signature flag")

        // Every other process's port-53 flow is matched exactly as before (#30).
        let dig = flow(path: "/usr/bin/dig", ip: "8.8.8.8")
        let denyDig = Rule(processPath: "/usr/bin/dig", direction: .outgoing, action: .deny, scope: .process)
        let allowDig = Rule(processPath: "/usr/bin/dig", direction: .outgoing, action: .allow, scope: .process)
        let denyPort53 = Rule(remotePort: 53, action: .deny)
        check(verdict(dig, [denyDig], .silentAllow) == .deny, "a deny rule for an app still blocks its own DNS on port 53")
        check(verdict(dig, [allowDig], .silentDeny) == .allow, "an allow rule for an app still lets its own DNS through")
        check(verdict(dig, [denyPort53], .silentAllow) == .deny, "a rule for port 53 still blocks an app's direct DNS")
        check(verdict(dig, [], .silentAllow) == .allow, "an app's direct DNS keeps Silent allow's default")

        // The requirement the extension checks running code against matches
        // Apple's resolver and nothing else on this Mac.
        let requirement = RuleMatcher.systemResolverRequirement
        check(staticCodePasses("/usr/sbin/mDNSResponder", requirement),
              "Apple's mDNSResponder on this Mac passes the resolver requirement")
        check(!staticCodePasses("/usr/bin/dig", requirement), "Apple's dig does not pass the resolver requirement")
        check(!staticCodePasses("/usr/sbin/mDNSResponderHelper", requirement),
              "Apple's mDNSResponderHelper does not pass the resolver requirement")
        check(!SystemResolverIdentity().isSigned(auditToken: nil),
              "a flow without an audit token is never vouched for")
        check(!SystemResolverIdentity().isSigned(auditToken: Data(repeating: 0, count: 32)),
              "an audit token that names no running process is never vouched for")

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
  -o "$TMP/run" "$ROOT"/Sources/Shared/*.swift "$ROOT/Sources/NetExt/SystemResolverIdentity.swift" "$TMP/verify.swift"
"$TMP/run"
