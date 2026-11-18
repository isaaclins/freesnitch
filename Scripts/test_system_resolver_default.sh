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

    /// `sent` stands for the extension's answer about the process that sent
    /// the flow: at the resolver's path and passing Apple's signature check.
    static func verdict(_ c: Connection, _ rules: [Rule], _ mode: AppMode, sent: Bool) -> RuleAction {
        matcher.explainedDecision(for: c, prepared: PreparedRuleSet(rules: rules), defaultMode: mode,
                                  sentBySystemResolver: sent).action
    }

    static func staticCodePasses(_ path: String, _ requirementText: String) -> Bool {
        var code: SecStaticCode?
        var requirement: SecRequirement?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code,
              SecRequirementCreateWithString(requirementText as CFString, [], &requirement) == errSecSuccess,
              let requirement else { return false }
        return SecStaticCodeCheckValidity(code, [], requirement) == errSecSuccess
    }

    static func ownAuditToken() -> Data? {
        var token = audit_token_t()
        var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
        let result = withUnsafeMutablePointer(to: &token) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
            }
        }
        guard result == KERN_SUCCESS else { return nil }
        return withUnsafeBytes(of: &token) { Data($0) }
    }

    static func main() {
        let resolver = "/usr/sbin/mDNSResponder"
        let lookup = flow(path: resolver)
        // A lookup the resolver sends on Safari's behalf is attributed to Safari.
        let safari = "/Applications/Safari.app/Contents/MacOS/Safari"
        let onBehalf = flow(path: safari)

        // The first live policy after setup: Alert mode, nothing decided yet.
        check(verdict(lookup, [], .alert, sent: true) == .allow,
              "a fresh install in Alert mode lets the system resolver's lookup through instead of pausing it")
        check(verdict(onBehalf, [], .alert, sent: true) == .allow,
              "a lookup the resolver sends on an app's behalf is let through too")
        check(verdict(lookup, [], .silentDeny, sent: true) == .allow,
              "Silent deny with no rule for the resolver does not cut DNS for the whole Mac")
        check(verdict(lookup, [], .silentAllow, sent: true) == .allow, "Silent allow is unchanged")
        check(verdict(flow(path: resolver, ip: "1.1.1.1", port: 853), [], .alert, sent: true) == .allow,
              "encrypted DNS from the resolver (DNS over TLS) is let through too")
        check(verdict(flow(path: resolver, ip: "1.1.1.1", port: 443), [], .alert, sent: true) == .allow,
              "encrypted DNS from the resolver (DNS over HTTPS profile) is let through too")

        // What the user decided still wins.
        let denyResolver = Rule(processPath: resolver, direction: .outgoing, action: .deny, scope: .process)
        check(verdict(lookup, [denyResolver], .alert, sent: true) == .deny,
              "a deny rule the user wrote for the resolver still blocks it")
        let askResolver = Rule(processPath: resolver, direction: .outgoing, action: .ask, scope: .process)
        check(verdict(lookup, [askResolver], .silentAllow, sent: true) == .ask,
              "an ask rule the user wrote for the resolver still asks")
        let legacyReverse = Rule(processName: "mDNSResponder", remoteHost: "11.176.156.17.in-addr.arpa", action: .deny)
        check(verdict(flow(path: resolver, host: "11.176.156.17.in-addr.arpa"), [legacyReverse], .alert, sent: true) == .deny,
              "an older deny rule for one reverse lookup still applies")
        let denySafari = Rule(processPath: safari, direction: .outgoing, action: .deny, scope: .process)
        check(verdict(onBehalf, [denySafari], .alert, sent: true) == .deny,
              "a deny rule for the app a lookup is made for still applies to it")
        check(verdict(flow(path: resolver, direction: .incoming), [], .alert, sent: true) == .ask,
              "incoming connections keep the normal default")

        // Path AND signature (#30): the extension vouches only when both hold.
        check(!RuleMatcher.isSystemResolver(senderPath: resolver, passesRequirement: false),
              "the resolver's path without a passed signature check is not the resolver")
        check(!RuleMatcher.isSystemResolver(senderPath: "/tmp/x/mDNSResponder", passesRequirement: true),
              "Apple's signed resolver copied anywhere else is not the resolver")
        check(!RuleMatcher.isSystemResolver(senderPath: "/usr/sbin/mDNSResponderHelper", passesRequirement: true),
              "a different system tool whose name starts the same is not the resolver")
        check(RuleMatcher.isSystemResolver(senderPath: resolver, passesRequirement: true),
              "Apple's resolver at its system path is the resolver")
        check(verdict(lookup, [], .alert, sent: false) == .ask,
              "a flow at the resolver's path the extension did not vouch for is asked about like any app")
        check(verdict(lookup, [], .silentDeny, sent: false) == .deny,
              "a flow at the resolver's path the extension did not vouch for is blocked in Silent deny like any app")

        // Every other process's port-53 flow is matched exactly as before (#30).
        let dig = flow(path: "/usr/bin/dig", ip: "8.8.8.8")
        let denyDig = Rule(processPath: "/usr/bin/dig", direction: .outgoing, action: .deny, scope: .process)
        let allowDig = Rule(processPath: "/usr/bin/dig", direction: .outgoing, action: .allow, scope: .process)
        let denyPort53 = Rule(remotePort: 53, action: .deny)
        check(verdict(dig, [], .alert, sent: false) == .ask, "an app's direct DNS is still asked about in Alert mode")
        check(verdict(dig, [], .silentDeny, sent: false) == .deny, "an app's direct DNS is still blocked in Silent deny")
        check(verdict(dig, [], .silentAllow, sent: false) == .allow, "an app's direct DNS keeps Silent allow's default")
        check(verdict(dig, [denyDig], .silentAllow, sent: false) == .deny, "a deny rule for an app still blocks its direct DNS")
        check(verdict(dig, [allowDig], .silentDeny, sent: false) == .allow, "an allow rule for an app still lets its direct DNS through")
        check(verdict(dig, [denyPort53], .silentAllow, sent: false) == .deny, "a rule for port 53 still blocks an app's direct DNS")

        // The requirement the extension checks running code against matches
        // Apple's resolver and nothing else on this Mac, and the check on a
        // real process answers no for anything that is not the resolver.
        let requirement = RuleMatcher.systemResolverRequirement
        check(staticCodePasses(resolver, requirement), "Apple's mDNSResponder on this Mac passes the resolver requirement")
        check(!staticCodePasses("/usr/bin/dig", requirement), "Apple's dig does not pass the resolver requirement")
        check(!staticCodePasses("/usr/sbin/mDNSResponderHelper", requirement),
              "Apple's mDNSResponderHelper does not pass the resolver requirement")
        let identity = SystemResolverIdentity()
        check(!identity.isSystemResolver(processAuditToken: nil), "a flow without an audit token is never vouched for")
        check(!identity.isSystemResolver(processAuditToken: Data(repeating: 0, count: 32)),
              "an audit token that names no running process is never vouched for")
        if let own = ownAuditToken() {
            check(SystemResolverIdentity.pid(from: own) == getpid(), "the pid is read from the audit token")
            check(!identity.isSystemResolver(processAuditToken: own), "a running process that is not the resolver is never vouched for")
        } else {
            check(false, "could not read this harness's own audit token")
        }

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
