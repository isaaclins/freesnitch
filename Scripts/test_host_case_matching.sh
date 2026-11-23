#!/usr/bin/env bash
# Host rules match whatever the letter case (issue #198). DNS names are
# case-insensitive, so a rule typed as API.EXAMPLE.COM covers a flow to
# api.example.com and the other way round. Compiled from the real shared
# sources. Each case goes through the prepared verdict path the extension and
# the DNS proxy use, and through matches(rule:connection:).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-host-case.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

@main
struct Verify {
    static var failures = 0
    static let matcher = RuleMatcher()

    static func check(_ ok: Bool, _ label: String) {
        if ok {
            print("host case harness: PASS: \(label)")
        } else {
            failures += 1
            print("host case harness: FAIL: \(label)")
        }
    }

    static func expect(ruleHost: String, flowHost: String, matches: Bool) {
        // The issue's case: a deny for one app in Silent Allow.
        let rule = Rule(processBundleId: "com.example.app", remoteHost: ruleHost,
                        direction: .any, action: .deny, scope: .process)
        let connection = Connection(pid: 1, processName: "App", processPath: "/Applications/App.app/Contents/MacOS/App",
                                    processBundleId: "com.example.app",
                                    remoteHost: flowHost, remoteIP: "198.51.100.7", remotePort: 443)
        let direct = matcher.matches(rule: rule, connection: connection)
        let prepared = matcher.decision(for: connection, rules: [rule], defaultMode: .silentAllow) == .deny
        check(direct == matches && prepared == matches,
              "\(ruleHost) \(matches ? "matches" : "does not match") \(flowHost) (direct \(direct), prepared \(prepared))")
    }

    static func main() {
        // Exact names, either side in capitals.
        expect(ruleHost: "API.EXAMPLE.COM", flowHost: "api.example.com", matches: true)
        expect(ruleHost: "api.example.com", flowHost: "API.Example.com", matches: true)
        expect(ruleHost: "Api.Example.Com", flowHost: "aPI.eXAMPLE.cOM", matches: true)
        // Wildcards and suffixes.
        expect(ruleHost: "*.EXAMPLE.COM", flowHost: "cdn.example.com", matches: true)
        expect(ruleHost: "*.Example.com", flowHost: "EXAMPLE.COM", matches: true)
        expect(ruleHost: "*.example.com", flowHost: "CDN.EXAMPLE.COM", matches: true)
        expect(ruleHost: ".EXAMPLE.COM", flowHost: "www.example.com", matches: true)
        // Case folding never widens a rule to other names.
        expect(ruleHost: "API.EXAMPLE.COM", flowHost: "api.example.org", matches: false)
        expect(ruleHost: "*.EXAMPLE.COM", flowHost: "notexample.com", matches: false)
        expect(ruleHost: "API.EXAMPLE.COM", flowHost: "www.api.example.com", matches: false)
        // An address in the host field still matches by address.
        expect(ruleHost: "198.51.100.7", flowHost: "Host.Example.com", matches: true)

        // The DNS proxy asks with the query name in lower case and a stub
        // that names no app; a deny for every app typed in capitals answers it.
        let everyApp = Rule(remoteHost: "Tracker.EXAMPLE.net", direction: .any, action: .deny, scope: .domain)
        let query = Connection(pid: 0, processName: "", processPath: "", remoteHost: "tracker.example.net",
                               direction: .outgoing, status: .pending)
        check(matcher.decision(for: query, rules: [everyApp], defaultMode: .silentAllow) == .deny,
              "DNS proxy query tracker.example.net is denied by Tracker.EXAMPLE.net")

        // Fail open stays: an allow typed in capitals in Silent Deny lets the
        // lower-case flow through and leaves other names to the default.
        let allow = Rule(processBundleId: "com.example.app", remoteHost: "UPDATES.EXAMPLE.COM",
                         direction: .any, action: .allow, scope: .process)
        func flow(_ host: String) -> Connection {
            Connection(pid: 1, processName: "App", processPath: "/Applications/App.app/Contents/MacOS/App",
                       processBundleId: "com.example.app", remoteHost: host, remoteIP: "198.51.100.8", remotePort: 443)
        }
        check(matcher.decision(for: flow("updates.example.com"), rules: [allow], defaultMode: .silentDeny) == .allow,
              "allow UPDATES.EXAMPLE.COM lets updates.example.com through in Silent Deny")
        check(matcher.decision(for: flow("ads.example.com"), rules: [allow], defaultMode: .silentDeny) == .deny,
              "allow UPDATES.EXAMPLE.COM leaves ads.example.com to the default")

        if failures == 0 {
            print("host case harness: PASS (all checks)")
        } else {
            print("host case harness: \(failures) FAILURES")
            exit(1)
        }
    }
}
SWIFT

xcrun swiftc -O -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos13.0 -parse-as-library \
  -o "$TMP/run" "$ROOT"/Sources/Shared/*.swift "$TMP/verify.swift"
"$TMP/run"
