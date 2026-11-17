#!/usr/bin/env bash
# Deterministic checks for how a rule's process path matches (issue #158).
# Compiled from the real shared sources. Each case goes through the prepared
# verdict path the extension and the DNS proxy use, and through
# matches(rule:connection:), which shares the same path check.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-path-match.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

@main
struct Verify {
    static var failures = 0
    static let matcher = RuleMatcher()

    static func expect(rulePath: String, processPath: String, matches: Bool) {
        let rule = Rule(processPath: rulePath, direction: .any, action: .deny, scope: .process)
        let connection = Connection(pid: 1, processName: "x", processPath: processPath, remoteIP: "198.51.100.1", remotePort: 443)
        let direct = matcher.matches(rule: rule, connection: connection)
        let prepared = matcher.decision(for: connection, rules: [rule], defaultMode: .silentAllow) == .deny
        let label = "\(rulePath) \(matches ? "matches" : "does not match") \(processPath)"
        if direct == matches && prepared == matches {
            print("path match harness: PASS: \(label)")
        } else {
            failures += 1
            print("path match harness: FAIL: \(label) (direct \(direct), prepared \(prepared))")
        }
    }

    static func main() {
        // A plain executable matches itself, not tools whose name starts the same.
        expect(rulePath: "/usr/local/bin/node", processPath: "/usr/local/bin/node", matches: true)
        expect(rulePath: "/usr/local/bin/node", processPath: "/usr/local/bin/nodemon", matches: false)
        expect(rulePath: "/usr/bin/ssh", processPath: "/usr/bin/ssh-agent", matches: false)
        // A bundle or folder covers everything inside it, with or without the slash.
        expect(rulePath: "/Applications/Discord.app/", processPath: "/Applications/Discord.app/Contents/MacOS/Discord", matches: true)
        expect(rulePath: "/Applications/Discord.app/",
               processPath: "/Applications/Discord.app/Contents/Frameworks/Discord Helper.app/Contents/MacOS/Discord Helper",
               matches: true)
        expect(rulePath: "/Applications/Discord.app", processPath: "/Applications/Discord.app/Contents/MacOS/Discord", matches: true)
        expect(rulePath: "/Applications/Discord.app", processPath: "/Applications/Discord.app", matches: true)
        expect(rulePath: "/Applications/Discord.app", processPath: "/Applications/Discord.app.old/Contents/MacOS/Discord", matches: false)
        expect(rulePath: "/Applications/Discord.app/", processPath: "/Applications/Discord.app.old/Contents/MacOS/Discord", matches: false)
        expect(rulePath: "/opt/homebrew/bin/", processPath: "/opt/homebrew/bin/wget", matches: true)
        expect(rulePath: "/usr/local/bin/node", processPath: "/usr/local/bin", matches: false)
        // A slash after a plain executable never matched it and still doesn't.
        expect(rulePath: "/usr/bin/curl/", processPath: "/usr/bin/curl", matches: false)
        // A root rule still covers every process.
        expect(rulePath: "/", processPath: "/usr/bin/curl", matches: true)

        // An allow for node no longer lets nodemon through in Silent deny:
        // nodemon falls back to the default mode, as with any app without a rule.
        let allowNode = Rule(processPath: "/usr/local/bin/node", direction: .any, action: .allow, scope: .process)
        func conn(_ path: String) -> Connection {
            Connection(pid: 1, processName: "x", processPath: path, remoteIP: "198.51.100.1", remotePort: 443)
        }
        let nodeVerdict = matcher.decision(for: conn("/usr/local/bin/node"), rules: [allowNode], defaultMode: .silentDeny)
        let nodemonVerdict = matcher.decision(for: conn("/usr/local/bin/nodemon"), rules: [allowNode], defaultMode: .silentDeny)
        if nodeVerdict == .allow && nodemonVerdict == .deny {
            print("path match harness: PASS: allow for node in Silent deny allows node and leaves nodemon to the default")
        } else {
            failures += 1
            print("path match harness: FAIL: allow for node in Silent deny (node \(nodeVerdict), nodemon \(nodemonVerdict))")
        }

        if failures == 0 {
            print("path match harness: PASS (all checks)")
        } else {
            print("path match harness: \(failures) FAILURES")
            exit(1)
        }
    }
}
SWIFT

xcrun swiftc -O -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos13.0 -parse-as-library \
  -o "$TMP/run" "$ROOT"/Sources/Shared/*.swift "$TMP/verify.swift"
"$TMP/run"
