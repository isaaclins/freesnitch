#!/bin/bash
# Regression harness for #199.
#
# A host rule written as `.example.com` must cover example.com and its
# subdomains, exactly like `*.example.com`. It used to be a plain text suffix,
# so a deny for `.example.com` also blocked `notexample.com`, a different
# domain the user never named.
#
# Both matcher paths are checked: the prepared rule set the filter uses for
# every verdict, and the public hostMatches the GUI uses for hit counts and
# coverage. Compiled from the real Sources/Shared.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/main.swift" <<'SWIFT'
import Foundation

var failures = 0
func check(_ condition: Bool, _ what: String) {
    if condition {
        print("host suffix boundary: PASS: \(what)")
    } else {
        print("host suffix boundary: FAIL: \(what)")
        failures += 1
    }
}

func connection(_ host: String) -> Connection {
    Connection(pid: 501,
               processName: "Demo",
               processPath: "/Applications/Demo.app/Contents/MacOS/Demo",
               processBundleId: "com.example.demo",
               remoteHost: host,
               remoteIP: "203.0.113.10",
               remotePort: 443,
               direction: .outgoing)
}

let matcher = RuleMatcher()

// What the filter decides: a deny rule for the pattern, everything else allowed.
func filterDenies(_ pattern: String, _ host: String) -> Bool {
    let rule = Rule(remoteHost: pattern, action: .deny, priority: 100)
    let set = PreparedRuleSet(rules: [rule])
    return matcher.decision(for: connection(host), prepared: set, defaultMode: .silentAllow) == .deny
}

let cases: [(host: String, covered: Bool)] = [
    ("example.com", true),
    ("api.example.com", true),
    ("a.b.example.com", true),
    ("notexample.com", false),
    ("badexample.com", false),
    ("example.com.evil.net", false),
    ("other.com", false),
]

for pattern in [".example.com", "*.example.com"] {
    for c in cases {
        let verb = c.covered ? "matches" : "does not match"
        check(matcher.hostMatches(pattern: pattern, host: c.host) == c.covered,
              "hostMatches: \(pattern) \(verb) \(c.host)")
        check(filterDenies(pattern, c.host) == c.covered,
              "filter verdict: \(pattern) \(verb) \(c.host)")
    }
}

// The two spellings agree everywhere, so neither blocks more than the other.
for c in cases {
    check(matcher.hostMatches(pattern: ".example.com", host: c.host)
              == matcher.hostMatches(pattern: "*.example.com", host: c.host),
          "`.example.com` and `*.example.com` agree for \(c.host)")
}

if failures > 0 {
    print("host suffix boundary verification: FAILED (\(failures))")
    exit(1)
}
print("host suffix boundary verification: PASS")
SWIFT

SHARED=()
while IFS= read -r file; do SHARED+=("$file"); done < <(find "$ROOT/Sources/Shared" -name '*.swift' | sort)

xcrun swiftc -O \
    -sdk "$(xcrun --show-sdk-path)" \
    -target arm64-apple-macos13.0 \
    -o "$WORK/harness" \
    "$WORK/main.swift" "${SHARED[@]}" \
    -lsqlite3

"$WORK/harness"
