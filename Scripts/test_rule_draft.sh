#!/usr/bin/env bash
# What the Add Rule sheet is filled with when a rule is started from a
# destination in Insights (#446): the app as the same bundle folder the Rules
# page would pick, a name when one is known and the address only when not, and
# a bundle id only when no path was recorded.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-rule-draft.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/main.swift" <<'SWIFT'
import Foundation

var failures = 0
func equal<T: Equatable>(_ actual: T, _ expected: T, _ message: String) {
    if actual == expected {
        print("rule draft: PASS: \(message)")
    } else {
        failures += 1
        FileHandle.standardError.write(Data("rule draft: FAIL: \(message) (expected \(expected), got \(actual))\n".utf8))
    }
}

// An app's main executable becomes its bundle folder, like choosing it on the Rules page.
let slack = RuleDraft(processPath: "/Applications/Slack.app/Contents/MacOS/Slack",
                      processBundleId: "com.tinyspeck.slackmacgap",
                      domain: "telemetry.example.net", remoteIP: "203.0.113.9")
equal(slack.appFilePath, "/Applications/Slack.app", "main executable resolves to its app bundle")
equal(slack.processBundleID, "", "bundle id is left out when the app is named by its folder")
equal(slack.fallbackBundleID, "com.tinyspeck.slackmacgap", "bundle id is kept for an app that is gone from disk")
equal(slack.remoteHost, "telemetry.example.net", "a known name fills the host")
equal(slack.remoteIP, "", "the address is left out when a name is known")
equal(slack.scope, .domain, "a named destination is domain scoped")

// A helper inside an app resolves to the outermost app, so the rule covers it and its siblings.
let helper = RuleDraft(processPath: "/Applications/Slack.app/Contents/Frameworks/Slack Helper.app/Contents/MacOS/Slack Helper",
                       processBundleId: "com.tinyspeck.slackmacgap.helper", domain: nil, remoteIP: "203.0.113.9")
equal(helper.appFilePath, "/Applications/Slack.app", "a helper resolves to the app that contains it")
equal(helper.remoteHost, "", "no name means no host")
equal(helper.remoteIP, "203.0.113.9", "the address fills the IP field")
equal(helper.scope, .ip, "an address-only destination is IP scoped")

// A command-line tool stays the executable itself.
let curl = RuleDraft(processPath: "/usr/bin/curl", processBundleId: nil, domain: "example.org", remoteIP: nil)
equal(curl.appFilePath, "/usr/bin/curl", "a tool outside any app is its own executable")
equal(curl.fallbackBundleID, nil, "no bundle id to fall back to")

// Rollups past 14 days keep only the bundle id: the rule names the app by it.
let rollup = RuleDraft(processPath: nil, processBundleId: "com.spotify.client", domain: "  ", remoteIP: "198.51.100.4")
equal(rollup.appFilePath, nil, "no path recorded")
equal(rollup.processBundleID, "com.spotify.client", "bundle id fills the field when no path was recorded")
equal(rollup.remoteHost, "", "a blank name counts as no name")
equal(rollup.scope, .ip, "blank name falls back to the address")

// From No Name for every app: just the address.
let anyApp = RuleDraft(processPath: nil, processBundleId: nil, domain: nil, remoteIP: "198.51.100.4")
equal(anyApp.appFilePath, nil, "no app for an any-app rule")
equal(anyApp.processBundleID, "", "no bundle id for an any-app rule")
equal(anyApp.remoteIP, "198.51.100.4", "the address is filled")

// A tool shipped inside an app is not the app: it stays its own executable.
equal(RuleDraft.appFilePath(forExecutable: "/Applications/Xcode.app/Contents/Developer/usr/bin/git"),
      "/Applications/Xcode.app/Contents/Developer/usr/bin/git", "a tool inside a bundle is not widened to the app")
// Insights may record the bundle folder itself (demo data, rollups): kept as it is.
equal(RuleDraft.appFilePath(forExecutable: "/Applications/Zed.app"), "/Applications/Zed.app", "a bundle folder stays the bundle")
// A path with no app bundle in it is kept as it is.
equal(RuleDraft.appFilePath(forExecutable: "/opt/tools/bin/thing"), "/opt/tools/bin/thing", "no .app component keeps the path")

if failures > 0 {
    FileHandle.standardError.write(Data("rule draft: \(failures) failure(s)\n".utf8))
    exit(1)
}
print("rule draft: all checks passed")
SWIFT

xcrun swiftc -O \
    "$ROOT/Sources/Shared/Models.swift" \
    "$ROOT/Sources/GUI/Views/RuleDraft.swift" \
    "$TMP/main.swift" \
    -o "$TMP/rule-draft" 2>"$TMP/build.log" || { cat "$TMP/build.log" >&2; exit 1; }
"$TMP/rule-draft"
