#!/usr/bin/env bash
# Regression harness for #217.
#
# "Allow Anyway" on a blocklist entry adds an allow rule for that one name.
# The DNS proxy used to refuse every listed name regardless of rules, so the
# lookup still got NXDOMAIN after the rule was stored. This drives the real
# DNSPolicy verdict the proxy answers each query with, using the exact rule the
# GUI writes, and checks that only that name gets through: the rest of the
# list, a broad allow with no host, an allow for one app, a disabled or expired override and a
# higher-priority deny all keep it blocked.
#
# Compiled from the real Sources/Helper and Sources/Shared, never a copy.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-allow-anyway.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

@main
struct Verify {
    static var failures = 0

    static func check(_ got: RuleAction, _ want: RuleAction, _ what: String) {
        if got == want {
            print("allow anyway: PASS: \(what)")
        } else {
            print("allow anyway: FAIL: \(what): got \(got), want \(want)")
            failures += 1
        }
    }

    static func main() {
        let list: Set<String> = ["ads.example", "tracker.example", "listed.example"]
        let allowAnyway = BlocklistDomain.allowAnywayRule(for: "ads.example", listName: "Ads")

        for mode in [AppMode.alert, .silentAllow, .silentDeny] {
            let policy = DNSPolicy(mode: mode, rules: [allowAnyway], blocklist: list)
            check(policy.verdict(forName: "ads.example"), .allow, "\(mode): the allowed name resolves")
            check(policy.verdict(forName: "tracker.example"), .deny, "\(mode): another listed name stays blocked")
            check(policy.verdict(forName: "x.tracker.example"), .deny, "\(mode): a subdomain of another listed name stays blocked")
        }

        let before = DNSPolicy(mode: .silentAllow, rules: [], blocklist: list)
        check(before.verdict(forName: "ads.example"), .deny, "without the rule the listed name is blocked")
        check(before.verdict(forName: "unlisted.example"), .allow, "an unlisted name follows the mode")

        let alertBefore = DNSPolicy(mode: .alert, rules: [], blocklist: list)
        check(alertBefore.verdict(forName: "ads.example"), .deny, "Alert mode blocks a listed name instead of asking")
        check(alertBefore.verdict(forName: "unlisted.example"), .ask, "Alert mode asks about an unlisted name")

        var disabled = allowAnyway
        disabled.enabled = false
        check(DNSPolicy(mode: .silentAllow, rules: [disabled], blocklist: list).verdict(forName: "ads.example"),
              .deny, "a disabled override does not pass the list")

        var expired = allowAnyway
        expired.expiresAt = Date(timeIntervalSinceNow: -60)
        check(DNSPolicy(mode: .silentAllow, rules: [expired], blocklist: list).verdict(forName: "ads.example"),
              .deny, "an expired override does not pass the list")

        let allowEverything = Rule(action: .allow, priority: 100)
        check(DNSPolicy(mode: .silentAllow, rules: [allowEverything], blocklist: list).verdict(forName: "ads.example"),
              .deny, "an allow with no host never switches a list off")
        check(DNSPolicy(mode: .silentAllow, rules: [allowEverything, allowAnyway], blocklist: list).verdict(forName: "ads.example"),
              .allow, "the override still counts behind a broader allow that decided first")
        check(DNSPolicy(mode: .silentAllow, rules: [allowEverything, allowAnyway], blocklist: list).verdict(forName: "tracker.example"),
              .deny, "the broader allow plus the override keeps the rest of the list blocked")

        let byName = Rule(processName: "Safari", remoteHost: "listed.example", action: .allow, priority: 100)
        check(DNSPolicy(mode: .silentAllow, rules: [byName], blocklist: list).verdict(forName: "listed.example"),
              .deny, "an app's allow rule (by name) does not open the name to every lookup")
        let byPath = Rule(processPath: "/Applications/Safari.app", remoteHost: "listed.example", action: .allow, priority: 100)
        check(DNSPolicy(mode: .silentAllow, rules: [byPath], blocklist: list).verdict(forName: "listed.example"),
              .deny, "an app's allow rule (by path) does not open the name to every lookup")
        let byBundle = Rule(processBundleId: "com.apple.Safari", remoteHost: "listed.example", action: .allow, priority: 100)
        check(DNSPolicy(mode: .silentAllow, rules: [byBundle], blocklist: list).verdict(forName: "listed.example"),
              .deny, "an app's allow rule (by bundle id) does not open the name to every lookup")

        check(DNSPolicy(mode: .silentAllow, rules: [allowAnyway], blocklist: list).verdict(forName: "www.ads.example"),
              .deny, "a subdomain of the allowed name stays blocked by the list")
        let wildcard = Rule(remoteHost: "*.tracker.example", action: .allow, priority: 100)
        let wildcardPolicy = DNSPolicy(mode: .silentAllow, rules: [wildcard], blocklist: list)
        check(wildcardPolicy.verdict(forName: "cdn.tracker.example"), .allow,
              "an app-less wildcard allow opens the names it covers")
        check(wildcardPolicy.verdict(forName: "listed.example"), .deny,
              "an app-less wildcard allow leaves names it doesn't cover blocked")

        let deny = Rule(remoteHost: "ads.example", action: .deny, priority: 100)
        check(DNSPolicy(mode: .silentAllow, rules: [deny, allowAnyway], blocklist: list).verdict(forName: "ads.example"),
              .deny, "a higher-priority deny for the name still wins")

        check(DNSPolicy(mode: .silentAllow, rules: [allowAnyway], blocklist: list)
                .replacingBlocklist(list.union(["more.example"])).verdict(forName: "ads.example"),
              .allow, "the override survives a blocklist refresh")
        check(DNSPolicy(mode: .silentAllow, rules: [allowAnyway], blocklist: list)
                .replacingRules([]).verdict(forName: "ads.example"),
              .deny, "removing the rule blocks the name again")

        if failures > 0 {
            print("allow anyway: \(failures) failure(s)")
            exit(1)
        }
        print("blocklist allow anyway verification: PASS")
    }
}
SWIFT

SDK="$(xcrun --show-sdk-path)"
# shellcheck disable=SC2046
xcrun swiftc -O -sdk "$SDK" -target arm64-apple-macos13.0 -parse-as-library \
  -o "$TMP/verify" \
  $(ls "$ROOT"/Sources/Helper/*.swift | grep -v '/main.swift$') \
  "$ROOT"/Sources/Shared/*.swift \
  "$TMP/verify.swift"
"$TMP/verify"
