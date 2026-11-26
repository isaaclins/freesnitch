#!/usr/bin/env bash
# Insights store open failures keep their reason (#266). Opens a store whose
# directory has the wrong mode, and one over a corrupt database, through the
# helper's own open path, and checks the reason reaches the helper's message
# instead of a bare "unavailable", and that an open store reports no failure.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-insights-open.XXXXXX")"
trap 'chmod -R u+rwx "$TMP" 2>/dev/null || true; rm -rf "$TMP"' EXIT

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

@main
struct InsightsOpenFailureHarness {
    static var failures = 0

    static func check(_ condition: Bool, _ message: String) {
        if condition {
            print("insights open harness: PASS: \(message)")
        } else {
            failures += 1
            FileHandle.standardError.write(Data("insights open harness: FAIL: \(message)\n".utf8))
        }
    }

    static func main() throws {
        let root = CommandLine.arguments[1]
        let uid = getuid()
        let fm = FileManager.default

        // A healthy store opens and reports no failure.
        let good = (root as NSString).appendingPathComponent("good")
        try fm.createDirectory(atPath: good, withIntermediateDirectories: false,
                               attributes: [.posixPermissions: 0o755])
        let goodPath = (good as NSString).appendingPathComponent("Insights/insights.sqlite")
        let opened = InsightsStore.openForHelper { try InsightsStore(path: goodPath, expectedUID: uid) }
        check(opened.store != nil && opened.failure == nil, "a healthy store opens without a failure")

        // Insecure mode: the Insights directory is world-readable.
        let loose = (root as NSString).appendingPathComponent("loose")
        try fm.createDirectory(atPath: loose + "/Insights", withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o755])
        chmod(loose, 0o755)
        chmod(loose + "/Insights", 0o755)
        let insecure = InsightsStore.openForHelper {
            try InsightsStore(path: loose + "/Insights/insights.sqlite", expectedUID: uid)
        }
        check(insecure.store == nil, "an insecure Insights directory does not open")
        let insecureMessage = InsightsStore.unavailableMessage(insecure.failure)
        check(insecureMessage.hasPrefix("insights store is unavailable: "),
              "the helper message keeps the unavailable prefix (\(insecureMessage))")
        check(insecureMessage.contains("insecure owner, type, or mode") && insecureMessage.contains(loose + "/Insights"),
              "the helper message names the insecure path")

        // Wrong owner: the store expects another uid.
        let owned = (root as NSString).appendingPathComponent("owned")
        try fm.createDirectory(atPath: owned, withIntermediateDirectories: false,
                               attributes: [.posixPermissions: 0o755])
        let wrongOwner = InsightsStore.openForHelper {
            try InsightsStore(path: owned + "/Insights/insights.sqlite", expectedUID: uid + 1)
        }
        check(wrongOwner.store == nil && (wrongOwner.failure ?? "").contains("insecure shared support directory"),
              "a wrong owner keeps its reason (\(wrongOwner.failure ?? "nil"))")

        // Corruption: a database file that is not SQLite.
        let corrupt = (root as NSString).appendingPathComponent("corrupt")
        try fm.createDirectory(atPath: corrupt + "/Insights", withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o755])
        chmod(corrupt, 0o755)
        chmod(corrupt + "/Insights", 0o700)
        let corruptFile = corrupt + "/Insights/insights.sqlite"
        try Data(repeating: 0x41, count: 8192).write(to: URL(fileURLWithPath: corruptFile))
        chmod(corruptFile, 0o600)
        let broken = InsightsStore.openForHelper { try InsightsStore(path: corruptFile, expectedUID: uid) }
        check(broken.store == nil, "a corrupt database does not open")
        let brokenReason = broken.failure ?? ""
        check(!brokenReason.isEmpty && brokenReason.lowercased().contains("not a database"),
              "a corrupt database keeps SQLite's reason (\(brokenReason))")

        // Without a reason the message is still the old one, never empty.
        check(InsightsStore.unavailableMessage(nil) == "insights store is unavailable",
              "a missing reason falls back to the plain message")

        if failures > 0 { exit(1) }
        print("insights open harness: PASS: all checks")
    }
}
SWIFT

# The helper must open the store through that path, not `try?`, which drops
# the reason before anything can log or report it.
HELPER="$ROOT/Sources/Helper/HelperService.swift"
if rg -q 'try\? InsightsStore\(' "$HELPER"; then
  echo 'insights open harness: FAIL: HelperService discards the store open error with try?' >&2
  exit 1
fi
rg -q 'InsightsStore.openForHelper\(\)' "$HELPER" || {
  echo 'insights open harness: FAIL: HelperService does not open the store through openForHelper' >&2
  exit 1
}
rg -q 'Insights store failed to open: \\\(failure\)' "$HELPER" || {
  echo 'insights open harness: FAIL: the startup log does not carry the open failure' >&2
  exit 1
}
# The overview report is where the app reads the switch from (#267); a
# store that never opened must refuse it with the reason, not a bare message.
if rg -q '"insights store is unavailable"' "$HELPER"; then
  echo 'insights open harness: FAIL: a helper reply still drops the open failure' >&2
  exit 1
fi

mkdir -p "$TMP/build" "$TMP/root"
xcrun swiftc -O \
  -sdk "$(xcrun --show-sdk-path)" \
  -target arm64-apple-macos13.0 \
  -parse-as-library \
  -o "$TMP/build/run" \
  $(ls "$ROOT"/Sources/Helper/*.swift | rg -v '/main.swift$') \
  "$ROOT"/Sources/Shared/*.swift \
  "$TMP/verify.swift"

"$TMP/build/run" "$TMP/root"
printf 'insights open failure verification: PASS\n'
