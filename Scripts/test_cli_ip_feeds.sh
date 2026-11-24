#!/usr/bin/env bash
# The command line's IP and CIDR feed commands (#209): `ip-feeds` lists,
# `ip-feed <id|name> on|off` toggles, and bad input is refused with a reason
# instead of being read as something else. Built from the real CLI and shared
# sources; nothing here talks to a helper.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-cli-ip-feeds.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/check.swift" <<'SWIFT'
import Foundation

@main
struct Check {
    static func main() {
        var failures: [String] = []
        func expect(_ ok: Bool, _ message: String) { if !ok { failures.append(message) } }
        func parse(_ args: [String]) -> Result<CLICommand, CLIError> {
            do { return .success(try CLIParser.parse(args).command) } catch let error as CLIError {
                return .failure(error)
            } catch { fatalError("unexpected error \(error)") }
        }

        if case .success(.ipFeeds) = parse(["ip-feeds"]) {} else { failures.append("`ip-feeds` must list the feeds") }
        if case .success(.ipFeeds) = parse(["ip-feeds", "--json"]) {} else { failures.append("`ip-feeds --json` must list the feeds") }
        if case .success(.ipFeed(let ref, let on)) = parse(["ip-feed", "Spamhaus DROP", "on"]) {
            expect(ref == "Spamhaus DROP" && on, "`ip-feed NAME on` must keep the name and turn it on")
        } else { failures.append("`ip-feed NAME on` must parse") }
        if case .success(.ipFeed(_, let on)) = parse(["ip-feed", "5B3B2F52-1F3C-4C2E-9E1E-2C0E0B6A0001", "off"]) {
            expect(!on, "`ip-feed ID off` must turn it off")
        } else { failures.append("`ip-feed ID off` must parse") }
        for bad in [["ip-feed"], ["ip-feed", "x"], ["ip-feed", "x", "maybe"], ["ip-feed", "x", "on", "extra"], ["ip-feeds", "refresh"]] {
            if case .success = parse(bad) { failures.append("`\(bad.joined(separator: " "))` must be refused") }
        }
        expect(CLIHelp.text(for: ["ip-feed"]).contains("ip-feed <id|name> <on|off>"), "`help ip-feed` must explain the command")
        expect(CLIHelp.text(for: []).contains("ip-feeds"), "the main help must list ip-feeds")

        let feeds = IPBlocklistCatalog.defaults
        let report = IPFeedsReport(feeds: feeds, status: IPBlocklistPolicy.disabled.status)
        expect(report.feed(named: "spamhaus drop")?.id == feeds[1].id, "a feed must be found by name in any case")
        expect(report.feed(named: feeds[2].id.uuidString.lowercased())?.id == feeds[2].id, "a feed must be found by id in any case")
        expect(report.feed(named: "nope") == nil, "an unknown feed must not match")

        guard failures.isEmpty else {
            failures.forEach { FileHandle.standardError.write(Data("cli ip feeds: FAIL: \($0)\n".utf8)) }
            exit(1)
        }
        print("cli ip feeds: PASS")
    }
}
SWIFT

# shellcheck disable=SC2046
xcrun swiftc -parse-as-library -o "$TMP/run" \
  $(ls "$ROOT"/Sources/CLI/*.swift | grep -v '/CLIEntry.swift$') \
  "$ROOT"/Sources/Shared/*.swift "$TMP/check.swift"
"$TMP/run"
