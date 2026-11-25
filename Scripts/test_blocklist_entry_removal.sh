#!/usr/bin/env bash
# Regression harness for #220: removing a name from a blocklist left it on the
# entries page, because the pane only reloaded when the list or the search
# changed. Drives the real store through removals and checks what the pane
# watches and which page it asks for. Built from the real sources, never a copy.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-entry-removal.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation
typealias P = BlocklistEntryPaging
var failures = 0
func check(_ ok: Bool, _ what: String) {
    print("entry removal: \(ok ? "PASS" : "FAIL"): \(what)")
    if !ok { failures += 1 }
}
@main struct Verify {
    static func main() throws {
        let store = try RuleStore(path: CommandLine.arguments[1])
        let size = 100
        let list = try store.addLocalBlocklist(name: "Mine", domains: (0..<102).map { "n\($0).example.com" })
        func page(_ offset: Int) -> BlocklistEntryPage {
            let p = store.blocklistEntries(blocklistID: list.id, search: "", offset: offset, limit: size)
            return BlocklistEntryPage(entries: p.entries, total: p.total, offset: offset)
        }
        let victim = page(0).entries[3]
        let after = try store.removeBlocklistEntries(id: list.id, domains: [victim])
        check(after.id == list.id && P.ContentVersion(after) != P.ContentVersion(list),
              "a removal keeps the list's id but changes what the pane watches")
        check(!page(0).entries.contains(victim) && page(0).total == 101, "the page asked for again has neither the name nor the old total")
        check(P.offsetToRetry(page(0), offset: 0, pageSize: size) == nil, "a page with names is shown as it is")

        let last = page(size).entries
        let emptied = try store.removeBlocklistEntries(id: list.id, domains: last)
        check(last.count == 1 && P.ContentVersion(emptied) != P.ContentVersion(after), "removing the only name on the last page is noticed")
        check(P.offsetToRetry(page(size), offset: size, pageSize: size) == 0, "the pane moves back to the page that is now last")
        check(P.offsetToRetry(BlocklistEntryPage(entries: [], total: 0, offset: size), offset: size, pageSize: size) == nil,
              "an empty list is shown as empty")
        if failures > 0 { exit(1) }
    }
}
SWIFT

xcrun swiftc -sdk "$(xcrun --show-sdk-path)" -target "$(uname -m)-apple-macos13.0" -parse-as-library -o "$TMP/run" \
  "$ROOT"/Sources/Shared/*.swift "$ROOT"/Sources/GUI/Views/BlocklistEntryPaging.swift "$TMP/verify.swift"
"$TMP/run" "$TMP/rules.db"
