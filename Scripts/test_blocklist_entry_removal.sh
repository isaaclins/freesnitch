#!/usr/bin/env bash
# Regression harness for #220.
#
# Removing a name from a blocklist left it on the entries page with the old
# total: the pane only asked the helper again when the selected list or the
# search changed, and a removal changes neither. This drives the real store the
# helper answers from through the removal, and checks that the list the GUI
# gets back differs in what the pane now watches, that the page asked for again
# no longer has the name, and that removing the only name on the last page
# moves back one page instead of showing an empty one.
#
# Compiled from the real Sources/Shared and the pane's paging rules, never a copy.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-entry-removal.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
SDK="$(xcrun --show-sdk-path)"
TARGET="$(uname -m)-apple-macos13.0"

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

@main
struct Verify {
    static var failures = 0
    static var passed = 0
    static let pageSize = 100

    static func check(_ ok: Bool, _ what: String) {
        if ok { passed += 1; print("entry removal: PASS: \(what)") }
        else { failures += 1; print("entry removal: FAIL: \(what)") }
    }

    static func main() throws {
        setvbuf(stdout, nil, _IONBF, 0)
        let store = try RuleStore(path: CommandLine.arguments[1])
        // Two names past a full page, so one is still on the second page after the first removal, like a list a user pages through.
        let names = (0..<(pageSize + 2)).map { String(format: "n%03d.example.com", $0) }
        let before = try store.addLocalBlocklist(name: "Mine", domains: names)
        let id = before.id

        // Remove a name that is on the first page.
        let firstPage = store.blocklistEntries(blocklistID: id, search: "", offset: 0, limit: pageSize)
        let victim = firstPage.entries[3]
        let afterFirst = try store.removeBlocklistEntries(id: id, domains: [victim])
        check(afterFirst.id == before.id, "the list keeps its id, so the old reload on a list change never fired")
        check(BlocklistEntryPaging.ContentVersion(afterFirst) != BlocklistEntryPaging.ContentVersion(before),
              "the list the helper reports after a removal differs in what the pane watches")
        let reloaded = store.blocklistEntries(blocklistID: id, search: "", offset: 0, limit: pageSize)
        check(!reloaded.entries.contains(victim), "the page asked for again no longer shows the removed name")
        check(reloaded.total == names.count - 1, "the page asked for again has the new total")
        check(BlocklistEntryPaging.offsetToRetry(emptyPage: reloaded.entries, total: reloaded.total,
                                                 offset: 0, pageSize: pageSize) == nil,
              "a page that still has names is shown as it is")

        // Remove the only name on the last page while that page is open.
        let lastPage = store.blocklistEntries(blocklistID: id, search: "", offset: pageSize, limit: pageSize)
        check(lastPage.entries.count == 1, "the second page holds one name")
        let previous = store.blocklistEntries(blocklistID: id, search: "", offset: 0, limit: 1).total
        let afterLast = try store.removeBlocklistEntries(id: id, domains: lastPage.entries)
        check(BlocklistEntryPaging.ContentVersion(afterLast) != BlocklistEntryPaging.ContentVersion(afterFirst),
              "removing the last name on a page is noticed too")
        let emptied = store.blocklistEntries(blocklistID: id, search: "", offset: pageSize, limit: pageSize)
        check(emptied.entries.isEmpty && emptied.total == previous - 1, "the old offset is now past the end")
        let retry = BlocklistEntryPaging.offsetToRetry(emptyPage: emptied.entries, total: emptied.total,
                                                       offset: pageSize, pageSize: pageSize)
        check(retry == 0, "the pane moves back to the page that is now the last one")
        if let retry {
            let shown = store.blocklistEntries(blocklistID: id, search: "", offset: retry, limit: pageSize)
            check(shown.entries.count == pageSize && shown.total == pageSize, "that page shows the names that are left")
        }

        // A list that really is empty, or an empty search, stays as it is.
        check(BlocklistEntryPaging.offsetToRetry(emptyPage: [], total: 0, offset: pageSize, pageSize: pageSize) == nil,
              "an empty list is shown as empty instead of paging back")
        check(BlocklistEntryPaging.offsetToRetry(emptyPage: [], total: 5, offset: 0, pageSize: pageSize) == nil,
              "the first page is never retried")

        guard failures == 0 else { print("entry removal: \(failures) FAIL"); exit(1) }
        print("entry removal: \(passed) assertions PASS")
    }
}
SWIFT

printf 'entry removal harness: building from the real shared sources\n'
xcrun swiftc -O -sdk "$SDK" -target "$TARGET" -parse-as-library \
  -o "$TMP/run" \
  "$ROOT"/Sources/Shared/*.swift \
  "$ROOT"/Sources/GUI/Views/BlocklistEntryPaging.swift \
  "$TMP/verify.swift"

"$TMP/run" "$TMP/rules.db"
