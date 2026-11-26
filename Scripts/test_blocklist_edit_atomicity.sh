#!/usr/bin/env bash
# Deterministic harness for blocklist hand edits that fail part way (issue #270).
#
# Compiled from the real shared sources against a real RuleStore. A trigger on
# a second connection makes SQLite refuse one name, the way a full disk or an
# I/O error would stop the write loop part way. Each command must then fail
# without leaving anything behind:
#
#   1. Creating a local list that fails leaves no list, no profile selection
#      and no stored edits, and the same name can be created afterwards.
#   2. Adding names that fails keeps the stored edits, the browsable names and
#      the count exactly as they were.
#   3. Removing names that fails keeps them, and keeps them out of the
#      "removed" edits, so the next refresh does not drop them either.
#   4. Resetting hand edits that fails keeps the edits and the names.
#   5. Once SQLite accepts the writes again, every command works normally.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-blocklist-atomic.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

SDK="$(xcrun --show-sdk-path)"
TARGET="arm64-apple-macos13.0"

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation
import SQLite3

@main
struct Verify {
    static var failures: [String] = []
    static var passed = 0

    static func expect(_ condition: Bool, _ message: String) {
        if condition { passed += 1 } else { failures.append(message) }
    }

    static func names(_ store: RuleStore, _ id: UUID) -> Set<String> {
        Set(store.blocklistEntries(blocklistID: id, search: "", offset: 0, limit: 1000).entries)
    }

    static func sql(_ path: String, _ statement: String) -> Bool {
        var db: OpaquePointer?
        defer { sqlite3_close(db) }
        return sqlite3_open(path, &db) == SQLITE_OK && sqlite3_exec(db, statement, nil, nil, nil) == SQLITE_OK
    }

    static func main() {
        let path = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("freesnitch-blatomic-\(UUID().uuidString).sqlite")
        defer { try? FileManager.default.removeItem(atPath: path) }
        guard let store = try? RuleStore(path: path) else {
            FileHandle.standardError.write(Data("blocklist edit atomicity harness: FAIL: could not open a RuleStore\n".utf8))
            exit(1)
        }
        let profile = Profile.defaultName

        // SQLite refuses to store or delete this one name, after earlier
        // writes of the same command already went through.
        guard sql(path, """
        CREATE TRIGGER fail_insert BEFORE INSERT ON blocklist_entries
            WHEN NEW.domain = 'boom.example' BEGIN SELECT RAISE(ABORT, 'disk I/O error'); END;
        CREATE TRIGGER fail_delete BEFORE DELETE ON blocklist_entries
            WHEN OLD.domain = 'boom.example' BEGIN SELECT RAISE(ABORT, 'disk I/O error'); END;
        """) else {
            FileHandle.standardError.write(Data("blocklist edit atomicity harness: FAIL: could not install the failure\n".utf8))
            exit(1)
        }

        // 1. Creating a local list.
        let before = store.allBlocklists().count
        let selectedBefore = (try? store.allBlocklists(forProfile: profile))?.filter(\.enabled).count
        do {
            _ = try store.addLocalBlocklist(name: "Mine", domains: ["a.example", "boom.example", "c.example"],
                                            profileName: profile)
            failures.append("creating a list whose names cannot be stored must fail")
        } catch {}
        expect(store.allBlocklists().count == before, "a failed create left a list behind")
        expect(!store.allBlocklists().contains { $0.name == "Mine" }, "a failed create left the list visible")
        expect((try? store.allBlocklists(forProfile: profile))?.filter(\.enabled).count == selectedBefore,
               "a failed create left a profile selection behind")
        let local: BlocklistInfo
        do {
            local = try store.addLocalBlocklist(name: "Mine", domains: ["a.example", "b.example"], profileName: profile)
        } catch {
            failures.append("the name of a failed create must be free again, got \(error)"); finish()
        }
        expect(names(store, local.id) == ["a.example", "b.example"], "a fresh local list must hold its names")

        // 2. Adding names.
        let editsBefore = store.blocklistEdits(id: local.id)
        do {
            _ = try store.addBlocklistEntries(id: local.id, domains: ["c.example", "boom.example", "d.example"])
            failures.append("adding a name that cannot be stored must fail")
        } catch {}
        expect(store.blocklistEdits(id: local.id) == editsBefore, "a failed add changed the stored edits")
        expect(names(store, local.id) == ["a.example", "b.example"], "a failed add left some names stored: \(names(store, local.id))")
        expect(store.blocklist(id: local.id)?.entryCount == 2, "a failed add changed the count")

        // 3. Removing names. boom.example is stored directly, past the trigger.
        _ = sql(path, "DROP TRIGGER fail_insert;")
        guard (try? store.addBlocklistEntries(id: local.id, domains: ["boom.example", "e.example"])) != nil else {
            failures.append("adding must work once SQLite accepts the write"); finish()
        }
        let afterAdd = store.blocklistEdits(id: local.id)
        do {
            _ = try store.removeBlocklistEntries(id: local.id, domains: ["a.example", "boom.example", "e.example"])
            failures.append("removing a name that cannot be deleted must fail")
        } catch {}
        expect(store.blocklistEdits(id: local.id) == afterAdd, "a failed remove changed the stored edits")
        expect(store.blocklistEdits(id: local.id).removed.isEmpty, "a failed remove recorded names as removed")
        expect(names(store, local.id) == ["a.example", "b.example", "boom.example", "e.example"],
               "a failed remove deleted some names: \(names(store, local.id))")
        expect(store.blocklist(id: local.id)?.entryCount == 4, "a failed remove changed the count")

        // 4. Resetting hand edits.
        do {
            try store.clearBlocklistEdits(id: local.id)
            failures.append("a reset whose names cannot be deleted must fail")
        } catch {}
        expect(store.blocklistEdits(id: local.id) == afterAdd, "a failed reset dropped the stored edits")
        expect(names(store, local.id).count == 4, "a failed reset deleted some names")

        // 5. Everything works again once SQLite does.
        _ = sql(path, "DROP TRIGGER fail_delete;")
        do {
            let info = try store.removeBlocklistEntries(id: local.id, domains: ["a.example", "boom.example"])
            expect(info.entryCount == 2, "a remove that works must update the count")
            expect(names(store, local.id) == ["b.example", "e.example"], "a remove that works must delete the names")
            try store.clearBlocklistEdits(id: local.id)
            expect(store.blocklistEdits(id: local.id) == BlocklistEdits(), "a reset that works must clear the edits")
        } catch {
            failures.append("commands must work once SQLite accepts the writes, got \(error)")
        }
        finish()
    }

    static func finish() -> Never {
        if failures.isEmpty {
            print("blocklist edit atomicity harness: PASS (\(passed) checks)")
            exit(0)
        }
        for f in failures { FileHandle.standardError.write(Data("blocklist edit atomicity harness: FAIL: \(f)\n".utf8)) }
        exit(1)
    }
}
SWIFT

xcrun swiftc -O -sdk "$SDK" -target "$TARGET" -parse-as-library \
  -o "$TMP/run" \
  "$ROOT"/Sources/Shared/*.swift \
  "$TMP/verify.swift"

"$TMP/run"
