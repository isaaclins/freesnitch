#!/usr/bin/env bash
# The rules and connection database is private to its owner (#290).
#
# The Insights store kept its folder at 0700 and its files at 0600, but the
# main database was created with whatever the helper's umask gave it, which for
# a launchd daemon is readable by every account on the Mac. That file holds
# every rule, profile, blocklist and recorded connection.
#
# This checks, against real files:
#   - a fresh store creates its folder 0700 and the database, -wal and -shm 0600
#   - an older install (folder 0755, files 0644) is tightened on the next open,
#     with its rules kept
#   - a database or folder that is a symlink, or owned by another account, is
#     refused instead of opened
#   - the helper opens the store for root only
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-rule-store-permissions.XXXXXX")"
trap 'chmod -R u+rwx "$TMP" 2>/dev/null || true; rm -rf "$TMP"' EXIT

if ! grep -q 'RuleStore(path: dbPath, owner: 0)' "$ROOT/Sources/Helper/HelperService.swift"; then
  echo "rule store permissions: FAIL: the helper does not open the store for root only"
  exit 1
fi

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation
import SQLite3

@main
struct Verify {
    static var failures = 0

    static func check(_ ok: Bool, _ label: String) {
        print("rule store permissions: \(ok ? "PASS" : "FAIL"): \(label)")
        if !ok { failures += 1 }
    }

    static func mode(_ path: String) -> mode_t? {
        var info = stat()
        guard lstat(path, &info) == 0 else { return nil }
        return info.st_mode & 0o7777
    }

    static func rule(_ host: String) -> Rule {
        Rule(processPath: "/Applications/Test.app/Contents/MacOS/Test", remoteHost: host, action: .allow)
    }

    static func addRule(_ store: RuleStore, _ host: String) throws {
        try store.mutatePolicy { state in state.appendToActiveProfile(rule(host)) }
    }

    static func main() throws {
        let base = CommandLine.arguments[1]

        // A fresh install.
        let fresh = base + "/fresh/FreeSnitch"
        let freshDB = fresh + "/freesnitch.sqlite"
        do {
            let store = try RuleStore(path: freshDB)
            try addRule(store, "fresh.example")
            check(mode(fresh) == 0o700, "a new folder is created 0700")
            for suffix in ["", "-wal", "-shm"] {
                check(mode(freshDB + suffix) == 0o600, "a new freesnitch.sqlite\(suffix) is 0600")
            }
        }

        // An older install, written before the store set any mode.
        let old = base + "/old/FreeSnitch"
        let oldDB = old + "/freesnitch.sqlite"
        do {
            let store = try RuleStore(path: oldDB)
            try addRule(store, "kept.example")
        }
        chmod(old, 0o755)
        for suffix in ["", "-wal", "-shm"] where mode(oldDB + suffix) != nil {
            chmod(oldDB + suffix, 0o644)
        }
        // The WAL is left behind, as after a crash, so it is there to tighten.
        _ = open(oldDB + "-wal", O_CREAT | O_WRONLY, 0o644)
        chmod(oldDB + "-wal", 0o644)
        do {
            let store = try RuleStore(path: oldDB)
            check(mode(old) == 0o700, "an older 0755 folder is tightened to 0700")
            for suffix in ["", "-wal", "-shm"] where mode(oldDB + suffix) != nil {
                check(mode(oldDB + suffix) == 0o600, "an older 0644 freesnitch.sqlite\(suffix) is tightened to 0600")
            }
            let hosts = (try? store.allRules().map { $0.remoteHost ?? "" }) ?? []
            check(hosts.contains("kept.example"), "the older install keeps its rules")
        }

        // A database that is a link to some other file.
        let linked = base + "/linked"
        try FileManager.default.createDirectory(atPath: linked, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: base + "/elsewhere.sqlite", contents: nil)
        chmod(base + "/elsewhere.sqlite", 0o644)
        symlink(base + "/elsewhere.sqlite", linked + "/freesnitch.sqlite")
        check((try? RuleStore(path: linked + "/freesnitch.sqlite")) == nil, "a database that is a symlink is refused")
        check(mode(base + "/elsewhere.sqlite") == 0o644, "the symlink's target is left alone")

        // A sidecar that is a link.
        let sidecar = base + "/sidecar"
        try FileManager.default.createDirectory(atPath: sidecar, withIntermediateDirectories: true)
        symlink(base + "/elsewhere.sqlite", sidecar + "/freesnitch.sqlite-wal")
        check((try? RuleStore(path: sidecar + "/freesnitch.sqlite")) == nil, "a -wal file that is a symlink is refused")

        // A folder that is a link.
        try FileManager.default.createDirectory(atPath: base + "/realdir", withIntermediateDirectories: true)
        symlink(base + "/realdir", base + "/linkdir")
        check((try? RuleStore(path: base + "/linkdir/freesnitch.sqlite")) == nil, "a folder that is a symlink is refused")

        // An existing install owned by another account (the store expects
        // someone else): refused, and nothing in it is changed.
        let other = base + "/other/FreeSnitch"
        try FileManager.default.createDirectory(atPath: other, withIntermediateDirectories: true)
        chmod(other, 0o755)
        FileManager.default.createFile(atPath: other + "/freesnitch.sqlite", contents: nil)
        chmod(other + "/freesnitch.sqlite", 0o644)
        check((try? RuleStore(path: other + "/freesnitch.sqlite", owner: geteuid() + 1)) == nil,
              "an existing folder owned by another account is refused")
        check(mode(other) == 0o755 && mode(other + "/freesnitch.sqlite") == 0o644,
              "a refused install is left as it was")

        if failures > 0 {
            print("rule store permissions: \(failures) check(s) failed")
            exit(1)
        }
        print("rule store permissions: all checks passed")
    }
}
SWIFT

xcrun swiftc -O -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos13.0 -parse-as-library \
  -o "$TMP/run" "$ROOT"/Sources/Shared/*.swift "$TMP/verify.swift" -lsqlite3
"$TMP/run" "$TMP"
