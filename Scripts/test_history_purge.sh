#!/usr/bin/env bash
# Delete History removes the saved connection rows from the policy database
# too, not only the Insights store (issue #294).
#
# The helper records every connection into freesnitch.sqlite, whether or not
# Insights recording is on. Delete History used to clear only the Insights
# files, so those rows survived a purge that said every recorded connection
# was removed. This replays the issue's steps against the shipping RuleStore:
# record connections, purge, then read the connections table AND the raw bytes
# of the database and its write-ahead log, because a row that is gone from the
# table but still readable in a freed page or in the log is not deleted.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-history-purge.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
  printf 'history purge verification: FAIL: %s\n' "$*" >&2
  exit 1
}

pass() {
  printf 'history purge verification: PASS: %s\n' "$*"
}

SERVICE="$ROOT/Sources/Helper/HelperService.swift"

# The helper's purge must clear both stores, and must still clear the policy
# database's copy when the Insights store could not be opened.
body="$(awk '/func purgeInsights\(reply:/{on=1} on{print} on&&/^    }$/{exit}' "$SERVICE")"
[[ -n "$body" ]] || fail "purgeInsights was not found in HelperService.swift"
grep -q 'insights.purge()' <<<"$body" || fail "purgeInsights no longer purges the Insights store"
grep -q 'store.purgeConnections()' <<<"$body" || fail "purgeInsights does not delete the policy database's connection rows"
if grep -qE 'guard let insights else' <<<"$body"; then
  fail "purgeInsights returns before deleting connection rows when the Insights store is unavailable"
fi
pass "Delete History clears the Insights store and the policy database's connection rows"

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

@main
struct HistoryPurgeHarness {
    static var failures = 0

    static func check(_ condition: Bool, _ message: String) {
        if condition {
            print("history purge harness: PASS: \(message)")
        } else {
            failures += 1
            FileHandle.standardError.write(Data("history purge harness: FAIL: \(message)\n".utf8))
        }
    }

    static func fileContains(_ path: String, _ needle: String) -> Bool {
        guard let data = FileManager.default.contents(atPath: path) else { return false }
        return data.range(of: Data(needle.utf8)) != nil
    }

    static func main() throws {
        let path = CommandLine.arguments[1]
        let marker = "history-marker-294.example"
        let store = try RuleStore(path: path)

        let rule = Rule(processPath: "/usr/bin/curl", processName: "curl",
                        remoteHost: "kept-rule.example", action: .deny)
        _ = try store.mutatePolicy { $0.rules.append(rule) }

        // Step 1 of the issue: the helper monitors and saves connections.
        // Enough rows that they spill past one page, like a real history.
        for index in 0..<400 {
            let connection = Connection(pid: Int32(1000 + index),
                                        processName: "curl",
                                        processPath: "/usr/bin/curl",
                                        remoteHost: "\(index).\(marker)",
                                        remoteIP: "203.0.113.\(index % 250)",
                                        remotePort: 443,
                                        status: index % 3 == 0 ? .denied : .allowed)
            try store.recordConnection(connection)
        }
        check(store.recentConnections(limit: 1000).count == 400, "the connections were saved before the purge")
        check(fileContains(path, marker) || fileContains(path + "-wal", marker),
              "the saved rows are on disk before the purge")

        // Step 2: Delete History.
        try store.purgeConnections()

        // Steps 3 and 4: read the connections table, then the raw files.
        check(store.recentConnections(limit: 1000).isEmpty, "no connection rows are left after the purge")
        check(store.recentConnections(limit: 1000, status: .denied).isEmpty,
              "no blocked connection rows are left after the purge")
        check(!fileContains(path, marker), "the database file holds no trace of the deleted rows")
        check(!fileContains(path + "-wal", marker), "the write-ahead log holds no trace of the deleted rows")

        // Delete History is about history: the rules stay.
        check((try store.allRules()).contains { $0.id == rule.id }, "the user's rule survives the purge")

        // The store keeps working, and a reopen agrees.
        let later = Connection(pid: 7, processName: "curl", processPath: "/usr/bin/curl",
                               remoteHost: "after.example", remoteIP: "198.51.100.7",
                               remotePort: 443, status: .allowed)
        try store.recordConnection(later)
        check(store.recentConnections(limit: 10).map(\.id) == [later.id], "new connections are saved after the purge")
        let reopened = try RuleStore(path: path)
        check(reopened.recentConnections(limit: 1000).map(\.id) == [later.id],
              "a reopened database shows only what came after the purge")
        check((try reopened.allRules()).contains { $0.id == rule.id }, "a reopened database still has the rule")

        if failures > 0 { exit(1) }
        print("history purge harness: PASS: all checks")
    }
}
SWIFT

mkdir -p "$TMP/build"
xcrun swiftc \
  -sdk "$(xcrun --show-sdk-path)" \
  -parse-as-library \
  -o "$TMP/build/run" \
  "$ROOT"/Sources/Shared/*.swift \
  "$TMP/verify.swift" \
  -lsqlite3
"$TMP/build/run" "$TMP/freesnitch.sqlite"
printf 'history purge verification: PASS\n'
