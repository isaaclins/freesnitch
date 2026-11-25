#!/usr/bin/env bash
# A failed rules read is an error, never an empty or partial policy (#279).
#
# The rules query used to answer `[]` when it could not be prepared, and to
# return whatever rows it had collected when stepping stopped on an error. The
# helper put that list into the authoritative snapshot as if it were the
# user's whole policy, and a policy change built on it started from no rules.
#
# This saves rules in a real database, then breaks only the rules read from a
# second connection, the way a damaged or changed table would, while the
# settings and profile reads keep working:
#   - the rules query cannot be prepared (the table is gone)
#   - the rules query is prepared but stepping fails part way
# Every policy read must throw, a policy change must refuse to commit, and once
# the table is back the full policy reads again with nothing lost.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-rules-read-failure.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation
import SQLite3

@main
struct Verify {
    static var failures = 0

    static func check(_ ok: Bool, _ label: String) {
        if ok {
            print("rules read failure: PASS: \(label)")
        } else {
            failures += 1
            print("rules read failure: FAIL: \(label)")
        }
    }

    static func isReadFailure(_ body: () throws -> Void) -> Bool {
        do {
            try body()
            return false
        } catch RuleStore.StoreError.policyReadFailed {
            return true
        } catch {
            print("rules read failure: unexpected error \(error)")
            return false
        }
    }

    /// A second connection, like any other writer of the same file.
    static func sql(_ path: String, _ statement: String) {
        var db: OpaquePointer?
        guard sqlite3_open(path, &db) == SQLITE_OK else { fatalError("open failed") }
        defer { sqlite3_close(db) }
        var err: UnsafeMutablePointer<CChar>?
        if sqlite3_exec(db, statement, nil, nil, &err) != SQLITE_OK {
            fatalError("setup SQL failed: \(err.map { String(cString: $0) } ?? "unknown")")
        }
    }

    static func main() throws {
        let path = CommandLine.arguments[1]
        let store = try RuleStore(path: path)
        _ = store.beginPolicySession()

        let always = Rule(remoteHost: "always.example", direction: .outgoing, action: .deny,
                          scope: .domain, priority: 70, profile: Profile.alwaysName)
        let first = Rule(remoteHost: "tracker.example", direction: .outgoing, action: .deny,
                         scope: .domain, priority: 60, profile: Profile.defaultName)
        let poison = Rule(remoteHost: "poison.example", direction: .outgoing, action: .allow,
                          scope: .domain, priority: 10, profile: Profile.alwaysName)
        _ = try store.mutatePolicy { draft in
            draft.mode = .silentDeny
            draft.rules = [always, first, poison]
        }
        _ = try store.createProfile(name: "Work")
        let healthy = try store.activePolicyState()
        let activeBefore = store.activeProfileName()
        check(healthy.rules.count == 3, "the saved policy reads in full before anything breaks")

        func expectEveryReadFails(_ how: String) {
            check(isReadFailure { _ = try store.activePolicyState() },
                  "\(how): the enforced policy read throws instead of publishing a short policy")
            check(isReadFailure { _ = try store.policyState() },
                  "\(how): the raw policy read throws")
            check(isReadFailure { _ = try store.allRules() },
                  "\(how): the rule list read throws")
            check(isReadFailure { _ = try store.activeLayeredRules() },
                  "\(how): the layered rules read throws")
            check(isReadFailure { _ = try store.activeProfilePolicy() },
                  "\(how): the active profile's policy read throws")
            check(isReadFailure {
                _ = try store.mutateActivePolicy { draft in draft.mode = .alert }
            }, "\(how): a policy change refuses to start from the failed read")
            check(store.getSetting("mode") == AppMode.silentDeny.rawValue,
                  "\(how): the refused change did not commit its mode")
            check(isReadFailure { _ = try store.setActiveProfile(name: "Work") },
                  "\(how): a profile switch whose policy cannot be read is refused")
            check(store.activeProfileName() == activeBefore,
                  "\(how): the refused switch left the active profile as it was")
        }

        // 1. The rules query cannot be prepared.
        sql(path, "ALTER TABLE rules RENAME TO rules_away;")
        expectEveryReadFails("prepare fails")
        sql(path, "ALTER TABLE rules_away RENAME TO rules;")

        // 2. The rules query is prepared, then a row fails while stepping. A
        //    view with the same columns raises a runtime error on one row. The
        //    row is in the Always layer, which every policy read includes.
        let columns = "id, process_bundle_id, process_path, process_name, remote_host, remote_ip, remote_port, "
            + "direction, action, scope, priority, profile, group_name, "
            + "CASE WHEN remote_host = 'poison.example' THEN json('{') ELSE notes END AS notes, "
            + "enabled, temporary, created_at, expires_at, last_used_at, hit_count, process_team_id"
        sql(path, "ALTER TABLE rules RENAME TO rules_real; CREATE VIEW rules AS SELECT \(columns) FROM rules_real;")
        expectEveryReadFails("a step fails")
        sql(path, "DROP VIEW rules; ALTER TABLE rules_real RENAME TO rules;")

        // 3. Back to normal: everything reads, nothing was lost or changed.
        let restored = try store.activePolicyState()
        check(Set(restored.rules.map(\.id)) == Set(healthy.rules.map(\.id)),
              "once the table is readable the full policy is back")
        check(restored.mode == healthy.mode && restored.generation == healthy.generation,
              "the refused changes left mode and generation untouched")

        if failures == 0 {
            print("rules read failure: PASS (all checks)")
        } else {
            print("rules read failure: \(failures) FAILURES")
            exit(1)
        }
    }
}
SWIFT

# The helper side: a failed read is answered as a failed snapshot and never
# republished, so the extension, pf and the DNS proxy keep the last full policy.
HELPER="$ROOT/Sources/Helper/HelperService.swift"
body() { awk -v sig="$2" 'index($0, sig) { on = 1 } on { print } on && /^    }$/ { exit }' "$1"; }
snapshot_reply="$(body "$HELPER" 'func getAuthoritativeSnapshot(')"
grep -Fq 'snapshot = try authoritativeSnapshot()' <<<"$snapshot_reply" \
  && grep -Fq 'reply(Data())' <<<"$snapshot_reply" \
  || { echo "rules read failure: FAIL: a failed policy read is not answered as a failed snapshot"; exit 1; }
republish="$(body "$HELPER" 'private func republishActivePolicy(')"
awk '/try store.activePolicyState\(\)/ { read = NR } /return false/ && read { refused = NR } /dns.applyPolicy/ { applied = NR }
     END { exit !(read && refused && applied && read < refused && refused < applied) }' <<<"$republish" \
  || { echo "rules read failure: FAIL: a failed policy read can still reach the DNS proxy on republish"; exit 1; }
echo "rules read failure: PASS: the helper keeps the last full policy when the read fails"

xcrun swiftc -O -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos13.0 -parse-as-library \
  -o "$TMP/run" "$ROOT"/Sources/Shared/*.swift "$TMP/verify.swift" -lsqlite3
"$TMP/run" "$TMP/rules.sqlite"
