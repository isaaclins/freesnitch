#!/usr/bin/env bash
# Delete History also empties the known-destination list that alert mode uses
# to skip the question (issue #229).
#
# Alert mode can let an app reach a destination it used before without asking.
# That list is built from Insights history and cached twice: in the helper and
# in the app. Delete History used to purge only the store, so both copies kept
# the old destinations until their next refresh (up to 30 seconds in the app),
# and a connection to an old destination in that window was allowed as known.
# This replays the issue's steps against the shipping InsightsStore and the
# app's contact cache, including an answer that was already on its way when
# the history was deleted.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-contact-purge.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
  printf 'contact history purge: FAIL: %s\n' "$*" >&2
  exit 1
}

pass() {
  printf 'contact history purge: PASS: %s\n' "$*"
}

SERVICE="$ROOT/Sources/Helper/HelperService.swift"
APPSTATE="$ROOT/Sources/GUI/ViewModels/AppState.swift"
INSIGHTS_VIEW="$ROOT/Sources/GUI/Views/InsightsView.swift"

# The helper rebuilds its copy from the emptied store before it replies, on the
# queue every other rebuild runs on.
body="$(awk '/func purgeInsights\(reply:/{on=1} on{print} on&&/^    }$/{exit}' "$SERVICE")"
[[ -n "$body" ]] || fail "purgeInsights was not found in HelperService.swift"
grep -q 'insightsMaintenanceQueue.sync' <<<"$body" || fail "the purge does not run on the queue that rebuilds the contact list"
grep -q 'insightsContactSnapshot = nil' <<<"$body" || fail "the helper keeps serving the old contact list while it deletes"
purge_line="$(grep -n 'insights.purge()' <<<"$body" | head -1 | cut -d: -f1)"
refresh_line="$(grep -n 'refreshInsightsContactSnapshot()' <<<"$body" | tail -1 | cut -d: -f1)"
reply_line="$(grep -n 'reply(failures.isEmpty' <<<"$body" | head -1 | cut -d: -f1)"
[[ -n "$purge_line" && -n "$refresh_line" && -n "$reply_line" ]] || fail "purge, rebuild or reply is missing from purgeInsights"
(( purge_line < refresh_line && refresh_line < reply_line )) || fail "the contact list is not rebuilt after the purge and before the reply"
try_block="$(awk '/try insights.purge\(\)/{on=1} on{print} on&&/\} catch \{/{exit}' <<<"$body")"
grep -q 'refreshInsightsContactSnapshot()' <<<"$try_block" || fail "the contact list is not rebuilt after a successful purge"
grep -q 'insightsContactHistoryDeleteFailed = true' <<<"$body" || fail "a failed purge does not stop later rebuilds from the old database"
refresh_body="$(awk '/private func refreshInsightsContactSnapshot\(\)/{on=1} on{print} on&&/^    }$/{exit}' "$SERVICE")"
grep -q 'guard !insightsContactHistoryDeleteFailed' <<<"$refresh_body" || fail "a later connection can rebuild known destinations after a failed purge"
pass "the helper rebuilds the contact list from the emptied store before it answers, and only when the purge worked"

# The app forgets its copy when Delete History is pressed, and the Insights
# window goes through that path instead of calling the helper directly.
grep -q 'state?.purgeInsightsHistory' "$INSIGHTS_VIEW" || fail "Delete History bypasses the app's contact cache"
if grep -q 'helper.purgeInsights' "$INSIGHTS_VIEW"; then
  fail "the Insights window still purges without clearing the contact cache"
fi
app_body="$(awk '/func purgeInsightsHistory\(/{on=1} on{print} on&&/^    }$/{exit}' "$APPSTATE")"
grep -q 'contactCache.beginDelete()' <<<"$app_body" || fail "the app does not forget known destinations when the delete starts"
grep -q 'finishContactDelete(id)' <<<"$app_body" || fail "the app does not end the delete when the helper answers"
grep -q 'contactDeleteTimeout' <<<"$app_body" || fail "a delete the helper never answers keeps known destinations off until relaunch"
finish_body="$(awk '/private func finishContactDelete\(/{on=1} on{print} on&&/^    }$/{exit}' "$APPSTATE")"
grep -q 'runningContactDeletes.remove(id) != nil' <<<"$finish_body" || fail "a delete can be ended twice (reply after the timeout)"
grep -q 'contactCache.endDelete()' <<<"$finish_body" || fail "the app does not drop answers asked for during the delete"
grep -q 'refreshContactClassifier()' <<<"$finish_body" || fail "the app does not fetch the emptied list after the delete"
if grep -qE 'contactClassifier[[:space:]]*=' "$APPSTATE"; then
  fail "the contact classifier is set outside the cache, which can bring a stale list back"
fi
pass "the app forgets known destinations when the history is deleted"

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

@main
struct ContactPurgeHarness {
    static var failures = 0

    static func check(_ condition: Bool, _ message: String) {
        if condition {
            print("contact purge harness: PASS: \(message)")
        } else {
            failures += 1
            FileHandle.standardError.write(Data("contact purge harness: FAIL: \(message)\n".utf8))
        }
    }

    static func observation(host: String, ip: String, at date: Date) -> FlowObservation {
        let connection = Connection(pid: 501, processName: "Chat",
                                    processPath: "/Applications/Chat.app/Contents/MacOS/Chat",
                                    processBundleId: "com.example.chat", remoteHost: host, remoteIP: ip,
                                    remotePort: 443, direction: .outgoing)
        return FlowObservation(connection: connection, observedAt: date)
    }

    static func main() throws {
        let now = Date()
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("freesnitch-contact-purge-\(UUID().uuidString)")
        let support = root.appendingPathComponent("Application Support")
        try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o755])
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try InsightsStore(path: support.appendingPathComponent("Insights/insights.sqlite").path,
                                      expectedUID: getuid())

        // Step 1: the app has a destination in its history, and the app's
        // cache holds it.
        try store.record([observation(host: "api.example.com", ip: "203.0.113.10",
                                      at: now.addingTimeInterval(-3600))])
        var cache = InsightsContactCache()
        let first = cache.beginRefresh()
        check(cache.apply(try store.contactSnapshot(now: now), for: first, now: now),
              "the first answer is applied")
        let again = observation(host: "api.example.com", ip: "203.0.113.10", at: now)
        check(cache.classifier.decision(for: again) == .knownContact,
              "before the delete, the old destination is known")

        // A periodic refresh asked the helper just before the delete; its
        // answer still holds the old history.
        let staleToken = cache.beginRefresh()
        let staleSnapshot = try store.contactSnapshot(now: now)

        // Step 2: Delete History. The app forgets first, then the store is purged.
        cache.beginDelete()
        check(cache.classifier.decision(for: again) != .knownContact,
              "while deleting, the old destination is not allowed as known")

        // The 30-second refresh fires while the helper is still deleting and
        // the helper answers it with the old list. That answer is the newest
        // request, and it must still not be taken.
        let duringToken = cache.beginRefresh()
        check(!cache.apply(staleSnapshot, for: duringToken, now: now),
              "an answer to a refresh started during the delete is dropped")
        check(cache.classifier.decision(for: again) != .knownContact,
              "a refresh during the delete does not bring the old destination back")
        try store.purge()

        // The stale answer arrives after the delete and must not bring the
        // old destination back.
        check(!cache.apply(staleSnapshot, for: staleToken, now: now),
              "an answer requested before the delete is dropped")
        check(cache.classifier.decision(for: again) != .knownContact,
              "the stale answer does not make the old destination known again")

        // The helper's reply arrives: fetch the emptied list.
        cache.endDelete()
        check(!cache.apply(staleSnapshot, for: duringToken, now: now),
              "a refresh from during the delete that answers after it is dropped")
        let fresh = cache.beginRefresh()
        check(cache.apply(try store.contactSnapshot(now: now), for: fresh, now: now),
              "the answer from after the delete is applied")

        // Steps 3 and 4: the app connects to the old destination right away.
        // It is judged against the emptied history, so alert mode asks.
        check(cache.classifier.isAvailable, "the emptied history is available, not an error")
        check(cache.classifier.decision(for: again) == .firstContact,
              "right after the delete, the old destination is a first contact")

        // History keeps working after the delete.
        try store.record([observation(host: "new.example.com", ip: "203.0.113.20", at: now)])
        let later = cache.beginRefresh()
        cache.apply(try store.contactSnapshot(now: now), for: later, now: now)
        check(cache.classifier.decision(for: observation(host: "new.example.com", ip: "203.0.113.20", at: now))
                == .knownContact,
              "a destination seen after the delete becomes known again")
        check(cache.classifier.decision(for: again) == .firstContact,
              "the deleted destination stays forgotten")

        // Two overlapping refreshes: only the newest answer counts.
        let older = cache.beginRefresh()
        let newer = cache.beginRefresh()
        check(cache.apply(try store.contactSnapshot(now: now), for: newer, now: now), "the newest answer is applied")
        check(!cache.apply(staleSnapshot, for: older, now: now), "an older answer arriving last is dropped")
        check(cache.classifier.decision(for: again) == .firstContact,
              "an out-of-order answer does not bring deleted history back")

        if failures > 0 { exit(1) }
        print("contact purge harness: PASS: all checks")
    }
}
SWIFT

mkdir -p "$TMP/build"
xcrun swiftc \
  -sdk "$(xcrun --show-sdk-path)" \
  -parse-as-library \
  -o "$TMP/build/run" \
  "$ROOT/Sources/Helper/InsightsStore.swift" \
  "$ROOT"/Sources/Shared/*.swift \
  "$TMP/verify.swift" \
  -lsqlite3
"$TMP/build/run"
printf 'contact history purge: PASS\n'
