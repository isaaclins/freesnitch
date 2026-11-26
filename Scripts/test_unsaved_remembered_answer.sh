#!/usr/bin/env bash
# Regression harness for #246.
#
# Answering an alert with "Remember this decision" closes the alert first and
# saves the rule afterwards. When the helper refused the rule, or could not be
# reached, the only trace was a log line in Settings: the alert closed like a
# success and the next connection was asked again with no word why.
#
# Checked here, against the real sources:
#   - the list of unsaved answers keeps what the alert window shows, in the
#     order answered, bounded, with a retry that fails again replacing its
#     earlier entry rather than stacking a second one
#   - Try Again keeps the notice up while it runs, a double click sends one
#     save, and a retry that worked clears the notice
#   - the app records a refused save into that list (not only the log), the
#     alert window stays open while the list has something in it, and the
#     helper call reports a dropped connection instead of never answering
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-unsaved-answer.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

failures=0
fail() { printf 'unsaved remembered answer: FAIL: %s\n' "$1" >&2; failures=$((failures + 1)); }
pass() { printf 'unsaved remembered answer: PASS: %s\n' "$1"; }

cat > "$WORK/main.swift" <<'SWIFT'
import Foundation

var failures = 0
func check(_ condition: Bool, _ what: String) {
    if condition {
        print("unsaved remembered answer: PASS: \(what)")
    } else {
        print("unsaved remembered answer: FAIL: \(what)")
        failures += 1
    }
}

// The rule the alert builds for "Deny, remember, this host", as the helper
// would have received it.
let connection = Connection(pid: 501, processName: "Slack",
                            processPath: "/Applications/Slack.app/Contents/MacOS/Slack",
                            processBundleId: "com.tinyspeck.slackmacgap",
                            remoteHost: "edgeapi.slack.com", remoteIP: "203.0.113.5",
                            remotePort: 443, direction: .outgoing)
guard let rule = connection.rememberedRule(scope: .thisHost, allow: false,
                                           profile: "Always", expiresAt: nil) else {
    print("unsaved remembered answer: FAIL: the alert made no rule to save")
    exit(1)
}

func answer(_ rule: Rule, _ reason: String) -> UnsavedRememberedAnswer {
    UnsavedRememberedAnswer(processName: "Slack", destination: "edgeapi.slack.com",
                            allow: false, rule: rule, reason: reason)
}

var list = UnsavedRememberedAnswers()
check(list.isEmpty && list.current == nil, "nothing is shown before a save fails")

// The helper's own refusal, word for word.
list.record(answer(rule, "The FreeSnitch helper is not connected."))
check(list.current?.reason == "The FreeSnitch helper is not connected.",
      "a refused save is shown with the helper's reason")
check(list.current?.rule.id == rule.id && list.current?.rule.action == .deny,
      "the shown answer carries the exact rule that was refused, for Try Again")

// Try Again: one save per click, and the notice stays while it is in flight,
// so the window does not close and reopen.
let first = list.current!.id
let retried = list.beginRetry(id: first)
check(retried?.rule.id == rule.id, "Try Again hands back the same rule to send again")
check(list.beginRetry(id: first) == nil, "a second click on the same answer sends nothing")
check(list.current?.id == first && list.isRetrying(first), "the notice stays while the retry is in flight")
// The retry worked: the notice goes.
list.take(id: first)
check(list.isEmpty && !list.isRetrying(first), "a retry that worked clears the notice")

// The retry is refused too: one entry for the rule, with the new reason.
list.record(answer(rule, "first"))
let before = list.current!.id
_ = list.beginRetry(id: before)
list.record(answer(rule, "rule saved but the firewall refused it: test"))
check(list.items.count == 1, "the same rule failing again replaces its entry")
check(!list.isRetrying(before) && list.current.map { !list.isRetrying($0.id) } == true,
      "a refused retry can be tried again")

check(list.current?.reason == "rule saved but the firewall refused it: test",
      "and shows the latest reason")

// With several waiting, a refused retry keeps its place on screen.
var two = UnsavedRememberedAnswers()
var other = rule
other.id = UUID()
two.record(answer(rule, "down"))
two.record(answer(other, "down"))
let onScreen = two.current!.id
_ = two.beginRetry(id: onScreen)
two.record(answer(rule, "still down"))
check(two.current?.rule.id == rule.id && two.current?.reason == "still down",
      "a refused retry stays the notice on screen, with the new reason")

// A helper that never answers a retry: the buttons come back.
var stuck = UnsavedRememberedAnswers()
stuck.record(answer(rule, "down"))
let hung = stuck.current!.id
_ = stuck.beginRetry(id: hung)
stuck.endRetry(id: hung)
check(!stuck.isRetrying(hung) && stuck.current?.id == hung,
      "a retry nobody answers gives the buttons back and keeps the notice")

// A helper that is down refuses every save: bounded, oldest dropped, shown in
// the order they were answered.
var many = UnsavedRememberedAnswers()
var rules: [Rule] = []
for i in 0..<(UnsavedRememberedAnswers.limit + 3) {
    var r = rule
    r.id = UUID()
    r.remoteHost = "host\(i).example"
    rules.append(r)
    many.record(answer(r, "down"))
}
check(many.items.count == UnsavedRememberedAnswers.limit, "the list is bounded")
check(many.current?.rule.id == rules[3].id, "the oldest kept answer is shown first")
check(many.items.last?.rule.id == rules.last?.id, "the newest answer is kept")

// Dismiss removes only that one.
let shown = many.current!.id
many.take(id: shown)
check(many.items.count == UnsavedRememberedAnswers.limit - 1 && many.current?.id != shown,
      "dismissing one leaves the others")

exit(failures == 0 ? 0 : 1)
SWIFT

if xcrun swiftc -O -o "$WORK/check" "$ROOT"/Sources/Shared/*.swift "$WORK/main.swift" 2>"$WORK/build.log"; then
  "$WORK/check" || failures=$((failures + 1))
else
  cat "$WORK/build.log" >&2
  fail "the harness does not compile against Sources/Shared"
fi

# The app side is SwiftUI and XPC, which this harness cannot drive, so the
# wiring the fix depends on is checked in the source itself.
STATE="$ROOT/Sources/GUI/ViewModels/AppState.swift"
CLIENT="$ROOT/Sources/GUI/App/HelperClient.swift"
WINDOWS="$ROOT/Sources/GUI/App/WindowManager.swift"
ALERT="$ROOT/Sources/GUI/Views/ConnectionAlert.swift"

save_body="$(awk '/private func saveRememberedRule\(/,/^    }$/' "$STATE")"
if grep -q 'unsavedRememberedAnswers.record(' <<<"$save_body" && grep -q 'unsavedRememberedAnswers.take(id: answer.id)' <<<"$save_body"; then
  pass "a refused remembered rule is recorded for the alert window, not only logged, and cleared once saved"
else
  fail "saveRememberedRule no longer records a refused save for the alert window"
fi
resolve_body="$(awk '/func resolveAlert\(/,/^    }$/' "$STATE")"
if grep -q 'saveRememberedRule(' <<<"$resolve_body" && ! grep -q 'helper.addRule(' <<<"$resolve_body"; then
  pass "answering an alert saves its rule through the path that reports failure"
else
  fail "resolveAlert saves its rule without the failure report"
fi

add_body="$(awk '/func addRule\(_ rule: Rule, completion:/,/^    }$/' "$CLIENT")"
if grep -q 'remoteObjectProxyWithErrorHandler' <<<"$add_body" && ! grep -q 'remote else' <<<"$add_body"; then
  pass "a helper that goes away mid-save reports an error instead of never answering"
else
  fail "addRule uses a proxy that swallows transport errors"
fi

if grep -q 'unsavedRememberedAnswers' "$WINDOWS"; then
  pass "the alert window stays open while an answer is unsaved"
else
  fail "the alert window closes without looking at unsaved answers"
fi
if grep -q 'UnsavedRememberedAnswerNotice(answer: unsaved, compact: true)' "$ALERT" \
   && grep -q 'UnsavedRememberedAnswerNotice(answer: unsaved, compact: false)' "$ALERT"; then
  pass "the notice is shown on its own and on top of the next question"
else
  fail "the notice is missing from the alert window"
fi

if [ "$failures" -ne 0 ]; then
  echo "unsaved remembered answer: $failures check group(s) failed" >&2
  exit 1
fi
echo "unsaved remembered answer: all checks passed"
