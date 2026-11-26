#!/usr/bin/env bash
# Regression gate for #264.
#
# The helper logged every line as one public string, so the unified log kept
# the DNS names it was asked about, app paths, resolver URLs and addresses in
# clear text for anyone who reads the log or a diagnostic capture. Interpolated
# values are now private unless a call marks them public.
#
# This replays the issue's case through the real helper code: a DNS ask that no
# app receives, an ask past the table bound and an ask that times out. It then
# reads this process's own unified log and checks that the host name is shown
# as <private> while the fixed wording, which says what failed, is still there.
# It also checks the rule import record, the bundle watchdog's audit line, the
# error form and the fold past four values, and that nothing in the helper,
# extension or shared code calls os_log around PSLog.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-log-privacy.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "log privacy: FAIL: $*" >&2; exit 1; }

# No direct os_log in code that runs as root or in the extension: it would
# bypass the private-by-default message type.
if grep -rn 'os_log(' "$ROOT/Sources/Helper" "$ROOT/Sources/NetExt" "$ROOT/Sources/Shared" \
     | grep -v '^'"$ROOT"'/Sources/Shared/Logger.swift:' ; then
  fail "os_log is called outside PSLog in helper, extension or shared code"
fi
# Values a reader could identify someone by must never be marked public.
if grep -rnE '\\\(public: *[^)]*(domain|[Pp]ath|[Hh]ost|url|URL|bundleId|storedValue|mac|name)\b' \
     "$ROOT/Sources/Helper" "$ROOT/Sources/NetExt" "$ROOT/Sources/Shared" \
     | grep -vE 'anchorPath|anchorName|hosts\.joined|\(public: host\)|rejectionReason\(for:' ; then
  fail "a host name, path, URL or name is logged as public"
fi

# The monitor build leaves out the network extension, so typecheck it here:
# a log line it builds with the wrong type must fail this check, not only the
# signed release build.
xcrun swiftc -typecheck -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos13.0 \
  "$ROOT"/Sources/NetExt/*.swift "$ROOT"/Sources/Shared/*.swift \
  || fail "the network extension sources do not compile"

mkdir -p "$TMP/build"
cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation
import OSLog

@main
struct LogPrivacyHarness {
    static var failures = 0
    static func check(_ condition: Bool, _ message: String) {
        if condition { print("log privacy: PASS: \(message)") }
        else { failures += 1; FileHandle.standardError.write(Data("log privacy: FAIL: \(message)\n".utf8)) }
    }

    static func lines(since start: Date) throws -> [String] {
        let store = try OSLogStore(scope: .currentProcessIdentifier)
        return try store.getEntries(at: store.position(date: start))
            .compactMap { $0 as? OSLogEntryLog }
            .filter { $0.subsystem == AppConstants.bundleIdGUI }
            .map(\.composedMessage)
    }

    static func main() throws {
        let start = Date().addingTimeInterval(-1)
        let secret = "payroll.internal.example"

        // Step 1 of the issue: no client receives the alert.
        let asks = DNSAskCoordinator()
        var answered = 0
        asks.ask(domain: secret, completion: { _ in answered += 1 }, sendAlert: { _ in 0 })
        // An ask that nobody answers in time.
        let timedOut = DispatchSemaphore(value: 0)
        asks.ask(domain: "timeout." + secret, timeout: 0.05,
                 completion: { _ in timedOut.signal() }, sendAlert: { _ in 1 })
        check(timedOut.wait(timeout: .now() + 5) == .success, "the unanswered ask resolved")
        // The table bound.
        for index in 0..<DNSAskCoordinator.capacity {
            _ = asks.admit(domain: "filler\(index).example", timeout: 30, completion: { _ in })
        }
        asks.ask(domain: "bound." + secret, completion: { _ in answered += 1 }, sendAlert: { _ in 1 })
        check(answered == 2, "both immediate asks failed open")

        // A rule import that deleted a rule for a personal host.
        let home = Rule(processPath: "/usr/bin/curl", processName: "curl", remoteHost: "nas.\(secret)",
                        action: .deny, scope: .domain, profile: "home")
        let replacement = Rule(processPath: "/usr/bin/curl", processName: "curl", remoteHost: "other.example",
                               action: .deny, scope: .domain, profile: "home")
        let plan = RuleImportPlan(current: [home], imported: [replacement])
        plan.logMessages.forEach { PSLog.notice(PSLog.helper, $0) }
        check(plan.logLines.contains { $0.contains("nas.\(secret)") },
              "the import record shown in the app still names the rule")

        // The watchdog's audit line keeps its counts but not the bundle path.
        let evidence = BundleAbsenceEvidence(bundlePath: "/Users/someone/Applications/FreeSnitch.app",
                                             observations: [Date(), Date()], decidedAt: Date())
        PSLog.error(PSLog.helper, "AUDIT: standing down. \(evidence.logSummary).")

        struct Leak: LocalizedError { var errorDescription: String? { "could not open /Users/someone/secret.db" } }
        PSLog.error(PSLog.helper, "store failed: \(error: Leak())")
        PSLog.error(PSLog.helper, "many: \("v1") \("v2") \("v3") \("v4") \("v5") \(public: 42) end")

        let logged = try lines(since: start)
        let mine = logged.filter { !$0.contains("filler") }
        check(!mine.contains { $0.contains(secret) || $0.contains("/Users/someone") },
              "no log line holds the host name or the user's path")
        check(mine.contains("No client received the DNS alert for '<private>'; resolving with the fail-open default."),
              "the undelivered ask still says what failed")
        check(mine.contains("DNS ask for '<private>' went unanswered for the ask timeout; resolving with the fail-open default."),
              "the timed-out ask still says what failed")
        check(mine.contains("DNS ask table is at its \(DNSAskCoordinator.capacity) entry bound; resolving '<private>' with the fail-open default."),
              "the bound keeps its number public")
        check(mine.contains { $0.hasPrefix("rule import: 1 rules imported into profiles [<private>]; 1 removed, 0 moved") },
              "the import summary keeps its counts")
        check(mine.contains { $0.hasPrefix("rule import removed: <private> in <private> (\(home.id.uuidString))") },
              "the removed rule keeps its ID")
        check(mine.contains { $0.contains("bundle=<private> absent_observations=2 span=") },
              "the audit line keeps its evidence counts")
        check(mine.contains { $0.contains("store failed: [") && $0.hasSuffix("] <private>") },
              "an error keeps its domain and code")
        check(mine.contains("many: <private> <private> <private> <private> 42 end"),
              "values past the fourth stay private")

        let missing: String? = nil
        let present: String? = "x"
        let optionals: PSLogMessage = "\(missing) \(present) \(public: present)"
        check(optionals.unredacted == "nil x x", "optionals log their value, not Optional(...)")
        let message: PSLogMessage = "a \(1) b \(public: 2) c"
        check(message.redacted == "a <private> b 2 c" && message.unredacted == "a 1 b 2 c",
              "redacted and full text")
        if failures > 0 { exit(1) }
    }
}
SWIFT

xcrun swiftc -O \
  -sdk "$(xcrun --show-sdk-path)" \
  -target arm64-apple-macos13.0 \
  -parse-as-library \
  -o "$TMP/build/run" \
  $(ls "$ROOT"/Sources/Helper/*.swift | grep -v '/main.swift$') \
  "$ROOT"/Sources/Shared/*.swift \
  "$TMP/verify.swift" \
  -lsqlite3
"$TMP/build/run"
echo "log privacy: all checks passed"
