#!/usr/bin/env bash
# Verification for CLI-answerable pending connection alerts (issue #25).
#
# The harness is compiled from the real helper and shared sources, never from a
# copy, and it exercises PendingAlertRegistry directly: that type is the whole
# safety boundary between a short-lived CLI process and a paused flow.
#
# What is asserted here, and why each one is a bug this feature could have
# introduced:
#   - a registered alert is listed with a stable id, so a script can answer the
#     question it actually read
#   - allow and deny each resolve exactly once, and a second answer is told what
#     answered first, so a CLI/GUI race cannot decide one flow twice
#   - an entry expires strictly before the flow's own ask timeout, so answering
#     from a script can never hold traffic longer than it is already held, and
#     the fail-open default still applies to everything that goes unanswered
#   - the registry is bounded like the DNS ask table, and overflow resolves
#     immediately with the fail-open default instead of queueing
#   - an id that never existed is refused with its own specific outcome
#   - with no app attached the list is empty and states the reason
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-pending-alerts.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

failures=0
fail() {
  printf 'pending alerts: FAIL: %s\n' "$1" >&2
  failures=$((failures + 1))
}
pass() { printf 'pending alerts: PASS: %s\n' "$1"; }

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

private final class AlertOwner {}

@main
struct PendingAlertHarness {
    static var failures = 0

    static func check(_ condition: Bool, _ message: String) {
        if condition {
            print("pending alert harness: PASS: \(message)")
        } else {
            failures += 1
            FileHandle.standardError.write(Data("pending alert harness: FAIL: \(message)\n".utf8))
        }
    }

    static func equal<T: Equatable>(_ actual: T, _ expected: T, _ message: String) {
        check(actual == expected, "\(message) (expected \(expected), got \(actual))")
    }

    /// Records every resolution the registry delivers, so "exactly once" is an
    /// assertion about counts rather than about the last value seen.
    final class ResolutionLog: @unchecked Sendable {
        private var values: [PendingAlertResolution] = []
        private let lock = NSLock()

        func append(_ resolution: PendingAlertResolution) {
            lock.lock(); values.append(resolution); lock.unlock()
        }

        var all: [PendingAlertResolution] {
            lock.lock(); defer { lock.unlock() }
            return values
        }

        var count: Int { all.count }
        var first: PendingAlertResolution? { all.first }
    }

    static func descriptor(id: UUID = UUID(),
                           process: String = "Beeper",
                           bundle: String? = "com.beeper.app",
                           path: String = "/Applications/Beeper.app",
                           host: String = "api.example.com",
                           ip: String = "203.0.113.10",
                           port: Int = 443,
                           askedAt: Date = Date(),
                           lifetime: TimeInterval = 30) -> PendingAlertDescriptor {
        PendingAlertDescriptor(id: id,
                               processName: process,
                               processPath: path,
                               processBundleId: bundle,
                               remoteHost: host,
                               remoteIP: ip,
                               remotePort: port,
                               direction: .outgoing,
                               protocolName: "tcp",
                               askedAt: askedAt,
                               expiresAt: askedAt.addingTimeInterval(lifetime))
    }

    static func main() {
        // MARK: a registered alert is listed with a stable id
        do {
            let registry = PendingAlertRegistry()
            let first = descriptor(askedAt: Date().addingTimeInterval(-2))
            let second = descriptor(process: "Slack", host: "", ip: "203.0.113.20")
            let log = ResolutionLog()
            equal(registry.register(first, onResolve: log.append), .registered, "the first alert is queued")
            equal(registry.register(second, onResolve: log.append), .registered, "the second alert is queued")
            equal(registry.pending().map(\.id), [first.id, second.id], "alerts are listed oldest first")
            equal(registry.pending().map(\.id), [first.id, second.id], "the listed ids are stable across reads")
            equal(registry.count, 2, "both alerts are outstanding")
            equal(log.count, 0, "listing an alert does not resolve it")
            let listed = registry.pending().first!
            equal(listed.processName, "Beeper", "the listing carries the process")
            equal(listed.destination, "api.example.com", "the listing carries the destination name")
            equal(listed.remoteIP, "203.0.113.10", "the listing carries the address")
            equal(listed.remotePort, 443, "the listing carries the port")
            equal(registry.pending().last?.destination, "203.0.113.20",
                  "an alert with no name shows the address as its destination, never an invented name")
        }

        // MARK: allow and deny each resolve exactly once
        for allow in [true, false] {
            let registry = PendingAlertRegistry()
            let alert = descriptor()
            let log = ResolutionLog()
            _ = registry.register(alert, onResolve: log.append)
            let outcome = registry.answer(id: alert.id, allow: allow, by: .cli)
            equal(outcome, .answered(alert), "answering \(allow ? "allow" : "deny") reports the answered alert")
            equal(log.count, 1, "answering \(allow ? "allow" : "deny") resolves the flow exactly once")
            equal(log.first?.kind, .answered, "the resolution is an answer")
            equal(log.first?.allow, allow, "the resolution carries the \(allow ? "allow" : "deny") verdict")
            equal(log.first?.flowVerdict, allow, "the verdict applied to the flow is the one that was given")
            equal(log.first?.answeredBy, .cli, "the resolution names the command line as the answerer")
            equal(registry.count, 0, "an answered alert leaves the registry")
            equal(registry.pending().count, 0, "an answered alert is no longer listed")

            // MARK: a second answer is refused with the specific reason
            let again = registry.answer(id: alert.id, allow: !allow, by: .cli)
            guard case .alreadyAnswered(let by, _) = again else {
                check(false, "a second answer reports already-answered")
                continue
            }
            equal(by, .cli, "the second answer is told who answered first")
            equal(log.count, 1, "a second answer does not resolve the flow again")
        }

        // MARK: the app answering first wins, and the CLI is told so
        do {
            let registry = PendingAlertRegistry()
            let alert = descriptor()
            let log = ResolutionLog()
            _ = registry.register(alert, onResolve: log.append)
            _ = registry.withdraw(id: alert.id)
            equal(log.count, 1, "an app answer resolves the registration exactly once")
            equal(log.first?.kind, .withdrawn, "the app answer withdraws the entry")
            check(log.first?.flowVerdict == nil, "a withdrawal carries no verdict for the flow")
            guard case .alreadyAnswered(let by, _) = registry.answer(id: alert.id, allow: true, by: .cli) else {
                check(false, "a command line answer after the app answered reports already-answered")
                exit(1)
            }
            equal(by, .gui, "the command line is told the app answered it")
        }

        // MARK: concurrent answers resolve the flow exactly once
        do {
            let registry = PendingAlertRegistry()
            let alert = descriptor()
            let log = ResolutionLog()
            _ = registry.register(alert, onResolve: log.append)
            let lock = NSLock()
            var answered = 0
            var alreadyAnswered = 0
            DispatchQueue.concurrentPerform(iterations: 16) { index in
                let outcome = index % 2 == 0
                    ? registry.answer(id: alert.id, allow: true, by: .cli)
                    : registry.withdraw(id: alert.id)
                lock.lock()
                if case .answered = outcome { answered += 1 } else { alreadyAnswered += 1 }
                lock.unlock()
            }
            equal(answered, 1, "exactly one of sixteen racing answers wins")
            equal(alreadyAnswered, 15, "every losing answer is told the alert was already answered")
            equal(log.count, 1, "a racing answer never resolves the flow twice")
        }

        // MARK: an unknown id is its own specific outcome
        do {
            let registry = PendingAlertRegistry()
            equal(registry.answer(id: UUID(), allow: true, by: .cli), .unknown,
                  "an id that never existed is reported as unknown, not as already answered")
            let alert = descriptor()
            _ = registry.register(alert) { _ in }
            _ = registry.answer(id: alert.id, allow: true, by: .cli)
            guard case .alreadyAnswered = registry.answer(id: alert.id, allow: true, by: .cli) else {
                check(false, "a known id is never reported as unknown")
                exit(1)
            }
            pass("a known id is never reported as unknown")
        }

        // MARK: expiry can never outlive the flow's own budget
        do {
            check(PendingAlertLimits.maxLifetime < PendingAlertLimits.flowAskTimeout,
                  "a registry entry expires strictly before the flow's ask timeout")
            check(PendingAlertRegistry.defaultDecision,
                  "an unanswered or unanswerable alert falls back to the fail-open default")
            let registry = PendingAlertRegistry()
            let now = Date()
            // A caller asking for ten minutes is clamped, not trusted.
            let greedy = descriptor(askedAt: now, lifetime: 600)
            _ = registry.register(greedy, now: now) { _ in }
            let listed = registry.pending(now: now).first
            check(listed != nil, "the clamped alert is still listed")
            let granted = listed!.expiresAt.timeIntervalSince(now)
            check(granted <= PendingAlertLimits.maxLifetime + 0.001,
                  "a ten minute request is clamped to \(PendingAlertLimits.maxLifetime) seconds (granted \(granted))")
            check(granted < PendingAlertLimits.flowAskTimeout,
                  "the granted budget is shorter than the flow's own ask timeout")
            check(listed!.secondsRemaining(now: now) <= Int(PendingAlertLimits.maxLifetime),
                  "the reported remaining time never exceeds the maximum lifetime")
        }

        // MARK: an alert nobody answers expires on its own, once
        do {
            let registry = PendingAlertRegistry()
            let alert = descriptor(lifetime: 0.4)
            let log = ResolutionLog()
            _ = registry.register(alert, onResolve: log.append)
            equal(registry.count, 1, "the short-lived alert is outstanding")
            Thread.sleep(forTimeInterval: 1.2)
            equal(log.count, 1, "an unanswered alert is resolved exactly once by its own timeout")
            equal(log.first?.kind, .expired, "the unanswered alert resolves as expired")
            check(log.first?.flowVerdict == nil,
                  "expiry carries no verdict, so the caller resumes with the fail-open default")
            equal(registry.count, 0, "an expired alert leaves the registry")
            equal(registry.pending().count, 0, "an expired alert is never listed as answerable")
            guard case .expired = registry.answer(id: alert.id, allow: false, by: .cli) else {
                check(false, "answering an expired alert reports that it expired")
                exit(1)
            }
            pass("answering an expired alert reports that it expired")
        }

        // MARK: a past deadline is refused rather than queued
        do {
            let registry = PendingAlertRegistry()
            let log = ResolutionLog()
            let stale = descriptor(askedAt: Date().addingTimeInterval(-120), lifetime: 30)
            equal(registry.register(stale, onResolve: log.append),
                  .resolvedImmediately(log.first ?? .expired()),
                  "an alert whose budget already ran out is never queued")
            equal(log.first?.kind, .expired, "it resolves immediately as expired")
            equal(registry.count, 0, "nothing was queued")
        }

        // MARK: the registry is bounded and overflow does not queue
        do {
            let registry = PendingAlertRegistry()
            let log = ResolutionLog()
            var queued: [UUID] = []
            for _ in 0..<PendingAlertLimits.capacity {
                let alert = descriptor()
                queued.append(alert.id)
                equal(registry.register(alert, onResolve: log.append), .registered, "an alert below the bound is queued")
            }
            equal(registry.count, PendingAlertLimits.capacity, "the registry fills to exactly its capacity")
            let overflowing = descriptor()
            let admission = registry.register(overflowing, onResolve: log.append)
            equal(admission, .resolvedImmediately(.overflow(at: log.first?.at ?? Date())),
                  "past the bound the registration resolves immediately instead of queueing")
            equal(log.count, 1, "the overflowing registration resolved exactly once")
            equal(log.first?.kind, .overflow, "the overflow resolution says so")
            check(log.first?.flowVerdict == nil,
                  "overflow carries no verdict, so the caller resumes with the fail-open default")
            equal(registry.count, PendingAlertLimits.capacity, "the bound is not exceeded")
            check(!registry.pending().contains { $0.id == overflowing.id },
                  "an overflowing alert is never listed as answerable")
            // A duplicate id is the same non-queueing path: never replace a
            // live entry, because that would strand the first flow.
            let duplicate = descriptor(id: queued[0])
            let duplicateLog = ResolutionLog()
            _ = registry.register(duplicate, onResolve: duplicateLog.append)
            equal(duplicateLog.count, 1, "a duplicate id resolves immediately instead of replacing a live entry")
            equal(duplicateLog.first?.kind, .overflow, "a duplicate id takes the non-queueing path")
        }

        // MARK: a client that goes away takes its alerts with it
        do {
            let registry = PendingAlertRegistry()
            let owner = AlertOwner()
            let log = ResolutionLog()
            let alert = descriptor()
            _ = registry.register(alert, ownerKey: ObjectIdentifier(owner), onResolve: log.append)
            registry.withdrawAll(ownerKey: ObjectIdentifier(owner))
            equal(log.count, 1, "a disconnected client's alert is resolved exactly once")
            equal(registry.count, 0, "a disconnected client leaves nothing answerable behind")
        }

        // MARK: an empty list always says why it is empty
        do {
            let detached = PendingAlertListing(alerts: [], guiAttached: false)
            equal(detached.alerts.count, 0, "with no app attached the list is empty")
            equal(detached.reason, PendingAlertListing.noGUIReason,
                  "with no app attached the reason is stated instead of implying a broken feature")
            check(detached.reason?.contains("app is not running") == true,
                  "the stated reason names the missing app")
            check(detached.reason?.contains("fail-open") == true,
                  "the stated reason keeps the fail-open promise visible")
            let attached = PendingAlertListing(alerts: [], guiAttached: true)
            equal(attached.reason, PendingAlertListing.noneReason,
                  "an attached app with nothing waiting has its own reason")
            let populated = PendingAlertListing(alerts: [descriptor()], guiAttached: true)
            check(populated.reason == nil, "a non-empty list needs no reason")
            equal(populated.capacity, PendingAlertLimits.capacity, "the listing reports the bound")
        }

        // MARK: remembered decisions produce the same rules the app would store
        do {
            let named = descriptor()
            let unnamed = descriptor(host: "", ip: "203.0.113.55")
            equal(PendingAlertRuleFactory.defaultScope(for: named), .domain,
                  "a named destination defaults to a domain rule")
            equal(PendingAlertRuleFactory.defaultScope(for: unnamed), .ip,
                  "an unnamed destination falls back to an address rule")

            let answered = PendingAlertAnswer(allow: false, scope: nil, remember: .no)
            check((try? PendingAlertRuleFactory.rule(for: named, answer: answered)) ?? nil == nil,
                  "answering without --remember stores no rule")

            let forever = try! PendingAlertRuleFactory.rule(
                for: named,
                answer: PendingAlertAnswer(allow: true, scope: .domain, remember: .forever))!
            equal(forever.action, .allow, "an allow answer stores an allow rule")
            equal(forever.scope, .domain, "the requested scope is honored")
            equal(forever.remoteHost, "api.example.com", "the domain rule targets the asked destination")
            equal(forever.processBundleId, "com.beeper.app", "a remembered rule stays app specific")
            check(forever.expiresAt == nil, "a permanent decision has no expiration")
            check(!forever.temporary, "a permanent decision is not marked temporary")

            let now = Date()
            let temporary = try! PendingAlertRuleFactory.rule(
                for: unnamed,
                answer: PendingAlertAnswer(allow: false, scope: nil, remember: .duration(1800)),
                now: now)!
            equal(temporary.action, .deny, "a deny answer stores a deny rule")
            equal(temporary.scope, .ip, "an unnamed destination stores an address rule")
            equal(temporary.remoteIP, "203.0.113.55", "the address rule pins the observed address")
            check(temporary.temporary, "a timed decision is marked temporary")
            equal(temporary.expiresAt.map { Int($0.timeIntervalSince(now).rounded()) }, 1800,
                  "the remembered duration becomes the rule expiration")

            let port = try! PendingAlertRuleFactory.rule(
                for: named,
                answer: PendingAlertAnswer(allow: true, scope: .port, remember: .forever))!
            equal(port.remotePort, 443, "a port rule carries the asked port")
            check(port.remoteHost == nil && port.remoteIP == nil, "a port rule is not also pinned to a destination")

            let process = try! PendingAlertRuleFactory.rule(
                for: named,
                answer: PendingAlertAnswer(allow: true, scope: .process, remember: .forever))!
            equal(process.scope, .process, "a process rule keeps process scope")
            check(process.remoteHost == nil && process.remoteIP == nil && process.remotePort == nil,
                  "a process rule matches the app rather than one destination")

            // A rule that would match nothing is refused instead of stored.
            for (scope, alert, label) in [
                (PendingAlertScope.domain, unnamed, "a domain rule for a destination with no name"),
                (PendingAlertScope.port, descriptor(port: 0), "a port rule for an alert with no port"),
                (PendingAlertScope.process, descriptor(bundle: nil, path: ""), "a process rule for an alert with no app identity"),
                (PendingAlertScope.ip, descriptor(host: "api.example.com", ip: ""), "an address rule for an alert with no address")
            ] {
                do {
                    _ = try PendingAlertRuleFactory.rule(
                        for: alert,
                        answer: PendingAlertAnswer(allow: true, scope: scope, remember: .forever))
                    check(false, "\(label) is refused")
                } catch {
                    check(true, "\(label) is refused: \(error.localizedDescription)")
                }
            }
        }

        // MARK: durations are bounded on the way in
        do {
            equal(try? PendingAlertDuration.parse("30m").seconds, 1800, "30m parses to half an hour")
            equal(try? PendingAlertDuration.parse("2h").seconds, 7200, "2h parses to two hours")
            equal(try? PendingAlertDuration.parse("1d").seconds, 86400, "1d parses to a day")
            equal(try? PendingAlertDuration.parse("forever").kind, .forever, "forever is a permanent rule")
            for bad in ["1s", "400d", "-5m", "abc", "", "5"] {
                do {
                    _ = try PendingAlertDuration.parse(bad)
                    check(false, "the duration `\(bad)` is refused")
                } catch {
                    check(true, "the duration `\(bad)` is refused")
                }
            }
            do {
                try PendingAlertAnswer(allow: true, scope: .ip, remember: .no).validate()
                check(false, "a scope without a remembered decision is refused")
            } catch {
                check(true, "a scope without a remembered decision is refused")
            }
        }

        // The shell half of this test compares these against the real sources.
        print("harness-value maxLifetime=\(Int(PendingAlertLimits.maxLifetime))")
        print("harness-value flowAskTimeout=\(Int(PendingAlertLimits.flowAskTimeout))")
        print("harness-value capacity=\(PendingAlertLimits.capacity)")

        if failures > 0 {
            FileHandle.standardError.write(Data("pending alert harness: \(failures) failure(s)\n".utf8))
            exit(1)
        }
        print("pending alert harness: PASS: all checks")
    }

    static func pass(_ message: String) { print("pending alert harness: PASS: \(message)") }
}
SWIFT

mkdir -p "$TMP/build"
xcrun swiftc -O \
  -sdk "$(xcrun --show-sdk-path)" \
  -target arm64-apple-macos13.0 \
  -parse-as-library \
  -o "$TMP/build/run" \
  $(ls "$ROOT"/Sources/Helper/*.swift | rg -v '/main.swift$') \
  "$ROOT"/Sources/Shared/*.swift \
  "$TMP/verify.swift"

"$TMP/build/run" | tee "$TMP/harness.log"

harness_value() {
  sed -n "s/^harness-value $1=//p" "$TMP/harness.log"
}

# The registry budget is only safe relative to the budgets in the sources that
# actually hold the flow. Read both of those out of the real files rather than
# trusting a constant that could drift.
MAX_LIFETIME="$(harness_value maxLifetime)"
EXTENSION_TIMEOUT="$(rg -o 'private let askTimeout: TimeInterval = ([0-9]+)' -r '$1' "$ROOT/Sources/NetExt/FilterDataProvider.swift" | head -1)"
HELPER_TIMEOUT="$(rg -o 'static let askTimeout: TimeInterval = ([0-9]+)' -r '$1' "$ROOT/Sources/Helper/HelperService.swift" | head -1)"

[[ -n "$MAX_LIFETIME" && -n "$EXTENSION_TIMEOUT" && -n "$HELPER_TIMEOUT" ]] \
  || fail "could not read the alert lifetime and both ask timeouts from the real sources"
if [[ "$MAX_LIFETIME" -lt "$EXTENSION_TIMEOUT" ]]; then
  pass "a registered alert (${MAX_LIFETIME}s) expires before the extension's flow budget (${EXTENSION_TIMEOUT}s)"
else
  fail "a registered alert (${MAX_LIFETIME}s) can outlive the extension's flow budget (${EXTENSION_TIMEOUT}s)"
fi
if [[ "$MAX_LIFETIME" -lt "$HELPER_TIMEOUT" ]]; then
  pass "a registered alert (${MAX_LIFETIME}s) expires before the helper's ask budget (${HELPER_TIMEOUT}s)"
else
  fail "a registered alert (${MAX_LIFETIME}s) can outlive the helper's ask budget (${HELPER_TIMEOUT}s)"
fi

require_text() {
  local file="$1" needle="$2" message="$3"
  if grep -Fq "$needle" "$file"; then
    pass "$message"
  else
    fail "$message"
  fi
}

HELPER="$ROOT/Sources/Helper/HelperService.swift"
PROVIDER="$ROOT/Sources/NetExt/FilterDataProvider.swift"
APP_STATE="$ROOT/Sources/GUI/ViewModels/AppState.swift"
RUNNER="$ROOT/Sources/CLI/CLIRunner.swift"

# The CLI must not have become a notification client to make this work.
require_text "$HELPER" "if !XPCPeerValidator.isCLI(newConnection) {" \
  "the CLI is still refused notification-client status by the helper listener"
require_text "$HELPER" "XPCPeerValidator.isCLI(connection)" \
  "the helper refuses a pending alert registration from the CLI"
# Fail open is still the extension's answer to an unanswered flow.
require_text "$PROVIDER" "workQueue.asyncAfter(deadline: .now() + askTimeout) { resumeOnce(NEFilterNewFlowVerdict.allow()) }" \
  "an unanswered flow still resumes with the fail-open allow verdict"
# The app is still the only process that answers the extension.
require_text "$APP_STATE" "registerPendingAlertWithHelper(alert)" \
  "the app registers the alert it presents"
require_text "$APP_STATE" "withdrawPendingAlertFromHelper(alert.id)" \
  "the app claims the registry entry when a human answers in the app"
require_text "$APP_STATE" "guard finishAlert(id: alert.id, allow: allow, remember: remember) else { return }" \
  "the app answers each alert exactly once"
require_text "$APP_STATE" "PendingAlertRegistry.defaultDecision" \
  "the app applies the fail-open default when the registry cannot queue an alert"
# Each way of failing to answer keeps its own code, so a script can tell them
# apart instead of parsing prose.
for code in alert_already_answered alert_expired alert_not_found alert_rule_not_stored; do
  require_text "$RUNNER" "\"$code\"" "alerts answer reports $code specifically"
done
require_text "$ROOT/docs/CLI.md" "freesnitch alerts answer" \
  "the CLI documentation describes answering an alert"

if [[ "$failures" -gt 0 ]]; then
  printf 'pending alerts verification: FAILED (%d)\n' "$failures" >&2
  exit 1
fi
printf 'pending alerts verification: PASS\n'
