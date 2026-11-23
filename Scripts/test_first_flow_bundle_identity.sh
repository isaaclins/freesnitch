#!/usr/bin/env bash
# The first flow of an app gets the same bundle id rules as its later flows
# (#197).
#
# The extension answers a flow's bundle identity from a cache and reads it in
# the background on a miss, so the first flow of an app used to be matched
# with no bundle id at all: a deny rule for the app missed and, in Silent
# Allow, the flow went through. The harness replays that against the real
# BundleIdentifierCache and the real RuleMatcher, with the signature check and
# the Info.plist read held until the harness lets them finish, and checks:
#   - before the read, the flow has no bundle id and its deny rule misses (the
#     bug, shown so the replay is known to reach it)
#   - such a flow is reported as waiting on its identity, and a bundle rule
#     could decide it, so the extension holds it
#   - once the read finishes, the waiting flow gets the same verdict as a
#     later flow: deny for a deny rule, allow for an allow rule in Alert mode,
#     deny for the id an unsigned app's Info.plist claims
#   - every flow waiting on the same app is woken by one read
#   - a read that never finishes holds the flow at most the timeout and the
#     flow is then decided as before, with what is known (fail open)
#   - nothing waits when no bundle rule could decide the flow: no bundle
#     rules, a rule without a bundle id that already decides it, a bundle rule
#     for another port, an executable outside an .app, or a signature that
#     could not be read once already
#   - new code at a path already known waits for its own signature check
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-first-flow.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
FILTER="$ROOT/Sources/NetExt/FilterDataProvider.swift"

# The cache and everything it needs, exactly as the extension compiles it.
{
  printf 'import Foundation\nimport Darwin\nimport os.log\n'
  awk '/^struct AppBundleMetadata/{on=1} on && /^#endif/{exit} on' "$FILTER"
} > "$TMP/cache.swift"
grep -q 'func whenIdentityKnown' "$TMP/cache.swift"
grep -q 'typealias FlowIdentity' "$TMP/cache.swift"

cat > "$TMP/main.swift" <<'SWIFT'
import Foundation

func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else {
        FileHandle.standardError.write(Data(("first flow harness: FAIL: " + message + "\n").utf8))
        exit(1)
    }
    print("first flow harness: ok: " + message)
}

/// Lets a test decide when the background read finishes.
final class Gate: @unchecked Sendable {
    private let condition = NSCondition()
    private var open = false
    func wait() { condition.lock(); while !open { condition.wait() }; condition.unlock() }
    func release() { condition.lock(); open = true; condition.broadcast(); condition.unlock() }
}

let app = "/Applications/Example.app/Contents/MacOS/Example"
let token = Data(repeating: 1, count: 32)
let otherToken = Data(repeating: 2, count: 32)
let signed = CodeSigningIdentity.SignedBundle(identifier: "com.example.app", team: "TEAM123456")

func makeCache(gate: Gate, signature: CodeSigningIdentity.Resolution = .resolved(signed),
               claimed: String = "com.example.app") -> BundleIdentifierCache {
    BundleIdentifierCache(
        read: { _ in gate.wait(); return .read(AppBundleMetadata(bundleIdentifier: claimed, version: "1.0")) },
        identify: { _, _ in gate.wait(); return signature },
        codeHash: { token in token.map { CDHash(($0.first == 2 ? 2 : 1, 0, 0)) } })
}

func flow(path: String = app, port: Int = 443) -> Connection {
    Connection(pid: 42, processName: "Example", processPath: path,
               remoteHost: "example.com", remoteIP: "93.184.216.34", remotePort: port,
               direction: .outgoing, status: .pending)
}

func withIdentity(_ c: Connection, _ m: AppBundleMetadata?) -> Connection {
    var c = c
    c.processBundleId = m?.bundleIdentifier
    c.processTeamId = m?.bundleIdentifier == nil ? nil : m?.team
    c.claimedBundleId = m?.claimedBundleIdentifier
    return c
}

let matcher = RuleMatcher()
let queue = DispatchQueue(label: "harness.work")

/// What the extension does for a paused flow: wait, then decide.
func decideAfterWait(_ cache: BundleIdentifierCache, path: String = app, auditToken: Data = token,
                     timeout: TimeInterval = 10, prepared: PreparedRuleSet, mode: AppMode,
                     port: Int = 443) -> (action: RuleAction, timedOut: Bool)? {
    let done = DispatchSemaphore(value: 0)
    var result: (RuleAction, Bool)?
    cache.whenIdentityKnown(forExecutablePath: path, auditToken: auditToken, timeout: timeout, queue: queue) { identity, timedOut in
        let c = withIdentity(flow(path: path, port: port), identity.metadata)
        result = (matcher.decision(for: c, prepared: prepared, defaultMode: mode), timedOut)
        done.signal()
    }
    return done.wait(timeout: .now() + 20) == .success ? result : nil
}

let denyRule = Rule(processBundleId: "com.example.app", action: .deny, priority: 100)
let denies = PreparedRuleSet(rules: [denyRule])

// 1. The replay: a deny rule for the app, Silent Allow, first flow.
do {
    let gate = Gate()
    let cache = makeCache(gate: gate)
    let first = cache.cachedIdentity(forExecutablePath: app, auditToken: token)
    expect(first.metadata?.bundleIdentifier == nil, "before the read the first flow has no bundle id")
    expect(matcher.decision(for: withIdentity(flow(), first.metadata), prepared: denies, defaultMode: .silentAllow) == .allow,
           "decided without waiting, the first flow misses its deny rule and is allowed (the bug)")
    expect(first.pending, "the first flow is reported as still waiting on its identity")
    expect(matcher.bundleRuleMightDecide(for: withIdentity(flow(), first.metadata), prepared: denies),
           "a deny rule for the app could decide it, so the extension holds the flow")
    // Several flows of the same app wait at once; one read wakes them all.
    var waiting: [DispatchSemaphore] = []
    var verdicts: [RuleAction] = []
    let verdictLock = NSLock()
    for _ in 0..<5 {
        let s = DispatchSemaphore(value: 0)
        waiting.append(s)
        cache.whenIdentityKnown(forExecutablePath: app, auditToken: token, timeout: 10, queue: queue) { identity, timedOut in
            let v = matcher.decision(for: withIdentity(flow(), identity.metadata), prepared: denies, defaultMode: .silentAllow)
            verdictLock.lock(); verdicts.append(timedOut ? .ask : v); verdictLock.unlock()
            s.signal()
        }
    }
    // Nothing is decided while the read is held: every wait has looked at
    // the cache once the work queue has run what was queued on it.
    queue.sync {}
    verdictLock.lock(); let early = verdicts.count; verdictLock.unlock()
    expect(early == 0, "no waiting flow is decided while the read is still running")
    gate.release()
    for s in waiting { _ = s.wait(timeout: .now() + 20) }
    expect(verdicts.count == 5 && verdicts.allSatisfy { $0 == .deny },
           "once the read finishes, every waiting first flow is denied by the app's deny rule")
    let later = cache.cachedIdentity(forExecutablePath: app, auditToken: token)
    expect(!later.pending && matcher.decision(for: withIdentity(flow(), later.metadata), prepared: denies, defaultMode: .silentAllow) == .deny,
           "a later flow gets the same deny, without waiting")
}

// 2. An allow rule in Alert mode: the first flow is allowed, not asked about.
do {
    let gate = Gate()
    let cache = makeCache(gate: gate)
    let allows = PreparedRuleSet(rules: [Rule(processBundleId: "com.example.app", processTeamId: "TEAM123456", action: .allow)])
    _ = cache.cachedIdentity(forExecutablePath: app, auditToken: token)
    gate.release()
    let r = decideAfterWait(cache, prepared: allows, mode: .alert)
    expect(r?.action == .allow && r?.timedOut == false, "an allow rule for the app allows its first flow in Alert mode")
}

// 3. An unsigned app: only the Info.plist claims the id, and a deny still applies.
do {
    let gate = Gate()
    let cache = makeCache(gate: gate, signature: .resolved(nil))
    let first = cache.cachedIdentity(forExecutablePath: app, auditToken: token)
    expect(first.pending, "an unsigned app's first flow waits for its Info.plist")
    gate.release()
    let r = decideAfterWait(cache, prepared: denies, mode: .silentAllow)
    expect(r?.action == .deny, "a deny rule matches the id an unsigned app's Info.plist claims on its first flow")
}

// 4. A read that never finishes: bounded wait, then decided as before.
do {
    let gate = Gate()
    let cache = makeCache(gate: gate)
    _ = cache.cachedIdentity(forExecutablePath: app, auditToken: token)
    let started = Date()
    let r = decideAfterWait(cache, timeout: 0.3, prepared: denies, mode: .silentAllow)
    let waited = Date().timeIntervalSince(started)
    expect(r?.timedOut == true, "a read that does not finish ends the wait at the timeout")
    expect(waited < 5, "the flow is not held past its timeout (waited \(String(format: "%.2f", waited)) s)")
    expect(r?.action == .allow, "after the timeout the flow is decided with what is known, failing open as before")
    gate.release()
    cache.waitForPendingResolves()
}

// 5. Nothing to wait for.
do {
    let gate = Gate()
    gate.release()
    let cache = makeCache(gate: gate)
    let c = flow()
    expect(!matcher.bundleRuleMightDecide(for: c, prepared: PreparedRuleSet(rules: [Rule(remoteHost: "example.com", action: .deny)])),
           "no bundle rule: the flow is decided at once")
    let pathFirst = PreparedRuleSet(rules: [
        Rule(processPath: app, action: .allow, priority: 200),
        denyRule,
    ])
    expect(!matcher.bundleRuleMightDecide(for: c, prepared: pathFirst),
           "a higher rule without a bundle id already decides the flow: no wait")
    let bundleFirst = PreparedRuleSet(rules: [
        Rule(processBundleId: "com.example.app", action: .deny, priority: 200),
        Rule(processPath: app, action: .allow, priority: 100),
    ])
    expect(matcher.bundleRuleMightDecide(for: c, prepared: bundleFirst),
           "a bundle rule above a path rule could still decide the flow: it waits")
    let otherPort = PreparedRuleSet(rules: [Rule(processBundleId: "com.example.app", remotePort: 22, action: .deny)])
    expect(!matcher.bundleRuleMightDecide(for: c, prepared: otherPort),
           "a bundle rule for another port cannot decide this flow: no wait")
    let expired = PreparedRuleSet(rules: [Rule(processBundleId: "com.example.app", action: .deny, expiresAt: Date(timeIntervalSinceNow: -60))])
    expect(!matcher.bundleRuleMightDecide(for: c, prepared: expired), "an expired bundle rule: no wait")

    let tool = cache.cachedIdentity(forExecutablePath: "/usr/local/bin/tool", auditToken: token)
    expect(!tool.pending, "an executable outside an .app never gets a bundle identity, so it never waits")

    let failing = makeCache(gate: gate, signature: .unavailable)
    _ = failing.cachedIdentity(forExecutablePath: app, auditToken: token)
    failing.waitForPendingResolves()
    expect(!failing.cachedIdentity(forExecutablePath: app, auditToken: token).pending,
           "code whose signature could not be read once is not waited on again on every flow")

    let noHash = makeCache(gate: gate)
    _ = noHash.cachedIdentity(forExecutablePath: app, auditToken: nil)
    noHash.waitForPendingResolves()
    expect(!noHash.cachedIdentity(forExecutablePath: app, auditToken: nil).pending,
           "a flow whose code hash the kernel would not give waits only for the plist, once")
}

// 6. New code at a known path waits for its own signature check.
do {
    let gate = Gate()
    gate.release()
    let cache = makeCache(gate: gate)
    _ = cache.cachedIdentity(forExecutablePath: app, auditToken: token)
    cache.waitForPendingResolves()
    expect(!cache.cachedIdentity(forExecutablePath: app, auditToken: token).pending, "checked code is not waited on")
    let swapped = cache.cachedIdentity(forExecutablePath: app, auditToken: otherToken)
    expect(swapped.pending && swapped.metadata?.bundleIdentifier == nil,
           "new code at the same path has no signed id yet and waits for its own check")
    let r = decideAfterWait(cache, auditToken: otherToken, prepared: denies, mode: .silentAllow)
    expect(r?.action == .deny && r?.timedOut == false, "and gets the app's deny once checked")
}

print("first flow harness: PASS")
SWIFT

SHARED=()
while IFS= read -r file; do SHARED+=("$file"); done < <(find "$ROOT/Sources/Shared" -name '*.swift' | sort)
mkdir -p "$TMP/build"
xcrun swiftc -swift-version 5 -O -o "$TMP/build/run" "${SHARED[@]}" "$TMP/cache.swift" "$TMP/main.swift" -lsqlite3
"$TMP/build/run"
