#!/usr/bin/env bash
# Replays a failed app Info.plist read against the extension's real
# BundleIdentifierCache and the real plist reader (#268).
#
# Before the fix a read or parse failure was cached as "this app has no bundle
# id" for the full five-minute entry lifetime, without a log line, so a rule
# scoped to that bundle id silently stopped matching. The harness checks that:
#   - a failed read is logged, with the app path and the reason
#   - it is not cached as "no bundle id": once the plist is readable again the
#     identifier is back within seconds, not minutes
#   - a refresh that fails keeps answering the identifier read before it
#   - a readable plist without a bundle id, and an executable outside an .app,
#     are still a plain "no bundle id" and are not logged as failures
#   - an app whose plist stays broken is retried with growing gaps, not on every flow
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-bundle-metadata.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
FILTER="$ROOT/Sources/NetExt/FilterDataProvider.swift"

# The cache and everything it needs, exactly as the extension compiles it.
{
  printf 'import Foundation\nimport Darwin\nimport os.log\n'
  awk '/^struct AppBundleMetadata/{on=1} on && /^#endif/{exit} on' "$FILTER"
} > "$TMP/cache.swift"
grep -q 'final class BundleIdentifierCache' "$TMP/cache.swift"

cat > "$TMP/main.swift" <<'SWIFT'
import Foundation
import os.log

/// Stand-in for the shared logger that remembers what was logged.
enum PSLog {
    static let netext = OSLog.disabled
    nonisolated(unsafe) static var errors: [String] = []
    nonisolated(unsafe) static var infos: [String] = []
    private static let lock = NSLock()
    static func error(_ log: OSLog, _ msg: String) { lock.lock(); errors.append(msg); lock.unlock() }
    static func info(_ log: OSLog, _ msg: String) { lock.lock(); infos.append(msg); lock.unlock() }
    static func reset() { lock.lock(); errors = []; infos = []; lock.unlock() }
}

func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else {
        FileHandle.standardError.write(Data(("bundle metadata harness: FAIL: " + message + "\n").utf8))
        exit(1)
    }
    print("bundle metadata harness: ok: " + message)
}

let root = URL(fileURLWithPath: CommandLine.arguments[1])

func makeApp(_ name: String) -> (plist: URL, executable: String) {
    let app = root.appendingPathComponent("\(name).app")
    try! FileManager.default.createDirectory(at: app.appendingPathComponent("Contents/MacOS"),
                                             withIntermediateDirectories: true)
    return (app.appendingPathComponent("Contents/Info.plist"),
            app.appendingPathComponent("Contents/MacOS/\(name)").path)
}

func writePlist(_ url: URL, _ dict: [String: Any]) {
    let data = try! PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
    try! data.write(to: url)
}

func writeGarbage(_ url: URL) {
    // What a reader sees mid-update: a truncated plist.
    try! Data("<?xml version=\"1.0\"?><plist><dict><key>CFBundleIdent".utf8).write(to: url)
}

/// A clock the test moves by hand, so nothing here depends on how fast the
/// machine is.
final class FakeClock: @unchecked Sendable {
    private var nanos: UInt64 = 1_000_000_000
    private let lock = NSLock()
    func now() -> UInt64 { lock.lock(); defer { lock.unlock() }; return nanos }
    func advance(_ seconds: Double) { lock.lock(); nanos += UInt64(seconds * 1_000_000_000); lock.unlock() }
}

final class Counter: @unchecked Sendable {
    private var n = 0
    private let lock = NSLock()
    func bump() { lock.lock(); n += 1; lock.unlock() }
    var value: Int { lock.lock(); defer { lock.unlock() }; return n }
}

/// One flow from `path`: what the verdict path sees, then let any read it
/// scheduled finish, as it would before the next flow on a real Mac.
@discardableResult
func flow(_ cache: BundleIdentifierCache, _ path: String) -> String? {
    let answer = cache.cachedBundleId(forExecutablePath: path)
    cache.waitForPendingResolves()
    return answer
}

// 1. The reported case: the first read of an app's plist fails (mid-update),
//    then the plist is fine again. Default lifetime (300 s) and retry, as the
//    extension uses them.
do {
    PSLog.reset()
    let clock = FakeClock()
    let app = makeApp("Updating")
    writeGarbage(app.plist)
    let cache = BundleIdentifierCache(clock: { clock.now() })
    expect(flow(cache, app.executable) == nil, "first flow has no identity yet")
    expect(flow(cache, app.executable) == nil, "a broken plist gives no identity")
    expect(PSLog.errors.count == 1 && PSLog.errors[0].contains(app.executable),
           "the failed Info.plist read is logged with the app it belongs to")
    writePlist(app.plist, ["CFBundleIdentifier": "com.example.updating", "CFBundleShortVersionString": "2.0"])
    clock.advance(1)
    flow(cache, app.executable) // due again: schedules the retry
    expect(flow(cache, app.executable) == "com.example.updating",
           "one second later the identity is back, not after five minutes")
    expect(PSLog.infos.contains { $0.contains("com.example.updating") }, "the recovery is logged")
}

// 2. An app that was identified, whose plist then fails on the periodic
//    refresh, keeps the identity it had instead of dropping to "no bundle id",
//    but only for one more lifetime, so a path taken over by another app does
//    not keep an old identity forever.
do {
    PSLog.reset()
    let clock = FakeClock()
    let app = makeApp("Refreshing")
    writePlist(app.plist, ["CFBundleIdentifier": "com.example.refreshing"])
    let cache = BundleIdentifierCache(clock: { clock.now() })
    flow(cache, app.executable)
    expect(flow(cache, app.executable) == "com.example.refreshing", "identified once")
    writeGarbage(app.plist)
    clock.advance(300)
    flow(cache, app.executable) // stale: schedules the refresh, which fails
    expect(flow(cache, app.executable) == "com.example.refreshing",
           "a failed refresh keeps the identity read before it")
    expect(PSLog.errors.count == 1 && PSLog.errors[0].contains("com.example.refreshing"),
           "the failed refresh is logged, saying which identity is kept")
    clock.advance(300)
    flow(cache, app.executable)
    expect(flow(cache, app.executable) == nil,
           "after two lifetimes without a good read the old identity is dropped")
}

// 3. Plain "no bundle id" answers are still plain and quiet.
do {
    PSLog.reset()
    let app = makeApp("NoIdentity")
    writePlist(app.plist, ["LSUIElement": true])
    let cache = BundleIdentifierCache()
    flow(cache, app.executable)
    flow(cache, "/usr/bin/curl")
    expect(flow(cache, app.executable) == nil, "a readable plist without an id has no id")
    expect(flow(cache, "/usr/bin/curl") == nil, "a tool outside an .app has no id")
    expect(PSLog.errors.isEmpty, "neither is logged as a failed read")
}

// 4. A plist that stays broken is retried with growing gaps (1, 2, 4 ... s, at
//    most the lifetime), logged once, and never read on every flow.
do {
    PSLog.reset()
    let clock = FakeClock()
    let reads = Counter()
    let app = makeApp("Broken")
    writeGarbage(app.plist)
    let cache = BundleIdentifierCache(read: { path in
        reads.bump()
        return BundleIdentifierCache.readBundleMetadata(atAppPath: path)
    }, clock: { clock.now() })
    // Ten flows a second for ten minutes.
    for _ in 0..<6000 {
        flow(cache, app.executable)
        clock.advance(0.1)
    }
    // Reads at 0, 1, 3, 7, 15, 31, 63, 127, 255 and 511 s (gaps double, capped at
    // the 300 s lifetime): 10 in 600 s.
    expect(reads.value == 10, "a plist that stays broken is retried with growing gaps (\(reads.value) reads for 6000 flows)")
    expect(PSLog.errors.count == 1, "and logged once while it stays broken (\(PSLog.errors.count) lines)")
    writePlist(app.plist, ["CFBundleIdentifier": "com.example.broken"])
    clock.advance(300)
    flow(cache, app.executable)
    expect(flow(cache, app.executable) == "com.example.broken", "and picked up once it reads again")
    expect(PSLog.infos.count == 1 && PSLog.infos[0].contains("com.example.broken"), "the recovery is logged once")
}

print("bundle metadata harness: PASS")
SWIFT

mkdir -p "$TMP/build" "$TMP/apps"
xcrun swiftc -O \
  -sdk "$(xcrun --show-sdk-path)" \
  -target arm64-apple-macos13.0 \
  -o "$TMP/build/run" \
  "$TMP/cache.swift" "$TMP/main.swift"

"$TMP/build/run" "$TMP/apps"
printf 'bundle metadata cache: PASS\n'
