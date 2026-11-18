#!/usr/bin/env bash
# iPhone and iPad apps on Apple silicon get their bundle id (#325).
#
# Such an app runs from a wrapper, /Applications/X.app/Wrapper/X.app/X, and is
# a shallow iOS bundle: its Info.plist sits at the bundle root, with no
# Contents folder. The extension only ever looked in Contents/Info.plist, so
# these apps never got a bundle id and a rule scoped to one never matched.
#
# The harness compiles the extension's real BundleIdentifierCache and the
# shared plist lookup, lays out real bundles on disk and checks that:
#   - a wrapped iOS app resolves to its own bundle id and version
#   - a normal Mac app still reads Contents/Info.plist
#   - a Mac app is never read from a stray Info.plist at its root
#   - a Mac app without an Info.plist is a failed read (logged and retried),
#     never answered from a root Info.plist; a binary outside any .app has none
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-wrapped-ios.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
FILTER="$ROOT/Sources/NetExt/FilterDataProvider.swift"

{
  printf 'import Foundation\nimport Darwin\nimport os.log\n'
  awk '/^struct AppBundleMetadata/{on=1} on && /^#endif/{exit} on' "$FILTER"
} > "$TMP/cache.swift"
grep -q 'final class BundleIdentifierCache' "$TMP/cache.swift"

cat > "$TMP/main.swift" <<'SWIFT'
import Foundation
import os.log

enum PSLog {
    static let netext = OSLog.disabled
    static func error(_ log: OSLog, _ msg: String) {}
    static func info(_ log: OSLog, _ msg: String) {}
}

func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else {
        FileHandle.standardError.write(Data(("wrapped ios harness: FAIL: " + message + "\n").utf8))
        exit(1)
    }
    print("wrapped ios harness: ok: " + message)
}

let root = URL(fileURLWithPath: CommandLine.arguments[1])
let fm = FileManager.default

func mkdir(_ url: URL) { try! fm.createDirectory(at: url, withIntermediateDirectories: true) }
func plist(_ url: URL, _ dict: [String: Any]) {
    try! PropertyListSerialization.data(fromPropertyList: dict, format: .binary, options: 0).write(to: url)
}
func touch(_ url: URL) { try! Data().write(to: url) }
func meta(_ executable: URL) -> AppBundleMetadataRead? {
    BundleIdentifierCache.appBundlePath(forExecutablePath: executable.path)
        .map { BundleIdentifierCache.readBundleMetadata(atAppPath: $0) }
}
func readMeta(_ executable: URL) -> AppBundleMetadata? {
    if case .read(let m)? = meta(executable) { return m }
    return nil
}

// A wrapped iOS app as the App Store installs it on an Apple silicon Mac.
let outer = root.appendingPathComponent("Applications/Notes Pad.app")
let inner = outer.appendingPathComponent("Wrapper/Notes Pad.app")
mkdir(inner)
plist(inner.appendingPathComponent("Info.plist"),
      ["CFBundleIdentifier": "com.example.notespad", "CFBundleShortVersionString": "4.2", "CFBundleVersion": "17"])
plist(outer.appendingPathComponent("Wrapper/iTunesMetadata.plist"), ["itemName": "Notes Pad"])
try! fm.createSymbolicLink(atPath: outer.appendingPathComponent("WrappedBundle").path,
                           withDestinationPath: "Wrapper/Notes Pad.app")
let iosExecutable = inner.appendingPathComponent("Notes Pad")
touch(iosExecutable)

// A normal Mac app, with a decoy Info.plist at its root that must be ignored.
let mac = root.appendingPathComponent("Applications/Editor.app")
mkdir(mac.appendingPathComponent("Contents/MacOS"))
plist(mac.appendingPathComponent("Contents/Info.plist"),
      ["CFBundleIdentifier": "com.example.editor", "CFBundleShortVersionString": "1.0"])
plist(mac.appendingPathComponent("Info.plist"), ["CFBundleIdentifier": "com.example.decoy"])
let macExecutable = mac.appendingPathComponent("Contents/MacOS/Editor")
touch(macExecutable)

// A Mac app whose Info.plist is missing, with a decoy at its root.
let broken = root.appendingPathComponent("Applications/Broken.app")
mkdir(broken.appendingPathComponent("Contents/MacOS"))
plist(broken.appendingPathComponent("Info.plist"), ["CFBundleIdentifier": "com.example.decoy"])
let brokenExecutable = broken.appendingPathComponent("Contents/MacOS/Broken")
touch(brokenExecutable)

let loose = root.appendingPathComponent("bin/tool")
mkdir(loose.deletingLastPathComponent())
touch(loose)

let iosApp = BundleIdentifierCache.appBundlePath(forExecutablePath: iosExecutable.path)
expect(iosApp == inner.path + "/", "the innermost .app of a wrapped iOS app is the iOS bundle")
let iosMeta = readMeta(iosExecutable)
expect(iosMeta?.bundleIdentifier == "com.example.notespad", "a wrapped iOS app gets its bundle id")
expect(iosMeta?.version == "4.2 (17)", "a wrapped iOS app gets its version")

let macMeta = readMeta(macExecutable)
expect(macMeta?.bundleIdentifier == "com.example.editor", "a Mac app still reads Contents/Info.plist, never a root Info.plist")

let brokenFailed: Bool
if case .failed? = meta(brokenExecutable) { brokenFailed = true } else { brokenFailed = false }
expect(brokenFailed, "a Mac app with no Contents/Info.plist is a failed read, not a root Info.plist")

expect(BundleIdentifierCache.appBundlePath(forExecutablePath: loose.path) == nil, "a binary outside any .app has no bundle")

// The whole path the extension takes for a flow: first sight queues the read,
// the next flow from the same process sees the bundle id.
let cache = BundleIdentifierCache()
_ = cache.cachedMetadata(forExecutablePath: iosExecutable.path)
cache.waitForPendingResolves()
expect(cache.cachedMetadata(forExecutablePath: iosExecutable.path)?.claimedBundleIdentifier == "com.example.notespad",
       "the extension's cache answers a wrapped iOS app's bundle id")
print("wrapped ios harness: all checks passed")
SWIFT

xcrun swiftc -swift-version 5 -O -o "$TMP/harness" \
  "$ROOT/Sources/Shared/AppBundleIdentity.swift" "$ROOT/Sources/Shared/CodeSigningIdentity.swift" \
  "$TMP/cache.swift" "$TMP/main.swift"
"$TMP/harness" "$TMP/fixtures"
