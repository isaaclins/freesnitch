#!/usr/bin/env bash
# Replays #370: FreeSnitch opened from a disk image or Downloads offers to move
# itself into Applications. Compiles the shipping InstallLocation.swift and
# LegacyPureSnitch.swift and runs the move against a fake bundle and a fake
# Applications folder in a scratch directory. Nothing here touches the real
# /Applications, launchd, or PureSnitch.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-install-location.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/main.swift" <<'SWIFT'
import Foundation

var failures = 0
func check(_ ok: Bool, _ what: String) {
    print("install location: \(ok ? "PASS" : "FAIL"): \(what)")
    if !ok { failures += 1 }
}

let fm = FileManager.default
let work = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)

func makeBundle(at url: URL, build: String) {
    try! fm.createDirectory(at: url.appendingPathComponent("Contents/MacOS"), withIntermediateDirectories: true)
    let info: NSDictionary = ["CFBundleVersion": build]
    info.write(to: url.appendingPathComponent("Contents/Info.plist"), atomically: true)
    fm.createFile(atPath: url.appendingPathComponent("Contents/MacOS/FreeSnitch").path, contents: Data("bin".utf8))
}

func ok(_ r: Result<Void, InstallLocation.MoveError>) -> Bool { if case .success = r { return true }; return false }

func quarantined(_ path: String) -> Bool {
    getxattr(path, "com.apple.quarantine", nil, 0, 0, XATTR_NOFOLLOW) >= 0
}

// A downloaded copy carries the quarantine flag on the bundle and inside it.
let downloads = work.appendingPathComponent("Downloads", isDirectory: true)
let source = downloads.appendingPathComponent("FreeSnitch.app", isDirectory: true)
makeBundle(at: source, build: "35")
let flag = "0081;00000000;Safari;"
for path in [source.path, source.appendingPathComponent("Contents/MacOS/FreeSnitch").path] {
    _ = flag.withCString { setxattr(path, "com.apple.quarantine", $0, strlen($0), 0, XATTR_NOFOLLOW) }
}
check(quarantined(source.path), "the fixture is quarantined like a download")

// Empty Applications: copy, and the copy is not quarantined, so macOS will
// not translocate it out of Applications again.
let apps = work.appendingPathComponent("Applications", isDirectory: true)
try! fm.createDirectory(at: apps, withIntermediateDirectories: true)
let destination = apps.appendingPathComponent("FreeSnitch.app", isDirectory: true)
check(InstallLocation.plan(source: source, applications: apps) == .copy(to: destination),
      "with nothing installed, the plan is to copy into Applications")
check(ok(InstallLocation.copyBundle(from: source, to: destination)), "the copy succeeds")
check(fm.fileExists(atPath: destination.appendingPathComponent("Contents/MacOS/FreeSnitch").path),
      "the copied bundle is complete")
check(!quarantined(destination.path) && !quarantined(destination.appendingPathComponent("Contents/MacOS/FreeSnitch").path),
      "the copy carries no quarantine flag, on the bundle or inside it")
check(quarantined(source.path), "the original is left as it was until the app trashes it")
check(try! fm.contentsOfDirectory(atPath: apps.path) == ["FreeSnitch.app"], "no staging leftovers in Applications")

// Something already installed is never replaced or deleted.
let marker = destination.appendingPathComponent("Contents/marker")
fm.createFile(atPath: marker.path, contents: Data())
check(InstallLocation.plan(source: source, applications: apps) == .existing(destination, isOlder: false),
      "the same build already installed is offered for opening, not replaced")
check(!ok(InstallLocation.copyBundle(from: source, to: destination)), "copying over an installed copy refuses")
check(fm.fileExists(atPath: marker.path), "the installed copy is untouched")

let olderApps = work.appendingPathComponent("OlderApplications", isDirectory: true)
makeBundle(at: olderApps.appendingPathComponent("FreeSnitch.app"), build: "34")
check(InstallLocation.plan(source: source, applications: olderApps)
        == .existing(olderApps.appendingPathComponent("FreeSnitch.app", isDirectory: true), isOlder: true),
      "an older installed build is recognised, so the app doesn't reopen the downgrade")

// A copy that fails halfway leaves nothing behind.
let lockedApps = work.appendingPathComponent("LockedApplications", isDirectory: true)
try! fm.createDirectory(at: lockedApps, withIntermediateDirectories: true)
try! fm.setAttributes([.posixPermissions: 0o555], ofItemAtPath: lockedApps.path)
let lockedResult = InstallLocation.copyBundle(from: source, to: lockedApps.appendingPathComponent("FreeSnitch.app"))
try! fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: lockedApps.path)
check(!ok(lockedResult), "a folder the user can't write to reports a failure")
check(try! fm.contentsOfDirectory(atPath: lockedApps.path).isEmpty, "a failed copy leaves no partial bundle")

check(InstallLocation.translocatedOriginal(of: source) == nil, "a bundle that isn't translocated has no other original")
check(InstallLocation.isInApplications(URL(fileURLWithPath: "/Applications/FreeSnitch.app"), home: "/Users/x")
      && InstallLocation.isInApplications(URL(fileURLWithPath: "/Users/x/Applications/FreeSnitch.app"), home: "/Users/x")
      && !InstallLocation.isInApplications(URL(fileURLWithPath: "/Users/x/Downloads/FreeSnitch.app"), home: "/Users/x"),
      "Applications and ~/Applications count as installed, Downloads doesn't")

// PureSnitch detection looks at its two fixed paths only.
var asked: [String] = []
let none = LegacyPureSnitch.detect { asked.append($0); return false }
check(!none.any, "no PureSnitch, nothing offered")
check(asked == ["/Applications/PureSnitch.app", "/Library/LaunchDaemons/io.isaaclins.puresnitch.helper.plist"],
      "detection checks exactly the old app and the old helper plist")
check(LegacyPureSnitch.detect { $0.hasSuffix(".plist") } == .init(app: false, daemon: true),
      "a helper left behind without the app is still found")

exit(failures == 0 ? 0 : 1)
SWIFT

# The two files reach into HelperClient for the Applications check; a stub
# keeps the harness from compiling the whole app.
cat > "$TMP/stubs.swift" <<'SWIFT'
import Foundation
enum HelperClient { @MainActor static var isInApplicationsFolder: Bool { false } }
SWIFT

swiftc -O -o "$TMP/run" "$TMP/main.swift" "$TMP/stubs.swift" \
  "$ROOT/Sources/GUI/App/InstallLocation.swift" "$ROOT/Sources/GUI/App/LegacyPureSnitch.swift" 2>&1
"$TMP/run" "$TMP"

# Static guards: the privileged removal never names FreeSnitch, and the
# move never deletes the installed copy.
script="$(awk '/private static let removeDaemon = """/ { on = 1; next } on && /^    """$/ { exit } on' "$ROOT/Sources/GUI/App/LegacyPureSnitch.swift")"
printf '%s\n' "$script" | grep -q 'launchctl bootout system/io.isaaclins.puresnitch.helper' \
  || { echo "install location: FAIL: could not read the PureSnitch removal script" >&2; exit 1; }
printf '%s\n' "$script" | grep -qi 'freesnitch' \
  && { echo "install location: FAIL: the PureSnitch removal script names FreeSnitch" >&2; exit 1; }
echo "install location: PASS: the PureSnitch removal script never names FreeSnitch"
if grep -nE 'removeItem\(at: (destination|installed)|trashItem\(at: (destination|installed)' "$ROOT/Sources/GUI/App/InstallLocation.swift"; then
  echo "install location: FAIL: the move can delete the installed copy" >&2; exit 1
fi
echo "install location: PASS: the move never deletes the installed copy"
