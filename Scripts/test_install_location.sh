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

// A bundle whose flag can't be removed (owned by someone else) must say so,
// or a translocated copy in Applications would relaunch itself forever.
let locked = work.appendingPathComponent("Locked.app", isDirectory: true)
makeBundle(at: locked, build: "35")
_ = flag.withCString { setxattr(locked.path, "com.apple.quarantine", $0, strlen($0), 0, XATTR_NOFOLLOW) }
try! fm.setAttributes([.posixPermissions: 0o555], ofItemAtPath: locked.path)
let lockedCleared = InstallLocation.clearQuarantine(at: locked)
let writable = access(locked.path, W_OK) == 0  // root can still write
try! fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: locked.path)
check(writable || !lockedCleared, "clearing reports failure when the flag stays")
check(InstallLocation.clearQuarantine(at: locked), "clearing reports success once the flag is gone")
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

// A bundle that arrives read-only keeps its flag on the copy. That copy must
// not count as moved (it would run translocated again), and must not be left
// behind half-made.
let readOnly = work.appendingPathComponent("ReadOnly/FreeSnitch.app", isDirectory: true)
makeBundle(at: readOnly, build: "35")
_ = flag.withCString { setxattr(readOnly.path, "com.apple.quarantine", $0, strlen($0), 0, XATTR_NOFOLLOW) }
try! fm.setAttributes([.posixPermissions: 0o555], ofItemAtPath: readOnly.path)
let roApps = work.appendingPathComponent("ROApplications", isDirectory: true)
try! fm.createDirectory(at: roApps, withIntermediateDirectories: true)
let roResult = InstallLocation.copyBundle(from: readOnly, to: roApps.appendingPathComponent("FreeSnitch.app"))
try! fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: readOnly.path)
check(!ok(roResult), "a copy that keeps the download flag is reported as a failure")
check((try? fm.contentsOfDirectory(atPath: roApps.path))?.isEmpty == true, "nothing is left in Applications after that failure")

// #413: a move cut off mid-copy (crash, force quit) left its hidden staging
// folder behind. The next move removes those, read-only insides included,
// and nothing else in the folder.
let leftApps = work.appendingPathComponent("LeftoverApplications", isDirectory: true)
try! fm.createDirectory(at: leftApps, withIntermediateDirectories: true)
let leftover = leftApps.appendingPathComponent(".FreeSnitch.app.partial-\(UUID().uuidString)", isDirectory: true)
makeBundle(at: leftover, build: "35")
try! fm.setAttributes([.posixPermissions: 0o555], ofItemAtPath: leftover.appendingPathComponent("Contents").path)
let lookalikes = [".FreeSnitch.app.partial-notauuid", ".FreeSnitch.app.partial-\(UUID().uuidString.lowercased())",
                  ".Other.app.partial-\(UUID().uuidString)", "FreeSnitch.app.partial-\(UUID().uuidString)", "Other.app"]
for name in lookalikes { makeBundle(at: leftApps.appendingPathComponent(name), build: "1") }
let outside = work.appendingPathComponent("Outside", isDirectory: true)
makeBundle(at: outside, build: "1")
let linked = ".FreeSnitch.app.partial-\(UUID().uuidString)"
try! fm.createSymbolicLink(atPath: leftApps.appendingPathComponent(linked).path, withDestinationPath: outside.path)
let leftDestination = leftApps.appendingPathComponent("FreeSnitch.app", isDirectory: true)
check(ok(InstallLocation.copyBundle(from: source, to: leftDestination)), "a move with a leftover staging folder present succeeds")
check(!fm.fileExists(atPath: leftover.path), "the next move removes a leftover staging folder")
check(Set(try! fm.contentsOfDirectory(atPath: leftApps.path)) == Set(lookalikes + [linked, "FreeSnitch.app"]),
      "lookalike names, other apps and a symlinked staging name are all left alone")
check(fm.fileExists(atPath: outside.appendingPathComponent("Contents/MacOS/FreeSnitch").path),
      "the folder a symlinked staging name points to is untouched")
let launchApps = work.appendingPathComponent("LaunchApplications", isDirectory: true)
let launchLeftover = launchApps.appendingPathComponent(".FreeSnitch.app.partial-\(UUID().uuidString)", isDirectory: true)
makeBundle(at: launchLeftover, build: "35")
makeBundle(at: launchApps.appendingPathComponent("FreeSnitch.app"), build: "35")
InstallLocation.removeLeftoverStaging(in: launchApps)
check(try! fm.contentsOfDirectory(atPath: launchApps.path) == ["FreeSnitch.app"], "launch cleanup removes the leftover and keeps the installed app")
InstallLocation.removeLeftoverStaging(in: work.appendingPathComponent("Missing", isDirectory: true))
check(true, "a missing Applications folder is fine")

check(InstallLocation.translocatedOriginal(of: source) == nil, "a bundle that isn't translocated has no other original")

// #400: only a downloaded copy is asked at launch. A build folder isn't.
let homeDir = work.appendingPathComponent("home", isDirectory: true)
let dlCopy = homeDir.appendingPathComponent("Downloads/FreeSnitch.app", isDirectory: true)
makeBundle(at: dlCopy, build: "35")
let devBuild = work.appendingPathComponent("DerivedData/Build/Products/Debug/FreeSnitch.app", isDirectory: true)
makeBundle(at: devBuild, build: "35")
check(InstallLocation.cameFromDownload(dlCopy, home: homeDir.path), "a copy in Downloads is asked about at launch")
check(InstallLocation.cameFromDownload(source, home: homeDir.path), "a copy with the download flag is asked about at launch")
check(!InstallLocation.cameFromDownload(devBuild, home: homeDir.path), "a contributor's build folder isn't asked about at launch")
check(InstallLocation.shouldTrashOriginal(dlCopy, home: homeDir.path), "after a move, a Downloads copy goes to the Trash")
check(!InstallLocation.shouldTrashOriginal(devBuild, home: homeDir.path), "after a move, a contributor's build output stays")
check(InstallLocation.offersOpenInstalled(isOlder: false, sourceFromDownload: true), "a downloaded copy of an installed build offers Open It")
check(!InstallLocation.offersOpenInstalled(isOlder: false, sourceFromDownload: false), "a build from a folder never quietly opens the installed copy")
check(!InstallLocation.offersOpenInstalled(isOlder: true, sourceFromDownload: true), "a newer download over an older install says to replace it")
check(InstallLocation.isInApplications(URL(fileURLWithPath: "/Applications/FreeSnitch.app"), home: "/Users/x")
      && InstallLocation.isInApplications(URL(fileURLWithPath: "/Users/x/Applications/FreeSnitch.app"), home: "/Users/x")
      && !InstallLocation.isInApplications(URL(fileURLWithPath: "/Users/x/Downloads/FreeSnitch.app"), home: "/Users/x"),
      "Applications and ~/Applications count as installed, Downloads doesn't")

// #412: macOS activates a system extension only from /Applications, so the
// firewall build in ~/Applications is not installed. Real bundles, so the
// rule reads the extension from the bundle itself, as the app does.
let userApps = homeDir.appendingPathComponent("Applications", isDirectory: true)
let firewallCopy = userApps.appendingPathComponent("FreeSnitch.app", isDirectory: true)
makeBundle(at: firewallCopy, build: "35")
try! fm.createDirectory(at: firewallCopy.appendingPathComponent("Contents/Library/SystemExtensions/io.isaaclins.freesnitch.netext.systemextension"),
                        withIntermediateDirectories: true)
let monitorCopy = userApps.appendingPathComponent("Monitor/FreeSnitch.app", isDirectory: true)
makeBundle(at: monitorCopy, build: "35")
check(InstallLocation.embedsSystemExtension(firewallCopy) && !InstallLocation.embedsSystemExtension(monitorCopy),
      "the firewall build is told apart from the monitor build by its embedded extension")
check(!InstallLocation.isInApplications(firewallCopy, home: homeDir.path),
      "a firewall build in ~/Applications doesn't count as installed")
check(InstallLocation.isInApplications(monitorCopy, home: homeDir.path),
      "a monitor build in ~/Applications still counts as installed")
check(InstallLocation.isInApplications(URL(fileURLWithPath: "/Applications/FreeSnitch.app"), home: homeDir.path, embedsSystemExtension: true),
      "a firewall build in /Applications counts as installed")
check(InstallLocation.asksAtLaunch(firewallCopy, home: homeDir.path),
      "a firewall build in ~/Applications is asked to move at launch")
check(!InstallLocation.shouldTrashOriginal(firewallCopy, home: homeDir.path),
      "after a move, the ~/Applications copy stays, since its helper may still be registered")
let oldMonitor = work.appendingPathComponent("home2/Applications/FreeSnitch.app", isDirectory: true)
makeBundle(at: oldMonitor, build: "30")
let downloadedMonitor = homeDir.appendingPathComponent("Downloads/Monitor/FreeSnitch.app", isDirectory: true)
makeBundle(at: downloadedMonitor, build: "35")
check(!InstallLocation.userCopyCountsAsInstalled(source: firewallCopy, userCopy: oldMonitor),
      "a firewall build never stops at a monitor copy in ~/Applications; it goes to /Applications")
check(!InstallLocation.userCopyCountsAsInstalled(source: downloadedMonitor, userCopy: firewallCopy),
      "a firewall copy in ~/Applications isn't counted as installed for a monitor download either")
check(InstallLocation.userCopyCountsAsInstalled(source: downloadedMonitor, userCopy: oldMonitor),
      "a monitor download stops at the monitor copy in ~/Applications, as before")
// #418: the new /Applications copy registers the helper again, once, so
// launchd stops running it from the ~/Applications copy.
let newCopy = URL(fileURLWithPath: "/Applications/FreeSnitch.app")
check(InstallLocation.shouldReregister(requestedPath: "/Applications/FreeSnitch.app", running: newCopy),
      "the copy the move made registers the helper again")
check(!InstallLocation.shouldReregister(requestedPath: "/Applications/FreeSnitch.app", running: firewallCopy),
      "the old ~/Applications copy never acts on the request")
check(!InstallLocation.shouldReregister(requestedPath: nil, running: newCopy),
      "without a move, nothing is registered again")
let defaultsKey = InstallLocation.reregisterKey
UserDefaults.standard.set(newCopy.path, forKey: defaultsKey)
let first = InstallLocation.takeReregisterRequest(running: newCopy)
let second = InstallLocation.takeReregisterRequest(running: newCopy)
check(first && !second, "the request is used once and then cleared")
UserDefaults.standard.set(newCopy.path, forKey: defaultsKey)
_ = InstallLocation.takeReregisterRequest(running: firewallCopy)
check(UserDefaults.standard.string(forKey: defaultsKey) == nil, "a request read by another copy is cleared too, so it can't fire later")
check(InstallLocation.offersOpenInstalled(isOlder: false, sourceFromDownload: InstallLocation.asksAtLaunch(firewallCopy, home: homeDir.path)),
      "a ~/Applications copy of an installed build offers to open the /Applications one")

// PureSnitch detection looks at its two fixed paths only.
var asked: [String] = []
let none = LegacyPureSnitch.detect(listing: { nil }) { asked.append($0); return false }
check(!none.any, "no PureSnitch, nothing offered")
check(asked == ["/Applications/PureSnitch.app", "/Library/LaunchDaemons/io.isaaclins.puresnitch.helper.plist"],
      "detection checks exactly the old app and the old helper plist")
check(LegacyPureSnitch.detect(listing: { nil }) { $0.hasSuffix(".plist") } == .init(app: false, daemon: true),
      "a helper left behind without the app is still found")

// Since macOS 15.3 the Trash may leave PureSnitch's extension running. It is
// found on its own from `systemextensionsctl list`, and one already waiting
// for the restart doesn't count.
let activeListing = """
1 extension(s)
--- com.apple.system_extension.network_extension
enabled\tactive\tteamID\tbundleID (version)\tname\t[state]
*\t*\tBHAF4L4726\tio.isaaclins.puresnitch.netext (1.0/1)\tPureSnitchNetExt\t[activated enabled]
"""
let leavingListing = activeListing.replacingOccurrences(of: "[activated enabled]", with: "[terminated waiting to uninstall on reboot]")
let freeSnitchOnly = activeListing.replacingOccurrences(of: "io.isaaclins.puresnitch.netext", with: "io.isaaclins.freesnitch.netext")
check(LegacyPureSnitch.detect(listing: { activeListing }) { _ in false } == .init(app: false, daemon: false, extensionActive: true),
      "a PureSnitch extension still active without its app is found")
check(!LegacyPureSnitch.detect(listing: { leavingListing }) { _ in false }.any, "one waiting to be removed at restart isn't")
check(!LegacyPureSnitch.detect(listing: { freeSnitchOnly }) { _ in false }.any, "FreeSnitch's own extension is never taken for PureSnitch's")
check(LegacyPureSnitch.extensionOnlyText.contains("Login Items & Extensions") && LegacyPureSnitch.extensionOnlyText.contains("delete"),
      "with only the extension left, the question says where to delete it")
// A listing tool that hangs must not hold launch: it is given up after the
// time limit and counts as "not seen".
let listingStart = Date()
let hung = LegacyPureSnitch.readExtensionListing(timeout: 1, tool: "/bin/sleep", arguments: ["30"])
check(hung == nil && Date().timeIntervalSince(listingStart) < 3,
      "a hanging extension listing is given up after its time limit")
check(LegacyPureSnitch.readExtensionListing(timeout: 3, tool: "/bin/echo", arguments: ["io.isaaclins.puresnitch.netext"])?.contains("puresnitch") == true,
      "a listing that answers in time is read")

// #399: the question only promises a password prompt when the helper is part
// of the removal, and only mentions the Trash when the app is there.
let both = LegacyPureSnitch.removalText(.init(app: true, daemon: true))
let appOnly = LegacyPureSnitch.removalText(.init(app: true, daemon: false))
let helperOnly = LegacyPureSnitch.removalText(.init(app: false, daemon: true))
check(both.contains("password") && both.contains("Trash"), "app and helper: the question mentions the password and the Trash")
check(!appOnly.contains("password") && appOnly.contains("Trash"), "app only: no password is promised")
check(helperOnly.contains("password") && !helperOnly.contains("Trash"), "helper only: the password is mentioned, the Trash isn't")

// Choosing Remove: FreeSnitch's own filter may only start once the removal
// is done, and also when it failed, so the filter never stays off for good.
@MainActor func runRemoval(helper: LegacyPureSnitch.Outcome, trash: LegacyPureSnitch.Outcome?, app: Bool) -> [String] {
    var events: [String] = []
    var done = false
    LegacyPureSnitch.performRemoval(
        .init(app: app, daemon: true),
        removeHelper: { _ in Thread.sleep(forTimeInterval: 0.05); return helper },
        trashApp: { completion in
            events.append("trash")
            DispatchQueue.main.async { completion(trash ?? .removed) }
        },
        report: { _ in events.append("report") },
        then: { events.append("startup"); done = true })
    events.append("returned")
    let deadline = Date().addingTimeInterval(5)
    while !done && Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.01)) }
    return events
}
MainActor.assumeIsolated {
    check(runRemoval(helper: .removed, trash: .removed, app: true) == ["returned", "trash", "report", "startup"],
          "with Remove chosen, the filter starts only after PureSnitch went to the Trash and the result was shown")
    check(runRemoval(helper: .failed("x"), trash: nil, app: true) == ["returned", "report", "startup"],
          "a failed helper removal still lets the filter start, after saying so")
    check(runRemoval(helper: .cancelled, trash: nil, app: true) == ["returned", "report", "startup"],
          "a cancelled password prompt still lets the filter start")
    check(runRemoval(helper: .removed, trash: .failed("y"), app: true) == ["returned", "trash", "report", "startup"],
          "a failed move to the Trash still lets the filter start, after saying so")
}

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
grep -q 'launchctl bootout system/io.isaaclins.puresnitch.helper' <<<"$script" \
  || { echo "install location: FAIL: could not read the PureSnitch removal script" >&2; exit 1; }
grep -qi 'freesnitch' <<<"$script" \
  && { echo "install location: FAIL: the PureSnitch removal script names FreeSnitch" >&2; exit 1; }
echo "install location: PASS: the PureSnitch removal script never names FreeSnitch"
if grep -nE 'removeItem\(at: (destination|installed)|trashItem\(at: (destination|installed)' "$ROOT/Sources/GUI/App/InstallLocation.swift"; then
  echo "install location: FAIL: the move can delete the installed copy" >&2; exit 1
fi
echo "install location: PASS: the move never deletes the installed copy"
grep -q 'versionState, installState != .wrongLocation' "$ROOT/Sources/GUI/Views/HelperBanner.swift" \
  || { echo "install location: FAIL: a helper mismatch can hide the Move banner of a copy outside Applications" >&2; exit 1; }
echo "install location: PASS: a copy outside Applications shows Move before Repair Helper"
grep -B1 'let info = BannerInfo(helperOtherCopy:' "$ROOT/Sources/GUI/Views/HelperBanner.swift" | grep -q 'helperInstallState != .wrongLocation' \
  || { echo "install location: FAIL: the other-copy warning can hide the Move banner" >&2; exit 1; }
echo "install location: PASS: a copy outside Applications shows Move before the other-copy warning"
helper_swift="$ROOT/Sources/GUI/App/HelperClient.swift"
awk '/func reregisterAfterCopy/ { inside = 1 } inside && /unregister/ { bad = 1 } inside && /^    }$/ { inside = 0 } END { exit bad ? 1 : 0 }' "$helper_swift" \
  && grep -q 'if isInUserApplications(original) {' "$ROOT/Sources/GUI/App/InstallLocation.swift" \
  && grep -A4 'let reregister = InstallLocation.takeReregisterRequest()' "$helper_swift" | grep -q 'case .alreadyEnabled:' \
  || { echo "install location: FAIL: the copy out of ~/Applications doesn't hand the helper over, or the handover can unregister" >&2; exit 1; }
echo "install location: PASS: a copy out of ~/Applications registers the helper again from /Applications, without unregistering"
app_swift="$ROOT/Sources/GUI/App/FreeSnitchApp.swift"
[ "$(grep -c 'systemExtension.activate()' "$app_swift")" = 1 ] \
  && awk '/LegacyPureSnitch.offerRemovalAtLaunch \{/ { inside = 1 } inside && /systemExtension.activate\(\)/ { found = 1 } inside && /^        }$/ { inside = 0 } END { exit found ? 0 : 1 }' "$app_swift" \
  || { echo "install location: FAIL: the filter can start outside the PureSnitch continuation" >&2; exit 1; }
echo "install location: PASS: the filter starts only from the PureSnitch continuation"

# #403: the move question can be open before the window manager exists, so
# nothing outside applicationDidFinishLaunching may force-unwrap it: menu
# commands, the Settings redirect and the reopen handler all go through `?.`.
outside="$(awk '/func applicationDidFinishLaunching/ { skip = 1 } skip && /^    }$/ { skip = 0; next } !skip' "$app_swift")"
if printf '%s\n' "$outside" | grep -nE 'windowManager[.!]'; then
  echo "install location: FAIL: the window manager is used without a check outside launch setup" >&2; exit 1
fi
grep -q 'delegate.windowManager?.showPage' <<<"$outside" \
  || { echo "install location: FAIL: could not find the menu commands to check" >&2; exit 1; }
echo "install location: PASS: menu commands and reopen do nothing until the window manager exists"

