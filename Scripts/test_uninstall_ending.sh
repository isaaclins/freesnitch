#!/usr/bin/env bash
# Replays #215: when macOS refuses to unregister the helper during an uninstall,
# the uninstall still finishes the rest, but it must not end on "FreeSnitch is
# uninstalled" or quit silently. Replays #272 the same way for the person's own
# files: a folder holding a locked file (chflags uchg) is really created in a
# scratch folder, the shipping cleanup tries to delete it, and the folder must
# be reported as still there. Compiles the shipping UninstallEnding.swift and
# checks every ending. Nothing here touches launchd, pf, the real app or any
# file outside the scratch folder.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-uninstall-ending.XXXXXX")"
# A locked file left by a failed run must not make the cleanup itself fail.
trap 'chflags -R nouchg "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT

cat > "$TMP/main.swift" <<'SWIFT'
import Foundation

var failures = 0
func check(_ ok: Bool, _ what: String) {
    print("uninstall ending: \(ok ? "PASS" : "FAIL"): \(what)")
    if !ok { failures += 1 }
}

// What SMAppService.unregister reported in the case #215 describes, as
// HelperRecovery.registrationErrorDetails formats it.
let refused = "domain=SMAppServiceErrorDomain, code=1, description=Operation not permitted"

let helperOnly = UninstallEnding.Leftovers(helper: refused, userData: [])
check(UninstallEnding.after(helperProblem: refused, userDataLeft: [], extensionPendingReboot: false) == .leftBehind(helperOnly),
      "helper kept, extension gone: the ending says the helper is left, instead of quitting silently")
check(UninstallEnding.after(helperProblem: refused, userDataLeft: [], extensionPendingReboot: true) == .leftBehind(helperOnly),
      "helper kept, extension waits for a restart: the ending says the helper is left, not 'uninstalled'")
check(UninstallEnding.after(helperProblem: nil, userDataLeft: [], extensionPendingReboot: true) == .doneUntilRestart,
      "helper removed, extension waits for a restart: 'uninstalled, finishes at restart'")
check(UninstallEnding.after(helperProblem: nil, userDataLeft: [], extensionPendingReboot: false) == .quit,
      "everything removed: the app quits")

// #272: files the person owns that could not be deleted.
let container = "~/Library/Group Containers/BHAF4L4726.io.isaaclins.freesnitch"
check(UninstallEnding.after(helperProblem: nil, userDataLeft: [container], extensionPendingReboot: false)
        == .leftBehind(.init(helper: nil, userData: [container])),
      "a file left, extension gone: the ending names it, instead of quitting silently")
check(UninstallEnding.after(helperProblem: nil, userDataLeft: [container], extensionPendingReboot: true)
        == .leftBehind(.init(helper: nil, userData: [container])),
      "a file left, extension waits for a restart: the ending names it, not 'uninstalled'")
check(UninstallEnding.after(helperProblem: refused, userDataLeft: [container], extensionPendingReboot: false)
        == .leftBehind(.init(helper: refused, userData: [container])),
      "helper and a file left: the ending names both")

// The cleanup itself, on real files in the scratch folder.
let scratch = URL(fileURLWithPath: CommandLine.arguments[1])
let fm = FileManager.default
let locked = scratch.appendingPathComponent("Group Containers/locked")
let lockedFile = locked.appendingPathComponent("prefs.plist")
let plain = scratch.appendingPathComponent("Application Support/FreeSnitch")
let plist = scratch.appendingPathComponent("Preferences/io.isaaclins.freesnitch.plist")
let never = scratch.appendingPathComponent("Never/Created")
try! fm.createDirectory(at: locked, withIntermediateDirectories: true)
try! fm.createDirectory(at: plain.appendingPathComponent("sub"), withIntermediateDirectories: true)
try! fm.createDirectory(at: plist.deletingLastPathComponent(), withIntermediateDirectories: true)
try! Data("x".utf8).write(to: lockedFile)
try! Data("x".utf8).write(to: locked.appendingPathComponent("other"))
try! Data("x".utf8).write(to: plain.appendingPathComponent("sub/file"))
try! Data("x".utf8).write(to: plist)
// The issue's own example: an immutable file the current user cannot delete.
try! fm.setAttributes([.immutable: true], ofItemAtPath: lockedFile.path)

let left = UninstallCleanup.remove([locked, plain, plist, never])
check(left == [locked],
      "a folder holding a locked file is reported as still there; deleted and never-created paths are not (got \(left.map(\.lastPathComponent)))")
check(fm.fileExists(atPath: locked.path) && !fm.fileExists(atPath: plain.path) && !fm.fileExists(atPath: plist.path),
      "the report matches the disk")

// Once the lock is gone, a second attempt removes it and reports nothing.
try! fm.setAttributes([.immutable: false], ofItemAtPath: lockedFile.path)
check(UninstallCleanup.remove([locked]).isEmpty, "the unlocked folder is deleted and nothing is reported")

// A link to a folder is removed itself; its target is neither deleted nor
// mistaken for the link still being there.
let target = scratch.appendingPathComponent("target")
try! fm.createDirectory(at: target, withIntermediateDirectories: true)
let link = scratch.appendingPathComponent("link")
try! fm.createSymbolicLink(at: link, withDestinationURL: target)
check(UninstallCleanup.remove([link]).isEmpty && fm.fileExists(atPath: target.path),
      "a symbolic link is removed and reported gone; what it points at is left alone")

// The unregister error itself is only trusted while macOS still lists the
// helper: one that was never registered (#409) also makes unregister fail.
check(UninstallEnding.helperLeftBehind(unregisterError: refused, stillListed: true) == refused,
      "unregister failed and macOS still lists the helper: it is reported as left behind")
check(UninstallEnding.helperLeftBehind(unregisterError: refused, stillListed: false) == nil,
      "unregister failed but macOS no longer lists the helper: nothing is reported as left")
check(UninstallEnding.helperLeftBehind(unregisterError: nil, stillListed: true) == nil,
      "unregister succeeded: nothing is reported as left")

exit(failures == 0 ? 0 : 1)
SWIFT

swiftc -o "$TMP/check" "$ROOT/Sources/GUI/App/UninstallEnding.swift" "$TMP/main.swift"
mkdir "$TMP/home"
"$TMP/check" "$TMP/home"
