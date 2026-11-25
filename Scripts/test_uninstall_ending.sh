#!/usr/bin/env bash
# Replays #215: when macOS refuses to unregister the helper during an uninstall,
# the uninstall still finishes the rest, but it must not end on "FreeSnitch is
# uninstalled" or quit silently. Compiles the shipping UninstallEnding.swift
# and checks every ending. Nothing here touches launchd, pf or the real app.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-uninstall-ending.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

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

check(UninstallEnding.after(helperProblem: refused, extensionPendingReboot: false) == .helperLeft(refused),
      "helper kept, extension gone: the ending says the helper is left, instead of quitting silently")
check(UninstallEnding.after(helperProblem: refused, extensionPendingReboot: true) == .helperLeft(refused),
      "helper kept, extension waits for a restart: the ending says the helper is left, not 'uninstalled'")
check(UninstallEnding.after(helperProblem: nil, extensionPendingReboot: true) == .doneUntilRestart,
      "helper removed, extension waits for a restart: 'uninstalled, finishes at restart'")
check(UninstallEnding.after(helperProblem: nil, extensionPendingReboot: false) == .quit,
      "everything removed: the app quits")

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
"$TMP/check"
