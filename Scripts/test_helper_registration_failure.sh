#!/usr/bin/env bash
# Regression harness for the failed-registration banner (issue #409).
#
# Every helper registration error used to end with "Move FreeSnitch into
# /Applications and try again", although registration only runs from
# Applications. The message is now built from what macOS reported. This
# compiles the real HelperRegistrationFailure.swift and checks that
#   - the move advice appears only when the app is outside Applications,
#   - the message carries macOS's own description and error code,
#   - the known ServiceManagement codes get advice that fits them,
#   - the banner and the registration path use this message, not a fixed tail.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-registration-failure.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/main.swift" <<'SWIFT'
import Foundation

var failures = 0
func expect(_ ok: Bool, _ what: String) {
    if ok { print("ok   \(what)") } else { print("FAIL \(what)"); failures += 1 }
}
func msg(_ domain: String, _ code: Int, _ text: String, _ inApps: Bool) -> String {
    HelperRegistrationFailure.message(domain: domain, code: code, description: text, inApplications: inApps)
}
let move = "Move FreeSnitch into /Applications"

let denied = msg("SMAppServiceErrorDomain", 1, "Operation not permitted", true)
expect(!denied.contains(move), "in Applications: no move advice")
expect(denied.contains("Operation not permitted") && denied.contains("SMAppServiceErrorDomain 1"), "says what macOS reported")
expect(denied.contains("Allow in the Background"), "switched-off helper points at Login Items")

expect(msg("kSMErrorDomainFramework", 11, "Launch denied", true).contains("Allow in the Background"), "launch denied by user points at Login Items")
expect(msg("SMAppServiceErrorDomain", 3, "Invalid signature", true).contains("signed release again"), "bad signature says reinstall")
expect(msg("SMAppServiceErrorDomain", 108, "Unable to read plist", true).contains("declaration"), "unreadable plist says reinstall")

expect(!msg("SMAppServiceErrorDomain", 3, "No such process", true).contains("signed"), "code 3 that isn't a signature error gets no signature advice")
expect(msg("SMAppServiceErrorDomain", 9, "Job must be enabled", true).contains("Allow in the Background"), "must-be-enabled points at Login Items")
expect(!msg("kSMErrorDomainLaunchd", 11, "Resource deadlock avoided", true).contains("Allow in the Background"), "launchd errno codes get no kSMError advice")
let fallback = msg("SMAppServiceErrorDomain", 1, "The operation couldn't be completed. (SMAppServiceErrorDomain error 1.)", true)
expect(fallback.components(separatedBy: "SMAppServiceErrorDomain").count == 2, "fallback description doesn't repeat the domain and code")

let other = msg("NSPOSIXErrorDomain", 5, "Input/output error.", true)
expect(!other.contains(move), "unrelated error: no move advice")
expect(other.contains("Input/output error (NSPOSIXErrorDomain 5)."), "unrelated error keeps its own text, no double period")

expect(msg("SMAppServiceErrorDomain", 1, "Operation not permitted", false).contains(move), "outside Applications: move advice")
expect(msg("SMAppServiceErrorDomain", 1, "  ", true).contains("registration failed"), "empty description still reads")

exit(failures == 0 ? 0 : 1)
SWIFT

swiftc "$ROOT/Sources/GUI/App/HelperRegistrationFailure.swift" "$TMP/main.swift" -o "$TMP/harness"
"$TMP/harness"

# The banner and the registration path must use the built message.
if grep -q 'Move FreeSnitch into /Applications and try again' "$ROOT/Sources/GUI/Views/HelperBanner.swift"; then
  echo "FAIL the banner still appends the move advice to every failure"; exit 1
fi
[ "$(grep -c 'HelperRegistrationFailure.message(' "$ROOT/Sources/GUI/App/HelperClient.swift")" -ge 2 ] \
  || { echo "FAIL registration or repair no longer builds the message from the error"; exit 1; }
echo "ok   banner and registration path use the built message"
