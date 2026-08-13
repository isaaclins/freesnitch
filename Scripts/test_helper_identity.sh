#!/usr/bin/env bash
# Regression harness for the stale running helper (issue #36).
#
# The harness is compiled from the real helper and shared sources, never from a
# copy, and it runs from inside a throwaway .app so the production code path
# that resolves the containing bundle is the one under test.
#
# It simulates an in-place update: the process starts inside build 19, the
# Info.plist on disk is then replaced with build 20 underneath it, and the
# harness asserts that
#   - the running identity did not change,
#   - the installed identity did change,
#   - the mismatch is detected by the same predicate the CLI and GUI use.
#
# Before the fix the helper reported the disk value at call time, so the stale
# process answered "0.2.0 (20)" and nothing surfaced the staleness.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-helper-identity.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

SDK="$(xcrun --show-sdk-path)"
TARGET="arm64-apple-macos13.0"
APP="$TMP/FreeSnitch.app"

write_info_plist() {
  local build="$1"
  cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>io.isaaclins.freesnitch</string>
    <key>CFBundleShortVersionString</key>
    <string>0.2.0</string>
    <key>CFBundleVersion</key>
    <string>${build}</string>
</dict>
</plist>
PLIST
}

mkdir -p "$APP/Contents/MacOS"
write_info_plist 19

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

/// Collects every failure so one run reports all broken invariants.
final class Failures {
    private var messages: [String] = []

    func expect(_ condition: Bool, _ message: @autoclosure () -> String) {
        if !condition { messages.append(message()) }
    }

    var all: [String] { messages }
}

@main
struct HelperIdentityHarness {
    /// The update the helper does not survive: the bundle's Info.plist is
    /// rewritten while this process keeps running the older executable.
    static func installUpdate(build: String) throws {
        guard let appURL = AppBundleIdentity.containingAppURL else {
            throw NSError(domain: "harness", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "the harness is not running inside an .app"])
        }
        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CFBundleIdentifier</key>
            <string>io.isaaclins.freesnitch</string>
            <key>CFBundleShortVersionString</key>
            <string>0.2.0</string>
            <key>CFBundleVersion</key>
            <string>\(build)</string>
        </dict>
        </plist>
        """
        try Data(plist.utf8).write(to: appURL.appendingPathComponent("Contents/Info.plist"))
    }

    static func main() {
        let failures = Failures()

        // Process start: exactly what the helper's main.swift does.
        AppBundleIdentity.captureRunningIdentity()
        let capturedAtStart = HelperService.runningVersion
        failures.expect(capturedAtStart == "0.2.0 (19)",
                        "running identity at start is \(capturedAtStart), expected 0.2.0 (19)")
        failures.expect(HelperService.installedVersion == "0.2.0 (19)",
                        "installed identity at start is \(HelperService.installedVersion), expected 0.2.0 (19)")
        failures.expect(!HelperService.isStaleProcess,
                        "a freshly started process reported itself stale")

        do {
            try installUpdate(build: "20")
        } catch {
            FileHandle.standardError.write(Data("helper identity harness: FAIL: \(error.localizedDescription)\n".utf8))
            exit(1)
        }

        // The bundle on disk is now build 20; this process is still build 19.
        failures.expect(HelperService.runningVersion == capturedAtStart,
                        "the running identity changed under the process: \(HelperService.runningVersion)")
        failures.expect(HelperService.runningVersion == "0.2.0 (19)",
                        "the stale process reports \(HelperService.runningVersion), expected 0.2.0 (19)")
        failures.expect(HelperService.installedVersion == "0.2.0 (20)",
                        "the installed identity is \(HelperService.installedVersion), expected 0.2.0 (20)")
        failures.expect(HelperService.runningVersion != HelperService.installedVersion,
                        "running and installed identities collapsed into one value")
        failures.expect(HelperService.isStaleProcess,
                        "the stale process was not detected as stale")

        // The exact predicate the CLI and GUI use to decide a helper is stale.
        failures.expect(!AppConstants.identityMatches(reported: HelperService.runningVersion,
                                                     expected: HelperService.installedVersion),
                        "identityMatches accepted a build 19 process against a build 20 install")

        // The bug this test exists for: a call-time disk read reports the new
        // build, so the stale process looked current.
        failures.expect(AppBundleIdentity.current == "0.2.0 (20)",
                        "the call-time disk read is \(AppBundleIdentity.current ?? "nil"), expected 0.2.0 (20)")
        failures.expect(AppBundleIdentity.current != AppBundleIdentity.running,
                        "the call-time read and the captured running identity are the same value, so staleness is invisible again")

        let report = AppBundleIdentity.report()
        failures.expect(report.isStale, "the identity report did not flag the stale process")
        failures.expect(report.running == "0.2.0 (19)" && report.installed == "0.2.0 (20)",
                        "the identity report collapsed running/installed: \(report)")
        failures.expect(!AppBundleIdentity.isStale(running: nil, installed: "0.2.0 (20)"),
                        "an unknown running identity was claimed to be stale")
        failures.expect(!AppBundleIdentity.isStale(running: "0.2.0 (20)", installed: nil),
                        "an unknown installed identity was claimed to be stale")

        // The status payload keeps both facts apart on the wire.
        let status = HelperStatus(version: HelperService.runningVersion,
                                  running: true,
                                  pfctlActive: false,
                                  dnsProxyActive: false,
                                  dnsProxyPort: 53,
                                  activeRules: 0,
                                  blockedToday: 0,
                                  installedVersion: HelperService.installedVersion)
        do {
            let encoded = try FreeSnitchWireCodec.encode(status)
            let decoded = try FreeSnitchWireCodec.decode(HelperStatus.self, from: encoded)
            failures.expect(decoded.version == "0.2.0 (19)",
                            "status round trip lost the running version: \(decoded.version)")
            failures.expect(decoded.installedVersion == "0.2.0 (20)",
                            "status round trip lost the installed version: \(decoded.installedVersion ?? "nil")")
        } catch {
            failures.expect(false, "status round trip failed: \(error.localizedDescription)")
        }

        // A status payload from a helper that predates this split still decodes.
        let legacy = Data(#"{"version":"0.2.0 (19)","running":true,"pfctlActive":false,"dnsProxyActive":false,"dnsProxyPort":53,"activeRules":0,"blockedToday":0,"mode":"alert"}"#.utf8)
        do {
            let decoded = try FreeSnitchWireCodec.decode(HelperStatus.self, from: legacy)
            failures.expect(decoded.installedVersion == nil,
                            "a legacy status payload invented an installed version")
        } catch {
            failures.expect(false, "a legacy status payload no longer decodes: \(error.localizedDescription)")
        }

        // The only supported repair is a kickstart. Never an unregister.
        failures.expect(AppConstants.helperKickstartArguments == ["kickstart", "-k", "system/io.isaaclins.freesnitch.helper"],
                        "the helper restart arguments are not a kickstart: \(AppConstants.helperKickstartArguments)")
        failures.expect(AppConstants.helperKickstartCommand == "sudo launchctl kickstart -k system/io.isaaclins.freesnitch.helper",
                        "the documented recovery command changed: \(AppConstants.helperKickstartCommand)")

        let problems = failures.all
        guard problems.isEmpty else {
            for problem in problems {
                FileHandle.standardError.write(Data(("helper identity harness: FAIL: " + problem + "\n").utf8))
            }
            exit(1)
        }
        print("helper identity harness: captured 0.2.0 (19) at start, disk moved to 0.2.0 (20), running value unchanged")
        print("helper identity harness: stale process detected, running and installed reported separately")
        print("helper identity harness: PASS")
    }
}
SWIFT

# shellcheck disable=SC2046
xcrun swiftc -O -sdk "$SDK" -target "$TARGET" -parse-as-library \
  -o "$TMP/run" \
  $(ls "$ROOT"/Sources/Helper/*.swift | grep -v '/main.swift$') \
  "$ROOT"/Sources/Shared/*.swift \
  "$TMP/verify.swift"
cp "$TMP/run" "$APP/Contents/MacOS/FreeSnitchHelper"

printf 'helper identity harness: running from %s\n' "$APP/Contents/MacOS/FreeSnitchHelper"
"$APP/Contents/MacOS/FreeSnitchHelper"

# The restart path must stay a kickstart. #24 showed that unregistering an
# enabled helper can remove the service entirely.
HELPER_SERVICE="$ROOT/Sources/Helper/HelperService.swift"
GUI_HELPER="$ROOT/Sources/GUI/App/HelperClient.swift"
for forbidden in bootout bootstrap unload "remove(" unregister; do
  if grep -Fq -- "$forbidden" <(awk '
      /func restartForUpdate\(/ { active = 1; depth = 0 }
      active {
        print
        opens = gsub(/\{/, "{")
        closes = gsub(/\}/, "}")
        depth += opens - closes
        if (depth == 0) exit
      }
    ' "$HELPER_SERVICE"); then
    printf 'helper identity harness: FAIL: restartForUpdate uses `%s` instead of a kickstart\n' "$forbidden" >&2
    exit 1
  fi
done
grep -Fq 'AppConstants.helperKickstartArguments' "$HELPER_SERVICE" \
  || { printf 'helper identity harness: FAIL: the helper restart no longer uses the shared kickstart arguments\n' >&2; exit 1; }
grep -Fq 'proxy.restartForUpdate' "$GUI_HELPER" \
  || { printf 'helper identity harness: FAIL: the GUI no longer drives the helper restart on the update path\n' >&2; exit 1; }

printf 'helper identity verification: PASS\n'
