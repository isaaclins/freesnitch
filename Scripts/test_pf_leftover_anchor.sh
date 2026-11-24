#!/usr/bin/env bash
# Harness for what pf keeps once enforcement is off (issues #189, #190).
#
# The harness is compiled from the real helper and shared sources, never from a
# copy. It checks that:
#
#   1. Turning enforcement off empties the anchor file as well as the kernel
#      anchor, so a later load of /etc/pf.conf (boot, a VPN, another tool)
#      cannot bring the last rules back (#190).
#   2. Clearing a leftover anchor at helper start does the same, so a restarted
#      helper never leaves rules in pf that it reports as off and no longer
#      updates (#189).
#   3. A flush that fails at helper start is reported, and the file is still
#      emptied.
#   4. Neither creates an anchor file that was not there.
#   5. Turning enforcement off throws, and keeps the anchor marked as loaded,
#      when neither the flush nor loading an empty rule set succeeds, so the
#      helper cannot report the firewall off while the old rules may still
#      block (#211). Either one succeeding is enough to call the anchor empty.
#   6. The GUI toggle and the CLI read enforcement as on while either the pf
#      anchor or the DNS proxy is active (#211).
#
# Nothing here touches the real pf or /etc: PFManager is pointed at a scratch
# anchor file and a stub pfctl that only logs its arguments, and install() is
# only called with a scratch pf.conf that already names the anchor, so it never
# edits the real one. That HelperService clears the anchor at
# start, before it accepts a client, is checked by
# Scripts/audit_firewall_safety.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-pf-leftover.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

SDK="$(xcrun --show-sdk-path)"
TARGET="arm64-apple-macos13.0"

cat > "$TMP/pfctl" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$PF_STUB_LOG"
[[ -e "$PF_STUB_FAIL" ]] && { printf 'stub failure\n' >&2; exit 1; }
# One argument string per line in PF_STUB_FAIL_ARGS fails just that call.
if [[ -s "$PF_STUB_FAIL_ARGS" ]] && grep -qxF -- "$*" "$PF_STUB_FAIL_ARGS"; then
  printf 'stub failure for %s\n' "$*" >&2; exit 1
fi
exit 0
STUB
chmod +x "$TMP/pfctl"

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

final class Checks {
    private var failures: [String] = []
    private var passed = 0

    func expect(_ condition: Bool, _ message: String) {
        if condition {
            passed += 1
        } else {
            failures.append(message)
        }
    }

    func finish() {
        guard failures.isEmpty else {
            for failure in failures {
                FileHandle.standardError.write(Data(("pf leftover harness: FAIL: " + failure + "\n").utf8))
            }
            exit(1)
        }
        print("pf leftover harness: real sources: \(passed) assertions PASS")
    }
}

@main
struct Verify {
    static func main() throws {
        let checks = Checks()
        let env = ProcessInfo.processInfo.environment
        let work = env["PF_WORK"]!
        let stub = env["PF_STUB"]!
        let log = env["PF_STUB_LOG"]!
        let anchor = (work as NSString).appendingPathComponent("puresnitch")

        let deny = Rule(remoteIP: "203.0.113.7", action: .deny, scope: .ip)
        let rendered = PFManager(anchorPath: anchor, pfctl: stub).renderAnchor(rules: [deny])
        checks.expect(rendered.split(separator: "\n").contains { $0.hasPrefix("block") && $0.contains("203.0.113.7") },
                      "the harness rule must render as a block line")

        func reset() throws {
            try rendered.write(toFile: anchor, atomically: true, encoding: .utf8)
            try "".write(toFile: log, atomically: true, encoding: .utf8)
        }
        func pfctlCalls() -> String { (try? String(contentsOfFile: log, encoding: .utf8)) ?? "" }
        func anchorFile() -> String? { try? String(contentsOfFile: anchor, encoding: .utf8) }

        let cases: [(String, (PFManager) throws -> Void)] = [
            ("turning enforcement off", { try $0.uninstall() }),
            ("a helper start", { try $0.clearLeftoverAnchor() }),
        ]
        for (name, unload) in cases {
            try reset()
            let pf = PFManager(anchorPath: anchor, pfctl: stub)
            var warnings: [String] = []
            pf.onWarning = { warnings.append($0) }
            // Rules recorded while enforcement is off must not reach the file.
            try pf.applyRules([deny])
            try unload(pf)
            checks.expect(anchorFile() == PFManager.emptyAnchor,
                          "after \(name) the anchor file still holds rules pf.conf would load")
            checks.expect(!(anchorFile() ?? "").contains("block"),
                          "after \(name) the anchor file still holds a block line")
            checks.expect(pfctlCalls().contains("-a puresnitch -F all"),
                          "\(name) did not flush the kernel anchor")
            checks.expect(!pfctlCalls().contains("-d"), "\(name) disabled pf for the whole Mac")
            checks.expect(!pf.isLoaded, "after \(name) pf still reports the anchor as loaded")
            checks.expect(warnings.isEmpty, "\(name) warned: \(warnings)")
        }

        // A flush that fails at helper start is reported, not swallowed: no
        // client is connected yet to hear a warning. The file is still emptied.
        try reset()
        try "".write(toFile: env["PF_STUB_FAIL"]!, atomically: true, encoding: .utf8)
        var startError: Error?
        do { try PFManager(anchorPath: anchor, pfctl: stub).clearLeftoverAnchor() } catch { startError = error }
        checks.expect(startError != nil, "a failed flush at helper start went unreported")
        checks.expect(anchorFile() == PFManager.emptyAnchor,
                      "a failed flush at helper start left the rules in the anchor file")
        try FileManager.default.removeItem(atPath: env["PF_STUB_FAIL"]!)

        // At helper start a failed flush alone is not an error: loading the
        // empty rule set still empties the kernel anchor (#211).
        try reset()
        try "-a puresnitch -F all\n".write(toFile: env["PF_STUB_FAIL_ARGS"]!, atomically: true, encoding: .utf8)
        var flushOnlyError: Error?
        do { try PFManager(anchorPath: anchor, pfctl: stub).clearLeftoverAnchor() } catch { flushOnlyError = error }
        try "".write(toFile: env["PF_STUB_FAIL_ARGS"]!, atomically: true, encoding: .utf8)
        checks.expect(flushOnlyError == nil,
                      "a helper start reported an error although the empty load cleared the anchor")
        checks.expect(pfctlCalls().contains("-a puresnitch -f /dev/null"),
                      "a helper start with a failed flush did not load the empty rule set")

        // Turning enforcement off with the kernel anchor stuck (#211). The
        // scratch pf.conf already names the anchor, so install() leaves it
        // alone and only the stub pfctl is called.
        let pfConf = (work as NSString).appendingPathComponent("pf.conf")
        try "anchor \"puresnitch\"\nload anchor \"puresnitch\" from \"\(anchor)\"\n"
            .write(toFile: pfConf, atomically: true, encoding: .utf8)
        let failArgs = env["PF_STUB_FAIL_ARGS"]!
        let flushCall = "-a puresnitch -F all"
        let emptyLoadCall = "-a puresnitch -f /dev/null"
        let stuckCases: [(String, [String], Bool)] = [
            ("both the flush and the empty load fail", [flushCall, emptyLoadCall], true),
            ("only the flush fails", [flushCall], false),
            ("only the empty load fails", [emptyLoadCall], false),
        ]
        for (name, failing, expectThrow) in stuckCases {
            try reset()
            let pf = PFManager(anchorPath: anchor, pfctl: stub, pfConfPath: pfConf)
            try pf.install(rules: [deny])
            checks.expect(pf.isLoaded, "\(name): the harness install did not load the anchor")
            try (failing.joined(separator: "\n") + "\n").write(toFile: failArgs, atomically: true, encoding: .utf8)
            var offError: Error?
            do { try pf.uninstall() } catch { offError = error }
            try "".write(toFile: failArgs, atomically: true, encoding: .utf8)
            checks.expect(pfctlCalls().contains(flushCall) && pfctlCalls().contains(emptyLoadCall),
                          "\(name): turning enforcement off did not try both the flush and the empty load")
            checks.expect(anchorFile() == PFManager.emptyAnchor,
                          "\(name): the anchor file still holds rules pf.conf would load")
            if expectThrow {
                checks.expect(offError != nil,
                              "\(name): turning enforcement off reported success with the old rules possibly in pf")
                checks.expect(offError?.localizedDescription.contains("may still be active") == true,
                              "\(name): the error does not say the old rules may still be active: \(String(describing: offError))")
                checks.expect(pf.isLoaded,
                              "\(name): pf reports the anchor unloaded although nothing confirmed it is empty")
                // Rule edits still reach the rules left in pf, so a deny the
                // user deletes now cannot keep blocking.
                try "".write(toFile: log, atomically: true, encoding: .utf8)
                checks.expect(try pf.applyRules([]), "\(name): a rule edit no longer reaches the stuck anchor")
                // A retry that works turns enforcement off for real.
                try pf.uninstall()
                checks.expect(!pf.isLoaded, "\(name): a retry that worked still reports the anchor loaded")
            } else {
                checks.expect(offError == nil, "\(name): one working cleanup step should be enough: \(String(describing: offError))")
                checks.expect(!pf.isLoaded, "\(name): pf still reports the anchor as loaded")
            }
        }

        // What the toggle and the CLI read as enforcement: pf left loaded by a
        // failed turn-off, with the DNS proxy stopped, is still on (#211).
        func status(pf: Bool, dns: Bool) -> HelperStatus {
            HelperStatus(version: "test", running: true, pfctlActive: pf, dnsProxyActive: dns,
                         dnsProxyPort: 53, activeRules: 0, blockedToday: 0)
        }
        checks.expect(status(pf: true, dns: false).enforcementActive,
                      "a loaded pf anchor with the DNS proxy stopped reads as enforcement off")
        checks.expect(status(pf: false, dns: true).enforcementActive,
                      "a running DNS proxy without the pf anchor reads as enforcement off")
        checks.expect(status(pf: true, dns: true).enforcementActive, "full enforcement reads as off")
        checks.expect(!status(pf: false, dns: false).enforcementActive, "nothing running reads as enforcement on")

        // A Mac where enforcement was never on has no anchor file; clearing
        // must not create one.
        try FileManager.default.removeItem(atPath: anchor)
        try PFManager(anchorPath: anchor, pfctl: stub).clearLeftoverAnchor()
        checks.expect(!FileManager.default.fileExists(atPath: anchor),
                      "a helper start created an anchor file that was not there")

        checks.finish()
    }
}
SWIFT

printf 'pf leftover harness: building from the real helper and shared sources\n'
# shellcheck disable=SC2046
xcrun swiftc -O -sdk "$SDK" -target "$TARGET" -parse-as-library \
  -o "$TMP/run" \
  $(ls "$ROOT"/Sources/Helper/*.swift | grep -v '/main.swift$') \
  "$ROOT"/Sources/Shared/*.swift \
  "$TMP/verify.swift"

mkdir -p "$TMP/work"
PF_WORK="$TMP/work" PF_STUB="$TMP/pfctl" PF_STUB_LOG="$TMP/pfctl.log" PF_STUB_FAIL="$TMP/pfctl.fail" PF_STUB_FAIL_ARGS="$TMP/pfctl.fail-args" "$TMP/run"

# The toggle must take its state from that same property, or the GUI can read
# off while pf still blocks (#211).
grep -q 'let live = status.enforcementActive' "$ROOT/Sources/GUI/ViewModels/AppState.swift" \
  || { printf 'pf leftover harness: FAIL: the enforcement toggle does not read HelperStatus.enforcementActive\n' >&2; exit 1; }

printf 'pf leftover verification: PASS\n'
