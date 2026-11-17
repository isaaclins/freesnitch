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
#
# Nothing here touches the real pf or /etc: PFManager is pointed at a scratch
# anchor file and a stub pfctl that only logs its arguments, and install() is
# never called (it edits /etc/pf.conf). That HelperService clears the anchor at
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
PF_WORK="$TMP/work" PF_STUB="$TMP/pfctl" PF_STUB_LOG="$TMP/pfctl.log" PF_STUB_FAIL="$TMP/pfctl.fail" "$TMP/run"

printf 'pf leftover verification: PASS\n'
