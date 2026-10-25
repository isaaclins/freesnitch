#!/usr/bin/env bash
# Checks that the live speed updates about once a second (issue #156).
#
# Compiled from the real NetMonitor and shared sources. It runs the monitor
# for a few seconds (nettop and lsof only read; nothing is enforced), counts
# the traffic samples, and checks the counter arithmetic on fixed readings.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-live-speed.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

@main
struct Verify {
    static var failures = 0

    static func check(_ name: String, _ condition: Bool) {
        print("live speed harness: \(condition ? "PASS" : "FAIL"): \(name)")
        if !condition { failures += 1 }
    }

    static func main() {
        typealias T = NetMonitor.InterfaceTotals
        let before = ["en0": T(bytesIn: 1_000, bytesOut: 500), "en1": T(bytesIn: 9_000, bytesOut: 9_000)]
        let after = ["en0": T(bytesIn: 4_000, bytesOut: 700), "en1": T(bytesIn: 10, bytesOut: 9_100),
                     "en5": T(bytesIn: 7_000_000, bytesOut: 7_000_000)]
        let (bytesIn, bytesOut) = NetMonitor.delta(from: before, to: after)
        check("bytes are summed over interfaces seen twice", bytesIn == 3_000 && bytesOut == 300)
        check("a new interface adds nothing for its first second", bytesIn < 7_000_000)
        check("a reset counter adds nothing instead of wrapping", bytesIn == 3_000)

        let interfaces = NetMonitor.interfaceTotals()
        check("the Mac's interfaces can be read", !interfaces.isEmpty)
        check("loopback is not counted", interfaces["lo0"] == nil)

        let monitor = NetMonitor()
        let lock = NSLock()
        var samples = 0
        monitor.onSample = { _ in lock.lock(); samples += 1; lock.unlock() }
        monitor.start()
        Thread.sleep(forTimeInterval: 6.5)
        monitor.stop()
        lock.lock(); let count = samples; lock.unlock()
        check("about one speed sample per second (\(count) in 6.5 s)", count >= 5)

        if failures > 0 {
            print("live speed harness: \(failures) FAILURES")
            exit(1)
        }
        print("live speed harness: PASS (all checks)")
    }
}
SWIFT

xcrun swiftc -O -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos13.0 -parse-as-library \
  -o "$TMP/run" "$ROOT/Sources/Helper/NetMonitor.swift" "$ROOT"/Sources/Shared/*.swift "$TMP/verify.swift"
"$TMP/run"
