#!/usr/bin/env bash
# Checks that the live speed updates about once a second (issue #156).
#
# Compiled from the real NetMonitor and shared sources. The rate arithmetic is
# driven with fixed readings at fixed uptimes, so no check depends on how fast
# the machine is. The real monitor is then started once (nettop and lsof only
# read; nothing is enforced) and the harness waits for its first two samples
# as a signal, with a deadline only to keep a broken timer from hanging CI.
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
        check("AirDrop and sharing interfaces are not counted",
              !interfaces.keys.contains { $0.hasPrefix("awdl") || $0.hasPrefix("llw") || $0.hasPrefix("ap") })

        check("the live speed is sampled once a second",
              NetMonitor.trafficSampleInterval == .seconds(1))

        // Ticks driven at chosen uptimes instead of waiting on the real clock.
        do {
            let monitor = NetMonitor()
            var rates: [(Int64, Int64)] = []
            monitor.onSample = { rates.append(($0.bytesIn, $0.bytesOut)) }
            monitor.recordTraffic(["en0": T(bytesIn: 1_000, bytesOut: 1_000)], at: 100)
            check("the first reading is only a baseline", rates.isEmpty)
            monitor.recordTraffic(["en0": T(bytesIn: 4_000, bytesOut: 1_500)], at: 101)
            check("one second later the rate is the bytes moved in that second",
                  rates.count == 1 && rates.last! == (3_000, 500))
            monitor.recordTraffic(["en0": T(bytesIn: 6_000, bytesOut: 2_500)], at: 103)
            check("a tick that fires late still reports bytes per second",
                  rates.count == 2 && rates.last! == (1_000, 500))
            monitor.recordTraffic(["en0": T(bytesIn: 9_000, bytesOut: 9_000)], at: 103)
            check("a second reading at the same instant reports nothing instead of dividing by zero",
                  rates.count == 2)
            monitor.recordTraffic(["en0": T(bytesIn: 9_500, bytesOut: 9_000)], at: 103.5)
            check("half a second later the rate is scaled up to a full second",
                  rates.count == 3 && rates.last! == (1_000, 0))
        }

        // The real timer delivers samples. Waiting on the samples themselves,
        // not on a guessed number of seconds, keeps this from failing on a
        // busy machine; the deadline only stops a dead timer hanging the run.
        let monitor = NetMonitor()
        let gotTwo = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var samples = 0
        monitor.onSample = { _ in
            lock.lock(); samples += 1; let n = samples; lock.unlock()
            if n == 2 { gotTwo.signal() }
        }
        monitor.start()
        let delivered = gotTwo.wait(timeout: .now() + 120) == .success
        monitor.stop()
        check("the running monitor delivers speed samples", delivered)

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
