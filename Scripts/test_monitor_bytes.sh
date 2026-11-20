#!/usr/bin/env bash
# Checks that the Network Monitor gives each connection its bytes (issue #466).
#
# The report: Top Processes showed Radioplayer at 101.7 MB while its
# destinations, Top Domains and Top Countries all read 0 bytes. lsof lists the
# connections but has no byte counts, and nettop ran per process only, so no
# connection ever got a number. Compiled from the real NetMonitor: a frame in
# nettop's own per-socket format (captured from macOS) is parsed, then the
# real monitor runs once (nettop and lsof only read; nothing is enforced) and
# the harness waits for a connection that carries bytes, with a deadline only
# to keep a broken monitor from hanging the run.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-monitor-bytes.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

@main
struct Verify {
    static var failures = 0

    static func check(_ name: String, _ condition: Bool) {
        print("monitor bytes harness: \(condition ? "PASS" : "FAIL"): \(name)")
        if !condition { failures += 1 }
    }

    static func main() {
        // `nettop -x -n -L 1 -J bytes_in,bytes_out` on macOS, header removed.
        let frame = [
            "launchd.1,0,0,",
            "tcp4 *:445<->*:*,,,",
            "tcp6 *.445<->*.*,,,",
            "apsd.147,5742457,1664833,",
            "tcp4 192.168.1.144:58261<->17.57.146.59:5223,5742457,1664833,",
            "Radioplayer.1905,113246208,55296,",
            "tcp4 192.168.1.144:50123<->178.248.48.9:443,113000000,50000,",
            "quic4 192.168.1.144:57686<->52.85.185.61:443,246208,5296,",
            "rapportd.636,444691,247483,",
            "tcp6 fe80::866:bf75:855c:abc9%en1.49181<->fe80::18e0:1490:7045:7b9f%en1.53786,5313,22100,",
            "udp4 *:*<->*:*,,,",
            "Vivaldi Helper.2681,11534336,937984,",
            "python3.12.991,0,0,",
        ]
        let (usages, sockets) = NetMonitor.parseFrame(frame)
        typealias K = NetMonitor.SocketKey
        typealias B = NetMonitor.SocketBytes

        check("every process line is still a process total",
              usages.map(\.processName) == ["launchd", "apsd", "Radioplayer", "rapportd", "Vivaldi Helper", "python3.12"])
        check("a process total keeps its own bytes",
              usages.first { $0.pid == 1905 }.map { $0.bytesIn == 113_246_208 && $0.bytesOut == 55_296 } == true)
        check("socket lines are not read as processes", !usages.contains { $0.processName.contains("<->") })
        check("an IPv4 connection gets its bytes under its own process",
              sockets[K(pid: 1905, localPort: 50123, remotePort: 443)] == B(bytesIn: 113_000_000, bytesOut: 50_000))
        check("a QUIC connection gets its bytes",
              sockets[K(pid: 1905, localPort: 57686, remotePort: 443)] == B(bytesIn: 246_208, bytesOut: 5_296))
        check("an IPv6 link-local connection gets its bytes (port after the last dot)",
              sockets[K(pid: 636, localPort: 49181, remotePort: 53786)] == B(bytesIn: 5_313, bytesOut: 22_100))
        check("a socket is never credited to the process before it",
              sockets[K(pid: 147, localPort: 50123, remotePort: 443)] == nil)
        check("listening sockets and sockets without counts are skipped", sockets.count == 4)

        // The real monitor, end to end: a connection lsof lists must arrive
        // with the bytes nettop counted for it.
        let monitor = NetMonitor()
        let got = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var done = false
        monitor.onConnections = { conns in
            guard conns.contains(where: { $0.bytesIn + $0.bytesOut > 0 }) else { return }
            lock.lock(); let first = !done; done = true; lock.unlock()
            if first { got.signal() }
        }
        monitor.start()
        let delivered = got.wait(timeout: .now() + 120) == .success
        monitor.stop()
        check("the running monitor reports connections with their bytes", delivered)

        if failures > 0 {
            print("monitor bytes harness: \(failures) FAILURES")
            exit(1)
        }
        print("monitor bytes harness: PASS (all checks)")
    }
}
SWIFT

xcrun swiftc -O -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos13.0 -parse-as-library \
  -o "$TMP/run" "$ROOT/Sources/Helper/NetMonitor.swift" "$ROOT"/Sources/Shared/*.swift "$TMP/verify.swift"
"$TMP/run"
