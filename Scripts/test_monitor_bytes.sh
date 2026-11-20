#!/usr/bin/env bash
# Checks that the Network Monitor gives each connection its bytes (issue #466).
#
# The report: Top Processes showed Radioplayer at 101.7 MB while its
# destinations, Top Domains and Top Countries all read 0 bytes. lsof lists the
# connections but has no byte counts, and nettop ran per process only, so no
# connection ever got a number. Compiled from the real NetMonitor: a frame in
# nettop's own per-socket format (captured from macOS) is parsed, then the
# harness moves 2 MB over its own loopback connection, runs the real monitor
# once (nettop and lsof only read; nothing is enforced) and waits for that
# connection to arrive with its bytes. The deadline only keeps a broken
# monitor from hanging the run.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-monitor-bytes.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation
import Darwin

/// A connected TCP pair on 127.0.0.1 that has moved `sending` bytes from the
/// client to the server, kept open until `close()`.
final class LoopbackPair {
    let clientPort: Int
    let serverPort: Int
    private var fds: [Int32] = []

    init?(sending total: Int) {
        func port(_ fd: Int32) -> Int {
            var addr = sockaddr_in(); var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            _ = withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
            }
            return Int(UInt16(bigEndian: addr.sin_port))
        }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let listener = socket(AF_INET, SOCK_STREAM, 0)
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard listener >= 0, bound == 0, listen(listener, 1) == 0 else { return nil }
        addr.sin_port = UInt16(port(listener)).bigEndian
        let client = socket(AF_INET, SOCK_STREAM, 0)
        let connected = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(client, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        let server = accept(listener, nil, nil)
        guard client >= 0, connected == 0, server >= 0 else { return nil }
        Darwin.close(listener)
        fds = [client, server]
        clientPort = port(client)
        serverPort = Int(UInt16(bigEndian: addr.sin_port))

        let reader = DispatchQueue(label: "reader")
        let drained = DispatchSemaphore(value: 0)
        reader.async {
            var buffer = [UInt8](repeating: 0, count: 65_536)
            var received = 0
            while received < total {
                let n = read(server, &buffer, buffer.count)
                if n <= 0 { break }
                received += n
            }
            drained.signal()
        }
        let chunk = [UInt8](repeating: 7, count: 65_536)
        var sent = 0
        while sent < total {
            let n = write(client, chunk, min(chunk.count, total - sent))
            if n <= 0 { return nil }
            sent += n
        }
        drained.wait()
    }

    func close() { fds.forEach { Darwin.close($0) }; fds = [] }
}

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
        func key(_ pid: Int32, _ local: Int, _ remote: String, _ port: Int) -> K {
            K(pid: pid, localPort: local, remoteAddress: NetMonitor.normalizedAddress(remote), remotePort: port)
        }

        check("every process line is still a process total",
              usages.map(\.processName) == ["launchd", "apsd", "Radioplayer", "rapportd", "Vivaldi Helper", "python3.12"])
        check("a process total keeps its own bytes",
              usages.first { $0.pid == 1905 }.map { $0.bytesIn == 113_246_208 && $0.bytesOut == 55_296 } == true)
        check("socket lines are not read as processes", !usages.contains { $0.processName.contains("<->") })
        check("an IPv4 connection gets its bytes under its own process",
              sockets[key(1905, 50123, "178.248.48.9", 443)] == B(bytesIn: 113_000_000, bytesOut: 50_000))
        check("a QUIC connection gets its bytes",
              sockets[key(1905, 57686, "52.85.185.61", 443)] == B(bytesIn: 246_208, bytesOut: 5_296))
        // lsof writes this socket's remote end as [fe80:f::18e0:1490:7045:7b9f].
        check("an IPv6 link-local connection is found under lsof's spelling of the address",
              sockets[key(636, 49181, "[fe80:f::18e0:1490:7045:7b9f]", 53786)] == B(bytesIn: 5_313, bytesOut: 22_100))
        check("a socket is never credited to the process before it",
              sockets[key(147, 50123, "178.248.48.9", 443)] == nil)
        check("listening sockets and sockets without counts are skipped", sockets.count == 4)

        // Two accepted connections can share both ports; they stay apart.
        let shared = NetMonitor.parseFrame([
            "sshd.50,300,30,",
            "tcp4 10.0.0.2:22<->10.0.0.7:50000,100,10,",
            "tcp4 10.0.0.2:22<->10.0.0.9:50000,200,20,",
        ]).sockets
        check("connections that share both ports keep their own bytes",
              shared[key(50, 22, "10.0.0.7", 50000)] == B(bytesIn: 100, bytesOut: 10)
                && shared[key(50, 22, "10.0.0.9", 50000)] == B(bytesIn: 200, bytesOut: 20))
        check("IPv4 behind IPv6 is the same address",
              NetMonitor.normalizedAddress("[::ffff:178.248.48.9]") == "178.248.48.9")
        check("a scoped and an embedded link-local address are the same address",
              NetMonitor.normalizedAddress("fe80::1%en1") == NetMonitor.normalizedAddress("[fe80:f::1]"))

        // Saved history holds the same socket once per poll with its running
        // total; a summary takes only the latest row of each.
        let early = Date(timeIntervalSince1970: 1_000), late = Date(timeIntervalSince1970: 1_002)
        let history = [
            Connection(pid: 1905, processName: "Radioplayer", processPath: "/R", localPort: 50123,
                       remoteIP: "178.248.48.9", remotePort: 443, bytesIn: 100, bytesOut: 1, lastSeen: early),
            Connection(pid: 1905, processName: "Radioplayer", processPath: "/R", localPort: 50123,
                       remoteIP: "178.248.48.9", remotePort: 443, bytesIn: 300, bytesOut: 3, lastSeen: late),
            Connection(pid: 1905, processName: "Radioplayer", processPath: "/R", localPort: 57686,
                       remoteIP: "52.85.185.61", remotePort: 443, bytesIn: 50, bytesOut: 5, lastSeen: early),
        ]
        let latest = Connection.latestPerSocket(history)
        check("one row per socket, the latest", latest.count == 2 && latest[0].bytesIn == 300 && latest[1].bytesIn == 50)

        // The real monitor, end to end, on traffic this harness makes itself:
        // a loopback connection carrying a known amount must arrive with it.
        let payload = 2_000_000
        guard let pair = LoopbackPair(sending: payload) else {
            check("a loopback connection can be opened", false)
            exit(1)
        }
        let monitor = NetMonitor()
        let got = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var done = false
        let me = getpid()
        monitor.onConnections = { conns in
            let client = conns.first { $0.pid == me && $0.localPort == pair.clientPort && $0.remotePort == pair.serverPort }
            let server = conns.first { $0.pid == me && $0.localPort == pair.serverPort && $0.remotePort == pair.clientPort }
            guard let client, let server,
                  client.bytesOut >= Int64(payload), server.bytesIn >= Int64(payload) else { return }
            lock.lock(); let first = !done; done = true; lock.unlock()
            if first { got.signal() }
        }
        monitor.start()
        let delivered = got.wait(timeout: .now() + 120) == .success
        monitor.stop()
        pair.close()
        check("the running monitor reports a connection with the bytes it moved, on both ends", delivered)

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
