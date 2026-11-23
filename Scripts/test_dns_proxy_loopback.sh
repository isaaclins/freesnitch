#!/usr/bin/env bash
# The DNS proxy must only be reachable from this Mac (issue #205).
#
# The harness compiles the shipping helper sources and binds plain listeners
# with DNSProxy.listenerParameters on a free high port, so it tests exactly
# the bind the helper uses without starting the proxy itself or touching
# port 53 or the Mac's DNS settings. It then checks:
#
#   - 127.0.0.1 and ::1 accept TCP connections and UDP datagrams,
#   - the same port on every non-loopback address of this Mac does not,
#   - a wildcard bind (what the helper did before) does accept on those
#     addresses, so the harness can tell the bug from the fix,
#   - DNSProxy.isLoopbackPeer accepts only loopback peers.
#
# A runner with no non-loopback IPv4 or IPv6 address skips the LAN half and
# says so; the loopback and peer checks still run.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-dns-loopback.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

SDK="$(xcrun --show-sdk-path)"
TARGET="arm64-apple-macos13.0"

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation
import Network
import Darwin

struct Checks {
    var failures = 0
    mutating func expect(_ ok: Bool, _ message: String) {
        if ok { print("  ok   \(message)") } else { print("  FAIL \(message)"); failures += 1 }
    }
}

/// Every address of this Mac that is up and not loopback or link-local.
func externalAddresses() -> [NWEndpoint.Host] {
    var hosts: [NWEndpoint.Host] = []
    var list: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&list) == 0, let first = list else { return [] }
    defer { freeifaddrs(list) }
    var cursor: UnsafeMutablePointer<ifaddrs>? = first
    while let entry = cursor {
        defer { cursor = entry.pointee.ifa_next }
        let flags = Int32(entry.pointee.ifa_flags)
        guard flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0, let addr = entry.pointee.ifa_addr else { continue }
        var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let family = Int32(addr.pointee.sa_family)
        guard family == AF_INET || family == AF_INET6 else { continue }
        let length = socklen_t(family == AF_INET ? MemoryLayout<sockaddr_in>.size : MemoryLayout<sockaddr_in6>.size)
        guard getnameinfo(addr, length, &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
        let text = String(cString: buffer)
        if family == AF_INET, let v4 = IPv4Address(text), !v4.isLinkLocal { hosts.append(.ipv4(v4)) }
        if family == AF_INET6, !text.contains("%"), let v6 = IPv6Address(text), !v6.isLinkLocal { hosts.append(.ipv6(v6)) }
    }
    return hosts
}

/// Starts a TCP and a UDP listener with `params` builders and waits for ready.
final class Bound {
    let listeners: [NWListener]
    var tcpAccepted = 0
    var udpReceived = 0
    /// isLoopbackPeer of every connection the listener really accepted.
    var peerVerdicts: [Bool] = []
    let lock = NSLock()
    let queue = DispatchQueue(label: "harness")

    init(tcp: NWParameters, udp: NWParameters, port: NWEndpoint.Port?) throws {
        func make(_ p: NWParameters) throws -> NWListener {
            if let port { return try NWListener(using: p, on: port) }
            return try NWListener(using: p)
        }
        listeners = [try make(tcp), try make(udp)]
        let ready = DispatchSemaphore(value: 0)
        var failed = false
        for (index, listener) in listeners.enumerated() {
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready: ready.signal()
                case .failed: failed = true; ready.signal()
                default: break
                }
            }
            listener.newConnectionHandler = { [weak self] conn in
                guard let self else { return }
                self.lock.lock(); self.peerVerdicts.append(DNSProxy.isLoopbackPeer(conn.endpoint)); self.lock.unlock()
                conn.start(queue: self.queue)
                if index == 0 {
                    self.lock.lock(); self.tcpAccepted += 1; self.lock.unlock()
                    conn.cancel()
                } else {
                    conn.receiveMessage { data, _, _, _ in
                        if data != nil { self.lock.lock(); self.udpReceived += 1; self.lock.unlock() }
                        conn.cancel()
                    }
                }
            }
            listener.start(queue: queue)
        }
        for _ in listeners { _ = ready.wait(timeout: .now() + 5) }
        if failed { throw NSError(domain: "harness", code: 1, userInfo: [NSLocalizedDescriptionKey: "listener failed"]) }
    }
    func verdicts() -> [Bool] { lock.lock(); defer { lock.unlock() }; return peerVerdicts }
    func counts() -> (Int, Int) { lock.lock(); defer { lock.unlock() }; return (tcpAccepted, udpReceived) }
    func cancel() { listeners.forEach { $0.cancel() } }
}

/// True when a TCP connection to host:port reaches the ready state.
func tcpConnects(_ host: NWEndpoint.Host, _ port: NWEndpoint.Port) -> Bool {
    let conn = NWConnection(host: host, port: port, using: .tcp)
    let done = DispatchSemaphore(value: 0)
    var ready = false
    conn.stateUpdateHandler = { state in
        switch state {
        case .ready: ready = true; done.signal()
        case .failed, .waiting, .cancelled: done.signal()
        default: break
        }
    }
    conn.start(queue: DispatchQueue(label: "tcp-probe"))
    _ = done.wait(timeout: .now() + 3)
    conn.cancel()
    return ready
}

/// Sends one datagram to host:port.
func sendUDP(_ host: NWEndpoint.Host, _ port: NWEndpoint.Port) {
    let conn = NWConnection(host: host, port: port, using: .udp)
    let done = DispatchSemaphore(value: 0)
    conn.stateUpdateHandler = { state in
        if case .ready = state {
            conn.send(content: Data([0x12, 0x34]), completion: .contentProcessed { _ in done.signal() })
        } else if case .failed = state { done.signal() }
    }
    conn.start(queue: DispatchQueue(label: "udp-probe"))
    _ = done.wait(timeout: .now() + 3)
    Thread.sleep(forTimeInterval: 0.3)
    conn.cancel()
}

func freePort() -> NWEndpoint.Port {
    // A random high port; collisions only make a bind fail, which the harness reports.
    NWEndpoint.Port(rawValue: UInt16.random(in: 40000...60000))!
}

@main
struct Main {
    static func main() {
        var checks = Checks()
        let external = externalAddresses()

        print("peer check")
        func peer(_ text: String) -> Bool {
            DNSProxy.isLoopbackPeer(.hostPort(host: NWEndpoint.Host(text), port: 53))
        }
        checks.expect(peer("127.0.0.1"), "127.0.0.1 is a loopback peer")
        checks.expect(peer("127.8.9.10"), "127.8.9.10 is a loopback peer")
        checks.expect(peer("::1"), "::1 is a loopback peer")
        checks.expect(peer("::ffff:127.0.0.1"), "::ffff:127.0.0.1 is a loopback peer")
        for text in ["::127.0.0.1", "192.168.1.20", "10.0.0.2", "100.64.1.1", "0.0.0.0", "fe80::1", "2001:db8::1", "::ffff:192.168.1.20", "::"] {
            checks.expect(!peer(text), "\(text) is not a loopback peer")
        }
        checks.expect(!DNSProxy.isLoopbackPeer(.service(name: "x", type: "_dns._udp", domain: "local", interface: nil)),
                      "a non host:port endpoint is not a loopback peer")
        checks.expect(DNSProxy.loopbackHosts.count == 2, "the proxy binds exactly two hosts")
        for host in DNSProxy.loopbackHosts {
            checks.expect(DNSProxy.isLoopbackPeer(.hostPort(host: host, port: 53)), "the proxy only binds loopback (\(host))")
        }

        print("helper bind")
        let port = freePort()
        var bound: [Bound] = []
        do {
            for host in DNSProxy.loopbackHosts {
                bound.append(try Bound(tcp: DNSProxy.listenerParameters(.tcp, host: host, port: port),
                                       udp: DNSProxy.listenerParameters(.udp, host: host, port: port),
                                       port: nil))
            }
        } catch {
            checks.expect(false, "binding the helper's loopback listeners on \(port): \(error)")
        }
        func total() -> (Int, Int) { bound.reduce((0, 0)) { ($0.0 + $1.counts().0, $0.1 + $1.counts().1) } }

        for host in DNSProxy.loopbackHosts {
            checks.expect(tcpConnects(host, port), "tcp to \(host):\(port) is accepted")
            let before = total().1
            sendUDP(host, port)
            checks.expect(total().1 > before, "udp to \(host):\(port) is received")
        }

        if external.isEmpty {
            print("  skip no non-loopback address on this machine, the LAN half cannot run here")
        }
        for host in external {
            let (tcpBefore, udpBefore) = total()
            checks.expect(!tcpConnects(host, port), "tcp to \(host):\(port) is refused")
            sendUDP(host, port)
            let (tcpAfter, udpAfter) = total()
            checks.expect(tcpAfter == tcpBefore, "no tcp connection from \(host) reached the listener")
            checks.expect(udpAfter == udpBefore, "no udp datagram sent to \(host) reached the listener")
        }
        let realPeers = bound.flatMap { $0.verdicts() }
        checks.expect(!realPeers.isEmpty && realPeers.allSatisfy { $0 },
                      "every connection really accepted over loopback passes isLoopbackPeer (\(realPeers.count) seen)")
        bound.forEach { $0.cancel() }

        if !external.isEmpty {
            print("wildcard bind (the behaviour before #205), to prove the probe can see the bug")
            let wildPort = freePort()
            do {
                let tcp = NWParameters.tcp; tcp.allowLocalEndpointReuse = true
                let udp = NWParameters.udp; udp.allowLocalEndpointReuse = true
                let wild = try Bound(tcp: tcp, udp: udp, port: wildPort)
                var reached = false
                for host in external where tcpConnects(host, wildPort) { reached = true }
                checks.expect(reached, "a wildcard bind is reachable through a non-loopback address")
                // Over a LAN address the peer is that address, not loopback,
                // so the peer check would close these if the bind ever widened.
                Thread.sleep(forTimeInterval: 0.3)
                let lanPeers = wild.verdicts()
                checks.expect(!lanPeers.isEmpty && !lanPeers.contains(true),
                              "connections really accepted through a non-loopback address fail isLoopbackPeer (\(lanPeers.count) seen)")
                wild.cancel()
            } catch {
                checks.expect(false, "binding the wildcard control listener: \(error)")
            }
        }

        if checks.failures > 0 {
            print("dns proxy loopback: \(checks.failures) failure(s)")
            exit(1)
        }
    }
}
SWIFT

# shellcheck disable=SC2046
xcrun swiftc -O -sdk "$SDK" -target "$TARGET" -parse-as-library \
  -o "$TMP/verify" \
  $(ls "$ROOT"/Sources/Helper/*.swift | grep -v '/main.swift$') \
  "$ROOT"/Sources/Shared/*.swift \
  "$TMP/verify.swift"
"$TMP/verify"
printf 'dns proxy loopback verification: PASS\n'
