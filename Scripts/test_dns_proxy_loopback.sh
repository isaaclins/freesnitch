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
#   - DNSProxy.isLoopbackPeer accepts only loopback peers,
#   - a listener whose port is already taken is created without a throw and
#     fails later in its state handler, and the helper's handler then stops
#     the proxy reporting itself running for 127.0.0.1 (UDP and TCP) but not
#     for ::1 (issue #490), checked on the handler alone and on a real
#     DNSProxy started on a squatted high port, never on port 53.
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
    /// Signalled once per accepted TCP connection and per received datagram,
    /// so the probes wait for an arrival instead of sleeping.
    let tcpArrival = DispatchSemaphore(value: 0)
    let udpArrival = DispatchSemaphore(value: 0)
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
                    self.tcpArrival.signal()
                    conn.cancel()
                } else {
                    conn.receiveMessage { data, _, _, _ in
                        if data != nil {
                            self.lock.lock(); self.udpReceived += 1; self.lock.unlock()
                            self.udpArrival.signal()
                        }
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

        print("what Settings counts as reaching the proxy")
        checks.expect(DNSProxy.loopbackHosts.map { "\($0)" } == [DNSProxyAddress.ipv4, DNSProxyAddress.ipv6],
                      "Settings and the helper agree on the proxy's addresses")
        for server in ["127.0.0.1", "::1"] {
            checks.expect(DNSProxyAddress.reachesProxy(server), "\(server) reaches the proxy")
        }
        for server in ["127.0.0.2", "127.0.0.53", "192.168.1.20", "9.9.9.9", "::", "fe80::1"] {
            checks.expect(!DNSProxyAddress.reachesProxy(server), "\(server) does not reach the proxy")
        }
        let own: Set<String> = ["127.0.0.1", "::1", "192.168.1.20", "fd00::20"]
        checks.expect(DNSProxyAddress.ownNetworkResolvers(["192.168.1.20", "9.9.9.9", "fd00::20"], own: own) == ["192.168.1.20", "fd00::20"],
                      "a DNS server set to this Mac's own network address is named")
        checks.expect(DNSProxyAddress.ownNetworkResolvers(["127.0.0.1", "::1", "127.0.0.2", "192.168.1.1"], own: own).isEmpty,
                      "loopback and other machines are not counted as this Mac's network address")

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
        /// Waits up to `seconds` for any listener to report an arrival.
        func anyArrival(within seconds: Double) -> Bool {
            let deadline = DispatchTime.now() + seconds
            while DispatchTime.now() < deadline {
                for b in bound {
                    if b.tcpArrival.wait(timeout: .now()) == .success { return true }
                    if b.udpArrival.wait(timeout: .now()) == .success { return true }
                }
                Thread.sleep(forTimeInterval: 0.02)
            }
            return false
        }

        for (host, b) in zip(DNSProxy.loopbackHosts, bound) {
            checks.expect(tcpConnects(host, port), "tcp to \(host):\(port) is accepted")
            checks.expect(b.tcpArrival.wait(timeout: .now() + 5) == .success, "the tcp connection to \(host) reached its listener")
            sendUDP(host, port)
            checks.expect(b.udpArrival.wait(timeout: .now() + 5) == .success, "udp to \(host):\(port) is received")
        }

        if external.isEmpty {
            print("  skip no non-loopback address on this machine, the LAN half cannot run here")
        }
        for host in external {
            let (tcpBefore, udpBefore) = total()
            checks.expect(!tcpConnects(host, port), "tcp to \(host):\(port) is refused")
            sendUDP(host, port)
            // Proving that nothing arrived can only be a bounded wait.
            checks.expect(!anyArrival(within: 1), "nothing sent to \(host) arrived within a second")
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
                var reached = 0
                for host in external where tcpConnects(host, wildPort) {
                    if wild.tcpArrival.wait(timeout: .now() + 5) == .success { reached += 1 }
                }
                checks.expect(reached > 0, "a wildcard bind is reachable through a non-loopback address")
                // Over a LAN address the peer is that address, not loopback,
                // so the peer check would close these if the bind ever widened.
                let lanPeers = wild.verdicts()
                checks.expect(!lanPeers.isEmpty && !lanPeers.contains(true),
                              "connections really accepted through a non-loopback address fail isLoopbackPeer (\(lanPeers.count) seen)")
                wild.cancel()
            } catch {
                checks.expect(false, "binding the wildcard control listener: \(error)")
            }
        }

        print("a listener whose port is taken (#490)")
        for host in DNSProxy.loopbackHosts {
            let primary = host == DNSProxy.loopbackHosts[0]
            for proto in ["udp", "tcp"] {
                let takenPort = freePort()
                let base: () -> NWParameters = { proto == "udp" ? .udp : .tcp }
                // The squatter binds without address reuse, so the helper's
                // listener cannot share the port.
                let squatParams = base()
                squatParams.requiredLocalEndpoint = .hostPort(host: host, port: takenPort)
                let squatReady = DispatchSemaphore(value: 0)
                guard let squatter = try? NWListener(using: squatParams) else {
                    checks.expect(false, "could not create the \(proto) squatter on \(host)"); continue
                }
                squatter.newConnectionHandler = { $0.cancel() }
                squatter.stateUpdateHandler = { if case .ready = $0 { squatReady.signal() } }
                squatter.start(queue: DispatchQueue(label: "squatter"))
                guard squatReady.wait(timeout: .now() + 5) == .success else {
                    checks.expect(false, "the \(proto) squatter on \(host):\(takenPort) never got ready"); squatter.cancel(); continue
                }
                let listener: NWListener
                do {
                    listener = try NWListener(using: DNSProxy.listenerParameters(base(), host: host, port: takenPort))
                    checks.expect(true, "\(proto) on a taken \(host) port is created without a throw")
                } catch {
                    checks.expect(false, "\(proto) on a taken \(host) port threw instead of failing later: \(error)")
                    squatter.cancel(); continue
                }
                let failed = DispatchSemaphore(value: 0)
                let lock = NSLock()
                var stoppedProxy = false
                let helperHandler = DNSProxy.listenerStateHandler(proto, host: host, primary: primary) {
                    lock.lock(); stoppedProxy = true; lock.unlock()
                }
                listener.newConnectionHandler = { $0.cancel() }
                listener.stateUpdateHandler = { state in
                    helperHandler(state)
                    if case .failed = state { failed.signal() }
                }
                listener.start(queue: DispatchQueue(label: "taken"))
                checks.expect(failed.wait(timeout: .now() + 5) == .success, "\(proto) on a taken \(host) port reports .failed")
                lock.lock(); let stopped = stoppedProxy; lock.unlock()
                if primary {
                    checks.expect(stopped, "a failed \(proto) listener on \(host) stops the proxy reporting itself running")
                } else {
                    checks.expect(!stopped, "a failed \(proto) listener on \(host) leaves the proxy running")
                }
                listener.cancel()
                squatter.cancel()
            }
        }

        print("a real proxy started on a taken port (#490)")
        /// Squats `proto` on host:port without address reuse; nil if it can't.
        func squat(_ proto: String, _ host: NWEndpoint.Host, _ port: NWEndpoint.Port) -> NWListener? {
            let params: NWParameters = proto == "udp" ? .udp : .tcp
            params.requiredLocalEndpoint = .hostPort(host: host, port: port)
            guard let l = try? NWListener(using: params) else { return nil }
            let ready = DispatchSemaphore(value: 0)
            l.newConnectionHandler = { $0.cancel() }
            l.stateUpdateHandler = { if case .ready = $0 { ready.signal() } }
            l.start(queue: DispatchQueue(label: "squat"))
            guard ready.wait(timeout: .now() + 5) == .success else { l.cancel(); return nil }
            return l
        }
        /// True once `proxy.running` equals `want` within `seconds`.
        func settles(_ proxy: DNSProxy, to want: Bool, within seconds: Double) -> Bool {
            let deadline = DispatchTime.now() + seconds
            while DispatchTime.now() < deadline {
                if proxy.running == want { return true }
                Thread.sleep(forTimeInterval: 0.02)
            }
            return proxy.running == want
        }
        // Only 127.0.0.1 here: on macOS a port squatted on ::1 also makes the
        // 127.0.0.1 bind of the same port fail, so a ::1-only failure can't
        // be staged with a real proxy. The handler check above covers ::1.
        let host = DNSProxy.loopbackHosts[0]
        for proto in ["tcp", "udp"] {
            let takenPort = freePort()
            guard let squatter = squat(proto, host, takenPort) else {
                checks.expect(false, "could not squat \(proto) \(host):\(takenPort)"); continue
            }
            let proxy = DNSProxy()
            do { try proxy.start(port: takenPort.rawValue) } catch {
                checks.expect(false, "start on a taken \(proto) \(host) port threw: \(error)")
                squatter.cancel(); continue
            }
            checks.expect(settles(proxy, to: false, within: 5),
                          "a proxy whose \(proto) port on \(host) is taken stops reporting itself running")
            // The same proxy starts again once the port is free: the
            // leftover listeners are cancelled and the new generation
            // stays running.
            squatter.cancel()
            do {
                try proxy.start(port: takenPort.rawValue)
                checks.expect(proxy.running && !settles(proxy, to: false, within: 1),
                              "starting again on the freed \(proto) port keeps the proxy running")
            } catch { checks.expect(false, "restart on the freed port threw: \(error)") }
            proxy.stop()
            checks.expect(!proxy.running, "stop clears running")
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
