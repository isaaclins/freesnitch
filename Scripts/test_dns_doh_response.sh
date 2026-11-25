#!/usr/bin/env bash
# The DNS proxy only hands a client a DoH reply that is a DNS answer to its
# question (issue #210).
#
# The harness compiles the shipping helper sources, runs a small plain-HTTP
# DoH stand-in on a free loopback port and a real DNSProxy on another free
# high port, never port 53 and never the Mac's DNS settings. Each case points
# the proxy at a different path of the stand-in and sends a query over UDP
# (and one over TCP):
#
#   - HTTP 503 with an HTML error page, HTTP 200 with an HTML page, HTTP 200
#     with an empty body, HTTP 200 with a DNS reply to another name, and a
#     resolver that is not listening all come back as SERVFAIL carrying the
#     client's ID and question, never as the error page's bytes,
#   - none of those reach onResolve,
#   - a good answer is passed through unchanged and reported to onResolve,
#   - a good answer that carries ID 0 comes back with the client's ID.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-dns-doh.XXXXXX")"
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

func freePort() -> UInt16 {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    defer { close(fd) }
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_addr.s_addr = inet_addr("127.0.0.1")
    addr.sin_port = 0
    var len = socklen_t(MemoryLayout<sockaddr_in>.size)
    _ = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, len) } }
    _ = withUnsafeMutablePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
    return UInt16(bigEndian: addr.sin_port)
}

func query(id: UInt16, name: String, type: UInt16 = 1) -> Data {
    var d = Data([UInt8(id >> 8), UInt8(id & 0xff), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0])
    for label in name.split(separator: ".") {
        d.append(UInt8(label.utf8.count)); d.append(contentsOf: Array(label.utf8))
    }
    d.append(0); d.append(contentsOf: [UInt8(type >> 8), UInt8(type & 0xff), 0, 1])
    return d
}

/// A reply to `q` with one A record 192.0.2.7, optionally for another name.
func answer(to q: Data, id: UInt16? = nil, name: String? = nil) -> Data {
    var r: Data
    if let name { r = query(id: 0, name: name) } else { r = q }
    let qid = id ?? (UInt16(q[0]) << 8 | UInt16(q[1]))
    r[0] = UInt8(qid >> 8); r[1] = UInt8(qid & 0xff)
    r[2] = 0x81; r[3] = 0x80
    r[6] = 0; r[7] = 1
    r.append(contentsOf: [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7])
    return r
}

/// Plain HTTP/1.1 DoH stand-in. The request path picks the reply.
final class FakeDoH {
    let listener: NWListener
    let port: UInt16
    let queue = DispatchQueue(label: "fake-doh")
    init() throws {
        port = freePort()
        let params = NWParameters.tcp
        params.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: NWEndpoint.Port(rawValue: port)!)
        listener = try NWListener(using: params)
        listener.newConnectionHandler = { [weak self] c in self?.serve(c) }
        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { if case .ready = $0 { ready.signal() } }
        listener.start(queue: queue)
        _ = ready.wait(timeout: .now() + 5)
    }
    func serve(_ c: NWConnection) {
        c.start(queue: queue)
        read(c, Data())
    }
    func read(_ c: NWConnection, _ acc: Data) {
        c.receive(minimumIncompleteLength: 1, maximumLength: 65535) { data, _, done, _ in
            var buf = acc; if let data { buf.append(data) }
            guard let sep = buf.range(of: Data("\r\n\r\n".utf8)) else {
                if done { c.cancel() } else { self.read(c, buf) }; return
            }
            let head = String(decoding: buf[..<sep.lowerBound], as: UTF8.self)
            let length = head.split(separator: "\r\n")
                .first { $0.lowercased().hasPrefix("content-length:") }
                .flatMap { Int($0.split(separator: ":")[1].trimmingCharacters(in: .whitespaces)) } ?? 0
            let body = buf[sep.upperBound...]
            if body.count < length { if done { c.cancel() } else { self.read(c, buf) }; return }
            let path = head.split(separator: " ").dropFirst().first.map(String.init) ?? "/"
            self.respond(c, path: path, query: Data(body.prefix(length)))
        }
    }
    func respond(_ c: NWConnection, path: String, query q: Data) {
        let html = Data("<!DOCTYPE html><html><body><h1>503 Service Unavailable</h1></body></html>".utf8)
        let (status, type, body): (String, String, Data)
        switch path {
        case "/503": (status, type, body) = ("503 Service Unavailable", "text/html", html)
        case "/html200": (status, type, body) = ("200 OK", "text/html", html)
        case "/empty": (status, type, body) = ("200 OK", "application/dns-message", Data())
        case "/otherq": (status, type, body) = ("200 OK", "application/dns-message", answer(to: q, name: "other.example"))
        case "/id0": (status, type, body) = ("200 OK", "application/dns-message", answer(to: q, id: 0))
        default: (status, type, body) = ("200 OK", "application/dns-message", answer(to: q))
        }
        var out = Data("HTTP/1.1 \(status)\r\nContent-Type: \(type)\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n".utf8)
        out.append(body)
        c.send(content: out, completion: .contentProcessed { _ in c.cancel() })
    }
}

func exchange(_ q: Data, port: UInt16, tcp: Bool) -> Data? {
    let conn = NWConnection(host: .ipv4(.loopback), port: NWEndpoint.Port(rawValue: port)!, using: tcp ? .tcp : .udp)
    let got = DispatchSemaphore(value: 0)
    var result: Data?
    let queue = DispatchQueue(label: "client")
    conn.start(queue: queue)
    if tcp {
        var framed = Data([UInt8(q.count >> 8), UInt8(q.count & 0xff)]); framed.append(q)
        conn.send(content: framed, completion: .contentProcessed { _ in })
        conn.receive(minimumIncompleteLength: 2, maximumLength: 65535) { data, _, _, _ in
            if let data, data.count >= 2 { result = data.subdata(in: 2..<data.count) }
            got.signal()
        }
    } else {
        conn.send(content: q, completion: .contentProcessed { _ in })
        conn.receiveMessage { data, _, _, _ in result = data; got.signal() }
    }
    _ = got.wait(timeout: .now() + 8)
    conn.cancel()
    return result
}

func rcode(_ d: Data) -> UInt8 { d[3] & 0x0f }
func id(_ d: Data) -> UInt16 { UInt16(d[0]) << 8 | UInt16(d[1]) }

@main
struct Verify {
    static func main() throws {
        var checks = Checks()
        let doh = try FakeDoH()
        let proxy = DNSProxy()
        let resolvedLock = NSLock(); var resolved: [String: [String]] = [:]
        proxy.onResolve = { name, ips in resolvedLock.lock(); resolved[name] = ips; resolvedLock.unlock() }
        let proxyPort = freePort()
        try proxy.start(port: proxyPort)
        defer { proxy.stop() }
        Thread.sleep(forTimeInterval: 0.3)
        let deadPort = freePort()

        var nextID: UInt16 = 0x1200
        func ask(_ path: String, host: String = "127.0.0.1", port: UInt16? = nil, tcp: Bool = false) -> (Data, Data?) {
            nextID &+= 1
            let name = "case\(nextID).example"
            proxy.dohURL = "http://\(host):\(port ?? doh.port)\(path)"
            let q = query(id: nextID, name: name)
            return (q, exchange(q, port: proxyPort, tcp: tcp))
        }
        func wasResolved(_ q: Data) -> Bool {
            let name = DNSWire.firstQuestion(q)!.name
            resolvedLock.lock(); defer { resolvedLock.unlock() }
            return resolved[name] != nil
        }

        let failures: [(String, String, UInt16?, Bool)] = [
            ("/503", "HTTP 503 with an HTML error page", nil, false),
            ("/503", "HTTP 503 with an HTML error page over TCP", nil, true),
            ("/html200", "HTTP 200 with an HTML page", nil, false),
            ("/empty", "HTTP 200 with an empty body", nil, false),
            ("/otherq", "HTTP 200 with a DNS reply to another name", nil, false),
            ("/dns-query", "a resolver that is not listening", deadPort, false),
        ]
        for (path, what, port, tcp) in failures {
            let (q, reply) = ask(path, port: port, tcp: tcp)
            guard let reply else { checks.expect(false, "\(what): the client got no reply"); continue }
            checks.expect(reply.count >= 12 && rcode(reply) == 2 && reply[2] & 0x80 != 0,
                          "\(what): the client gets SERVFAIL")
            checks.expect(reply.count >= 12 && id(reply) == id(q), "\(what): the reply carries the client's ID")
            checks.expect(DNSWire.firstQuestion(reply)?.name == DNSWire.firstQuestion(q)?.name,
                          "\(what): the reply echoes the client's question")
            checks.expect(reply.range(of: Data("html".utf8)) == nil,
                          "\(what): no error page bytes reach the client")
            checks.expect(!wasResolved(q), "\(what): nothing is reported to onResolve")
        }

        for tcp in [false, true] {
            let via = tcp ? "TCP" : "UDP"
            let (q, reply) = ask("/dns-query", tcp: tcp)
            checks.expect(reply == answer(to: q), "a good answer over \(via) is passed through unchanged")
            checks.expect(wasResolved(q), "a good answer over \(via) is reported to onResolve")
        }

        let (q0, reply0) = ask("/id0")
        checks.expect(reply0 != nil && id(reply0!) == id(q0) && rcode(reply0!) == 0,
                      "a good answer with ID 0 comes back with the client's ID")
        checks.expect(reply0.map { $0.subdata(in: 2..<$0.count) } == answer(to: q0).subdata(in: 2..<answer(to: q0).count),
                      "a good answer with ID 0 is otherwise unchanged")

        if checks.failures > 0 {
            print("dns doh response: \(checks.failures) failure(s)")
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
printf 'dns doh response verification: PASS\n'
