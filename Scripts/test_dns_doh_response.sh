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
#     client's ID and question, never as the error page's bytes, and so
#     does a resolver address that does not parse,
#   - none of those reach onResolve,
#   - a good answer is passed through unchanged and reported to onResolve,
#   - a good answer that carries ID 0 comes back with the client's ID,
#   - an answer larger than a DNS message can be (#249), announced with a
#     Content-Length or streamed without one, is SERVFAIL over UDP and TCP,
#     and a streamed one is cut off while it arrives instead of being read
#     to the end, while an answer of exactly 65,535 bytes still comes back
#     over TCP whole and behind a matching length prefix,
#   - a reply too big for the TCP length prefix is framed as SERVFAIL.
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

/// Whether something already holds 127.0.0.1:`port` for this socket type.
func isBound(_ port: UInt16, _ type: Int32) -> Bool {
    let fd = socket(AF_INET, type, 0)
    defer { close(fd) }
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_addr.s_addr = inet_addr("127.0.0.1")
    addr.sin_port = port.bigEndian
    let rc = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
    }
    return rc != 0 && errno == EADDRINUSE
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

/// `answer(to:)` padded with trailing bytes to `size` in all. The padding
/// sits after the records the header counts, so it still reads as a reply.
func padded(_ q: Data, to size: Int) -> Data {
    var r = answer(to: q)
    r.append(Data(repeating: 0, count: size - r.count))
    return r
}

/// Plain HTTP/1.1 DoH stand-in. The request path picks the reply.
final class FakeDoH {
    let listener: NWListener
    /// Bytes of the streamed oversized body the proxy accepted before it
    /// stopped reading.
    let streamLock = NSLock()
    var streamedBytes = 0
    var streamFinished = false
    static let streamTotal = 256 * 1024 * 1024
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
        case "/max": (status, type, body) = ("200 OK", "application/dns-message", padded(q, to: 65_535))
        case "/huge": (status, type, body) = ("200 OK", "application/dns-message", padded(q, to: 65_536))
        case "/stream":
            // No Content-Length: the body runs until the connection closes,
            // so only counting it while it arrives can stop it.
            let head = Data("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nConnection: close\r\n\r\n".utf8)
            streamLock.lock(); streamedBytes = 0; streamFinished = false; streamLock.unlock()
            c.send(content: head, completion: .contentProcessed { _ in })
            stream(c, first: padded(q, to: 64 * 1024), sent: 0)
            return
        default: (status, type, body) = ("200 OK", "application/dns-message", answer(to: q))
        }
        var out = Data("HTTP/1.1 \(status)\r\nContent-Type: \(type)\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n".utf8)
        out.append(body)
        c.send(content: out, completion: .contentProcessed { _ in c.cancel() })
    }
    func stream(_ c: NWConnection, first: Data, sent: Int) {
        let chunk = sent == 0 ? first : Data(repeating: 0, count: 64 * 1024)
        c.send(content: chunk, completion: .contentProcessed { error in
            let total = sent + chunk.count
            if error != nil || total >= FakeDoH.streamTotal {
                self.streamLock.lock(); self.streamedBytes = total; self.streamFinished = error == nil; self.streamLock.unlock()
                c.cancel(); return
            }
            self.stream(c, first: first, sent: total)
        })
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
        // Reads one whole frame: the length prefix, then that many bytes.
        // A prefix that promises fewer bytes than arrive is reported as the
        // frame plus whatever followed it, so a mismatch shows.
        func read(_ acc: Data) {
            conn.receive(minimumIncompleteLength: 1, maximumLength: 1 << 20) { data, _, done, _ in
                var buf = acc; if let data { buf.append(data) }
                if buf.count >= 2 {
                    let len = Int(buf[0]) << 8 | Int(buf[1])
                    if buf.count >= 2 + len && (len > 0 || done || data == nil) {
                        result = buf.subdata(in: 2..<buf.count); got.signal(); return
                    }
                }
                if done || data == nil { if buf.count >= 2 { result = buf.subdata(in: 2..<buf.count) }; got.signal(); return }
                read(buf)
            }
        }
        read(Data())
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
        // Listeners bind asynchronously. Wait until both 127.0.0.1 sockets
        // are taken, so no query goes out before the proxy can receive it.
        let readyBy = Date().addingTimeInterval(10)
        while !(isBound(proxyPort, SOCK_DGRAM) && isBound(proxyPort, SOCK_STREAM)) && Date() < readyBy {
            usleep(10_000)
        }
        checks.expect(isBound(proxyPort, SOCK_DGRAM) && isBound(proxyPort, SOCK_STREAM), "the proxy is listening on 127.0.0.1")
        let deadPort = freePort()

        var nextID: UInt16 = 0x1200
        func ask(_ path: String, host: String = "127.0.0.1", port: UInt16? = nil, tcp: Bool = false) -> (Data, Data?) {
            nextID &+= 1
            let name = "case\(nextID).example"
            proxy.dohURL = "http://\(host):\(port ?? doh.port)\(path)"
            let q = query(id: nextID, name: name)
            return (q, exchange(q, port: proxyPort, tcp: tcp))
        }
        func askURL(_ url: String) -> (Data, Data?) {
            nextID &+= 1
            proxy.dohURL = url
            let q = query(id: nextID, name: "case\(nextID).example")
            return (q, exchange(q, port: proxyPort, tcp: false))
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
            ("", "a resolver address that does not parse", nil, false),
        ]
        for (path, what, port, tcp) in failures {
            let (q, reply) = path.isEmpty ? askURL("http://[not a url") : ask(path, port: port, tcp: tcp)
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

        // #249: an answer larger than a DNS message can be.
        for (path, what) in [("/huge", "an announced 65,536 byte answer"), ("/stream", "an unannounced endless answer")] {
            for tcp in [false, true] {
                let via = tcp ? "TCP" : "UDP"
                let started = Date()
                let (q, reply) = ask(path, tcp: tcp)
                guard let reply else { checks.expect(false, "\(what) over \(via): the client got no reply"); continue }
                checks.expect(reply.count >= 12 && rcode(reply) == 2 && id(reply) == id(q),
                              "\(what) over \(via): the client gets SERVFAIL with its ID")
                checks.expect(reply.count < 512, "\(what) over \(via): no part of the oversized body reaches the client")
                checks.expect(!wasResolved(q), "\(what) over \(via): nothing is reported to onResolve")
                checks.expect(Date().timeIntervalSince(started) < 5, "\(what) over \(via): the failure comes back at once")
                if path == "/stream" {
                    let stopBy = Date().addingTimeInterval(5)
                    var sent = 0, finished = true
                    repeat {
                        usleep(20_000)
                        doh.streamLock.lock(); sent = doh.streamedBytes; finished = doh.streamFinished; doh.streamLock.unlock()
                    } while sent == 0 && Date() < stopBy
                    checks.expect(sent > 0 && !finished && sent < FakeDoH.streamTotal / 4,
                                  "\(what) over \(via): the proxy stops reading it early (\(sent / 1024) KiB of \(FakeDoH.streamTotal / 1024) KiB sent)")
                }
            }
        }
        let (qMax, replyMax) = ask("/max", tcp: true)
        checks.expect(replyMax == padded(qMax, to: 65_535),
                      "a 65,535 byte answer over TCP comes back whole behind a matching length")

        let bigQuery = query(id: 0x4242, name: "big.example")
        let tooBig = padded(bigQuery, to: 65_536)
        let frame = DNSWire.tcpFrame(tooBig, for: bigQuery)
        checks.expect(frame.map { Int($0[0]) << 8 | Int($0[1]) == $0.count - 2 } == true,
                      "a reply too big for the TCP prefix is framed with a matching length")
        checks.expect(frame.map { $0.count >= 14 && rcode($0.subdata(in: 2..<$0.count)) == 2 } == true,
                      "a reply too big for the TCP prefix is framed as SERVFAIL")
        let fits = padded(bigQuery, to: 65_535)
        checks.expect(DNSWire.tcpFrame(fits, for: bigQuery) == Data([0xff, 0xff]) + fits,
                      "a 65,535 byte reply is framed unchanged")
        checks.expect(DNSProxy.upstreamAnswer(data: tooBig, response: HTTPURLResponse(url: URL(string: "https://x.example")!, statusCode: 200, httpVersion: nil, headerFields: nil),
                                              error: nil, query: bigQuery) != .answer(tooBig),
                      "a 65,536 byte body is never accepted as an answer")

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
