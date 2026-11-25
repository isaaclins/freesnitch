#!/usr/bin/env bash
# Regression harness for #283.
#
# The DNS proxy judged only the name that was looked up. An unlisted alias
# whose CNAME points at a blocklisted name came back with the listed name's
# address. This sends real DNS queries through a real DNSProxy on a free
# 127.0.0.1 port (never port 53, the Mac's DNS settings are not touched) to a
# stand-in DoH upstream on 127.0.0.1 that replays an answer recorded from
# Cloudflare: www.microsoft.com -> www.microsoft.com-c-3.edgekey.net ->
# e13678.dscb.akamaiedge.net -> 184.25.54.100. It checks that:
#
#   - with no list or rule the recorded answer is passed through unchanged,
#   - a listed target, at either step of the chain or by a parent domain,
#     turns the answer into NXDOMAIN, in Silent Allow and in Silent Deny,
#   - "Allow Anyway" for the target lets it through again,
#   - a deny rule naming the target refuses it; one for another port, one
#     for one app, a disabled one and one behind an allow for the target don't,
#   - allowing the looked-up name by rule does not switch the list off for
#     its target, and an allow with no host never does,
#   - the block is counted and reported with the target that caused it.
#
# Compiled from the real Sources/Helper and Sources/Shared, never a copy.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-cname.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation
import Network

func hex(_ s: String) -> Data {
    var d = Data(); var i = s.startIndex
    while i < s.endIndex { let j = s.index(i, offsetBy: 2); d.append(UInt8(s[i..<j], radix: 16)!); i = j }
    return d
}

// A Cloudflare DoH answer for www.microsoft.com A, recorded 2026-11-25. Its
// names use compression pointers, as real answers do.
let recorded = hex("12348180000100030000000003777777096d6963726f736f667403636f6d0000010001c00c0005000100000d9a002303777777096d6963726f736f667407636f6d2d632d3307656467656b6579036e657400c02f000500010000030e00190665313336373804647363620a616b616d616965646765c04dc05e000100010000000b0004b8193664")

/// A one-answer DoH server: every POST gets `recorded` back, with the
/// query's own id so the client accepts it.
final class FakeUpstream {
    let listener: NWListener
    let port: UInt16
    let queue = DispatchQueue(label: "upstream")
    init() throws {
        port = freePort()
        listener = try NWListener(using: .tcp, on: NWEndpoint.Port(rawValue: port)!)
        listener.newConnectionHandler = { [queue] conn in
            conn.start(queue: queue)
            FakeUpstream.read(conn, Data())
        }
        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { if case .ready = $0 { ready.signal() } }
        listener.start(queue: queue)
        _ = ready.wait(timeout: .now() + 5)
    }
    static func read(_ conn: NWConnection, _ buf: Data) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, done, err in
            var buf = buf; if let data { buf.append(data) }
            let sep = Data("\r\n\r\n".utf8)
            if let r = buf.range(of: sep) {
                let head = String(decoding: buf[..<r.lowerBound], as: UTF8.self).lowercased()
                let len = head.split(separator: "\r\n").first { $0.hasPrefix("content-length:") }
                    .flatMap { Int($0.dropFirst("content-length:".count).trimmingCharacters(in: .whitespaces)) } ?? 0
                let body = buf[r.upperBound...]
                if body.count >= len {
                    var answer = recorded
                    if body.count >= 2 { answer[0] = body[body.startIndex]; answer[1] = body[body.startIndex + 1] }
                    var out = Data("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: \(answer.count)\r\nConnection: close\r\n\r\n".utf8)
                    out.append(answer)
                    conn.send(content: out, completion: .contentProcessed { _ in conn.cancel() })
                    return
                }
            }
            if done || err != nil { conn.cancel(); return }
            read(conn, buf)
        }
    }
}

func query(_ name: String, id: UInt16) -> Data {
    var d = Data([UInt8(id >> 8), UInt8(id & 0xff), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0])
    for label in name.split(separator: ".") { d.append(UInt8(label.utf8.count)); d.append(contentsOf: label.utf8) }
    d.append(contentsOf: [0, 0, 1, 0, 1])
    return d
}

func ask(_ port: UInt16, _ payload: Data) -> Data? {
    let conn = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!, using: .udp)
    let got = DispatchSemaphore(value: 0)
    var answer: Data?
    conn.stateUpdateHandler = { state in
        if case .ready = state {
            conn.send(content: payload, completion: .contentProcessed { _ in })
            conn.receiveMessage { data, _, _, _ in answer = data; got.signal() }
        }
    }
    conn.start(queue: DispatchQueue(label: "client"))
    _ = got.wait(timeout: .now() + 4)
    conn.cancel()
    return answer
}

func freePort() -> UInt16 {
    // A random high port; a collision only makes a bind fail, which the
    // harness reports.
    UInt16.random(in: 40000...60000)
}

@main
struct Verify {
    static var failures = 0
    static func check(_ ok: Bool, _ what: String) {
        print(ok ? "cname: PASS: \(what)" : "cname: FAIL: \(what)")
        if !ok { failures += 1 }
    }

    static func main() {
        setvbuf(stdout, nil, _IONBF, 0)
        let upstream = try! FakeUpstream()
        let proxy = DNSProxy()
        var port = freePort()
        while port == upstream.port { port = freePort() }
        let blockLock = NSLock(); var blocks: [(String, String?)] = []
        proxy.onBlock = { d, r in blockLock.lock(); blocks.append((d, r)); blockLock.unlock() }
        proxy.dohURL = "http://127.0.0.1:\(upstream.port)/dns-query"
        do { try proxy.start(port: port) } catch { print("cname: FAIL: start: \(error)"); exit(1) }
        Thread.sleep(forTimeInterval: 0.5)
        guard proxy.running else { print("cname: FAIL: the proxy did not start on \(port)"); exit(1) }
        var id: UInt16 = 0x4000

        enum Outcome: Equatable { case passed, nxdomain, other(String) }
        func lookup(_ mode: AppMode, _ list: Set<String>, _ rules: [Rule]) -> Outcome {
            proxy.applyPolicy(mode: mode, rules: rules)
            proxy.blocklist = list
            id &+= 1
            let q = query("www.microsoft.com", id: id)
            guard let a = ask(port, q) else { return .other("no reply") }
            guard a.count > 12, a[0] == q[0], a[1] == q[1] else { return .other("wrong id") }
            if a[3] & 0x0f == 3, a[6] == 0, a[7] == 0 { return .nxdomain }
            var expected = recorded; expected[0] = q[0]; expected[1] = q[1]
            return a == expected ? .passed : .other("changed answer")
        }

        let target = "e13678.dscb.akamaiedge.net"
        check(DNSWire.cnameTargets(recorded) == ["www.microsoft.com-c-3.edgekey.net", target],
              "both CNAME targets are read from the recorded answer")
        check(DNSWire.extractAnswers(recorded) == ["184.25.54.100"], "the address is still read")

        for mode in [AppMode.silentAllow, .silentDeny] {
            let allowName = Rule(remoteHost: "www.microsoft.com", action: .allow, priority: 50)
            let rules = mode == .silentDeny ? [allowName] : []
            check(lookup(mode, [], rules) == .passed, "\(mode): no list, the recorded answer passes unchanged")
            check(lookup(mode, [target], rules) == .nxdomain, "\(mode): listed final target is refused")
            check(lookup(mode, ["www.microsoft.com-c-3.edgekey.net"], rules) == .nxdomain, "\(mode): listed middle target is refused")
            check(lookup(mode, ["akamaiedge.net"], rules) == .nxdomain, "\(mode): a listed parent of the target is refused")
            check(lookup(mode, ["other.example"], rules) == .passed, "\(mode): an unrelated list entry changes nothing")
        }

        let anyway = BlocklistDomain.allowAnywayRule(for: target, listName: "Ads")
        check(lookup(.silentAllow, ["akamaiedge.net"], [anyway]) == .passed, "Allow Anyway for the target lets it through")
        let anywayAlias = BlocklistDomain.allowAnywayRule(for: "www.microsoft.com", listName: "Ads")
        check(lookup(.silentAllow, ["akamaiedge.net"], [anywayAlias]) == .nxdomain,
              "allowing the looked-up name does not switch the list off for its target")
        check(lookup(.silentAllow, ["akamaiedge.net"], [Rule(action: .allow, priority: 100)]) == .nxdomain,
              "an allow with no host does not switch the list off for a target")

        let denyTarget = Rule(remoteHost: "*.edgekey.net", action: .deny, priority: 50)
        check(lookup(.silentAllow, [], [denyTarget]) == .nxdomain, "a deny rule naming the target refuses it")
        check(lookup(.silentAllow, [], [Rule(remoteHost: target, remotePort: 443, action: .deny, priority: 50)]) == .passed,
              "a deny rule for one port of the target does not refuse the lookup")
        check(lookup(.silentAllow, [], [Rule(processName: "Safari", remoteHost: target, action: .deny, priority: 50)]) == .passed,
              "a deny rule for one app does not refuse the lookup for all")
        var off = denyTarget; off.enabled = false
        check(lookup(.silentAllow, [], [off]) == .passed, "a disabled deny rule does nothing")
        let denyEdge = Rule(remoteHost: "*.akamaiedge.net", action: .deny, priority: 50)
        check(lookup(.silentAllow, [], [Rule(remoteHost: target, action: .allow, priority: 100), denyEdge]) == .passed,
              "an allow for the target ahead of a broader deny lets it through")
        check(lookup(.silentAllow, [], [Rule(remoteHost: target, action: .allow, priority: 100), denyTarget]) == .nxdomain,
              "an allow for the last target does not excuse a denied step before it")

        blockLock.lock(); let seen = blocks; blockLock.unlock()
        check(seen.contains { $0.0 == "www.microsoft.com" && $0.1 == "via \(target)" },
              "the block is reported for the looked-up name with its target")
        let stats = proxy.statistics
        check(stats.blocked == seen.count && stats.queries == stats.blocked + stats.allowed,
              "each lookup is counted once, as blocked or allowed (\(stats))")

        proxy.stop()
        if failures > 0 { print("cname: \(failures) failure(s)"); exit(1) }
        print("dns cname target verification: PASS")
    }
}
SWIFT

SDK="$(xcrun --show-sdk-path)"
# shellcheck disable=SC2046
xcrun swiftc -O -sdk "$SDK" -target arm64-apple-macos13.0 -parse-as-library \
  -o "$TMP/verify" \
  $(ls "$ROOT"/Sources/Helper/*.swift | grep -v '/main.swift$') \
  "$ROOT"/Sources/Shared/*.swift \
  "$TMP/verify.swift"
"$TMP/verify"
