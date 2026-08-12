import Foundation
import Network

final class DNSProxy: @unchecked Sendable {
    private var udpListener: NWListener?
    private var tcpListener: NWListener?
    private let queue = DispatchQueue(label: "io.isaaclins.freesnitch.dns", qos: .userInitiated)
    private let upstreamQueue = DispatchQueue(label: "io.isaaclins.freesnitch.dns.up")
    private(set) var port: UInt16 = 53
    private(set) var running = false

    var blocklist: Set<String> = []
    var rules: [Rule] = []
    var mode: AppMode = .alert
    var matcher = RuleMatcher()
    var dohURL: String = AppConstants.defaultDoHUpstream
    var onBlock: ((String, String?) -> Void)?
    var onResolve: ((String, [String]) -> Void)?
    var onAsk: ((String, @escaping (Bool) -> Void) -> Void)?

    private let stats = DNSStats()

    var statistics: (queries: Int, blocked: Int, allowed: Int) { stats.snapshot() }

    func start(port: UInt16 = 53) throws {
        if running { return }   // already listening; avoid re-binding port 53
        self.port = port
        let params = NWParameters.udp
        params.allowLocalEndpointReuse = true
        guard let p = NWEndpoint.Port(rawValue: port) else {
            throw NSError(domain: "DNSProxy", code: 1, userInfo: [NSLocalizedDescriptionKey: "bad port"])
        }
        let udp = try NWListener(using: params, on: p)
        udp.newConnectionHandler = { [weak self] conn in self?.handleUDP(conn) }
        udp.stateUpdateHandler = { [weak self] state in
            if case let .failed(err) = state {
                PSLog.error(PSLog.dns, "udp listener failed: \(err)")
                self?.running = false
            }
        }
        udp.start(queue: queue)
        self.udpListener = udp

        let tparams = NWParameters.tcp
        tparams.allowLocalEndpointReuse = true
        let tcp = try NWListener(using: tparams, on: p)
        tcp.newConnectionHandler = { [weak self] conn in self?.handleTCP(conn) }
        tcp.start(queue: queue)
        self.tcpListener = tcp

        running = true
        PSLog.info(PSLog.dns, "dns proxy listening on \(port) (udp+tcp)")
    }

    func stop() {
        udpListener?.cancel(); tcpListener?.cancel()
        udpListener = nil; tcpListener = nil
        running = false
    }

    // MARK: - UDP path
    private func handleUDP(_ conn: NWConnection) {
        conn.start(queue: queue)
        receiveUDP(conn)
    }
    private func receiveUDP(_ conn: NWConnection) {
        conn.receiveMessage { [weak self] data, _, _, _ in
            guard let self, let data = data, !data.isEmpty else {
                conn.cancel(); return
            }
            self.process(payload: data, isTCP: false) { reply in
                guard let reply else { conn.cancel(); return }
                conn.send(content: reply, completion: .contentProcessed { _ in conn.cancel() })
            }
        }
    }

    // MARK: - TCP path
    private func handleTCP(_ conn: NWConnection) {
        conn.start(queue: queue)
        readTCP(conn, accumulated: Data())
    }
    private func readTCP(_ conn: NWConnection, accumulated: Data) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65535) { [weak self] data, _, _, _ in
            guard let self else { conn.cancel(); return }
            guard let data = data, !data.isEmpty else { conn.cancel(); return }
            var buf = accumulated + data
            while buf.count >= 2 {
                let len = (Int(buf[0]) << 8) | Int(buf[1])
                if buf.count < 2 + len { break }
                let payload = buf.subdata(in: 2..<(2+len))
                buf.removeSubrange(0..<(2+len))
                self.process(payload: payload, isTCP: true) { reply in
                    guard let reply else { return }
                    var framed = Data()
                    framed.append(UInt8((reply.count >> 8) & 0xff))
                    framed.append(UInt8(reply.count & 0xff))
                    framed.append(reply)
                    conn.send(content: framed, completion: .contentProcessed { _ in })
                }
            }
            self.readTCP(conn, accumulated: buf)
        }
    }

    // MARK: - DNS processing
    private func process(payload: Data, isTCP: Bool, reply: @escaping (Data?) -> Void) {
        stats.incrQueries()
        guard let q = DNSWire.firstQuestion(payload) else {
            reply(nil); return
        }
        let domain = q.name.lowercased()
        let connStub = Connection(pid: 0, processName: "", processPath: "", remoteHost: domain, direction: .outgoing, status: .pending)
        let action = matcher.decision(for: connStub, rules: rules, defaultMode: mode)

        if action == .deny || isBlocklisted(domain) {
            stats.incrBlocked()
            onBlock?(domain, nil)
            if let resp = DNSWire.nxResponse(for: payload) { reply(resp) } else { reply(nil) }
            return
        }

        if action == .ask {
            onAsk?(domain) { allow in
                if !allow {
                    self.stats.incrBlocked()
                    self.onBlock?(domain, "ask-denied")
                    if let resp = DNSWire.nxResponse(for: payload) { reply(resp) } else { reply(nil) }
                    return
                }
                self.forwardDoH(payload: payload, domain: domain, reply: reply)
            }
            return
        }

        forwardDoH(payload: payload, domain: domain, reply: reply)
    }

    private func isBlocklisted(_ domain: String) -> Bool {
        if blocklist.contains(domain) { return true }
        var parts = domain.split(separator: ".")
        while parts.count >= 2 {
            let candidate = parts.joined(separator: ".")
            if blocklist.contains(candidate) { return true }
            parts.removeFirst()
        }
        return false
    }

    private func forwardDoH(payload: Data, domain: String, reply: @escaping (Data?) -> Void) {
        stats.incrAllowed()
        guard let url = URL(string: dohURL) else { reply(nil); return }
        var req = URLRequest(url: url, timeoutInterval: 5)
        req.httpMethod = "POST"
        req.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        req.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        req.httpBody = payload
        let task = URLSession.shared.dataTask(with: req) { data, _, _ in
            if let data = data {
                if let ips = DNSWire.extractAnswers(data) {
                    self.onResolve?(domain, ips)
                }
                reply(data)
            } else {
                reply(nil)
            }
        }
        task.resume()
    }
}

final class DNSStats: @unchecked Sendable {
    private let lock = NSLock()
    private var queries = 0
    private var blocked = 0
    private var allowed = 0
    func incrQueries() { lock.lock(); queries += 1; lock.unlock() }
    func incrBlocked() { lock.lock(); blocked += 1; lock.unlock() }
    func incrAllowed() { lock.lock(); allowed += 1; lock.unlock() }
    func snapshot() -> (queries: Int, blocked: Int, allowed: Int) {
        lock.lock(); defer { lock.unlock() }
        return (queries, blocked, allowed)
    }
}

enum DNSWire {
    struct Question { let name: String; let type: UInt16; let cls: UInt16 }

    static func firstQuestion(_ data: Data) -> Question? {
        guard data.count > 12 else { return nil }
        var pos = 12
        guard let (name, end) = readName(data, from: pos) else { return nil }
        pos = end
        guard pos + 4 <= data.count else { return nil }
        let type = UInt16(data[pos]) << 8 | UInt16(data[pos+1])
        let cls = UInt16(data[pos+2]) << 8 | UInt16(data[pos+3])
        return Question(name: name, type: type, cls: cls)
    }

    static func readName(_ data: Data, from start: Int) -> (String, Int)? {
        var labels: [String] = []
        var pos = start
        var jumped = false
        var endOfFirstName = start
        var safety = 0
        while pos < data.count {
            safety += 1
            if safety > 128 { return nil }
            let len = Int(data[pos])
            if len == 0 {
                pos += 1
                if !jumped { endOfFirstName = pos }
                return (labels.joined(separator: "."), endOfFirstName)
            }
            if (len & 0xc0) == 0xc0 {
                guard pos + 1 < data.count else { return nil }
                let offset = ((len & 0x3f) << 8) | Int(data[pos+1])
                if !jumped { endOfFirstName = pos + 2 }
                pos = offset
                jumped = true
                continue
            }
            pos += 1
            guard pos + len <= data.count else { return nil }
            let label = data.subdata(in: pos..<(pos+len))
            labels.append(String(data: label, encoding: .utf8) ?? "?")
            pos += len
        }
        return nil
    }

    static func nxResponse(for query: Data) -> Data? {
        guard query.count > 12 else { return nil }
        var resp = query
        // flags: QR=1, AA=1, RCODE=3 (NXDOMAIN), RD copied
        let rd = resp[2] & 0x01
        resp[2] = 0x80 | rd // QR=1
        resp[3] = 0x83      // RA=1, RCODE=3 NXDOMAIN
        // ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        resp[6] = 0; resp[7] = 0
        resp[8] = 0; resp[9] = 0
        resp[10] = 0; resp[11] = 0
        return resp
    }

    static func extractAnswers(_ data: Data) -> [String]? {
        guard data.count > 12 else { return nil }
        let ancount = Int(UInt16(data[6]) << 8 | UInt16(data[7]))
        guard ancount > 0 else { return [] }
        var pos = 12
        // skip question
        guard let q = firstQuestion(data) else { return nil }
        _ = q
        if let (_, end) = readName(data, from: 12) { pos = end + 4 } else { return nil }
        var out: [String] = []
        for _ in 0..<ancount {
            guard let (_, end) = readName(data, from: pos) else { break }
            pos = end
            guard pos + 10 <= data.count else { break }
            let type = UInt16(data[pos]) << 8 | UInt16(data[pos+1])
            let rdlen = Int(UInt16(data[pos+8]) << 8 | UInt16(data[pos+9]))
            pos += 10
            guard pos + rdlen <= data.count else { break }
            if type == 1 && rdlen == 4 {
                let ip = "\(data[pos]).\(data[pos+1]).\(data[pos+2]).\(data[pos+3])"
                out.append(ip)
            } else if type == 28 && rdlen == 16 {
                var parts: [String] = []
                for i in stride(from: 0, to: 16, by: 2) {
                    let v = UInt16(data[pos+i]) << 8 | UInt16(data[pos+i+1])
                    parts.append(String(format: "%x", v))
                }
                out.append(parts.joined(separator: ":"))
            }
            pos += rdlen
        }
        return out
    }
}
