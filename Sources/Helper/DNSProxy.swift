import Foundation
import Network

/// One complete, immutable DNS policy.
///
/// Mode, rules, prepared rules, blocklist and resolver are decided together
/// and published together, so a query that copies this value once can never
/// observe a mixture of two policies: new rules scanned in the old prepared
/// order, or a resolver from one transition paired with a mode from the next.
struct DNSPolicy: Sendable {
    let mode: AppMode
    let rules: [Rule]
    /// Ordering the rule set per query would repeat a filter, a copy and a
    /// sort for every name resolved. The order only changes when the rules do,
    /// so it is prepared once here and merely scanned per query. Building it
    /// inside the value is what makes one prepared set correspond to exactly
    /// one rule snapshot: there is no window in which the two disagree.
    let preparedRules: PreparedRuleSet
    /// The enabled allow rules that name a host, prepared the same way. A
    /// lookup one of them covers passes the blocklist (#217).
    let blocklistOverrides: PreparedRuleSet
    /// The enabled rules that name a host and no app, in their usual order.
    /// They decide what a CNAME target in an answer means (#283).
    let hostRules: PreparedRuleSet
    let blocklist: Set<String>
    let dohURL: String

    init(mode: AppMode = .alert,
         rules: [Rule] = [],
         blocklist: Set<String> = [],
         dohURL: String = AppConstants.defaultDoHUpstream) {
        self.mode = mode
        self.rules = rules
        self.preparedRules = PreparedRuleSet(rules: rules)
        self.blocklistOverrides = DNSPolicy.blocklistOverrides(in: rules)
        self.hostRules = DNSPolicy.hostRules(in: rules)
        self.blocklist = blocklist
        self.dohURL = dohURL
    }

    /// Carries an already prepared order forward. Only changes that leave the
    /// rules alone may use it, so the pairing cannot be faked.
    private init(mode: AppMode,
                 rules: [Rule],
                 preparedRules: PreparedRuleSet,
                 blocklistOverrides: PreparedRuleSet,
                 hostRules: PreparedRuleSet,
                 blocklist: Set<String>,
                 dohURL: String) {
        self.mode = mode
        self.rules = rules
        self.preparedRules = preparedRules
        self.blocklistOverrides = blocklistOverrides
        self.hostRules = hostRules
        self.blocklist = blocklist
        self.dohURL = dohURL
    }

    func replacingMode(_ newMode: AppMode) -> DNSPolicy {
        DNSPolicy(mode: newMode, rules: rules, preparedRules: preparedRules,
                  blocklistOverrides: blocklistOverrides, hostRules: hostRules, blocklist: blocklist, dohURL: dohURL)
    }

    func replacingBlocklist(_ newBlocklist: Set<String>) -> DNSPolicy {
        DNSPolicy(mode: mode, rules: rules, preparedRules: preparedRules,
                  blocklistOverrides: blocklistOverrides, hostRules: hostRules, blocklist: newBlocklist, dohURL: dohURL)
    }

    func replacingDoHURL(_ newDoHURL: String) -> DNSPolicy {
        DNSPolicy(mode: mode, rules: rules, preparedRules: preparedRules,
                  blocklistOverrides: blocklistOverrides, hostRules: hostRules, blocklist: blocklist, dohURL: newDoHURL)
    }

    func replacingRules(_ newRules: [Rule]) -> DNSPolicy {
        DNSPolicy(mode: mode, rules: newRules, blocklist: blocklist, dohURL: dohURL)
    }

    func replacing(mode newMode: AppMode, rules newRules: [Rule]) -> DNSPolicy {
        DNSPolicy(mode: newMode, rules: newRules, blocklist: blocklist, dohURL: dohURL)
    }

    /// What this policy does with a lookup for `domain`: `.deny` answers
    /// NXDOMAIN, `.ask` waits for the user, `.allow` forwards it.
    ///
    /// A deny rule stands. A name on an enabled blocklist is then refused,
    /// even where the rules or Alert mode would ask, unless an enabled allow
    /// rule that names a host covering it exists. That is the rule "Allow
    /// Anyway" writes (#217): the user saying this one name is fine despite
    /// the list. It counts even when a broader allow came first and decided
    /// the lookup, since that one says nothing about the list. An allow with
    /// no host, one that names an app, or the default mode never switches a
    /// list off, so every other name on the list stays blocked.
    func verdict(forName domain: String, matcher: RuleMatcher = RuleMatcher()) -> RuleAction {
        let stub = Connection(pid: 0, processName: "", processPath: "", remoteHost: domain,
                              direction: .outgoing, status: .pending)
        let action = matcher.decision(for: stub, prepared: preparedRules, defaultMode: mode)
        if action == .deny { return .deny }
        if Self.isBlocklisted(domain, in: blocklist),
           matcher.explainedDecision(for: stub, prepared: blocklistOverrides,
                                     defaultMode: .silentDeny).matchedRuleID == nil {
            return .deny
        }
        return action
    }

    /// Whether a lookup that resolved through the CNAME `target` must be
    /// refused (#283). A tracker hidden behind an unlisted alias of the site
    /// would otherwise get its address through, so each target in an answer
    /// is judged as if it had been looked up by name: it is refused when it
    /// is on an enabled blocklist and no allow rule naming a host covers it
    /// (the rule "Allow Anyway" writes), or when a deny rule that names a
    /// host covers it first. The mode and rules with no host never refuse a
    /// target: the user allowed the name they looked up, and only a list or a
    /// rule that names the target says anything about where it points. An
    /// allow or ask rule for the target ahead of a broader deny shields it,
    /// and the lookup is not asked about a second time.
    ///
    /// Deny rules that name an app are left out on purpose, although a direct
    /// lookup of the target is refused by them today (rules naming an app by
    /// name match any process there). The answer goes to every app, and a
    /// rule for one app must not refuse it for all.
    func refusesAliasTarget(_ target: String, matcher: RuleMatcher = RuleMatcher()) -> Bool {
        let name = target.lowercased()
        let stub = Connection(pid: 0, processName: "", processPath: "", remoteHost: name,
                              direction: .outgoing, status: .pending)
        if matcher.decision(for: stub, prepared: hostRules, defaultMode: .silentAllow) == .deny {
            return true
        }
        return Self.isBlocklisted(name, in: blocklist)
            && matcher.explainedDecision(for: stub, prepared: blocklistOverrides,
                                         defaultMode: .silentDeny).matchedRuleID == nil
    }

    /// The first CNAME target in `answer` this policy refuses, if any.
    func refusedAliasTarget(in answer: Data, matcher: RuleMatcher = RuleMatcher()) -> String? {
        DNSWire.cnameTargets(answer).first { refusesAliasTarget($0, matcher: matcher) }
    }

    // A rule that names an app speaks for that app only. DNS lookups reach
    // the proxy without one, and a rule naming an app just by its name
    // matches any process, so it must not open or close a name for all.
    private static func namesHostForEveryone(_ rule: Rule) -> Bool {
        func blank(_ value: String?) -> Bool { (value ?? "").isEmpty }
        return rule.enabled && !blank(rule.remoteHost)
            && blank(rule.processName) && blank(rule.processPath) && blank(rule.processBundleId)
    }

    private static func blocklistOverrides(in rules: [Rule]) -> PreparedRuleSet {
        PreparedRuleSet(rules: rules.filter { $0.action == .allow && namesHostForEveryone($0) })
    }

    private static func hostRules(in rules: [Rule]) -> PreparedRuleSet {
        PreparedRuleSet(rules: rules.filter(namesHostForEveryone))
    }

    /// True when `domain`, or a parent domain of it, is on the blocklist.
    static func isBlocklisted(_ domain: String, in blocklist: Set<String>) -> Bool {
        if blocklist.contains(domain) { return true }
        var parts = domain.split(separator: ".")
        while parts.count >= 2 {
            let candidate = parts.joined(separator: ".")
            if blocklist.contains(candidate) { return true }
            parts.removeFirst()
        }
        return false
    }
}

final class DNSProxy: @unchecked Sendable {
    /// Held for the whole of `start()` and `stop()`. Both are called from XPC
    /// handlers that can run on different queues at once (the app and the CLI
    /// turning enforcement on together), and without one lock across the
    /// `running` check, the cancel of the old listeners and the new set, two
    /// starts could both bind and leave one set running that nothing cancels
    /// anymore. `listeners` and `storedPort` are only touched under it.
    private let lifecycleLock = NSLock()
    private var listeners: [NWListener] = []
    private let queue = DispatchQueue(label: "io.isaaclins.freesnitch.dns", qos: .userInitiated)
    private let upstreamQueue = DispatchQueue(label: "io.isaaclins.freesnitch.dns.up")
    /// Backstop timers only. Kept off `queue` so a pending ask can never wait
    /// behind DNS handling, and vice versa.
    private let askQueue = DispatchQueue(label: "io.isaaclins.freesnitch.dns.ask", qos: .utility)
    /// The ask handler owns the 60 second human budget. This slightly longer
    /// backstop only covers a handler that never calls back at all, so that no
    /// query can leave this proxy without a reply.
    private let askBackstopTimeout: TimeInterval = 65
    private var storedPort: UInt16 = 53
    var port: UInt16 {
        lifecycleLock.lock(); defer { lifecycleLock.unlock() }
        return storedPort
    }
    /// Whether the proxy is fully serving 127.0.0.1. Written from XPC queues
    /// by start and stop and from `queue` by a listener that fails, so it
    /// lives behind a lock. Each start or stop begins a new generation, and
    /// a failure only clears `running` for the generation that started the
    /// failed listener, so a late failure can't undo a newer start.
    private let stateLock = NSLock()
    private var isRunning = false
    private var generation: UInt64 = 0
    var running: Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        return isRunning
    }

    /// Every listener of the current generation that failed, with its
    /// transport and reason, so the status can say which transports are
    /// still serving (#265). Cleared by each start and stop.
    private var failures: [DNSListenerFailure] = []
    var failedListeners: [DNSListenerFailure] { listenerState.failed }
    /// `running` and the failures read together, so a status never pairs
    /// one generation's flag with another's list.
    var listenerState: (running: Bool, failed: [DNSListenerFailure]) {
        stateLock.lock(); defer { stateLock.unlock() }
        return (isRunning, failures)
    }

    /// Starts a new generation with the given running state.
    private func beginGeneration(running: Bool) -> UInt64 {
        stateLock.lock(); defer { stateLock.unlock() }
        generation &+= 1
        isRunning = running
        failures = []
        return generation
    }

    /// Records a failed listener for the generation that started it. Only a
    /// 127.0.0.1 one clears `running`; a late failure from an older start
    /// changes nothing.
    private func listenerFailed(_ failure: DNSListenerFailure, primary: Bool, generation failed: UInt64) {
        stateLock.lock(); defer { stateLock.unlock() }
        guard generation == failed else { return }
        if !failures.contains(failure) { failures.append(failure) }
        if primary { isRunning = false }
    }

    /// The whole policy lives in one value behind one lock. Writers arrive on
    /// XPC and blocklist queues, readers on the DNS queue from `NWConnection`
    /// callbacks, and neither may see a half applied transition.
    private let policyLock = NSLock()
    private var storedPolicy = DNSPolicy()

    /// One coherent copy of the entire policy. A query takes this once and
    /// answers from its own copy, so a policy change during the query cannot
    /// change the decision halfway through it.
    func policySnapshot() -> DNSPolicy {
        policyLock.lock()
        defer { policyLock.unlock() }
        return storedPolicy
    }

    /// Publishes a new policy in a single store.
    ///
    /// The transform runs under the lock so that read, modify and write cannot
    /// interleave with another writer and lose an update. It is always a pure
    /// local computation: no network call, no upstream request and no user
    /// callback ever runs here, so the DNS path cannot deadlock behind it.
    private func updatePolicy(_ transform: (DNSPolicy) -> DNSPolicy) {
        policyLock.lock()
        storedPolicy = transform(storedPolicy)
        policyLock.unlock()
    }

    var blocklist: Set<String> {
        get { policySnapshot().blocklist }
        set { updatePolicy { $0.replacingBlocklist(newValue) } }
    }
    var rules: [Rule] {
        get { policySnapshot().rules }
        set { updatePolicy { $0.replacingRules(newValue) } }
    }
    var mode: AppMode {
        get { policySnapshot().mode }
        set { updatePolicy { $0.replacingMode(newValue) } }
    }
    var dohURL: String {
        get { policySnapshot().dohURL }
        set { updatePolicy { $0.replacingDoHURL(newValue) } }
    }
    var matcher = RuleMatcher()

    /// Applies a mode and a rule set as one transition.
    ///
    /// Setting the two properties in sequence publishes an intermediate policy
    /// that pairs the new mode with the old rules, which is a state no caller
    /// ever intended. A caller that changes both must use this.
    func applyPolicy(mode newMode: AppMode, rules newRules: [Rule]) {
        updatePolicy { $0.replacing(mode: newMode, rules: newRules) }
    }
    var onBlock: ((String, String?) -> Void)?
    var onResolve: ((String, [String]) -> Void)?
    var onAsk: ((String, @escaping (Bool) -> Void) -> Void)?

    private let stats = DNSStats()

    var statistics: (queries: Int, blocked: Int, allowed: Int) { stats.snapshot() }

    /// The proxy only ever serves this Mac. It binds the loopback addresses
    /// and nothing else, so another device on the same network cannot reach
    /// it through the Mac's LAN, VPN or any other address (#205). A wildcard
    /// bind would turn the Mac into an open DoH forwarder for its network.
    static let loopbackHosts: [NWEndpoint.Host] = [.ipv4(.loopback), .ipv6(.loopback)]

    /// Parameters for one listener pinned to `host`:`port`. Shared with the
    /// loopback harness so the test binds exactly what the helper binds.
    static func listenerParameters(_ base: NWParameters, host: NWEndpoint.Host, port: NWEndpoint.Port) -> NWParameters {
        base.allowLocalEndpointReuse = true
        base.requiredLocalEndpoint = .hostPort(host: host, port: port)
        return base
    }

    /// Defence in depth behind the loopback bind: a connection whose peer is
    /// not a loopback address is closed before anything is read from it.
    static func isLoopbackPeer(_ endpoint: NWEndpoint) -> Bool {
        guard case let .hostPort(host, _) = endpoint else { return false }
        // IPv4Address.isLoopback only answers for 127.0.0.1, while the whole
        // of 127.0.0.0/8 is loopback.
        func isLoopbackV4(_ address: IPv4Address) -> Bool { address.rawValue.first == 127 }
        switch host {
        case .ipv4(let address):
            return isLoopbackV4(address)
        case .ipv6(let address):
            if address.isLoopback { return true }
            // An IPv4 loopback peer can show up as ::ffff:127.x.y.z. asIPv4
            // also unwraps IPv4-compatible ::127.x.y.z, which is not loopback.
            if address.isIPv4Mapped, let mapped = address.asIPv4 { return isLoopbackV4(mapped) }
            return false
        default:
            return false
        }
    }

    func start(port: UInt16 = 53) throws {
        lifecycleLock.lock(); defer { lifecycleLock.unlock() }
        if running { return }   // already listening; avoid re-binding port 53
        storedPort = port
        guard let p = NWEndpoint.Port(rawValue: port) else {
            throw NSError(domain: "DNSProxy", code: 1, userInfo: [NSLocalizedDescriptionKey: "bad port"])
        }
        // A failed 127.0.0.1 listener clears `running` while the other
        // listeners from the last start may still hold their ports. Cancel
        // them so this start binds cleanly instead of leaking them.
        listeners.forEach { $0.cancel() }
        listeners = []
        // Running from before the first listener starts: a bind can fail on
        // `queue` before this function returns, and that failure must stick.
        let gen = beginGeneration(running: true)
        var started: [NWListener] = []
        var hosts: [String] = []
        for host in Self.loopbackHosts {
            // 127.0.0.1 is the address users point their DNS at, ::1 is served
            // as well. A port that is taken or a missing IPv6 loopback does not
            // throw here: NWListener(using:) only rejects parameters it cannot
            // build, and a bind that fails is reported later as `.failed` to
            // the state handler (see listenerStateHandler). So these catches
            // only see malformed parameters, and they keep the same split: a
            // bad 127.0.0.1 listener stops the start, a bad ::1 one is logged.
            let primary = Self.failureStopsProxy(on: host)
            do {
                started += try startListeners(on: host, port: p, primary: primary, generation: gen)
                hosts.append("\(host)")
            } catch where !primary {
                PSLog.error(PSLog.dns, "dns proxy could not create its listeners on \(host): \(error)")
                // Neither listener on this address runs, so the status lists both.
                for proto in ["udp", "tcp"] {
                    listenerFailed(DNSListenerFailure(transport: proto, address: "\(host)", reason: "\(error)"),
                                   primary: false, generation: gen)
                }
            } catch {
                started.forEach { $0.cancel() }
                _ = beginGeneration(running: false)
                throw error
            }
        }
        self.listeners = started
        PSLog.info(PSLog.dns, "dns proxy listening on \(hosts.joined(separator: " and ")) port \(port) (udp+tcp)")
    }

    func stop() {
        lifecycleLock.lock(); defer { lifecycleLock.unlock() }
        listeners.forEach { $0.cancel() }
        listeners = []
        _ = beginGeneration(running: false)
    }

    /// One UDP and one TCP listener on `host`:`port`. Nothing is started
    /// unless both could be created, so a throw leaves nothing listening.
    private func startListeners(on host: NWEndpoint.Host, port: NWEndpoint.Port, primary: Bool, generation: UInt64) throws -> [NWListener] {
        let udp = try NWListener(using: Self.listenerParameters(.udp, host: host, port: port))
        let tcp = try NWListener(using: Self.listenerParameters(.tcp, host: host, port: port))
        let failed: (DNSListenerFailure) -> Void = { [weak self] failure in
            self?.listenerFailed(failure, primary: primary, generation: generation)
        }
        udp.newConnectionHandler = { [weak self] conn in self?.handleUDP(conn) }
        udp.stateUpdateHandler = Self.listenerStateHandler("udp", host: host, onFailure: failed)
        tcp.newConnectionHandler = { [weak self] conn in self?.handleTCP(conn) }
        tcp.stateUpdateHandler = Self.listenerStateHandler("tcp", host: host, onFailure: failed)
        udp.start(queue: queue)
        tcp.start(queue: queue)
        return [udp, tcp]
    }

    /// How a listener reacts when its bind fails after `start`. A taken port
    /// or an unusable address only shows up here, as `.failed`.
    ///
    /// Every failure is logged and handed to `onFailure` with its transport,
    /// address and reason, and the helper's status lists it (#265). A failed
    /// 127.0.0.1 listener, UDP or TCP alike, means the proxy is no longer
    /// fully serving the address users point their DNS at, so the proxy also
    /// stops reporting itself running and the next `start()` binds
    /// everything again. Nothing else is torn down: the sibling listener that
    /// still works keeps answering, so a failure never blocks a lookup that
    /// would otherwise work. A failed ::1 listener leaves the proxy running,
    /// so a Mac without IPv6 loopback keeps its IPv4 proxy.
    static func listenerStateHandler(_ proto: String, host: NWEndpoint.Host,
                                     onFailure: @escaping (DNSListenerFailure) -> Void) -> (NWListener.State) -> Void {
        return { state in
            guard case let .failed(err) = state else { return }
            PSLog.error(PSLog.dns, "\(proto) listener on \(host) failed: \(err)")
            onFailure(DNSListenerFailure(transport: proto, address: "\(host)", reason: failureReason(err)))
        }
    }

    /// "Address already in use" reads better in a status line than
    /// "POSIXErrorCode(rawValue: 48): Address already in use".
    static func failureReason(_ error: NWError) -> String {
        if case let .posix(code) = error { return String(cString: strerror(code.rawValue)) }
        return "\(error)"
    }

    /// Only a failed 127.0.0.1 listener stops the proxy reporting itself
    /// running: that is the address users point their DNS at. A Mac without
    /// IPv6 loopback keeps its IPv4 proxy.
    static func failureStopsProxy(on host: NWEndpoint.Host) -> Bool {
        host == loopbackHosts[0]
    }

    // MARK: - UDP path
    private func handleUDP(_ conn: NWConnection) {
        guard Self.isLoopbackPeer(conn.endpoint) else {
            PSLog.error(PSLog.dns, "refused a udp dns query from a non-loopback peer")
            conn.cancel(); return
        }
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
        guard Self.isLoopbackPeer(conn.endpoint) else {
            PSLog.error(PSLog.dns, "refused a tcp dns query from a non-loopback peer")
            conn.cancel(); return
        }
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
                    guard let reply, let framed = DNSWire.tcpFrame(reply, for: payload) else { return }
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
        // One snapshot decides this query from here on, including the resolver
        // it is eventually forwarded to. A policy change that lands mid query
        // applies to the next query, never to half of this one.
        let policy = policySnapshot()
        let action = policy.verdict(forName: domain, matcher: matcher)

        if action == .deny {
            stats.incrBlocked()
            onBlock?(domain, nil)
            if let resp = DNSWire.nxResponse(for: payload) { reply(resp) } else { reply(nil) }
            return
        }

        if action == .ask {
            // The query gets exactly one reply. A human answer, a timeout
            // default, and a late duplicate answer can all arrive for the same
            // ask, and only the first one is allowed to settle the query.
            var answered = false
            let answerLock = NSLock()
            let settleOnce: (Bool) -> Void = { [weak self] allow in
                answerLock.lock()
                if answered { answerLock.unlock(); return }
                answered = true
                answerLock.unlock()
                guard let self else { reply(nil); return }
                if !allow {
                    self.stats.incrBlocked()
                    self.onBlock?(domain, "ask-denied")
                    if let resp = DNSWire.nxResponse(for: payload) { reply(resp) } else { reply(nil) }
                    return
                }
                self.forwardDoH(payload: payload, domain: domain, policy: policy, reply: reply)
            }
            let isAnswered: () -> Bool = {
                answerLock.lock(); defer { answerLock.unlock() }
                return answered
            }
            guard let onAsk else {
                // No ask handler is wired up, so there is nobody to ask. Fail
                // open rather than leave the resolver hanging.
                settleOnce(true)
                return
            }
            onAsk(domain, settleOnce)
            // Only a query that is still waiting needs a backstop. Asks that
            // the handler settled on the spot park no timer, so a flood of
            // them cannot pile up 65 seconds of retained replies.
            if !isAnswered() {
                askQueue.asyncAfter(deadline: .now() + askBackstopTimeout) { settleOnce(true) }
            }
            return
        }

        forwardDoH(payload: payload, domain: domain, policy: policy, reply: reply)
    }

    private func forwardDoH(payload: Data, domain: String, policy: DNSPolicy, reply: @escaping (Data?) -> Void) {
        guard let url = URL(string: policy.dohURL) else {
            stats.incrAllowed()
            PSLog.error(PSLog.dns, "doh upstream failed: the resolver address does not parse")
            reply(DNSWire.servFailResponse(for: payload)); return
        }
        let matcher = self.matcher
        var req = URLRequest(url: url, timeoutInterval: 5)
        req.httpMethod = "POST"
        req.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        req.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        req.httpBody = payload
        // The body is collected with a ceiling of one DNS message (#249), so a
        // resolver that sends more is cut off while it streams instead of
        // being buffered in full.
        BoundedDoH.shared.send(req) { data, response, error in
            switch Self.upstreamAnswer(data: data, response: response, error: error, query: payload) {
            case .answer(let answer):
                // The name was allowed, but the answer may lead to a name
                // that is not (#283). The same policy snapshot judges it.
                if let target = policy.refusedAliasTarget(in: answer, matcher: matcher) {
                    self.stats.incrBlocked()
                    self.onBlock?(domain, "via \(target)")
                    reply(DNSWire.nxResponse(for: payload))
                    return
                }
                self.stats.incrAllowed()
                if let ips = DNSWire.extractAnswers(answer) {
                    self.onResolve?(domain, ips)
                }
                reply(answer)
            case .failed(let reason):
                // The resolver could not answer. The client gets SERVFAIL,
                // the standard "upstream failed" reply, at once instead of an
                // HTTP error page parsed as DNS or a wait for its own timeout.
                self.stats.incrAllowed()
                PSLog.error(PSLog.dns, "doh upstream failed: \(reason)")
                reply(DNSWire.servFailResponse(for: payload))
            }
        }
    }

    enum UpstreamAnswer: Equatable {
        case answer(Data)
        case failed(String)
    }

    /// What a DoH exchange gave back for `query`. Only a 2xx HTTP response
    /// whose body is a DNS reply to the same question counts as an answer
    /// (RFC 8484 section 4.2.1). Anything else, an HTTP 503 error page
    /// included, is an upstream failure and never reaches the client as DNS
    /// bytes (#210).
    static func upstreamAnswer(data: Data?, response: URLResponse?, error: Error?, query: Data) -> UpstreamAnswer {
        if let error { return .failed("\(error.localizedDescription)") }
        guard let http = response as? HTTPURLResponse else { return .failed("no HTTP response") }
        guard (200..<300).contains(http.statusCode) else { return .failed("HTTP \(http.statusCode)") }
        guard let data, !data.isEmpty else { return .failed("HTTP \(http.statusCode) with an empty body") }
        guard data.count <= DNSWire.maxMessageBytes else {
            return .failed("HTTP \(http.statusCode) body of \(data.count) bytes is larger than a DNS message can be")
        }
        guard let answer = DNSWire.validatedResponse(data, for: query) else {
            return .failed("HTTP \(http.statusCode) body of \(data.count) bytes is not a DNS reply to the query")
        }
        return .answer(answer)
    }
}

/// DoH exchanges whose response body is capped at one DNS message (#249).
///
/// `URLSession.dataTask(with:completionHandler:)` holds the whole body in
/// memory before the handler sees any of it, whatever its size. Here every
/// chunk is counted as it arrives: a response that announces or delivers more
/// than `maxBytes` is cancelled at that point and completes with an
/// `oversizedResponse` error, which the proxy answers with SERVFAIL.
final class BoundedDoH: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    static let shared = BoundedDoH(maxBytes: DNSWire.maxMessageBytes)

    struct OversizedResponse: LocalizedError {
        let maxBytes: Int
        var errorDescription: String? { "the response is larger than \(maxBytes) bytes, the most a DNS message can be" }
    }

    typealias Completion = (Data?, URLResponse?, Error?) -> Void

    private final class Exchange {
        let completion: Completion
        var body = Data()
        var response: URLResponse?
        var failure: Error?
        init(completion: @escaping Completion) { self.completion = completion }
    }

    let maxBytes: Int
    private let lock = NSLock()
    private var exchanges: [Int: Exchange] = [:]
    private lazy var session: URLSession = {
        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = 1
        queue.name = "io.isaaclins.freesnitch.dns.doh"
        return URLSession(configuration: .ephemeral, delegate: self, delegateQueue: queue)
    }()

    init(maxBytes: Int) {
        self.maxBytes = maxBytes
    }

    /// Sends `request`; `completion` runs exactly once, on the session's
    /// delegate queue, with the body collected so far, the response and the
    /// error that ended the exchange.
    func send(_ request: URLRequest, completion: @escaping Completion) {
        lock.lock()
        let task = session.dataTask(with: request)
        exchanges[task.taskIdentifier] = Exchange(completion: completion)
        lock.unlock()
        task.resume()
    }

    private func exchange(for task: URLSessionTask) -> Exchange? {
        lock.lock(); defer { lock.unlock() }
        return exchanges[task.taskIdentifier]
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask,
                    didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let exchange = exchange(for: dataTask) else { completionHandler(.cancel); return }
        exchange.response = response
        // A resolver that says up front it will send too much is refused
        // before a single body byte is read.
        if response.expectedContentLength > Int64(maxBytes) {
            exchange.failure = OversizedResponse(maxBytes: maxBytes)
            completionHandler(.cancel)
            return
        }
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard let exchange = exchange(for: dataTask), exchange.failure == nil else { return }
        // Counted before appending, so the buffer never grows past the
        // ceiling even when the length was not announced or was a lie.
        guard data.count <= maxBytes - exchange.body.count else {
            exchange.failure = OversizedResponse(maxBytes: maxBytes)
            exchange.body = Data()
            dataTask.cancel()
            return
        }
        exchange.body.append(data)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        lock.lock()
        let exchange = exchanges.removeValue(forKey: task.taskIdentifier)
        lock.unlock()
        guard let exchange else { return }
        if let failure = exchange.failure {
            exchange.completion(nil, exchange.response, failure)
        } else {
            exchange.completion(exchange.body, exchange.response ?? task.response, error)
        }
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

    /// The largest DNS message there can be: DNS over TCP carries each one
    /// behind a two byte length (RFC 1035 section 4.2.2), and a UDP payload
    /// is smaller still.
    static let maxMessageBytes = 65_535

    /// `reply` behind its two byte TCP length prefix. A reply that does not
    /// fit the prefix becomes SERVFAIL for `query` instead, so the client
    /// never gets a length that does not match the bytes after it (#249).
    static func tcpFrame(_ reply: Data, for query: Data) -> Data? {
        let message: Data
        if reply.count <= maxMessageBytes {
            message = reply
        } else if let servFail = servFailResponse(for: query), servFail.count <= maxMessageBytes {
            message = servFail
        } else {
            return nil
        }
        var framed = Data([UInt8(message.count >> 8), UInt8(message.count & 0xff)])
        framed.append(message)
        return framed
    }

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

    /// SERVFAIL for `query`: the header with QR and RA set, the client's
    /// RD bit and opcode kept, and its question echoed back so the stub can
    /// match the reply. Records after the question are dropped.
    static func servFailResponse(for query: Data) -> Data? {
        let query = Data(query)
        guard query.count >= 12 else { return nil }
        var resp = Data(query.prefix(12))
        resp[2] = 0x80 | (query[2] & 0x79)  // QR=1, opcode and RD kept, AA/TC clear
        resp[3] = 0x82                      // RA=1, RCODE=2 SERVFAIL
        resp[6] = 0; resp[7] = 0
        resp[8] = 0; resp[9] = 0
        resp[10] = 0; resp[11] = 0
        if let end = questionEnd(query) {
            resp.append(query.subdata(in: 12..<end))
            resp[4] = 0; resp[5] = 1
        } else {
            resp[4] = 0; resp[5] = 0
        }
        return resp
    }

    /// End offset of the first question in `data`, if it parses.
    private static func questionEnd(_ data: Data) -> Int? {
        guard data.count > 12, let (_, end) = readName(data, from: 12), end + 4 <= data.count else { return nil }
        return end + 4
    }

    /// `body` if it is a DNS reply to `query`: a full header with QR set,
    /// the query's opcode and, when it carries a question, the query's name
    /// (any case), type and class. The ID is set to the query's, since RFC
    /// 8484 lets a client send ID 0 and some resolvers answer with 0. Nil for
    /// anything else, such as an HTML or text error page.
    static func validatedResponse(_ body: Data, for query: Data) -> Data? {
        // Copies start at index 0, which the readers below assume.
        var resp = Data(body)
        let query = Data(query)
        guard resp.count >= 12, query.count >= 12 else { return nil }
        guard resp[2] & 0x80 != 0 else { return nil }                  // QR: a response
        guard resp[2] & 0x78 == query[2] & 0x78 else { return nil }    // same opcode
        let qdcount = Int(UInt16(resp[4]) << 8 | UInt16(resp[5]))
        if qdcount > 0 {
            guard let asked = firstQuestion(query), let got = firstQuestion(resp) else { return nil }
            guard got.name.lowercased() == asked.name.lowercased(),
                  got.type == asked.type, got.cls == asked.cls else { return nil }
        } else {
            // Only an error reply may leave the question out (FORMERR,
            // SERVFAIL, NOTIMP, REFUSED); an answer without one is not to
            // this query.
            guard resp[3] & 0x0f != 0 else { return nil }
        }
        resp[0] = query[0]
        resp[1] = query[1]
        return resp
    }

    /// Each well-formed record in the answer section, as its type and where
    /// its data sits. Stops at the first record that does not parse.
    static func answerRecords(_ data: Data) -> [(type: UInt16, start: Int, length: Int)]? {
        guard data.count > 12 else { return nil }
        let ancount = Int(UInt16(data[6]) << 8 | UInt16(data[7]))
        guard ancount > 0 else { return [] }
        var pos = 12
        // skip question
        guard firstQuestion(data) != nil else { return nil }
        if let (_, end) = readName(data, from: 12) { pos = end + 4 } else { return nil }
        var out: [(type: UInt16, start: Int, length: Int)] = []
        for _ in 0..<ancount {
            guard let (_, end) = readName(data, from: pos) else { break }
            pos = end
            guard pos + 10 <= data.count else { break }
            let type = UInt16(data[pos]) << 8 | UInt16(data[pos+1])
            let rdlen = Int(UInt16(data[pos+8]) << 8 | UInt16(data[pos+9]))
            pos += 10
            guard pos + rdlen <= data.count else { break }
            out.append((type, pos, rdlen))
            pos += rdlen
        }
        return out
    }

    /// The names the CNAME records in the answer section point to, lowercased
    /// and without a trailing dot. Empty for an answer that does not parse.
    static func cnameTargets(_ data: Data) -> [String] {
        (answerRecords(data) ?? []).compactMap { record in
            guard record.type == 5, record.length > 0,
                  let (name, end) = readName(data, from: record.start),
                  end <= record.start + record.length, !name.isEmpty else { return nil }
            return name.lowercased()
        }
    }

    static func extractAnswers(_ data: Data) -> [String]? {
        guard let records = answerRecords(data) else { return nil }
        var out: [String] = []
        for record in records {
            let type = record.type, rdlen = record.length, pos = record.start
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
        }
        return out
    }
}
