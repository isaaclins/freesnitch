import Foundation

/// Owns the pending DNS "ask" decisions that sit between the DNS proxy and the
/// connected GUI clients.
///
/// Three properties matter here, and each one is a bug this type exists to
/// prevent:
/// - every completion runs exactly once, so a late GUI answer that arrives
///   after a timeout cannot reply to the same query twice
/// - no completion and no XPC call ever runs while the lock is held
/// - the table is bounded, so a missing or wedged GUI cannot grow it forever
final class DNSAskCoordinator: @unchecked Sendable {
    /// Fail open, exactly like the network extension's no-GUI path. FreeSnitch
    /// must never turn a missing or silent decision UI into a name resolution
    /// outage, so an ask that nobody answers resolves to allow and the query is
    /// forwarded normally. Blocking is only ever the result of a rule or of a
    /// human saying no.
    static let defaultDecision = true

    /// The same budget FilterDataProvider gives its own ask path, so both
    /// interactive paths wait the same 60 seconds for a human.
    static let askTimeout: TimeInterval = 60

    /// Hard bound on outstanding asks. Past this, new asks resolve with the
    /// default immediately instead of queueing, so a GUI that never answers
    /// cannot turn every asked domain into a retained closure.
    static let capacity = 128

    enum Admission: Equatable {
        /// The table was full: the completion already ran with the default and
        /// nothing is pending.
        case resolvedImmediately
        /// First waiter for this domain; the caller should broadcast an alert.
        case startedAsk
        /// An alert for this domain is already outstanding. Do not broadcast a
        /// second one; the answer wakes every waiter.
        case joinedAsk
    }

    private struct Waiter {
        let id: UInt64
        let completion: (Bool) -> Void
    }

    private var pendingAsks: [String: [Waiter]] = [:]
    private var waiterCount = 0
    private var nextWaiterID: UInt64 = 0
    private let askLock = NSLock()
    /// Timeouts fire on their own utility queue. They must never share a queue
    /// with DNS handling, because a timeout that waits behind query processing
    /// is the same hang it is supposed to break.
    private let askTimeoutQueue = DispatchQueue(label: "io.isaaclins.freesnitch.dns-ask-timeout", qos: .utility)

    /// Number of waiters currently parked. Test seam and diagnostics.
    var outstandingWaiters: Int {
        askLock.lock()
        let count = waiterCount
        askLock.unlock()
        return count
    }

    /// Number of distinct domains currently parked.
    var outstandingDomains: Int {
        askLock.lock()
        let count = pendingAsks.count
        askLock.unlock()
        return count
    }

    /// Runs one complete ask.
    ///
    /// `sendAlert` hands the question to the connected clients and returns how
    /// many of them actually received it. It runs outside the lock, because it
    /// performs XPC. A return of zero means there is nobody who could ever
    /// answer, and the ask resolves with the default right away.
    func ask(domain: String,
             timeout: TimeInterval? = nil,
             completion: @escaping (Bool) -> Void,
             sendAlert: (_ answer: @escaping (Bool) -> Void) -> Int) {
        switch admit(domain: domain, timeout: timeout, completion: completion) {
        case .resolvedImmediately:
            // The bound was hit; the completion already ran with the default.
            return
        case .joinedAsk:
            // An alert for this domain is already outstanding. Coalesce onto it
            // instead of raising a second identical prompt.
            return
        case .startedAsk:
            break
        }
        let delivered = sendAlert { [weak self] allow in
            self?.resolve(domain: domain, allow: allow)
        }
        if delivered <= 0 {
            // Nobody received the question, so nobody can ever answer it. Fail
            // open now instead of holding the query until the application's
            // resolver gives up, the same choice the network extension makes
            // when no GUI is attached.
            PSLog.error(PSLog.dns, "No client received the DNS alert for '\(domain)'; resolving with the fail-open default.")
            resolve(domain: domain, allow: Self.defaultDecision)
        }
    }

    /// Parks a completion until someone answers, the timeout expires, or the
    /// caller resolves it. `timeout` exists so tests can use a short budget;
    /// production always uses `askTimeout`.
    func admit(domain: String, timeout: TimeInterval? = nil, completion: @escaping (Bool) -> Void) -> Admission {
        askLock.lock()
        if waiterCount >= Self.capacity {
            askLock.unlock()
            PSLog.error(PSLog.dns, "DNS ask table is at its \(Self.capacity) entry bound; resolving '\(domain)' with the fail-open default.")
            completion(Self.defaultDecision)
            return .resolvedImmediately
        }
        nextWaiterID &+= 1
        let waiterID = nextWaiterID
        let isFirstForDomain = pendingAsks[domain] == nil
        pendingAsks[domain, default: []].append(Waiter(id: waiterID, completion: completion))
        waiterCount += 1
        askLock.unlock()

        let budget = timeout ?? Self.askTimeout
        askTimeoutQueue.asyncAfter(deadline: .now() + budget) { [weak self] in
            self?.expire(domain: domain, waiterID: waiterID)
        }
        return isFirstForDomain ? .startedAsk : .joinedAsk
    }

    /// Wakes every waiter parked on this domain. Coalescing is deliberate: one
    /// alert answers every in-flight query for the same name instead of the
    /// second query silently overwriting and abandoning the first completion.
    /// A second answer for the same domain finds an empty slot and does
    /// nothing, which is what makes each completion run exactly once.
    func resolve(domain: String, allow: Bool) {
        askLock.lock()
        let waiters = pendingAsks.removeValue(forKey: domain) ?? []
        waiterCount -= waiters.count
        askLock.unlock()
        for waiter in waiters { waiter.completion(allow) }
    }

    /// Resolves one specific waiter whose budget ran out, leaving any other
    /// waiter for the same domain still waiting for the human.
    private func expire(domain: String, waiterID: UInt64) {
        askLock.lock()
        var waiters = pendingAsks[domain] ?? []
        guard let index = waiters.firstIndex(where: { $0.id == waiterID }) else {
            askLock.unlock()
            return
        }
        let waiter = waiters.remove(at: index)
        if waiters.isEmpty {
            pendingAsks.removeValue(forKey: domain)
        } else {
            pendingAsks[domain] = waiters
        }
        waiterCount -= 1
        askLock.unlock()
        PSLog.error(PSLog.dns, "DNS ask for '\(domain)' went unanswered for the ask timeout; resolving with the fail-open default.")
        waiter.completion(Self.defaultDecision)
    }
}

final class HelperService: NSObject, HelperProtocol, @unchecked Sendable {
    private let store: RuleStore
    private let insights: InsightsStore?
    private let pf = PFManager()
    /// Profiles are helper-owned: the coordinator decides which profile is
    /// active and the service is the only door into it from outside.
    private let profiles: ProfileCommandService
    private let profileCoordinator: ProfileCoordinator
    private let profileQueue = DispatchQueue(label: "io.isaaclins.freesnitch.profiles", qos: .userInitiated)
    private let dns = DNSProxy()
    private let netmon = NetMonitor()
    private let blocklists: BlocklistManager
    private let listener: NSXPCListener
    private let insightsMaintenanceQueue = DispatchQueue(label: "io.isaaclins.freesnitch.insights-maintenance", qos: .utility)
    private var insightsMaintenanceTimer: DispatchSourceTimer?
    private let insightsObservationQueue = DispatchQueue(label: "io.isaaclins.freesnitch.insights-observations", qos: .utility)
    private let insightsObservationSlots = DispatchSemaphore(value: 64)
    private let insightsDNSQueue = DispatchQueue(label: "io.isaaclins.freesnitch.insights-dns", qos: .utility)
    private let insightsDNSSlots = DispatchSemaphore(value: 256)
    /// Reads are answered off the XPC connection queue so a slow disk cannot
    /// stall the connection that also carries policy calls.
    private let insightsQueryQueue = DispatchQueue(label: "io.isaaclins.freesnitch.insights-queries", qos: .userInitiated)
    private let insightsQuerySlots = DispatchSemaphore(value: 8)
    private let insightsContactCacheLock = NSLock()
    private var insightsContactSnapshot: InsightsContactSnapshot?
    private let insightsDropLock = NSLock()
    private var insightsDropCount = 0
    private var lastInsightsDropLog = Date.distantPast
    private var clientConnections: [NSXPCConnection] = []
    private let clientLock = NSLock()
    private let asks = DNSAskCoordinator()
    /// Connection alerts the running app has registered so they can be listed
    /// and answered from outside it. The helper never owns the flow itself; it
    /// owns the bounded, expiring index of what is answerable.
    private let pendingAlerts = PendingAlertRegistry()
    /// The helper is the sole owner of policy mutation and snapshot
    /// construction. This queue is never held across XPC replies, PF work, or
    /// other network operations.
    private let policyQueue = DispatchQueue(label: "io.isaaclins.freesnitch.policy")
    private var latestProcessUsage: [ProcessUsage] = []
    private var latestTrafficSample: TrafficSample?
    private var lastPFError: String?
    private let diagnosticsLock = NSLock()
    private var mode: AppMode = .alert
    private var policyGeneration: UInt64 = 0

    init(listener: NSXPCListener) throws {
        let dbDir = "/Library/Application Support/FreeSnitch"
        try? FileManager.default.createDirectory(atPath: dbDir, withIntermediateDirectories: true)
        let dbPath = (dbDir as NSString).appendingPathComponent("freesnitch.sqlite")
        self.store = try RuleStore(path: dbPath)
        self.insights = try? InsightsStore()
        if self.insights == nil {
            PSLog.error(PSLog.helper, "Insights store failed to open; observation recording is unavailable.")
        }
        let persistedPolicy = store.policyState()
        self.mode = persistedPolicy.mode
        self.policyGeneration = persistedPolicy.generation
        self.blocklists = BlocklistManager(store: store)
        let coordinator = ProfileCoordinator(store: store)
        self.profileCoordinator = coordinator
        self.profiles = ProfileCommandService(store: store, coordinator: coordinator)
        self.listener = listener
        super.init()

        pf.onWarning = { [weak self] message in
            self?.broadcast { client in
                client.notifyLog(level: "error", message: message)
            }
        }

        dns.dohURL = Self.restoredDoHUpstream(from: store.getSetting("doh_url"))

        // One transition, so the DNS path can never observe the restored rules
        // paired with the default mode.
        dns.applyPolicy(mode: persistedPolicy.mode, rules: persistedPolicy.rules)
        dns.onBlock = { [weak self] domain, reason in
            self?.broadcast { c in
                let payload: [String: Any] = ["domain": domain, "reason": reason ?? ""]
                if let data = try? JSONSerialization.data(withJSONObject: payload) {
                    c.notifyLog(level: "block", message: "blocked: \(domain)")
                    _ = data
                }
            }
        }
        dns.onResolve = { [weak self] domain, ips in
            let observedAt = Date()
            let mappings = ips.map {
                DNSMapping(domain: domain, ip: $0, observedAt: observedAt,
                           expiresAt: observedAt.addingTimeInterval(5 * 60))
            }
            self?.enqueueDNSMappings(mappings)
            self?.broadcast { c in
                c.notifyLog(level: "resolve", message: "\(domain) -> \(ips.joined(separator: ", "))")
            }
        }
        dns.onAsk = { [weak self] domain, completion in
            guard let self else { completion(DNSAskCoordinator.defaultDecision); return }
            self.handleDNSAsk(domain: domain, completion: completion)
        }
        blocklists.onUpdate = { [weak self] _ in
            self?.dns.blocklist = self?.blocklists.domains ?? []
        }
        // Address feeds are a different kind of list from the domain lists:
        // they are enforced where addresses are actually seen, in the pf
        // anchor, not in the DNS proxy. PFManager renders them behind the
        // user's own rules and behind the explicit loopback, DHCP and resolver
        // passes, so a feed can never take this machine off the network.
        // A profile switch changes strictness and the selected rule layers. It
        // affects new flows only: nothing here touches an established
        // connection, which is the guarantee #31 required.
        profiles.onPolicyChanged = { [weak self] _ in
            self?.republishActivePolicy()
        }
        profiles.onBlocklistsChanged = { [weak self] in
            guard let self else { return }
            Task {
                await self.blocklists.refresh()
                await self.blocklists.refreshIPBlocklists()
            }
        }
        blocklists.onIPBlocklistUpdate = { [weak self] set, _ in
            guard let self else { return }
            do {
                try self.pf.setIPBlocklist(set, resolverAddresses: self.configuredResolverAddresses())
            } catch {
                PSLog.error(PSLog.pf,
                            "address feed could not be published to the pf anchor: \(error.localizedDescription)")
            }
        }
        netmon.onConnections = { [weak self] conns in
            guard let self else { return }
            for c in conns {
                try? self.store.recordConnection(c)
            }
            self.broadcast { c in
                if let data = try? FreeSnitchWireCodec.encode(conns) {
                    c.notifyConnection(connectionJSON: data)
                }
            }
        }
        netmon.onSample = { [weak self] sample in
            guard let self else { return }
            self.diagnosticsLock.lock()
            self.latestTrafficSample = sample
            self.diagnosticsLock.unlock()
            self.broadcast { c in
                if let data = try? FreeSnitchWireCodec.encode(sample) {
                    c.notifyTraffic(sampleJSON: data)
                }
            }
        }
        netmon.onProcessUsage = { [weak self] usages in
            guard let self else { return }
            self.diagnosticsLock.lock()
            self.latestProcessUsage = usages
            self.diagnosticsLock.unlock()
            self.broadcast { c in
                if let data = try? FreeSnitchWireCodec.encode(usages) {
                    c.notifyProcessUsage(usageJSON: data)
                }
            }
        }

        listener.delegate = self
    }

    func start() {
        listener.resume()
        netmon.start()
        startInsightsMaintenance()
        Task { await blocklists.refresh() }
        Task { await blocklists.refreshIPBlocklists() }
        // Only a binding the user created can ever switch the active profile.
        profileCoordinator.startWatchingNetworks()
    }

    /// Republishes the active profile's policy to the DNS proxy and tells
    /// connected clients to resynchronize, so the extension is updated through
    /// the existing authoritative-snapshot path rather than from cached state.
    private func republishActivePolicy() {
        policyQueue.sync {
            let state = store.activePolicyState()
            mode = state.mode
            policyGeneration = state.generation
            dns.applyPolicy(mode: state.mode, rules: state.rules)
        }
        broadcast { client in
            client.notifyLog(level: "info", message: AppConstants.profilePolicyChangedLogMessage)
        }
    }

    /// The resolvers that must stay reachable no matter what any feed lists.
    /// A DoH upstream is a hostname, so only literal addresses are passed on;
    /// PFManager treats an empty list as "exempt nothing extra", and the
    /// loopback and DHCP passes are unconditional in either case.
    private func configuredResolverAddresses() -> [String] {
        let upstream = dns.dohURL
        guard let host = URL(string: upstream)?.host,
              PFHostValidator.kind(for: host) != .hostname else { return [] }
        return [host]
    }

    private func startInsightsMaintenance() {
        guard insights != nil, insightsMaintenanceTimer == nil else { return }
        insightsMaintenanceQueue.async { [weak self] in
            self?.pruneInsights()
            self?.refreshInsightsContactSnapshot()
        }
        let timer = DispatchSource.makeTimerSource(queue: insightsMaintenanceQueue)
        timer.schedule(deadline: .now() + 6 * 60 * 60, repeating: 6 * 60 * 60)
        timer.setEventHandler { [weak self] in
            self?.pruneInsights()
            self?.refreshInsightsContactSnapshot()
        }
        insightsMaintenanceTimer = timer
        timer.resume()
    }

    private func pruneInsights() {
        guard let insights else { return }
        do { try insights.prune() }
        catch { PSLog.error(PSLog.helper, "Insights prune failed: \(error.localizedDescription)") }
    }

    private func enqueueDNSMappings(_ mappings: [DNSMapping]) {
        guard !mappings.isEmpty, let insights else { return }
        guard insightsDNSSlots.wait(timeout: .now()) == .success else {
            noteInsightsDrop("DNS mapping")
            return
        }
        insightsDNSQueue.async { [weak self] in
            defer { self?.insightsDNSSlots.signal() }
            do { try insights.recordDNSMappings(mappings) }
            catch { PSLog.error(PSLog.helper, "DNS mapping recording failed: \(error.localizedDescription)") }
        }
    }

    private func enqueueObservations(_ observations: [FlowObservation],
                                     reply: @escaping (Bool, String?) -> Void) {
        guard let insights else {
            reply(false, "insights store is unavailable")
            return
        }
        guard insightsObservationSlots.wait(timeout: .now()) == .success else {
            noteInsightsDrop("observation")
            reply(false, "insights recording queue is full")
            return
        }
        insightsObservationQueue.async { [weak self] in
            defer { self?.insightsObservationSlots.signal() }
            do {
                try insights.record(observations)
                self?.insightsMaintenanceQueue.async { [weak self] in self?.refreshInsightsContactSnapshot() }
            } catch {
                PSLog.error(PSLog.helper, "Insights observation recording failed: \(error.localizedDescription)")
            }
        }
        reply(true, nil)
    }

    /// Rebuilds the first-contact evidence on a utility queue. The snapshot is
    /// swapped atomically only after the store query and validation succeed.
    private func refreshInsightsContactSnapshot() {
        guard let insights else { return }
        do {
            let snapshot = try insights.contactSnapshot()
            insightsContactCacheLock.lock()
            insightsContactSnapshot = snapshot
            insightsContactCacheLock.unlock()
        } catch {
            insightsContactCacheLock.lock()
            insightsContactSnapshot = nil
            insightsContactCacheLock.unlock()
            PSLog.error(PSLog.helper, "Insights contact history unavailable: \(error.localizedDescription)")
        }
    }

    private func noteInsightsDrop(_ kind: String) {
        insightsDropLock.lock()
        insightsDropCount += 1
        let now = Date()
        let count: Int?
        if now.timeIntervalSince(lastInsightsDropLog) >= 60 {
            lastInsightsDropLog = now
            count = insightsDropCount
            insightsDropCount = 0
        } else {
            count = nil
        }
        insightsDropLock.unlock()
        if let count {
            PSLog.error(PSLog.helper, "Dropped \(count) queued \(kind) insights batches because the bounded writer queue was full.")
        }
    }

    func registerClient(_ conn: NSXPCConnection) {
        clientLock.lock(); defer { clientLock.unlock() }
        clientConnections.append(conn)
    }

    func unregisterClient(_ conn: NSXPCConnection) {
        clientLock.lock()
        clientConnections.removeAll { $0 === conn }
        clientLock.unlock()
        // A client that went away cannot answer anything it registered. Drop
        // its entries; the extension still resumes those flows on its own
        // timeout with the fail-open default.
        pendingAlerts.withdrawAll(ownerKey: ObjectIdentifier(conn))
    }

    /// Number of connected notification clients, which is what makes a
    /// connection alert possible at all.
    private var connectedClientCount: Int {
        clientLock.lock()
        let count = clientConnections.count
        clientLock.unlock()
        return count
    }

    /// Returns the number of clients the block was actually delivered to. A
    /// caller that is waiting for an answer needs to know that nobody received
    /// the question.
    @discardableResult
    private func broadcast(_ block: (HelperClientProtocol) -> Void) -> Int {
        clientLock.lock()
        let conns = clientConnections
        clientLock.unlock()
        var delivered = 0
        for conn in conns {
            if let proxy = conn.remoteObjectProxy as? HelperClientProtocol {
                block(proxy)
                delivered += 1
            }
        }
        return delivered
    }

    /// The DNS ask path. Every exit resolves the query: a human answer, the ask
    /// timeout, the capacity bound, or an immediate default when there is
    /// nobody to ask. A DNS query that reaches this function is never left
    /// without a reply.
    private func handleDNSAsk(domain: String, completion: @escaping (Bool) -> Void) {
        asks.ask(domain: domain, completion: completion) { answer in
            let ruleHost: String
            if PFHostValidator.kind(for: domain) == .hostname {
                ruleHost = domain
            } else {
                ruleHost = ""
                PSLog.error(
                    PSLog.dns,
                    "DNS query name '\(domain)' is not a connectable PF destination: \(PFHostValidator.rejectionReason(for: domain)); no remembered host will be offered."
                )
            }
            let stub = Connection(pid: 0, processName: "dns", processPath: "", remoteHost: ruleHost, status: .pending)
            // An unencodable alert is the same situation as an unreachable
            // client: zero deliveries, so the coordinator fails open.
            guard let data = try? FreeSnitchWireCodec.encode(stub) else { return 0 }
            return broadcast { c in
                c.notifyAlert(connectionJSON: data) { allow, _ in answer(allow) }
            }
        }
    }

    static func restoredDoHUpstream(from storedValue: String?) -> String {
        guard let storedValue else { return AppConstants.defaultDoHUpstream }
        guard let reason = DoHUpstreamValidator.rejectionReason(for: storedValue) else {
            return storedValue
        }
        PSLog.error(
            PSLog.helper,
            "Rejected stored DoH upstream `\(storedValue)`: \(reason). Falling back to `\(AppConstants.defaultDoHUpstream)`."
        )
        return AppConstants.defaultDoHUpstream
    }

    // MARK: - HelperProtocol
    // Report the build identity, not just the marketing version, so a caller
    // can tell a helper left over from an earlier build of the same release
    // from the one it shipped with.
    //
    // The reported value is the identity captured when this process started,
    // never the Info.plist as it reads right now. An in-place update replaces
    // the bundle under a still-running root daemon, and reading disk at call
    // time made that daemon answer with a build whose code it is not running.
    func getVersion(reply: @escaping (String) -> Void) {
        reply(Self.runningVersion)
    }

    /// The build this process is executing.
    static var runningVersion: String {
        AppBundleIdentity.running ?? AppConstants.version
    }

    /// The build sitting in the app bundle on disk right now.
    static var installedVersion: String {
        AppBundleIdentity.installed ?? AppConstants.version
    }

    /// True when this process is older than the bundle it was launched from,
    /// which means helper-side fixes in the installed build are not active.
    static var isStaleProcess: Bool {
        AppBundleIdentity.isStale(running: AppBundleIdentity.running,
                                  installed: AppBundleIdentity.installed)
    }

    /// Replaces this stale process with the installed one.
    ///
    /// The only supported restart is `launchctl kickstart -k`, run as root by
    /// the helper itself on request of the owning signed GUI. The service stays
    /// registered throughout: never bootout, never unregister, because #24
    /// showed that path can remove the helper entirely. A helper that is not
    /// stale refuses, so this cannot be used to bounce a healthy daemon.
    func restartForUpdate(reply: @escaping (Bool, String?) -> Void) {
        guard Self.isStaleProcess else {
            reply(false, "The running helper is \(Self.runningVersion) and the installed app is \(Self.installedVersion); no restart is needed.")
            return
        }
        PSLog.info(
            PSLog.helper,
            "Restarting for update: running \(Self.runningVersion), installed \(Self.installedVersion). Using launchctl kickstart -k; the service stays registered."
        )
        reply(true, nil)
        // Answer first, then restart. launchd keeps the registration and starts
        // the installed binary again because the job is KeepAlive.
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 0.5) {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            process.arguments = AppConstants.helperKickstartArguments
            do {
                try process.run()
            } catch {
                PSLog.error(
                    PSLog.helper,
                    "launchctl kickstart failed: \(error.localizedDescription). The helper stays registered; run `\(AppConstants.helperKickstartCommand)`."
                )
            }
        }
    }

    private func authoritativePolicyState() -> RuleStore.PolicyState {
        policyQueue.sync {
            let state = store.policyState()
            mode = state.mode
            policyGeneration = state.generation
            return state
        }
    }

    /// Snapshot construction is serialized with every policy mutation and
    /// reads the persisted helper state, never a GUI or CLI cache.
    private func authoritativeSnapshot() -> SharedRuleBridge.Snapshot {
        policyQueue.sync {
            // The enforced policy is the ACTIVE profile's strictness plus the
            // two rule layers, Always and that profile. Publishing the raw
            // store state instead would enforce rules the active profile does
            // not select, which is the whole point of #31.
            let state = store.activePolicyState()
            mode = state.mode
            policyGeneration = state.generation
            return SharedRuleBridge.Snapshot(mode: state.mode,
                                             rules: state.rules,
                                             generation: state.generation)
        }
    }

    /// The database commit, generation advance, and runtime policy assignment
    /// are one ordered owner. PF work happens only after this returns.
    private func mutatePolicy(_ change: (inout RuleStore.PolicyDraft) throws -> Void) throws -> SharedRuleBridge.Snapshot {
        try policyQueue.sync {
            let state = try store.mutatePolicy(change)
            mode = state.mode
            policyGeneration = state.generation
            // Mode and rules belong to the same committed generation, so they
            // are published together. Assigning them one after the other left a
            // window where a query was judged by the new mode against the old
            // rules, which is the tear #47 removed inside DNSProxy.
            dns.applyPolicy(mode: state.mode, rules: state.rules)
            return SharedRuleBridge.Snapshot(mode: state.mode,
                                             rules: state.rules,
                                             generation: state.generation)
        }
    }

    func getAuthoritativeSnapshot(reply: @escaping (Data) -> Void) {
        let snapshot = authoritativeSnapshot()
        do {
            reply(try SharedRuleBridge.encode(snapshot))
        } catch {
            // Never answer with empty data and no reason. An empty reply reads
            // to the caller as a corrupt payload, which sent users chasing a
            // version mismatch that did not exist. See #57.
            PSLog.error(PSLog.helper,
                        "authoritative snapshot could not be encoded: \(error.localizedDescription)")
            reply(Data())
        }
    }

    func getStatus(reply: @escaping (Data) -> Void) {
        diagnosticsLock.lock()
        let pfctlError = lastPFError
        diagnosticsLock.unlock()
        let policy = authoritativePolicyState()
        let s = HelperStatus(
            version: Self.runningVersion,
            running: netmon.isRunning,
            pfctlActive: pf.isLoaded,
            pfctlError: pfctlError,
            dnsProxyActive: dns.running,
            dnsProxyPort: Int(dns.port),
            activeRules: policy.rules.count,
            blockedToday: dns.statistics.blocked,
            mode: policy.mode,
            policyGeneration: policy.generation,
            installedVersion: Self.installedVersion
        )
        reply((try? FreeSnitchWireCodec.encode(s)) ?? Data())
    }

    func setMode(rawValue: String, reply: @escaping (Bool, String?) -> Void) {
        guard let m = AppMode(rawValue: rawValue) else { reply(false, "invalid mode"); return }
        do {
            _ = try mutatePolicy { draft in draft.mode = m }
            reply(true, nil)
        } catch {
            reply(false, "could not persist mode: \(error)")
        }
    }

    // The helper is the trust boundary for rules. The CLI and the GUI validate
    // for a good error message; the helper validates because a malformed
    // address must never reach the store, whatever the caller did.
    private func rejectionReason(for rule: Rule) -> String? {
        guard let reason = RuleAddressValidator.rejectionReason(forRemoteIP: rule.remoteIP) else { return nil }
        return "rule \(rule.id.uuidString) has an invalid remote IP `\(rule.remoteIP ?? "")`: \(reason). \(RuleAddressValidator.remediation)"
    }

    private func mergedRules(_ incoming: [Rule], into existing: inout [Rule]) {
        for rule in incoming {
            if let index = existing.firstIndex(where: { $0.id == rule.id }) {
                existing[index] = rule
            } else {
                existing.append(rule)
            }
        }
    }

    func reloadRules(rulesJSON: Data, reply: @escaping (Bool, String?) -> Void) {
        do {
            try RuleTransportBoundary.validateRuleBatchBytes(rulesJSON)
            let rules = try FreeSnitchWireCodec.decode([Rule].self, from: rulesJSON)
            // Validate the whole batch before the helper opens its transaction.
            try RuleTransportBoundary.validate(rules: rules)
            if let reason = rules.compactMap({ rejectionReason(for: $0) }).first {
                reply(false, reason)
                return
            }
            _ = try mutatePolicy { draft in
                var merged = draft.rules
                mergedRules(rules, into: &merged)
                try RuleTransportBoundary.validate(rules: merged)
                draft.rules = merged
            }
            do {
                try applyRulesIfEnforcing()
                clearPFError()
            } catch {
                recordPFError(error)
                reply(false, "rules saved but the firewall refused the update: \(error)")
                return
            }
            reply(true, nil)
        } catch {
            reply(false, error.localizedDescription)
        }
    }

    func replaceRules(rulesJSON: Data, reply: @escaping (Bool, String?) -> Void) {
        do {
            try RuleTransportBoundary.validateRuleBatchBytes(rulesJSON)
            let rules = try FreeSnitchWireCodec.decode([Rule].self, from: rulesJSON)
            try RuleTransportBoundary.validate(rules: rules)
            if let reason = rules.compactMap({ rejectionReason(for: $0) }).first {
                reply(false, reason)
                return
            }
            _ = try mutatePolicy { draft in draft.rules = rules }
            do {
                try applyRulesIfEnforcing()
                clearPFError()
            } catch {
                recordPFError(error)
                reply(false, "rules saved but the firewall refused the update: \(error)")
                return
            }
            reply(true, nil)
        } catch {
            reply(false, error.localizedDescription)
        }
    }

    func addRule(ruleJSON: Data, reply: @escaping (Bool, String?) -> Void) {
        do {
            try RuleTransportBoundary.validateSingleRuleBytes(ruleJSON)
            let rule = try FreeSnitchWireCodec.decode(Rule.self, from: ruleJSON)
            try RuleTransportBoundary.validate(rule: rule)
            if let reason = rejectionReason(for: rule) {
                reply(false, reason)
                return
            }
            _ = try mutatePolicy { draft in
                var updated = draft.rules
                if let index = updated.firstIndex(where: { $0.id == rule.id }) {
                    updated[index] = rule
                } else {
                    updated.append(rule)
                }
                try RuleTransportBoundary.validate(rules: updated)
                draft.rules = updated
            }
            // Saved but not enforced is a real difference; say so instead of
            // reporting plain success.
            do { try applyRulesIfEnforcing() } catch {
                recordPFError(error)
                reply(false, "rule saved but the firewall refused it: \(error)")
                return
            }
            reply(true, nil)
        } catch {
            reply(false, error.localizedDescription)
        }
    }

    func removeRule(idString: String, reply: @escaping (Bool, String?) -> Void) {
        guard let id = UUID(uuidString: idString) else { reply(false, "bad uuid"); return }
        do {
            _ = try mutatePolicy { draft in
                draft.rules.removeAll { $0.id == id }
            }
            do { try applyRulesIfEnforcing() } catch {
                recordPFError(error)
                reply(false, "rule removed but the firewall refused the update: \(error)")
                return
            }
            reply(true, nil)
        } catch {
            reply(false, "\(error)")
        }
    }

    func listRules(profile: String, reply: @escaping (Data) -> Void) {
        let rules = store.allRules(profile: profile.isEmpty ? nil : profile)
        do {
            reply(try RuleTransportBoundary.encodeRuleBatch(rules))
        } catch {
            PSLog.error(PSLog.helper,
                        "rule list could not be encoded for a caller: \(error.localizedDescription)")
            reply(Data())
        }
    }

    /// Passive monitoring only. Starting the DNS proxy (which binds port 53 and
    /// takes over name resolution) and loading the pf anchor are *enforcement*
    /// and are gated behind setEnforcementEnabled. A monitor should never
    /// silently reconfigure the user's networking.
    func startMonitoring(reply: @escaping (Bool, String?) -> Void) {
        netmon.start()
        reply(true, nil)
    }

    /// pf only has an anchor loaded while enforcement is on; pushing rules at it
    /// otherwise is both pointless and a source of phantom errors.
    private func applyRulesIfEnforcing() throws {
        guard pf.isLoaded else { return }
        do {
            try pf.applyRules(dns.rules)
            clearPFError()
        } catch {
            recordPFError(error)
            throw error
        }
    }

    func setEnforcementEnabled(_ enabled: Bool, reply: @escaping (Bool, String?) -> Void) {
        let requestedState = enabled ? "on" : "off"
        PSLog.error(PSLog.helper, "AUDIT: enforcement \(requestedState) requested")
        if enabled {
            do {
                do {
                    try pf.install()
                    clearPFError()
                } catch {
                    recordPFError(error)
                    throw error
                }
                try dns.start(port: AppConstants.dnsProxyPort)
                reply(true, nil)
            } catch {
                _ = try? pf.uninstall()
                dns.stop()
                reply(false, "\(error)")
            }
        } else {
            dns.stop()
            do {
                try pf.uninstall()
                clearPFError()
                reply(true, nil)
            } catch {
                recordPFError(error)
                reply(false, "\(error)")
            }
        }
    }

    func stopMonitoring(reply: @escaping (Bool, String?) -> Void) {
        dns.stop(); netmon.stop(); reply(true, nil)
    }

    func currentConnections(reply: @escaping (Data) -> Void) {
        let conns = store.recentConnections(limit: 500)
        reply((try? FreeSnitchWireCodec.encode(conns)) ?? Data())
    }

    func currentTrafficSample(reply: @escaping (Data) -> Void) {
        diagnosticsLock.lock()
        let sample = latestTrafficSample ?? TrafficSample(timestamp: Date(), bytesIn: 0, bytesOut: 0)
        diagnosticsLock.unlock()
        reply((try? FreeSnitchWireCodec.encode(sample)) ?? Data())
    }

    func currentProcessUsage(reply: @escaping (Data) -> Void) {
        diagnosticsLock.lock()
        let usages = latestProcessUsage
        diagnosticsLock.unlock()
        reply((try? FreeSnitchWireCodec.encode(usages)) ?? Data())
    }

    func enableBlocklist(idString: String, enabled: Bool, reply: @escaping (Bool, String?) -> Void) {
        let lists = store.allBlocklists()
        guard let target = lists.first(where: { $0.id.uuidString == idString }) else {
            reply(false, "blocklist not found"); return
        }
        var updated = target
        updated.enabled = enabled
        do { try store.updateBlocklist(updated); reply(true, nil) } catch { reply(false, "\(error)") }
        Task { await self.blocklists.refresh() }
    }

    func listBlocklists(reply: @escaping (Data) -> Void) {
        reply((try? FreeSnitchWireCodec.encode(store.allBlocklists())) ?? Data())
    }

    func refreshBlocklists(reply: @escaping (Bool, String?) -> Void) {
        Task {
            await self.blocklists.refresh()
            reply(true, nil)
        }
    }

    func getDoHUpstream(reply: @escaping (String) -> Void) {
        let effectiveURL = dns.dohURL
        reply(effectiveURL)
    }

    func setDoHUpstream(url: String, reply: @escaping (Bool, String?) -> Void) {
        if let reason = DoHUpstreamValidator.rejectionReason(for: url) {
            reply(false, "Invalid DoH upstream `\(url)`: \(reason). \(DoHUpstreamValidator.remediation)")
            return
        }
        do {
            try store.setSetting("doh_url", url)
            dns.dohURL = url
            reply(true, nil)
        } catch {
            reply(false, "Could not save DoH upstream `\(url)`: \(error.localizedDescription)")
        }
    }

    func installPF(reply: @escaping (Bool, String?) -> Void) {
        PSLog.error(PSLog.helper, "AUDIT: pf install requested")
        do {
            try pf.install()
            clearPFError()
            reply(true, nil)
        } catch {
            recordPFError(error)
            reply(false, "\(error)")
        }
    }

    func uninstallPF(reply: @escaping (Bool, String?) -> Void) {
        PSLog.error(PSLog.helper, "AUDIT: pf uninstall requested")
        do {
            try pf.uninstall()
            clearPFError()
            reply(true, nil)
        } catch {
            recordPFError(error)
            reply(false, "\(error)")
        }
    }

    func flushAll(reply: @escaping (Bool, String?) -> Void) {
        PSLog.error(PSLog.helper, "AUDIT: firewall flush requested")
        do {
            try pf.uninstall()
            clearPFError()
            reply(true, nil)
        } catch {
            recordPFError(error)
            reply(false, "\(error)")
        }
    }

    func recentBlocked(limit: Int, reply: @escaping (Data) -> Void) {
        let conns = store.recentConnections(limit: limit, status: .denied)
        reply((try? FreeSnitchWireCodec.encode(conns)) ?? Data())
    }

    func recentDenied(limit: Int, reply: @escaping (Data) -> Void) {
        let conns = store.recentConnections(limit: limit, status: .denied)
        reply((try? FreeSnitchWireCodec.encode(conns)) ?? Data())
    }

    func ingestObservationBatch(observationBatch: Data, reply: @escaping (Bool, String?) -> Void) {
        guard observationBatch.count <= InsightsLimits.maxBatchBytes else {
            reply(false, "observation batch exceeds the byte limit")
            return
        }
        do {
            let batch = try FreeSnitchWireCodec.decode(FlowObservationBatch.self, from: observationBatch)
            try batch.validate(payloadBytes: observationBatch.count)
            enqueueObservations(batch.observations, reply: reply)
        } catch {
            PSLog.error(PSLog.helper, "Insights observation batch rejected: \(error.localizedDescription)")
            reply(false, error.localizedDescription)
        }
    }

    func getInsightsContactSnapshot(reply: @escaping (Data, String?) -> Void) {
        insightsContactCacheLock.lock()
        let snapshot = insightsContactSnapshot
        insightsContactCacheLock.unlock()
        guard let snapshot else {
            reply(Data(), "insights contact history is unavailable")
            return
        }
        do {
            let data = try FreeSnitchWireCodec.encode(snapshot)
            try snapshot.validate()
            guard data.count <= InsightsLimits.maxReportBytes else {
                reply(Data(), "insights contact history is oversized")
                return
            }
            reply(data, nil)
        } catch {
            reply(Data(), "insights contact history is malformed: \(error.localizedDescription)")
        }
    }

    // MARK: - Pending connection alerts

    func registerPendingAlert(descriptor: Data, reply: @escaping (Data, String?) -> Void) {
        guard descriptor.count <= PendingAlertLimits.maxDescriptorBytes else {
            reply(Data(), "the pending alert descriptor exceeds its byte limit")
            return
        }
        // The CLI is not an alert owner. It cannot receive the extension's
        // question, so letting it register one would only invent alerts that
        // nothing can answer.
        if let connection = NSXPCConnection.current(), XPCPeerValidator.isCLI(connection) {
            reply(Data(), "only the FreeSnitch app can register a pending connection alert")
            return
        }
        let alert: PendingAlertDescriptor
        do {
            alert = try FreeSnitchWireCodec.decode(PendingAlertDescriptor.self, from: descriptor)
            try alert.validate()
        } catch {
            reply(Data(), "the pending alert descriptor was rejected: \(error.localizedDescription)")
            return
        }
        let ownerKey = NSXPCConnection.current().map(ObjectIdentifier.init)
        // One reply per XPC request, whichever exit runs first.
        let replyLock = NSLock()
        var replied = false
        let answerOnce: (PendingAlertResolution) -> Void = { resolution in
            replyLock.lock()
            guard !replied else {
                replyLock.unlock()
                return
            }
            replied = true
            replyLock.unlock()
            guard let data = try? FreeSnitchWireCodec.encode(resolution) else {
                reply(Data(), "the pending alert resolution could not be encoded")
                return
            }
            reply(data, nil)
        }
        pendingAlerts.register(alert, ownerKey: ownerKey, onResolve: answerOnce)
    }

    func withdrawPendingAlert(idString: String, reply: @escaping (Bool, String?) -> Void) {
        guard let id = UUID(uuidString: idString) else {
            reply(false, "bad uuid")
            return
        }
        switch pendingAlerts.withdraw(id: id) {
        case .answered:
            reply(true, nil)
        case .alreadyAnswered(let answerer, _):
            reply(false, "the alert was already answered by the \(answerer.rawValue)")
        case .expired:
            reply(false, "the alert had already expired")
        case .unknown:
            reply(false, "no such pending alert")
        }
    }

    func listPendingAlerts(reply: @escaping (Data, String?) -> Void) {
        let listing = PendingAlertListing(alerts: pendingAlerts.pending(),
                                          guiAttached: connectedClientCount > 0)
        do {
            let data = try FreeSnitchWireCodec.encode(listing)
            guard data.count <= PendingAlertLimits.maxListingBytes else {
                reply(Data(), "the pending alert listing exceeds its byte limit")
                return
            }
            reply(data, nil)
        } catch {
            reply(Data(), "the pending alert listing could not be encoded: \(error.localizedDescription)")
        }
    }

    func answerPendingAlert(request: Data, reply: @escaping (Data, String?) -> Void) {
        guard request.count <= PendingAlertLimits.maxRequestBytes else {
            reply(Data(), "the pending alert answer exceeds its byte limit")
            return
        }
        let decoded: PendingAlertAnswerRequest
        do {
            decoded = try FreeSnitchWireCodec.decode(PendingAlertAnswerRequest.self, from: request)
            try decoded.answer.validate()
        } catch {
            reply(Data(), error.localizedDescription)
            return
        }
        let now = Date()
        // Claim first. The claim is what makes the flow resolve exactly once,
        // so it must not wait behind rule storage.
        let outcome = pendingAlerts.answer(id: decoded.id, allow: decoded.answer.allow, by: .cli, now: now)
        let response: PendingAlertAnswerResponse
        switch outcome {
        case .answered(let alert):
            PSLog.error(PSLog.helper,
                        "AUDIT: pending alert \(alert.id.uuidString) answered \(decoded.answer.allow ? "allow" : "deny") from the command line")
            response = storeRememberedRule(for: alert, answer: decoded.answer, now: now)
        case .alreadyAnswered(let answerer, let at):
            response = PendingAlertAnswerResponse(
                id: decoded.id,
                state: .alreadyAnswered,
                answeredBy: answerer,
                resolvedAt: at,
                message: "Alert \(decoded.id.uuidString) was already answered by the \(answerer.rawValue). An alert is answered exactly once.")
        case .expired(let at):
            response = PendingAlertAnswerResponse(
                id: decoded.id,
                state: .expired,
                resolvedAt: at,
                message: "Alert \(decoded.id.uuidString) expired before it was answered. The flow resumed with the fail-open default.")
        case .unknown:
            response = PendingAlertAnswerResponse(
                id: decoded.id,
                state: .unknown,
                message: "No alert with ID \(decoded.id.uuidString) is or was pending on this helper.")
        }
        do {
            reply(try FreeSnitchWireCodec.encode(response), nil)
        } catch {
            reply(Data(), "the pending alert answer could not be encoded: \(error.localizedDescription)")
        }
    }

    /// Stores the remembered rule for an answered alert through the same
    /// validated policy path every other rule uses. The flow is already
    /// answered at this point, so a rejected rule is reported, never retried
    /// against the flow.
    private func storeRememberedRule(for alert: PendingAlertDescriptor,
                                     answer: PendingAlertAnswer,
                                     now: Date) -> PendingAlertAnswerResponse {
        let verdict = answer.allow ? "Allowed" : "Denied"
        let base = "\(verdict) \(alert.processName.isEmpty ? "an unnamed process" : alert.processName) to \(alert.destination)."
        let rule: Rule?
        do {
            rule = try PendingAlertRuleFactory.rule(for: alert, answer: answer, now: now)
        } catch {
            return PendingAlertAnswerResponse(id: alert.id,
                                              state: .answered,
                                              allow: answer.allow,
                                              answeredBy: .cli,
                                              resolvedAt: now,
                                              descriptor: alert,
                                              ruleMessage: error.localizedDescription,
                                              message: "\(base) No rule was stored: \(error.localizedDescription)")
        }
        guard let rule else {
            return PendingAlertAnswerResponse(id: alert.id,
                                              state: .answered,
                                              allow: answer.allow,
                                              answeredBy: .cli,
                                              resolvedAt: now,
                                              descriptor: alert,
                                              message: "\(base) Nothing was remembered.")
        }
        if let reason = rejectionReason(for: rule) {
            return PendingAlertAnswerResponse(id: alert.id,
                                              state: .answered,
                                              allow: answer.allow,
                                              answeredBy: .cli,
                                              resolvedAt: now,
                                              descriptor: alert,
                                              ruleMessage: reason,
                                              message: "\(base) No rule was stored: \(reason)")
        }
        do {
            try RuleTransportBoundary.validate(rule: rule)
            _ = try mutatePolicy { draft in
                var updated = draft.rules
                updated.append(rule)
                try RuleTransportBoundary.validate(rules: updated)
                draft.rules = updated
            }
        } catch {
            return PendingAlertAnswerResponse(id: alert.id,
                                              state: .answered,
                                              allow: answer.allow,
                                              answeredBy: .cli,
                                              resolvedAt: now,
                                              descriptor: alert,
                                              ruleMessage: error.localizedDescription,
                                              message: "\(base) No rule was stored: \(error.localizedDescription)")
        }
        var ruleMessage: String?
        do { try applyRulesIfEnforcing() } catch {
            recordPFError(error)
            ruleMessage = "rule saved but the firewall refused the update: \(error.localizedDescription)"
        }
        let remembered = answer.remember.kind == .forever
            ? "permanently"
            : "for \(answer.remember.describedValue)"
        let scope = (answer.scope ?? PendingAlertRuleFactory.defaultScope(for: alert)).rawValue
        return PendingAlertAnswerResponse(id: alert.id,
                                          state: .answered,
                                          allow: answer.allow,
                                          answeredBy: .cli,
                                          resolvedAt: now,
                                          descriptor: alert,
                                          ruleStored: true,
                                          ruleID: rule.id,
                                          ruleMessage: ruleMessage,
                                          message: "\(base) Remembered \(remembered) with \(scope) scope.")
    }

    func getInsightsRecordingEnabled(reply: @escaping (Bool) -> Void) {
        reply(insights?.recordingEnabled ?? false)
    }

    func setInsightsRecordingEnabled(_ enabled: Bool, reply: @escaping (Bool, String?) -> Void) {
        guard let insights else {
            reply(false, "insights store is unavailable")
            return
        }
        do {
            try insights.setRecordingEnabled(enabled)
            reply(true, nil)
        } catch {
            reply(false, error.localizedDescription)
        }
    }

    func purgeInsights(reply: @escaping (Bool, String?) -> Void) {
        guard let insights else {
            reply(false, "insights store is unavailable")
            return
        }
        do {
            try insights.purge()
            reply(true, nil)
        } catch {
            PSLog.error(PSLog.helper, "Insights purge failed: \(error.localizedDescription)")
            reply(false, error.localizedDescription)
        }
    }

    /// The request is bounded and its content validated, because it is an
    /// instruction arriving from another process. The rows going back out are
    /// bounded but never content-judged: this store's own data must not be
    /// hidden from the user because one row looks unusual (#57).
    /// Profiles are answered off the XPC connection queue, like Insights, so a
    /// profile command can never stall connection handling. The request is
    /// bounded before it is decoded.
    func handleProfileCommand(request: Data, reply: @escaping (Data, String?) -> Void) {
        guard request.count <= ProfileTransportBoundary.maximumRequestBytes else {
            reply(Data(), "profile request exceeds the request byte limit")
            return
        }
        profileQueue.async { [weak self] in
            guard let self else {
                reply(Data(), "the helper is shutting down")
                return
            }
            let (data, message) = self.profiles.handle(requestData: request)
            reply(data, message)
        }
    }

    func queryInsights(request: Data, reply: @escaping (Data, String?) -> Void) {
        guard request.count <= InsightsLimits.maxQueryRequestBytes else {
            reply(Data(), "insights query exceeds the request byte limit")
            return
        }
        guard let insights else {
            reply(Data(), "insights store is unavailable")
            return
        }
        let query: InsightsQuery
        do {
            query = try FreeSnitchWireCodec.decode(InsightsQuery.self, from: request)
            try query.validate(payloadBytes: request.count)
        } catch {
            reply(Data(), error.localizedDescription)
            return
        }
        // Never block the XPC connection queue: it also carries policy calls.
        guard insightsQuerySlots.wait(timeout: .now()) == .success else {
            reply(Data(), "too many Insights queries are already running; try again")
            return
        }
        insightsQueryQueue.async { [weak self] in
            defer { self?.insightsQuerySlots.signal() }
            do {
                let report = try insights.report(for: query)
                let data = try FreeSnitchWireCodec.encode(report)
                try report.validateBounds(payloadBytes: data.count)
                reply(data, nil)
            } catch {
                PSLog.error(PSLog.helper, "Insights query failed: \(error.localizedDescription)")
                reply(Data(), error.localizedDescription)
            }
        }
    }

    private func recordPFError(_ error: Error) {
        diagnosticsLock.lock()
        lastPFError = error.localizedDescription
        diagnosticsLock.unlock()
        PSLog.error(PSLog.helper, "PF diagnostic: \(error.localizedDescription)")
    }

    private func clearPFError() {
        diagnosticsLock.lock()
        lastPFError = nil
        diagnosticsLock.unlock()
    }
}

extension HelperService: NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        guard XPCPeerValidator.isTrustedGUI(newConnection) else {
            PSLog.error(PSLog.helper, "SECURITY: rejected XPC peer failing the FreeSnitch GUI code requirement (pid \(newConnection.processIdentifier))")
            return false
        }
        newConnection.exportedInterface = HelperBridge.remoteInterface()
        newConnection.exportedObject = self
        newConnection.remoteObjectInterface = HelperBridge.exportedInterface()
        newConnection.invalidationHandler = { [weak self, weak newConnection] in
            if let c = newConnection { self?.unregisterClient(c) }
        }
        newConnection.interruptionHandler = { [weak self, weak newConnection] in
            if let c = newConnection { self?.unregisterClient(c) }
        }
        if !XPCPeerValidator.isCLI(newConnection) {
            registerClient(newConnection)
        }
        newConnection.resume()
        return true
    }

}
