import Foundation

final class HelperService: NSObject, HelperProtocol, BootPolicyProtocol, @unchecked Sendable {
    private let store: RuleStore
    private let pf = PFManager()
    private let dns = DNSProxy()
    private let netmon = NetMonitor()
    private let blocklists: BlocklistManager
    private let bootSnapshotStore: BootSnapshotStore
    private let listener: NSXPCListener
    private var clientConnections: [NSXPCConnection] = []
    private let clientLock = NSLock()
    private var pendingAsks: [String: (Bool) -> Void] = [:]
    private let askLock = NSLock()
    private var latestProcessUsage: [ProcessUsage] = []
    private var latestTrafficSample: TrafficSample?
    private var lastPFError: String?
    private let diagnosticsLock = NSLock()
    private var mode: AppMode = .alert

    init(listener: NSXPCListener) throws {
        let dbDir = "/Library/Application Support/FreeSnitch"
        try? FileManager.default.createDirectory(atPath: dbDir, withIntermediateDirectories: true)
        let dbPath = (dbDir as NSString).appendingPathComponent("freesnitch.sqlite")
        self.store = try RuleStore(path: dbPath)
        self.blocklists = BlocklistManager(store: store)
        self.bootSnapshotStore = BootSnapshotStore()
        self.listener = listener
        super.init()

        pf.onWarning = { [weak self] message in
            self?.broadcast { client in
                client.notifyLog(level: "error", message: message)
            }
        }

        if let modeStr = store.getSetting("mode"), let m = AppMode(rawValue: modeStr) {
            self.mode = m
        }

        dns.rules = store.allRules()
        dns.mode = mode
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
            self?.broadcast { c in
                c.notifyLog(level: "resolve", message: "\(domain) -> \(ips.joined(separator: ", "))")
            }
        }
        dns.onAsk = { [weak self] domain, completion in
            guard let self else { completion(true); return }
            self.askLock.lock()
            self.pendingAsks[domain] = completion
            self.askLock.unlock()
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
            guard let data = try? JSONEncoder().encode(stub) else { completion(true); return }
            self.broadcast { c in
                c.notifyAlert(connectionJSON: data) { allow, _ in
                    self.askLock.lock()
                    let cb = self.pendingAsks.removeValue(forKey: domain)
                    self.askLock.unlock()
                    cb?(allow)
                }
            }
        }
        blocklists.onUpdate = { [weak self] _ in
            self?.dns.blocklist = self?.blocklists.domains ?? []
        }
        netmon.onConnections = { [weak self] conns in
            guard let self else { return }
            for c in conns {
                try? self.store.recordConnection(c)
            }
            self.broadcast { c in
                if let data = try? JSONEncoder().encode(conns) {
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
                if let data = try? JSONEncoder().encode(sample) {
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
                if let data = try? JSONEncoder().encode(usages) {
                    c.notifyProcessUsage(usageJSON: data)
                }
            }
        }

        listener.delegate = self
    }

    func start() {
        listener.resume()
        netmon.start()
        Task { await blocklists.refresh() }
    }

    func registerClient(_ conn: NSXPCConnection) {
        clientLock.lock(); defer { clientLock.unlock() }
        clientConnections.append(conn)
    }

    func unregisterClient(_ conn: NSXPCConnection) {
        clientLock.lock(); defer { clientLock.unlock() }
        clientConnections.removeAll { $0 === conn }
    }

    private func broadcast(_ block: (HelperClientProtocol) -> Void) {
        clientLock.lock()
        let conns = clientConnections
        clientLock.unlock()
        for conn in conns {
            if let proxy = conn.remoteObjectProxy as? HelperClientProtocol {
                block(proxy)
            }
        }
    }

    // MARK: - HelperProtocol
    // Report the build identity, not just the marketing version, so a caller
    // can tell a helper left over from an earlier build of the same release
    // from the one it shipped with.
    func getVersion(reply: @escaping (String) -> Void) { reply(AppConstants.buildIdentity) }

    // MARK: - BootPolicyProtocol
    func loadBootSnapshot(reply: @escaping (Data) -> Void) {
        do {
            let snapshot = try bootSnapshotStore.read()
            let data = try SharedRuleBridge.encode(snapshot)
            PSLog.info(
                PSLog.helper,
                "boot policy cache loaded: mode \(snapshot.mode.rawValue), \(snapshot.rules.count) rules"
            )
            reply(data)
        } catch {
            PSLog.error(
                PSLog.helper,
                "boot policy cache unavailable: \(error.localizedDescription); the extension will fail open"
            )
            reply(Data())
        }
    }

    func storeBootSnapshot(snapshotJSON: Data, reply: @escaping (Bool, String?) -> Void) {
        do {
            let snapshot = try SharedRuleBridge.decode(snapshotJSON)
            try bootSnapshotStore.write(snapshot)
            PSLog.info(
                PSLog.helper,
                "boot policy cache stored: mode \(snapshot.mode.rawValue), \(snapshot.rules.count) rules"
            )
            reply(true, nil)
        } catch {
            let message = "boot policy cache was not stored: \(error.localizedDescription)"
            PSLog.error(PSLog.helper, message)
            reply(false, message)
        }
    }

    func getStatus(reply: @escaping (Data) -> Void) {
        diagnosticsLock.lock()
        let pfctlError = lastPFError
        diagnosticsLock.unlock()
        let s = HelperStatus(
            version: AppConstants.buildIdentity,
            running: netmon.isRunning,
            pfctlActive: pf.isLoaded,
            pfctlError: pfctlError,
            dnsProxyActive: dns.running,
            dnsProxyPort: Int(dns.port),
            activeRules: store.allRules().count,
            blockedToday: dns.statistics.blocked,
            mode: mode
        )
        reply((try? JSONEncoder().encode(s)) ?? Data())
    }

    func setMode(rawValue: String, reply: @escaping (Bool, String?) -> Void) {
        guard let m = AppMode(rawValue: rawValue) else { reply(false, "invalid mode"); return }
        self.mode = m
        dns.mode = m
        try? store.setSetting("mode", rawValue)
        reply(true, nil)
    }

    func reloadRules(rulesJSON: Data, reply: @escaping (Bool, String?) -> Void) {
        do {
            let rules = try JSONDecoder().decode([Rule].self, from: rulesJSON)
            for r in rules { try store.upsertRule(r) }
            dns.rules = store.allRules()
            do {
                try applyRulesIfEnforcing()
                clearPFError()
            } catch {
                recordPFError(error)
                throw error
            }
            reply(true, nil)
        } catch {
            reply(false, "\(error)")
        }
    }

    func addRule(ruleJSON: Data, reply: @escaping (Bool, String?) -> Void) {
        do {
            let rule = try JSONDecoder().decode(Rule.self, from: ruleJSON)
            try store.upsertRule(rule)
            dns.rules = store.allRules()
            // Saved but not enforced is a real difference; say so instead of
            // reporting plain success.
            do { try applyRulesIfEnforcing() } catch {
                recordPFError(error)
                reply(false, "rule saved but the firewall refused it: \(error)")
                return
            }
            reply(true, nil)
        } catch {
            reply(false, "\(error)")
        }
    }

    func removeRule(idString: String, reply: @escaping (Bool, String?) -> Void) {
        guard let id = UUID(uuidString: idString) else { reply(false, "bad uuid"); return }
        do {
            try store.deleteRule(id: id)
            dns.rules = store.allRules()
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
        reply((try? JSONEncoder().encode(rules)) ?? Data())
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
        reply((try? JSONEncoder().encode(conns)) ?? Data())
    }

    func currentTrafficSample(reply: @escaping (Data) -> Void) {
        diagnosticsLock.lock()
        let sample = latestTrafficSample ?? TrafficSample(timestamp: Date(), bytesIn: 0, bytesOut: 0)
        diagnosticsLock.unlock()
        reply((try? JSONEncoder().encode(sample)) ?? Data())
    }

    func currentProcessUsage(reply: @escaping (Data) -> Void) {
        diagnosticsLock.lock()
        let usages = latestProcessUsage
        diagnosticsLock.unlock()
        reply((try? JSONEncoder().encode(usages)) ?? Data())
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
        reply((try? JSONEncoder().encode(store.allBlocklists())) ?? Data())
    }

    func refreshBlocklists(reply: @escaping (Bool, String?) -> Void) {
        Task {
            await self.blocklists.refresh()
            reply(true, nil)
        }
    }

    func setDoHUpstream(url: String, reply: @escaping (Bool, String?) -> Void) {
        dns.dohURL = url
        try? store.setSetting("doh_url", url)
        reply(true, nil)
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
        reply((try? JSONEncoder().encode(conns)) ?? Data())
    }

    func recentDenied(limit: Int, reply: @escaping (Data) -> Void) {
        let conns = store.recentConnections(limit: limit, status: .denied)
        reply((try? JSONEncoder().encode(conns)) ?? Data())
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
