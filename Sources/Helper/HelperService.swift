import Foundation

final class HelperService: NSObject, HelperProtocol, @unchecked Sendable {
    private let store: RuleStore
    private let insights: InsightsStore?
    private let pf = PFManager()
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
    private let insightsDropLock = NSLock()
    private var insightsDropCount = 0
    private var lastInsightsDropLog = Date.distantPast
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
        self.insights = try? InsightsStore()
        if self.insights == nil {
            PSLog.error(PSLog.helper, "Insights store failed to open; observation recording is unavailable.")
        }
        self.blocklists = BlocklistManager(store: store)
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
            guard let data = try? FreeSnitchWireCodec.encode(stub) else { completion(true); return }
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
    }

    private func startInsightsMaintenance() {
        guard insights != nil, insightsMaintenanceTimer == nil else { return }
        insightsMaintenanceQueue.async { [weak self] in self?.pruneInsights() }
        let timer = DispatchSource.makeTimerSource(queue: insightsMaintenanceQueue)
        timer.schedule(deadline: .now() + 6 * 60 * 60, repeating: 6 * 60 * 60)
        timer.setEventHandler { [weak self] in self?.pruneInsights() }
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
            do { try insights.record(observations) }
            catch { PSLog.error(PSLog.helper, "Insights observation recording failed: \(error.localizedDescription)") }
        }
        reply(true, nil)
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
    func getVersion(reply: @escaping (String) -> Void) {
        reply(AppBundleIdentity.current ?? AppConstants.version)
    }

    func getStatus(reply: @escaping (Data) -> Void) {
        diagnosticsLock.lock()
        let pfctlError = lastPFError
        diagnosticsLock.unlock()
        let s = HelperStatus(
            version: AppBundleIdentity.current ?? AppConstants.version,
            running: netmon.isRunning,
            pfctlActive: pf.isLoaded,
            pfctlError: pfctlError,
            dnsProxyActive: dns.running,
            dnsProxyPort: Int(dns.port),
            activeRules: store.allRules().count,
            blockedToday: dns.statistics.blocked,
            mode: mode
        )
        reply((try? FreeSnitchWireCodec.encode(s)) ?? Data())
    }

    func setMode(rawValue: String, reply: @escaping (Bool, String?) -> Void) {
        guard let m = AppMode(rawValue: rawValue) else { reply(false, "invalid mode"); return }
        self.mode = m
        dns.mode = m
        try? store.setSetting("mode", rawValue)
        reply(true, nil)
    }

    // The helper is the trust boundary for rules. The CLI and the GUI validate
    // for a good error message; the helper validates because a malformed
    // address must never reach the store, whatever the caller did.
    private func rejectionReason(for rule: Rule) -> String? {
        guard let reason = RuleAddressValidator.rejectionReason(forRemoteIP: rule.remoteIP) else { return nil }
        return "rule \(rule.id.uuidString) has an invalid remote IP `\(rule.remoteIP ?? "")`: \(reason). \(RuleAddressValidator.remediation)"
    }

    func reloadRules(rulesJSON: Data, reply: @escaping (Bool, String?) -> Void) {
        do {
            let rules = try FreeSnitchWireCodec.decode([Rule].self, from: rulesJSON)
            // Reject the whole batch instead of storing a partial import.
            if let reason = rules.compactMap({ rejectionReason(for: $0) }).first {
                reply(false, reason)
                return
            }
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
            let rule = try FreeSnitchWireCodec.decode(Rule.self, from: ruleJSON)
            if let reason = rejectionReason(for: rule) {
                reply(false, reason)
                return
            }
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
        reply((try? FreeSnitchWireCodec.encode(rules)) ?? Data())
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
