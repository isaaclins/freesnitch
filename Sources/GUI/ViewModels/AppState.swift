import Foundation
import SwiftUI
import AppKit
import Combine

@MainActor
final class AppState: ObservableObject {
    /// Honest first-launch default. The helper's persisted policy replaces this
    /// as soon as it connects; until then the UI must not imply a fresh install
    /// is blocking when it is allowing and learning.
    @Published var mode: AppMode = .silentAllow
    @Published var connections: [Connection] = []
    @Published var rules: [Rule] = []
    @Published var blocklists: [BlocklistInfo] = []
    @Published var profiles: [Profile] = []
    @Published var activeProfile: String = "default"
    @Published var trafficHistory: [TrafficSample] = []
    @Published var currentIn: Int64 = 0
    @Published var currentOut: Int64 = 0
    @Published var totalIn: Int64 = 0
    @Published var totalOut: Int64 = 0
    @Published var deniedCount: Int = 0
    @Published var unconfirmedCount: Int = 0
    @Published var incomingCount: Int = 0
    @Published var pendingAlerts: [PendingAlert] = []
    @Published var helperConnected: Bool = false
    @Published var helperInstallState: HelperInstallState = .unknown
    @Published var helperVersionState: HelperVersionState = .unknown
    @Published var helperRepairState: HelperRepairState = .idle
    @Published var helperNeedsRepair: Bool = false
    @Published var pfctlEnabled: Bool = false
    @Published var dnsProxyEnabled: Bool = false
    @Published var logs: [LogEntry] = []
    @Published var topProcesses: [ProcessStats] = []
    @Published var topDomains: [DomainStats] = []
    @Published var topCountries: [CountryStats] = []
    @Published var searchQuery: String = ""
    @Published var filterSnapshotStatus = SharedRuleBridge.SnapshotStatus.unavailable(
        "Network extension IPC is not connected."
    )
    @Published var authoritativeSnapshotGeneration: UInt64?
    @Published var filterPersistenceDegraded = false
    @Published var filterPersistenceMessage: String?
    /// Set by SystemExtensionManager so the published snapshot state can also
    /// drive the extension lifecycle status without making the view model own
    /// that lifecycle.
    var filterSnapshotStatusHandler: ((SharedRuleBridge.SnapshotStatus) -> Void)?
    /// SystemExtensionManager owns persisted provider configuration. Keeping
    /// this callback separate from live XPC lets a save failure leave the
    /// active in-memory policy untouched.
    var filterSnapshotPersistenceHandler: ((SharedRuleBridge.Snapshot) -> Void)?

    /// Menu-bar speed readout. Off by default: the status item is a plain
    /// template glyph unless the user asks for numbers.
    @Published var showSpeedsInMenuBar: Bool = AppPreferences.bool(forKey: AppPreferences.Key.showSpeeds) {
        didSet {
            guard !applyingExternalPreferences else { return }
            AppPreferences.set(showSpeedsInMenuBar, forKey: AppPreferences.Key.showSpeeds)
        }
    }
    @Published var showAlertsOnAllSpaces: Bool = AppPreferences.defaults.object(forKey: AppPreferences.Key.alertsAllSpaces) as? Bool ?? true {
        didSet {
            guard !applyingExternalPreferences else { return }
            AppPreferences.set(showAlertsOnAllSpaces, forKey: AppPreferences.Key.alertsAllSpaces)
        }
    }

    /// pf anchor + DNS proxy. Off until the user asks for it.
    @Published var enforcementEnabled: Bool = AppPreferences.bool(forKey: AppPreferences.Key.enforcement) {
        didSet {
            guard !suppressEnforcementSideEffect, !applyingExternalPreferences else { return }
            AppPreferences.set(enforcementEnabled, forKey: AppPreferences.Key.enforcement)
            helper.setEnforcementEnabled(enforcementEnabled)
        }
    }
    private var suppressEnforcementSideEffect = false
    private var applyingExternalPreferences = false
    private var preferencesObserver: NSObjectProtocol?
    /// Only the newest helper getter response may update the GUI cache or
    /// publish a snapshot. This protects against out-of-order XPC replies.
    private var snapshotRequestSequence: UInt64 = 0

    /// Puts the toggle back where reality is after the helper refuses or rolls
    /// back an enforcement change, without bouncing another request off it.
    func setEnforcementFlagWithoutApplying(_ value: Bool) {
        suppressEnforcementSideEffect = true
        enforcementEnabled = value
        suppressEnforcementSideEffect = false
        AppPreferences.set(value, forKey: AppPreferences.Key.enforcement)
    }

    enum Prefs {
        static let enforcement = AppPreferences.Key.enforcement
        static let showSpeeds = AppPreferences.Key.showSpeeds
        static let alertsAllSpaces = AppPreferences.Key.alertsAllSpaces
    }

    let helper = HelperClient()
    private var processUsages: [ProcessUsage] = []

    struct PendingAlert: Identifiable {
        let id = UUID()
        let connection: Connection
        let reply: (Bool, Bool) -> Void
    }

    struct LogEntry: Identifiable {
        let id = UUID()
        let timestamp: Date
        let level: String
        let message: String
    }

    struct ProcessStats: Identifiable {
        let id: String
        let name: String
        let bytesIn: Int64
        let bytesOut: Int64
        let icon: NSImage?
        var total: Int64 { bytesIn + bytesOut }
    }

    struct DomainStats: Identifiable {
        let id: String
        let domain: String
        let bytesIn: Int64
        let bytesOut: Int64
        var total: Int64 { bytesIn + bytesOut }
    }

    struct CountryStats: Identifiable {
        let id: String
        let country: String
        let countryCode: String
        let bytesIn: Int64
        let bytesOut: Int64
        var total: Int64 { bytesIn + bytesOut }
    }

    init() {
        helper.state = self
        preferencesObserver = DistributedNotificationCenter.default().addObserver(
            forName: Notification.Name(AppPreferences.changeNotification),
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.adoptExternalPreferences() }
        }
        IPGeoCache.shared.onReady { [weak self] in
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                self.updateConnections(self.connections)
            }
        }
    }

    private func adoptExternalPreferences() {
        applyingExternalPreferences = true
        showSpeedsInMenuBar = AppPreferences.bool(forKey: AppPreferences.Key.showSpeeds)
        showAlertsOnAllSpaces = AppPreferences.defaults.object(forKey: AppPreferences.Key.alertsAllSpaces) as? Bool ?? true
        enforcementEnabled = AppPreferences.bool(forKey: AppPreferences.Key.enforcement)
        let externalMode = AppPreferences.string(forKey: AppPreferences.Key.mode).flatMap(AppMode.init(rawValue:))
        applyingExternalPreferences = false

        // The distributed preference says that a policy change happened, not
        // what rules the GUI should send. Ask the helper for both mode and
        // rules, and never construct a replacement from this cache.
        if externalMode != nil, externalMode != mode {
            syncSharedRules()
        }
    }

    /// Runs once the helper is reachable. Monitoring only: enabling pf and the
    /// DNS proxy rewrites the machine's firewall and resolver, so that stays an
    /// explicit opt-in in Settings rather than something that happens the first
    /// time the app launches.
    func bootstrap() {
        helper.startMonitoring()
        refreshRules()
        if enforcementEnabled { helper.setEnforcementEnabled(true) }
    }

    /// Refreshes the display cache and synchronizes the extension from one
    /// helper-owned snapshot. A getter failure leaves the extension and boot
    /// persistence untouched, so stale GUI rules cannot be sent.
    func refreshRules() {
        syncSharedRules()
    }

    /// Ask the helper for its authoritative mode, rules, and generation before
    /// either live delivery or boot persistence. No caller supplies policy
    /// content to this method.
    func syncSharedRules() {
        snapshotRequestSequence &+= 1
        let request = snapshotRequestSequence
        helper.authoritativeSnapshot { [weak self] snapshot, error in
            guard let self, request == self.snapshotRequestSequence else { return }
            guard let snapshot else {
                let message = error ?? "The helper did not return an authoritative rule snapshot."
                self.publishFilterSnapshotStatus(.unavailable(message))
                self.appendLog(level: "error", message: message)
                return
            }

            self.mode = snapshot.mode
            self.rules = snapshot.rules
            self.authoritativeSnapshotGeneration = snapshot.generation
            AppPreferences.set(snapshot.mode.rawValue, forKey: AppPreferences.Key.mode, notify: false)
            self.filterSnapshotPersistenceHandler?(snapshot)

            guard let data = try? RuleTransportBoundary.encodeSnapshot(snapshot) else {
                let status = SharedRuleBridge.SnapshotStatus.invalid("Could not encode the helper authoritative rule snapshot within the transport limits.", generation: snapshot.generation)
                self.publishFilterSnapshotStatus(status)
                return
            }
            IPCConnection.shared.sendSnapshot(data) { [weak self] status in
                Task { @MainActor in
                    guard let self, request == self.snapshotRequestSequence else { return }
                    self.publishFilterSnapshotStatus(status)
                }
            }
        }
    }

    private func publishFilterSnapshotStatus(_ status: SharedRuleBridge.SnapshotStatus) {
        filterSnapshotStatus = status
        filterSnapshotStatusHandler?(status)
    }

    func recordFilterPersistenceFailure(_ message: String) {
        filterPersistenceDegraded = true
        filterPersistenceMessage = message
        appendLog(level: "error", message: message)
    }

    func clearFilterPersistenceFailure() {
        filterPersistenceDegraded = false
        filterPersistenceMessage = nil
    }

    func setMode(_ m: AppMode) {
        helper.setMode(m) { [weak self] ok, message in
            guard let self else { return }
            guard ok else {
                self.appendLog(level: "error", message: "The helper rejected the mode change: \(message ?? "unknown error")")
                return
            }
            self.syncSharedRules()
        }
    }

    /// The status response is only a reachability hint. Refreshing the
    /// persisted mode also fetches the helper's complete authoritative policy.
    func adoptPersistedMode(_ m: AppMode) {
        guard mode != m else { return }
        syncSharedRules()
    }

    func updateConnections(_ conns: [Connection]) {
        let enriched = conns.map { connection -> Connection in
            var connection = connection
            if let geo = IPGeoCache.shared.lookup(connection.remoteIP) {
                connection.country = geo.country
                connection.countryCode = geo.countryCode
                connection.latitude = geo.lat
                connection.longitude = geo.lon
            }
            return connection
        }
        connections = enriched
        deniedCount = enriched.filter { $0.status == .denied }.count
        incomingCount = enriched.filter { $0.direction == .incoming }.count
        unconfirmedCount = enriched.filter { $0.status == .pending }.count
        Task { await self.recomputeAggregates() }
    }

    func updateProcessUsages(_ usages: [ProcessUsage]) {
        processUsages = usages
        Task { await self.recomputeAggregates() }
    }

    func appendSample(_ s: TrafficSample) {
        trafficHistory.append(s)
        if trafficHistory.count > 600 { trafficHistory.removeFirst(trafficHistory.count - 600) }
        currentIn = s.bytesIn
        currentOut = s.bytesOut
        totalIn &+= s.bytesIn
        totalOut &+= s.bytesOut
    }

    /// Beyond this many queued questions the UI stops being answerable, so the
    /// overflow is allowed rather than piling up behind an unclickable window.
    private static let maxPendingAlerts = 12

    func presentAlert(for c: Connection, reply: @escaping (Bool, Bool) -> Void) {
        // One question per process and destination. Without this a single
        // chatty process floods the queue with identical prompts.
        let isDuplicate = pendingAlerts.contains {
            $0.connection.processPath == c.processPath
                && $0.connection.remoteHost == c.remoteHost
                && $0.connection.remoteIP == c.remoteIP
                && $0.connection.remotePort == c.remotePort
        }
        if isDuplicate || pendingAlerts.count >= Self.maxPendingAlerts {
            reply(true, false)
            return
        }
        pendingAlerts.append(PendingAlert(connection: c, reply: reply))
    }

    func resolveAlert(_ alert: PendingAlert, allow: Bool, remember: Bool) {
        alert.reply(allow, remember)
        pendingAlerts.removeAll { $0.id == alert.id }
        // A rule keyed on the unspecified address matches nothing, so it would
        // never stop the next prompt. Answer the flow, remember nothing.
        let host = alert.connection.remoteHost.isEmpty ? alert.connection.remoteIP : alert.connection.remoteHost
        let isUnspecified = host.isEmpty || host == "0.0.0.0" || host == "::"
        if remember && !isUnspecified {
            let rule = Rule(
                processBundleId: alert.connection.processBundleId,
                processPath: alert.connection.processPath,
                processName: alert.connection.processName,
                remoteHost: alert.connection.remoteHost,
                remotePort: alert.connection.remotePort,
                direction: alert.connection.direction,
                action: allow ? .allow : .deny,
                scope: alert.connection.remoteHost.isEmpty ? .ip : .domain,
                priority: 100,
                profile: activeProfile,
                groupName: nil,
                notes: "Created from alert"
            )
            helper.addRule(rule) { [weak self] ok, message in
                guard let self else { return }
                guard ok else {
                    self.appendLog(level: "error", message: "The helper rejected the remembered rule: \(message ?? "unknown error")")
                    return
                }
                self.refreshRules()
            }
        }
    }

    func appendLog(level: String, message: String) {
        let entry = LogEntry(timestamp: Date(), level: level, message: message)
        logs.append(entry)
        if logs.count > 1000 { logs.removeFirst(logs.count - 1000) }
    }

    func recomputeAggregates() async {
        let conns = self.connections
        let usages = self.processUsages
        var byProc: [String: (Int64, Int64, NSImage?)] = [:]
        var byDom: [String: (Int64, Int64)] = [:]
        var byCountry: [String: (String, Int64, Int64)] = [:]
        for c in conns {
            let pkey = c.processBundleId ?? c.processPath
            let cur = byProc[pkey] ?? (0, 0, nil)
            byProc[pkey] = (cur.0, cur.1, cur.2 ?? AppIcon.resolve(bundleId: c.processBundleId, path: c.processPath, name: c.processName))
            let dom = c.remoteHost.isEmpty ? c.remoteIP : c.remoteHost
            let cd = byDom[dom] ?? (0, 0)
            byDom[dom] = (cd.0 + c.bytesIn, cd.1 + c.bytesOut)
            if let cc = c.countryCode, !cc.isEmpty {
                let cur = byCountry[cc] ?? (c.country ?? cc, 0, 0)
                byCountry[cc] = (cur.0, cur.1 + c.bytesIn, cur.2 + c.bytesOut)
            }
        }
        for usage in usages {
            let connection = usage.pid.flatMap { pid in
                conns.first { $0.pid == pid }
            } ?? conns.first { $0.processName == usage.processName }
            guard let connection else { continue }
            let pkey = connection.processBundleId ?? connection.processPath
            let cur = byProc[pkey] ?? (0, 0, nil)
            byProc[pkey] = (cur.0 + usage.bytesIn,
                            cur.1 + usage.bytesOut,
                            cur.2 ?? AppIcon.resolve(bundleId: connection.processBundleId,
                                                      path: connection.processPath,
                                                      name: connection.processName))
        }
        topProcesses = byProc.map { (k, v) in
            ProcessStats(id: k, name: (k as NSString).lastPathComponent, bytesIn: v.0, bytesOut: v.1, icon: v.2)
        }.sorted { $0.total > $1.total }.prefix(20).map { $0 }
        topDomains = byDom.map { (k, v) in
            DomainStats(id: k, domain: k, bytesIn: v.0, bytesOut: v.1)
        }.sorted { $0.total > $1.total }.prefix(20).map { $0 }
        topCountries = byCountry.map { (cc, v) in
            CountryStats(id: cc, country: v.0, countryCode: cc, bytesIn: v.1, bytesOut: v.2)
        }.sorted { $0.total > $1.total }.prefix(20).map { $0 }
    }

}
