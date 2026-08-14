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
    @Published private(set) var firstContactAskedToday = 0
    @Published private(set) var knownContactsAllowedToday = 0
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
    /// Credit for the offline geolocation database. DB-IP City Lite is CC BY
    /// 4.0 and requires this to be visible wherever its results are shown, so
    /// any view that draws geolocated endpoints must render it.
    let geoAttribution = IPGeoCache.attribution
    /// What the offline geolocation database currently knows. A view can use
    /// this to say "still downloading" or "unavailable" instead of drawing an
    /// empty map as though there were no traffic.
    @Published private(set) var geoStatus: IPGeoCache.Status = IPGeoCache.shared.status
    @Published var searchQuery: String = ""
    @Published var filterSnapshotStatus = SharedRuleBridge.SnapshotStatus.unavailable(
        "Network extension IPC is not connected."
    )
    @Published var authoritativeSnapshotGeneration: UInt64?
    /// The helper session the last authoritative snapshot came from. Shown
    /// beside the generation because only the pair explains an ordering
    /// rejection.
    @Published var authoritativeSnapshotEpoch: UInt64?
    @Published var filterPersistenceDegraded = false
    @Published var filterPersistenceMessage: String?
    /// What the app is doing, or wants the user to do, about an extension that
    /// refused the helper's policy. Never a request to restart the Mac.
    @Published var filterRecoveryMessage: String?
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
    /// True from the moment the helper is asked to change enforcement until it
    /// answers. The toggle is disabled for that window, so the UI never shows a
    /// state no daemon has agreed to yet (#80).
    @Published var enforcementChangePending = false
    /// Why the last enforcement change did not take. Shown next to the toggle,
    /// not just written to the log where nobody looks.
    @Published var enforcementFailure: String?
    private var suppressEnforcementSideEffect = false
    private var applyingExternalPreferences = false
    private var preferencesObserver: NSObjectProtocol?
    /// Only the newest helper getter response may update the GUI cache or
    /// publish a snapshot. This protects against out-of-order XPC replies.
    private var snapshotRequestSequence: UInt64 = 0
    /// Prepared by the helper from retained Insights history. This cache is
    /// memory-only on the alert path; an unavailable or stale classifier asks.
    private var contactClassifier = InsightsContactClassifier(snapshot: nil)
    private var contactRefreshTimer: Timer?

    /// Puts the toggle back where reality is after the helper refuses or rolls
    /// back an enforcement change, without bouncing another request off it.
    func setEnforcementFlagWithoutApplying(_ value: Bool) {
        suppressEnforcementSideEffect = true
        enforcementEnabled = value
        suppressEnforcementSideEffect = false
        AppPreferences.set(value, forKey: AppPreferences.Key.enforcement)
    }

    /// The helper carried the change out.
    func enforcementChangeSucceeded() {
        enforcementChangePending = false
        enforcementFailure = nil
    }

    /// The helper refused, or never heard the request. The toggle goes back to
    /// the state the system is really in, carrying the reason.
    func enforcementChangeFailed(revertingTo value: Bool, message: String) {
        setEnforcementFlagWithoutApplying(value)
        enforcementChangePending = false
        enforcementFailure = message
    }

    /// Enforcement as the helper reports it: the pf anchor is loaded and the
    /// DNS proxy is listening. This is what the toggle shows, so a helper that
    /// was restarted, or that stood enforcement down on its own, corrects the
    /// GUI instead of being contradicted by it. Answers that arrive while a
    /// change is in flight are stale by definition and are dropped.
    func adoptHelperEnforcement(_ status: HelperStatus?) {
        guard let status, !enforcementChangePending else { return }
        let live = status.pfctlActive && status.dnsProxyActive
        guard live != enforcementEnabled else { return }
        setEnforcementFlagWithoutApplying(live)
    }

    enum Prefs {
        static let enforcement = AppPreferences.Key.enforcement
        static let showSpeeds = AppPreferences.Key.showSpeeds
        static let alertsAllSpaces = AppPreferences.Key.alertsAllSpaces
    }

    let helper = HelperClient()
    private var processUsages: [ProcessUsage] = []

    struct PendingAlert: Identifiable {
        /// Stable for the life of the alert and shared with the helper, so the
        /// CLI can name exactly this question.
        let id: UUID
        let connection: Connection
        let reply: (Bool, Bool) -> Void

        init(id: UUID = UUID(), connection: Connection, reply: @escaping (Bool, Bool) -> Void) {
            self.id = id
            self.connection = connection
            self.reply = reply
        }
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
                self.geoStatus = IPGeoCache.shared.status
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
        refreshContactClassifier()
        if contactRefreshTimer == nil {
            let timer = Timer(timeInterval: 30, repeats: true) { [weak self] _ in
                self?.refreshContactClassifier()
            }
            RunLoop.main.add(timer, forMode: .common)
            contactRefreshTimer = timer
        }
        if enforcementEnabled { helper.setEnforcementEnabled(true) }
    }

    private func refreshContactClassifier() {
        helper.insightsContactSnapshot { [weak self] snapshot in
            guard let self else { return }
            // The classifier validates freshness and fields again. A helper
            // transport error therefore cannot turn into a silent allow.
            self.contactClassifier = InsightsContactClassifier(snapshot: snapshot)
        }
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
            self.authoritativeSnapshotEpoch = snapshot.epoch
            AppPreferences.set(snapshot.mode.rawValue, forKey: AppPreferences.Key.mode, notify: false)
            self.filterSnapshotPersistenceHandler?(snapshot)

            guard let data = try? RuleTransportBoundary.encodeSnapshot(snapshot) else {
                let status = SharedRuleBridge.SnapshotStatus.invalid("Could not encode the helper authoritative rule snapshot within the transport limits.",
                                                                     generation: snapshot.generation,
                                                                     epoch: snapshot.epoch)
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

    /// Recorded by SystemExtensionManager while it clears a rejected snapshot.
    /// A ready snapshot clears the message, so the UI never keeps warning about
    /// a state that has already recovered.
    func recordFilterRecovery(_ message: String?) {
        filterRecoveryMessage = message
        if let message { appendLog(level: "info", message: message) }
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
                // Nil city means the answer is the country centroid. The map
                // must present that as country level, not as a place.
                connection.city = geo.city
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
        // Alert mode's known-contact verdict is the settled #26 behavior:
        // allow silently, like the existing Silent Allow fallback, because a
        // retained observation is evidence that this app/destination pair is
        // known. Explicit rules have already been matched by the extension and
        // remain authoritative. If the cache is unavailable, stale, or
        // malformed, this switch falls through to the existing ask behavior.
        if mode == .alert,
           contactClassifier.decision(for: c) == .knownContact {
            knownContactsAllowedToday += 1
            reply(true, false)
            return
        }
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
        firstContactAskedToday += 1
        let alert = PendingAlert(connection: c, reply: reply)
        pendingAlerts.append(alert)
        registerPendingAlertWithHelper(alert)
    }

    /// Publishes the alert this app is already showing to the helper's bounded
    /// registry so `freesnitch alerts` can see and answer it.
    ///
    /// This is an index entry, not the flow. The extension's callback stays
    /// here, the registry entry expires before the flow's own budget, and a
    /// helper that is unreachable, too old, or full changes nothing about the
    /// alert this app is presenting.
    private func registerPendingAlertWithHelper(_ alert: PendingAlert) {
        guard let proxy = helper.remote else { return }
        guard proxy.registerPendingAlert != nil else {
            appendLog(level: "info",
                      message: "The running helper is too old to index pending alerts, so `freesnitch alerts` cannot see this one.")
            return
        }
        let now = Date()
        let descriptor = PendingAlertDescriptor(id: alert.id,
                                                connection: alert.connection,
                                                askedAt: now,
                                                expiresAt: now.addingTimeInterval(PendingAlertLimits.maxLifetime))
        guard let data = try? FreeSnitchWireCodec.encode(descriptor),
              data.count <= PendingAlertLimits.maxDescriptorBytes else {
            appendLog(level: "error", message: "A pending alert could not be encoded for the helper registry.")
            return
        }
        proxy.registerPendingAlert?(descriptor: data) { [weak self] payload, message in
            Task { @MainActor in
                self?.applyPendingAlertResolution(id: alert.id, payload: payload, message: message)
            }
        }
    }

    /// The helper reports how a registered alert finished. Only an answer from
    /// the command line, and the registry's own overflow, change anything here.
    private func applyPendingAlertResolution(id: UUID, payload: Data, message: String?) {
        if let message, !message.isEmpty {
            appendLog(level: "error", message: "The helper refused to index a connection alert: \(message)")
            return
        }
        guard let resolution = try? FreeSnitchWireCodec.decode(PendingAlertResolution.self, from: payload) else {
            appendLog(level: "error", message: "The helper returned an unreadable pending alert resolution.")
            return
        }
        switch resolution.kind {
        case .answered:
            // A remembered rule, if the answer asked for one, was already
            // stored by the helper, which owns policy.
            let allow = resolution.flowVerdict ?? PendingAlertRegistry.defaultDecision
            guard finishAlert(id: id, allow: allow, remember: false) else { return }
            appendLog(level: "info",
                      message: "A connection alert was answered from the command line: \(allow ? "allow" : "deny").")
        case .overflow:
            // The registry is full. Do not queue a question nobody can answer:
            // resume with the same fail-open default this view model already
            // uses when its own alert queue overflows.
            finishAlert(id: id, allow: PendingAlertRegistry.defaultDecision, remember: false)
        case .withdrawn, .expired:
            // Answered here, or no longer answerable from outside. The flow
            // still resumes on the extension's own timeout.
            break
        }
    }

    private func withdrawPendingAlertFromHelper(_ id: UUID) {
        guard let proxy = helper.remote, proxy.withdrawPendingAlert != nil else { return }
        proxy.withdrawPendingAlert?(idString: id.uuidString) { [weak self] ok, message in
            guard !ok, let message, !message.isEmpty else { return }
            Task { @MainActor in
                self?.appendLog(level: "info", message: "The pending alert registry did not accept this answer: \(message)")
            }
        }
    }

    /// Answers one pending alert exactly once. A second attempt, from the
    /// window or from a command line verdict that arrives at the same moment,
    /// finds nothing and does nothing.
    @discardableResult
    private func finishAlert(id: UUID, allow: Bool, remember: Bool) -> Bool {
        guard let index = pendingAlerts.firstIndex(where: { $0.id == id }) else { return false }
        let alert = pendingAlerts.remove(at: index)
        alert.reply(allow, remember)
        return true
    }

    func firstContactContext(for connection: Connection) -> String? {
        guard contactClassifier.isAvailable else { return nil }
        let count = contactClassifier.knownDestinationCount(for: connection) ?? 0
        return "First time this app has contacted this destination. You have allowed it to reach \(count) other place\(count == 1 ? "" : "s") in retained history."
    }

    func resolveAlert(_ alert: PendingAlert, allow: Bool, remember: Bool) {
        guard finishAlert(id: alert.id, allow: allow, remember: remember) else { return }
        // Claim the registry entry too, so a command line answer arriving after
        // this one is told the app already answered instead of appearing to
        // decide a flow that is already decided.
        withdrawPendingAlertFromHelper(alert.id)
        // A rule keyed on the unspecified address matches nothing, so it would
        // never stop the next prompt. Answer the flow, remember nothing.
        let host = alert.connection.remoteHost.isEmpty ? alert.connection.remoteIP : alert.connection.remoteHost
        let isUnspecified = host.isEmpty || host == "0.0.0.0" || host == "::"
        // The destination has to travel INTO the rule, not merely into this
        // check. A rule carrying an empty host and no address loses both
        // destination tests in the matcher, because each is an `if let`, and
        // silently becomes "this process, anywhere": an allow would grant far
        // more than the user approved. See issue #64.
        let usesAddress = alert.connection.remoteHost.isEmpty
        let ruleHost: String? = usesAddress ? nil : alert.connection.remoteHost
        let ruleIP: String? = usesAddress ? host : nil
        let hasDestination = !(ruleHost ?? ruleIP ?? "").isEmpty
        if remember && !isUnspecified && hasDestination {
            let rule = Rule(
                processBundleId: alert.connection.processBundleId,
                processPath: alert.connection.processPath,
                processName: alert.connection.processName,
                remoteHost: ruleHost,
                remoteIP: ruleIP,
                remotePort: alert.connection.remotePort,
                direction: alert.connection.direction,
                action: allow ? .allow : .deny,
                scope: usesAddress ? .ip : .domain,
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
        // Helper process usage is the better number when it exists: it is the
        // process total, not the sum of the connections we happen to be
        // holding. But it is not always there, and summing nothing produced a
        // Top Processes list reading 0 B for every row while Top Domains right
        // below it showed gigabytes from the same connections (#66). So both
        // are tracked and the connection sum is used only as the fallback.
        struct ProcAggregate {
            var usageIn: Int64 = 0
            var usageOut: Int64 = 0
            var connectionIn: Int64 = 0
            var connectionOut: Int64 = 0
            var hasUsage = false
            var name = ""
            var icon: NSImage?
        }
        var byProc: [String: ProcAggregate] = [:]
        var byDom: [String: (Int64, Int64)] = [:]
        var byCountry: [String: (String, Int64, Int64)] = [:]
        for c in conns {
            let pkey = c.processBundleId ?? c.processPath
            var entry = byProc[pkey] ?? ProcAggregate()
            entry.connectionIn += c.bytesIn
            entry.connectionOut += c.bytesOut
            if entry.name.isEmpty { entry.name = c.processName }
            if entry.icon == nil {
                entry.icon = AppIcon.resolve(bundleId: c.processBundleId, path: c.processPath, name: c.processName)
            }
            byProc[pkey] = entry
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
            var entry = byProc[pkey] ?? ProcAggregate()
            entry.usageIn += usage.bytesIn
            entry.usageOut += usage.bytesOut
            entry.hasUsage = true
            if entry.name.isEmpty { entry.name = connection.processName }
            if entry.icon == nil {
                entry.icon = AppIcon.resolve(bundleId: connection.processBundleId,
                                             path: connection.processPath,
                                             name: connection.processName)
            }
            byProc[pkey] = entry
        }
        topProcesses = byProc.map { (k, v) in
            // The key is a bundle id when we have one, and a bundle id is not a
            // name: `lastPathComponent` left rows reading "com.google.Chrome".
            let displayName = v.name.isEmpty ? (k as NSString).lastPathComponent : v.name
            return ProcessStats(id: k,
                                name: displayName,
                                bytesIn: v.hasUsage ? v.usageIn : v.connectionIn,
                                bytesOut: v.hasUsage ? v.usageOut : v.connectionOut,
                                icon: v.icon)
        }.sorted { $0.total > $1.total }.prefix(20).map { $0 }
        topDomains = byDom.map { (k, v) in
            DomainStats(id: k, domain: k, bytesIn: v.0, bytesOut: v.1)
        }.sorted { $0.total > $1.total }.prefix(20).map { $0 }
        topCountries = byCountry.map { (cc, v) in
            CountryStats(id: cc, country: v.0, countryCode: cc, bytesIn: v.1, bytesOut: v.2)
        }.sorted { $0.total > $1.total }.prefix(20).map { $0 }
    }

}
