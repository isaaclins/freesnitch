//
//  FilterDataProvider.swift
//  FreeSnitch Network System Extension
//
//  A NEFilterDataProvider content filter (the same mechanism Little Snitch
//  uses). Every new socket flow is evaluated against the rule set restored from
//  persisted provider configuration or delivered over XPC by the GUI. Flows with no decisive rule are PAUSED
//  and the GUI is asked over XPC; the flow resumes with the user's verdict.
//
//  Requires the `com.apple.developer.networking.networkextension`
//  (content-filter-provider-systemextension) entitlement and a signed +
//  notarized build placed in /Applications to activate.
//

#if canImport(NetworkExtension)
import NetworkExtension
import Foundation
import Darwin
import Security

/// What the extension actually knows about a flow's destination.
///
/// The macOS 27.0 SDK is explicit that this can be nothing at all:
/// `NEFilterSocketFlow.remoteFlowEndpoint` "may be nil when
/// [NEFilterDataProvider handleNewFlow:] is invoked and if so will be populated
/// upon receiving network data. In such a case, filtering on the flow may still
/// be performed based on its socket type, socket family or socket protocol."
/// (macOS 27.0 SDK, NEFilterFlow.h:123-128, identical wording for
/// `remoteEndpoint` at :130-135 and for the local endpoints at :143-155.)
///
/// In practice the property is often non-nil and still carries the wildcard the
/// socket was created with, so `::` and `0.0.0.0` mean "no destination yet",
/// never "the destination is ::". Recording the wildcard as a destination made
/// a third of all flows look attributable when they were not, so a wildcard is
/// classified as unknown here, once, for the verdict, the alert, and the
/// evidence store alike.
struct FlowDestination: Equatable {
    /// Host for host rules and for the UI: the flow's hostname when it carries
    /// one, otherwise the endpoint address. Empty when nothing is usable.
    let host: String
    /// Literal address for IP and CIDR rules. Empty when none is known.
    let ip: String
    /// A `remoteHostname` that cannot be a destination, for example a
    /// reverse-DNS query name. Reported by the caller, never used.
    let rejectedHostname: String?

    /// False when neither a host rule nor an IP rule can be evaluated for the
    /// flow. Process, bundle, port, and direction rules still apply.
    var isKnown: Bool { !host.isEmpty || !ip.isEmpty }

    static let unknown = FlowDestination(host: "", ip: "", rejectedHostname: nil)

    /// Deliberately not a stored destination: used only to ask ResolverBypass
    /// about a flow with no address, because an empty address is its
    /// unconditional fail-open answer.
    static let unspecifiedLookupToken = "::"

    /// Pure, allocation-light, and the single place that decides what counts as
    /// a destination. No I/O, so it is safe on the verdict path.
    static func resolve(endpointHost: String, remoteHostname: String?) -> FlowDestination {
        let address = isUnspecifiedAddress(endpointHost) ? "" : endpointHost
        var candidate = ""
        var rejected: String?
        if let remoteHostname, !remoteHostname.isEmpty, !isUnspecifiedAddress(remoteHostname) {
            switch PFHostValidator.kind(for: remoteHostname) {
            case .hostname, .ip: candidate = remoteHostname
            case .cidr, nil: rejected = remoteHostname
            }
        }
        return FlowDestination(host: host(candidate: candidate, address: address),
                               ip: literalAddress(address, fallback: candidate),
                               rejectedHostname: rejected)
    }

    /// True for the wildcard addresses a socket carries before it has a peer:
    /// `0.0.0.0`, `::`, every spelling of them, and the IPv4-mapped wildcard
    /// `::ffff:0.0.0.0`.
    static func isUnspecifiedAddress(_ text: String) -> Bool {
        guard !text.isEmpty else { return false }
        var v4 = in_addr()
        if text.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 { return v4.s_addr == 0 }
        var v6 = in6_addr()
        guard text.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 else { return false }
        let bytes = withUnsafeBytes(of: &v6) { Array($0) }
        guard bytes.count == 16 else { return false }
        if bytes.allSatisfy({ $0 == 0 }) { return true }
        let mapped = bytes[0..<10].allSatisfy { $0 == 0 } && bytes[10] == 0xff && bytes[11] == 0xff
        return mapped && bytes[12...].allSatisfy { $0 == 0 }
    }

    /// A PTR query name is not a destination, so a rejected hostname falls back
    /// to the endpoint address instead. This keeps bad data out of alerts and
    /// remembered rules, rather than relying only on the later PF anchor check.
    private static func host(candidate: String, address: String) -> String {
        if !candidate.isEmpty { return candidate }
        guard let kind = PFHostValidator.kind(for: address) else { return "" }
        switch kind {
        case .hostname, .ip: return address
        case .cidr: return ""
        }
    }

    private static func literalAddress(_ address: String, fallback: String) -> String {
        if PFHostValidator.kind(for: address) == .ip { return address }
        if PFHostValidator.kind(for: fallback) == .ip { return fallback }
        let normalized = address.lowercased().hasSuffix(".")
            ? String(address.dropLast()).lowercased()
            : address.lowercased()
        return normalized == "localhost" ? address : ""
    }
}

/// Bounded state that connects the reports macOS sends later to the exact
/// flows whose verdict asked for one. Kept independent of NetworkExtension so
/// its one-flow-one-category invariant can be tested without a live provider.
struct LateDestinationTracker {
    enum Outcome: Equatable {
        case ignored
        case arrivedBeforeClose
        case arrivedAtClose
        case stillUnknownAtClose
    }

    private var flows: [UUID: Bool] = [:]
    private var order: [UUID] = []
    private let capacity: Int
    private(set) var total: UInt64 = 0
    private(set) var evictions: UInt64 = 0

    init(capacity: Int = 4096) {
        precondition(capacity > 0)
        self.capacity = capacity
    }

    mutating func flag(_ id: UUID) {
        guard flows[id] == nil else { return }
        flows[id] = false
        total &+= 1
        order.append(id)
        guard order.count > capacity else { return }
        let oldest = order.removeFirst()
        flows.removeValue(forKey: oldest)
        evictions &+= 1
    }

    mutating func report(_ id: UUID, destinationKnown: Bool, isClose: Bool) -> Outcome {
        guard let arrivedBeforeClose = flows[id] else { return .ignored }
        if isClose {
            flows.removeValue(forKey: id)
            if let index = order.firstIndex(of: id) { order.remove(at: index) }
            guard !arrivedBeforeClose else { return .ignored }
            return destinationKnown ? .arrivedAtClose : .stillUnknownAtClose
        }
        guard destinationKnown, !arrivedBeforeClose else { return .ignored }
        flows[id] = true
        return .arrivedBeforeClose
    }
}

final class FilterDataProvider: NEFilterDataProvider {
    private enum SnapshotOrigin: Equatable {
        case none
        case boot
        case live
    }

    private let matcher = RuleMatcher()
    private let resolverBypass = ResolverBypass()
    private let systemResolverIdentity = SystemResolverIdentity()
    private let bundleIdentifierCache = BundleIdentifierCache()
    /// Processes already told about an allow rule their unsigned bundle id
    /// could not use; bounded, cleared when full.
    private var unverifiedBundleLoggedPIDs: Set<Int32> = []
    private let unverifiedBundleLogLock: UnsafeMutablePointer<os_unfair_lock_s> = {
        let lock = UnsafeMutablePointer<os_unfair_lock_s>.allocate(capacity: 1)
        lock.initialize(to: os_unfair_lock_s())
        return lock
    }()
    private let snapshotLock = NSLock()
    private var snapshot: SharedRuleBridge.Snapshot?
    /// The evaluation order derived from `snapshot`. Ordering per flow repeated
    /// a filter, a copy, and a sort for every connection, while the order only
    /// ever changes when the snapshot does. Always assigned through
    /// `setSnapshotLocked` so a scan can never use one snapshot's rules in
    /// another snapshot's order.
    private var preparedRules = PreparedRuleSet(rules: [])
    private var snapshotOrigin: SnapshotOrigin = .none
    private var snapshotStatus = SharedRuleBridge.SnapshotStatus.unavailable(
        "Network extension has not received a rule snapshot from the GUI."
    )
    private let workQueue = DispatchQueue(label: "io.isaaclins.freesnitch.netext.work")
    /// Serial, so watermark writes land in the order the policies were
    /// accepted. Never on the verdict or XPC reply path (#213).
    private let watermarkQueue = DispatchQueue(label: "io.isaaclins.freesnitch.netext.watermark", qos: .utility)
    /// In this extension's own sandbox container (root-owned, so no user
    /// process can write it).
    private let watermarkURL: URL? = FileManager.default
        .urls(for: .applicationSupportDirectory, in: .userDomainMask).first?
        .appendingPathComponent(SharedRuleBridge.LivePolicyWatermark.fileName)
    private let observationQueue = FlowObservationQueue(capacity: 1024)
    /// Which rules decided flows since the last observation batch (#434).
    /// Trylock-only on the verdict path, like the observation queue.
    private let ruleHitTally = RuleHitTally()
    private let observationDrainQueue = DispatchQueue(label: "io.isaaclins.freesnitch.netext.observations", qos: .utility)
    private let observationSignalLock: UnsafeMutablePointer<os_unfair_lock_s>
    private var observationDrainScheduled = false
    private var observationStopped = false
    private var lastObservationDropLog = Date.distantPast
    private let askTimeout: TimeInterval = 60
    /// Accounting for flows whose destination is unknown when the verdict is
    /// required. Held at a stable address, taken with trylock only, and never
    /// held across a log call, so the verdict path can never wait on it.
    private var rejectedHostnameCount: UInt64 = 0
    private var lastRejectedHostnameLogNanos: UInt64 = 0
    private let destinationAccountingLock: UnsafeMutablePointer<os_unfair_lock_s>
    private var unknownDestinationFlows: UInt64 = 0
    private var lateDestinationAtVerdictReport: UInt64 = 0
    private var lateDestinationAtFlowClose: UInt64 = 0
    private var stillUnknownAtFlowClose: UInt64 = 0
    private var lastDestinationLogNanos: UInt64 = 0
    private let destinationLogIntervalNanos: UInt64 = 60 * 1_000_000_000
    /// The framework delivers reports for flows that were never flagged. This
    /// tracker ties reports to the flows whose verdict carried `shouldReport`,
    /// and ensures each flow enters at most one outcome category.
    private var lateDestinationTracker = LateDestinationTracker()

    override init() {
        self.observationSignalLock = .allocate(capacity: 1)
        self.observationSignalLock.initialize(to: os_unfair_lock_s())
        self.destinationAccountingLock = .allocate(capacity: 1)
        self.destinationAccountingLock.initialize(to: os_unfair_lock_s())
        // Do not emit a summary for the first unknown flow before its verdict
        // has registered the identifier with the late-destination tracker.
        // Starting the cadence now makes the first line a real one-minute
        // summary rather than the misleading sentence "0 flows had no
        // destination" triggered by the first event.
        self.lastDestinationLogNanos = DispatchTime.now().uptimeNanoseconds
        super.init()
    }

    deinit {
        observationSignalLock.deinitialize(count: 1)
        observationSignalLock.deallocate()
        destinationAccountingLock.deinitialize(count: 1)
        destinationAccountingLock.deallocate()
    }

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        IPCConnection.shared.onSnapshot = { [weak self] data in
            guard let self else {
                return .unavailable("Network extension stopped before receiving the rule snapshot.")
            }
            return self.receiveSnapshot(data)
        }
        IPCConnection.shared.snapshotStatus = { [weak self] in
            self?.readSnapshotStatus()
                ?? .unavailable("Network extension stopped before receiving the rule snapshot.")
        }

        // Read the system-owned provider configuration synchronously before
        // applying filter settings. We intentionally do not observe later
        // configuration changes: while the GUI is present, its authenticated
        // live XPC snapshot is authoritative, and a later persisted read must
        // never replace a live policy.
        PSLog.info(PSLog.netext, "FILTER START: reading persisted provider boot policy")
        loadPersistedBootSnapshot()
        startFilterAfterBootSnapshot(completionHandler: completionHandler)
    }

    private func loadPersistedBootSnapshot() {
        guard let vendorConfiguration = filterConfiguration.vendorConfiguration,
              let value = vendorConfiguration[SharedRuleBridge.bootSnapshotVendorConfigurationKey] else {
            clearBootSnapshot("persisted provider boot policy is missing; filtering will fail open")
            return
        }
        guard let data = value as? Data else {
            clearBootSnapshot("persisted provider boot policy has an invalid property-list type; filtering will fail open")
            return
        }
        loadBootSnapshot(data)
    }

    /// Sets the snapshot and the order derived from it as one step. Callers
    /// must already hold `snapshotLock`.
    private func setSnapshotLocked(_ newValue: SharedRuleBridge.Snapshot?) {
        snapshot = newValue
        preparedRules = PreparedRuleSet(rules: newValue?.rules ?? [])
    }

    private func clearBootSnapshot(_ message: String) {
        snapshotLock.lock()
        let liveSnapshotAlreadyLoaded = snapshotOrigin == .live
        if !liveSnapshotAlreadyLoaded {
            setSnapshotLocked(nil)
            snapshotOrigin = .none
            snapshotStatus = .unavailable(message)
        }
        snapshotLock.unlock()
        if liveSnapshotAlreadyLoaded {
            PSLog.info(PSLog.netext, "ignoring persisted boot policy because a trusted live GUI snapshot is already active")
        } else {
            PSLog.error(PSLog.netext, message)
        }
    }

    private func startFilterAfterBootSnapshot(completionHandler: @escaping (Error?) -> Void) {
        IPCConnection.shared.startListener()
        // Empty rule list + .filterData default => every flow reaches handleNewFlow.
        // handleNewFlow explicitly allows flows until a valid snapshot exists.
        let settings = NEFilterSettings(rules: [], defaultAction: .filterData)
        apply(settings) { error in completionHandler(error) }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_unfair_lock_lock(observationSignalLock)
        observationStopped = true
        os_unfair_lock_unlock(observationSignalLock)
        // Let a queued live-policy record land before this instance goes
        // away, so the next start compares against the policy it enforced
        // last (#213). The write is one small file.
        watermarkQueue.sync {}
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else { return .allow() }
        let (conn, version, signatureChecked) = connection(from: socketFlow)
        // The compact evidence event is still created before any verdict work:
        // FlowObservation(connection: conn)
        _ = observationQueue.enqueue(FlowObservation(connection: conn, processVersion: version))
        signalObservationDrain()
        // FreeSnitch must never hold up its own traffic. The helper shells out
        // to nettop and lsof to observe connections, and pausing those to ask
        // the user deadlocks the app that is supposed to answer the question.
        if isOwnTraffic(conn) || isLoopback(conn.remoteIP) { return .allow() }
        // Decided once, before any rule is consulted: a flow can reach this
        // point with no destination at all, and that limitation is reported
        // rather than hidden behind a wildcard address.
        let destinationKnown = !conn.remoteIP.isEmpty || !conn.remoteHost.isEmpty
        let policy = currentPolicy()
        if isDNSOrDHCP(conn, snapshotOrigin: policy.origin) { return .allow() }
        // Equivalent to `guard let snapshot = currentSnapshot() else`, but
        // the snapshot and its boot/live origin must come from one locked read.
        guard let snapshot = policy.snapshot else {
            // No GUI-delivered policy is a degraded state, not an alert-mode
            // policy. Allowing here keeps a missing GUI from becoming a network
            // outage while the published status tells the UI that filtering is
            // not ready.
            return .allow()
        }
        // The process that sent the flow, not the app it is attributed to:
        // a lookup the resolver makes on an app's behalf is attributed to
        // that app (#422). Remembered per process, so this costs a path read
        // per flow and a signature check per process.
        // A process that sent its own flow from elsewhere is settled by the
        // path read above, without another one.
        let senderToken = socketFlow.sourceProcessAuditToken ?? socketFlow.sourceAppAuditToken
        let sentByOtherProcess = senderToken != socketFlow.sourceAppAuditToken
        let sentByResolver = conn.direction == .outgoing
            && (sentByOtherProcess || conn.processPath == RuleMatcher.systemResolverPath)
            && systemResolverIdentity.isSystemResolver(processAuditToken: senderToken)
        let decision = matcher.explainedDecision(for: conn, prepared: policy.prepared, defaultMode: snapshot.mode,
                                                 sentBySystemResolver: sentByResolver)
        // Only once the flow's own code was checked: before that, a missing
        // signed id means "not known yet", and the log would wrongly say the
        // signature does not vouch for a signed app. And only when the flow was
        // not allowed anyway (by a path rule, say), since then nothing is asked.
        if let skipped = decision.skippedUnverified, signatureChecked, decision.action != .allow {
            noteUnverifiedBundleId(conn, skipped: skipped)
        }
        // Counted, never waited on: a contended tally skips this match, and
        // the counts travel with the next observation batch.
        if let ruleID = decision.matchedRuleID {
            ruleHitTally.record(ruleID)
            signalObservationDrain()
        }
        switch decision.action {
        case .allow:
            return reportingLateDestination(.allow(), for: flow, port: conn.remotePort, destinationKnown: destinationKnown)
        case .deny:
            return reportingLateDestination(.drop(), for: flow, port: conn.remotePort, destinationKnown: destinationKnown)
        case .ask:
            promptAndResume(flow: flow, conn: conn)
            return .pause()
        }
    }

    // MARK: - Late destination

    /// Asks the framework to hand a flow back later, and only for flows whose
    /// destination was unknown when the verdict was made.
    ///
    /// `shouldReport` is a flag on a verdict that has already been decided:
    /// "the data provider does not need to wait for a response from the control
    /// provider before continuing to process the flow" and "setting this flag
    /// on a verdict for a socket flow will also cause the data provider's
    /// -[NEFilterProvider handleReport:] method to be called when the flow is
    /// closed" (macOS 27.0 SDK, NEFilterProvider.h:121-130). The reply lands in
    /// `handleReport(_:)`, which returns no verdict at all, so nothing on this
    /// path can delay a flow or revise a verdict.
    ///
    /// The alternative, `filterDataVerdictWithFilterInbound:...`, would hold
    /// the flow's first bytes until this extension answered again. That is
    /// waiting for an address, so it is deliberately not used.
    private func reportingLateDestination(_ verdict: NEFilterNewFlowVerdict,
                                          for flow: NEFilterFlow,
                                          port: Int,
                                          destinationKnown: Bool) -> NEFilterNewFlowVerdict {
        guard !destinationKnown else { return verdict }
        verdict.shouldReport = true
        // Register first. The summary reads the tracker's exact cumulative
        // count, so it must never run in the gap before this identifier exists.
        rememberFlaggedFlow(flow.identifier)
        if let socketFlow = flow as? NEFilterSocketFlow {
            noteUnknownDestination(socketFlow, port: port)
        }
        return verdict
    }

    /// Records a flagged flow, evicting the oldest when full. Eviction is
    /// counted rather than silent, because a dropped identifier means a later
    /// arrival for that flow can no longer be recognised and the tally
    /// undercounts.
    private func rememberFlaggedFlow(_ id: UUID) {
        os_unfair_lock_lock(destinationAccountingLock)
        lateDestinationTracker.flag(id)
        os_unfair_lock_unlock(destinationAccountingLock)
    }

    /// Classifies one report for a flow this provider flagged. Each flow enters
    /// exactly one late-destination category: first arrival before close, first
    /// arrival at close, or still unknown at close. Duplicate reports and
    /// reports for ordinary unflagged flows change no counter.
    private func classifyFlaggedReport(_ id: UUID, destinationKnown: Bool, isClose: Bool) {
        os_unfair_lock_lock(destinationAccountingLock)
        switch lateDestinationTracker.report(id, destinationKnown: destinationKnown, isClose: isClose) {
        case .arrivedBeforeClose: lateDestinationAtVerdictReport &+= 1
        case .arrivedAtClose: lateDestinationAtFlowClose &+= 1
        case .stillUnknownAtClose: stillUnknownAtFlowClose &+= 1
        case .ignored: break
        }
        os_unfair_lock_unlock(destinationAccountingLock)
    }

    /// Observation only. The verdict for this flow was returned long ago and is
    /// not revisited here: this callback returns Void, and the framework
    /// delivers it after the verdict it describes has been applied.
    override func handle(_ report: NEFilterReport) {
        guard let socketFlow = report.flow as? NEFilterSocketFlow else { return }
        // Statistics reports say nothing about whether an address appeared, and
        // counting them was how this tally came to describe ordinary traffic.
        let event = report.event
        guard event == .flowClosed || event == .newFlow || event == .dataDecision else { return }
        let isClose = event == .flowClosed
        let destination = FlowDestination.resolve(endpointHost: remoteAddress(of: socketFlow).host,
                                                  remoteHostname: socketFlow.remoteHostname)
        classifyFlaggedReport(socketFlow.identifier, destinationKnown: destination.isKnown, isClose: isClose)
    }

    /// Once per process: an allow rule named the bundle id this app's
    /// Info.plist claims, but the process's code signature does not vouch for
    /// that id (#351), or another team signed it than the rule's (#364), so
    /// the rule did not apply. Says why the user got an
    /// alert for an app they allowed. Trylock-only: a contended verdict skips
    /// the note instead of waiting.
    private func noteUnverifiedBundleId(_ conn: Connection, skipped: Rule) {
        guard os_unfair_lock_trylock(unverifiedBundleLogLock) else { return }
        if unverifiedBundleLoggedPIDs.count >= 1024 { unverifiedBundleLoggedPIDs.removeAll() }
        let first = unverifiedBundleLoggedPIDs.insert(conn.pid).inserted
        os_unfair_lock_unlock(unverifiedBundleLogLock)
        guard first else { return }
        let reason: String
        if conn.processBundleId == skipped.processBundleId {
            reason = "it is signed with that bundle id by team \(conn.processTeamId ?? "none"), but the rule was made for the app signed by team \(skipped.processTeamId ?? "none")"
        } else {
            reason = "its Info.plist claims that bundle id, but its code signature does not vouch for it (signed id: \(conn.processBundleId ?? "none"))"
        }
        PSLog.info(
            PSLog.netext,
            "The \(skipped.action.rawValue) rule for \(skipped.processBundleId ?? "") did not apply to \(conn.processPath) (pid \(conn.pid)): \(reason), so only deny and ask rules for that id apply."
        )
    }

    /// An IP or CIDR rule that cannot be evaluated is a limitation to state,
    /// not to paper over. Counting is trylock-only, so a contended verdict
    /// skips the tally instead of waiting, and the summary is emitted at most
    /// once a minute.
    /// A reverse-DNS query name arriving as `remoteHostname` is ordinary on a
    /// busy machine, so it is summarised on the same one minute cadence as the
    /// other destination accounting. Logging every occurrence put several error
    /// lines per second into the unified log, which buries the diagnostics that
    /// matter. Counting is trylock-only, so the verdict path never waits.
    private func noteRejectedHostname(_ rejected: String) {
        guard os_unfair_lock_trylock(destinationAccountingLock) else { return }
        rejectedHostnameCount &+= 1
        let now = DispatchTime.now().uptimeNanoseconds
        let due = now &- lastRejectedHostnameLogNanos >= destinationLogIntervalNanos
        if due { lastRejectedHostnameLogNanos = now }
        let count = rejectedHostnameCount
        os_unfair_lock_unlock(destinationAccountingLock)
        guard due else { return }
        PSLog.error(
            PSLog.netext,
            "Ignored \(count) unusable remote hostnames so far, most recently '\(rejected)': \(PFHostValidator.rejectionReason(for: rejected)); the endpoint address is used instead."
        )
    }

    private func noteUnknownDestination(_ flow: NEFilterSocketFlow, port: Int) {
        guard os_unfair_lock_trylock(destinationAccountingLock) else { return }
        unknownDestinationFlows &+= 1
        let now = DispatchTime.now().uptimeNanoseconds
        let due = now &- lastDestinationLogNanos >= destinationLogIntervalNanos
        if due { lastDestinationLogNanos = now }
        let flagged = lateDestinationTracker.total
        let lateAtVerdict = lateDestinationAtVerdictReport
        let lateAtClose = lateDestinationAtFlowClose
        let stillUnknown = stillUnknownAtFlowClose
        let evicted = lateDestinationTracker.evictions
        os_unfair_lock_unlock(destinationAccountingLock)
        guard due else { return }
        // Eviction means an identifier was forgotten before its flow closed, so
        // the tallies below undercount by at most that much. Say so rather than
        // presenting a short count as complete.
        let evictionNote = evicted == 0 ? "." : ", and \(evicted) were forgotten before closing, so the counts above are lower bounds."
        PSLog.error(
            PSLog.netext,
            "\(flagged) flows had no destination at verdict time: IP and CIDR rules cannot be evaluated for them, "
            + "only process, bundle, port, and direction rules apply. "
            + "Latest such flow: socket family \(flow.socketFamily), type \(flow.socketType), "
            + "protocol \(flow.socketProtocol), remote port \(port). "
            + "Of those same flows, an address arrived later for \(lateAtVerdict) before close and \(lateAtClose) at close, "
            + "while \(stillUnknown) closed with no address at all\(evictionNote)"
        )
    }

    // MARK: - Observation drain

    private func drainObservationBatch() {
        while true {
            os_unfair_lock_lock(observationSignalLock)
            let stopped = observationStopped
            os_unfair_lock_unlock(observationSignalLock)
            guard !stopped else { return }

            let observations = observationQueue.drain(maximum: InsightsLimits.maxBatchCount)
            logObservationDropsIfNeeded()
            // Rule hits ride along with the observations of the flows they
            // decided (#434), or alone when those were already sent. A batch
            // that cannot be sent puts them back.
            let hits = ruleHitTally.drain(maximum: InsightsLimits.maxBatchCount)
            guard !observations.isEmpty || !hits.isEmpty else {
                finishObservationDrainIfIdle()
                return
            }
            var candidate = observations
            var payload: Data?
            repeat {
                payload = try? FreeSnitchWireCodec.encode(FlowObservationBatch(observations: candidate, ruleHits: hits))
                if let payload, payload.count <= InsightsLimits.maxBatchBytes { break }
                guard !candidate.isEmpty else { break }
                candidate.removeLast()
            } while true

            var sent = false
            if let payload, payload.count <= InsightsLimits.maxBatchBytes {
                sent = IPCConnection.shared.sendObservationBatch(payload)
            }
            if !sent && !hits.isEmpty {
                // Kept for the next flow's drain. Looping here would take
                // the same hits straight back out while the app is away.
                ruleHitTally.restore(hits)
                finishObservationDrainIfIdle()
                return
            }
        }
    }

    private func signalObservationDrain() {
        guard os_unfair_lock_trylock(observationSignalLock) else { return }
        let shouldSchedule = !observationStopped && !observationDrainScheduled
        if shouldSchedule { observationDrainScheduled = true }
        os_unfair_lock_unlock(observationSignalLock)
        guard shouldSchedule else { return }
        observationDrainQueue.async { [weak self] in self?.drainObservationBatch() }
    }

    private func finishObservationDrainIfIdle() {
        os_unfair_lock_lock(observationSignalLock)
        observationDrainScheduled = false
        os_unfair_lock_unlock(observationSignalLock)
        if !observationQueue.isEmpty { signalObservationDrain() }
    }

    private func logObservationDropsIfNeeded() {
        let dropped = observationQueue.takeFullDropCount()
        guard dropped > 0, Date().timeIntervalSince(lastObservationDropLog) >= 60 else { return }
        lastObservationDropLog = Date()
        PSLog.error(PSLog.netext,
                    "insights observation queue dropped \(dropped) full-ring observations; contention drops are immediate and uncounted")
    }

    // MARK: - Ask flow

    private func promptAndResume(flow: NEFilterFlow, conn: Connection) {
        guard let data = try? JSONEncoder().encode(conn) else {
            resumeFlow(flow, with: NEFilterNewFlowVerdict.allow()); return
        }
        var settled = false
        let lock = NSLock()
        let destinationKnown = !conn.remoteIP.isEmpty || !conn.remoteHost.isEmpty
        let resumeOnce: (NEFilterNewFlowVerdict) -> Void = { [weak self] verdict in
            lock.lock(); defer { lock.unlock() }
            guard let self, !settled else { return }
            settled = true
            self.resumeFlow(flow, with: self.reportingLateDestination(verdict, for: flow, port: conn.remotePort, destinationKnown: destinationKnown))
        }

        let asked = IPCConnection.shared.promptUser(flowJSON: data) { allow, _ in
            resumeOnce(allow ? NEFilterNewFlowVerdict.allow() : NEFilterNewFlowVerdict.drop())
        }
        if !asked {
            // No GUI connected: fail open so the user's network keeps working.
            resumeOnce(NEFilterNewFlowVerdict.allow())
            return
        }
        // Safety net: never hold a flow forever if the GUI never answers.
        workQueue.asyncAfter(deadline: .now() + askTimeout) { resumeOnce(NEFilterNewFlowVerdict.allow()) }
    }

    // MARK: - Self exemption

    /// Identity, not file path. macOS stages this extension under
    /// /Library/SystemExtensions/<uuid>/, nowhere near the app bundle, so
    /// deriving "our directory" from Bundle.main is wrong: walking up from the
    /// staged copy lands on "/" and would exempt every process on the machine.
    private func isOwnTraffic(_ conn: Connection) -> Bool {
        guard conn.pid > 0 else { return false }
        if isOwnCode(pid: conn.pid) { return true }
        // nettop and lsof are Apple-signed binaries in /usr, so they can only be
        // recognised as ours through the helper that spawned them.
        guard let parent = parentPID(of: conn.pid), parent > 0 else { return false }
        return isOwnCode(pid: parent)
    }

    private func isOwnCode(pid: Int32) -> Bool {
        var code: SecCode?
        let attributes = [kSecGuestAttributePid as String: pid] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code else { return false }
        let requirementText = [AppConstants.bundleIdGUI, AppConstants.bundleIdCLI, AppConstants.bundleIdHelper, AppConstants.bundleIdNetExt]
            .map { "identifier \"\($0)\"" }
            .joined(separator: " or ")
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(requirementText as CFString, [], &requirement) == errSecSuccess,
              let requirement else { return false }
        return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
    }

    private func isLoopback(_ ip: String) -> Bool {
        ip.hasPrefix("127.") || ip == "::1" || ip == "localhost"
    }

    /// DHCP and DHCPv6 remain exempt for every policy state, as they are in
    /// the pf anchor (issue #186). Port 53 is exempt only
    /// while a valid helper boot snapshot is active, and only for a configured
    /// resolver. If resolver configuration is unavailable during that boot
    /// window, ResolverBypass fails open so name resolution still works.
    ///
    /// A flow with no destination is looked up as the wildcard address rather
    /// than as an empty string on purpose: ResolverBypass answers an empty
    /// address with an unconditional yes, which would turn every
    /// unattributable port-53 flow into a blanket boot-window exemption. The
    /// wildcard is never a configured resolver, so such a flow keeps exactly
    /// the answer it received before the destination was recorded honestly.
    private func isDNSOrDHCP(_ conn: Connection, snapshotOrigin: SnapshotOrigin) -> Bool {
        if [67, 68, 546, 547].contains(conn.remotePort) { return true }
        guard conn.remotePort == 53, snapshotOrigin == .boot else { return false }
        let lookup = conn.remoteIP.isEmpty ? FlowDestination.unspecifiedLookupToken : conn.remoteIP
        return resolverBypass.allowsDNS(to: lookup)
    }

    private func parentPID(of pid: Int32) -> Int32? {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        guard result == 0, size > 0 else { return nil }
        return info.kp_eproc.e_ppid
    }

    // MARK: - Flow -> Connection

    /// The flow as a connection, and the app version shown with it. Both come
    /// from one cache lookup, so a flow pays for one kernel code-hash call.
    private func connection(from flow: NEFilterSocketFlow) -> (Connection, version: String?, signatureChecked: Bool) {
        let (host, port) = remoteAddress(of: flow)
        let destination = FlowDestination.resolve(endpointHost: host, remoteHostname: flow.remoteHostname)
        if let rejected = destination.rejectedHostname {
            noteRejectedHostname(rejected)
        }
        let remoteHost = destination.host
        let remoteIP = destination.ip
        let pid = flow.sourceAppAuditToken.flatMap(auditTokenToPID) ?? 0
        let path = pid > 0 ? pathForPID(pid) : ""
        let name = path.isEmpty ? "Unknown" : (path as NSString).lastPathComponent
        let metadata = bundleIdentifierCache.cachedMetadata(forExecutablePath: path,
                                                            auditToken: flow.sourceAppAuditToken)
        let connection = Connection(
            pid: Int32(pid),
            processName: name,
            processPath: path,
            processBundleId: metadata?.bundleIdentifier,
            processTeamId: metadata?.bundleIdentifier == nil ? nil : metadata?.team,
            claimedBundleId: metadata?.claimedBundleIdentifier,
            remoteHost: remoteHost,
            remoteIP: remoteIP,
            remotePort: port,
            direction: flow.direction == .outbound ? .outgoing : .incoming,
            status: .pending
        )
        return (connection, metadata?.version, metadata?.signatureChecked ?? false)
    }

    /// `remoteEndpoint` is deprecated and reports the unspecified address
    /// (0.0.0.0 or ::) on current macOS, which is why alerts showed no
    /// destination. `remoteFlowEndpoint` carries the real one when there is
    /// one; see `FlowDestination` for what happens when there is not.
    private func remoteAddress(of flow: NEFilterSocketFlow) -> (host: String, port: Int) {
        if #available(macOS 15.0, *), case let .hostPort(host, port) = flow.remoteFlowEndpoint {
            let text: String
            switch host {
            case .ipv4(let address): text = "\(address)"
            case .ipv6(let address): text = "\(address)"
            case .name(let name, _): text = name
            @unknown default: text = ""
            }
            // Strip the interface scope IPv6 literals carry, e.g. fe80::1%en0.
            let bare = text.split(separator: "%").first.map(String.init) ?? text
            return (bare, Int(port.rawValue))
        }
        let legacy = flow.remoteEndpoint as? NWHostEndpoint
        return (legacy?.hostname ?? "", Int(legacy?.port ?? "0") ?? 0)
    }

    private func auditTokenToPID(_ data: Data) -> Int? {
        guard data.count >= MemoryLayout<audit_token_t>.size else { return nil }
        var token = audit_token_t()
        _ = withUnsafeMutableBytes(of: &token) { data.copyBytes(to: $0, count: $0.count) }
        // token.val.5 is the pid. This avoids linking libbsm for audit_token_to_pid.
        return Int(token.val.5)
    }

    private func pathForPID(_ pid: Int) -> String {
        let maxSize = 4096   // PROC_PIDPATHINFO_MAXSIZE
        var buf = [CChar](repeating: 0, count: maxSize)
        let n = proc_pidpath(Int32(pid), &buf, UInt32(maxSize))
        return n > 0 ? String(cString: buf) : ""
    }

    // MARK: - Rule snapshot

    private func loadBootSnapshot(_ data: Data) {
        do {
            let decoded = try SharedRuleBridge.decodeBootSnapshot(data)
            // A saved policy older than the last live policy this extension
            // enforced is one the app failed to replace. It may still hold a
            // rule the user removed, so it never loads; filtering fails open
            // until the app sends the current policy (#213).
            if let watermarkURL,
               let watermark = SharedRuleBridge.LivePolicyWatermark.read(from: watermarkURL),
               watermark.supersedes(decoded) {
                clearBootSnapshot(
                    "persisted boot policy (session \(decoded.epoch), generation \(decoded.generation)) is older than the last live policy "
                    + "(session \(watermark.epoch), generation \(watermark.generation)), usually because the app's last save failed, "
                    + "so it is not loaded and filtering will fail open until the app sends the current rules"
                )
                return
            }
            let received = SharedRuleBridge.applyingBootPolicySafety(decoded)
            if decoded.mode == .silentDeny && received.mode == .alert {
                PSLog.error(
                    PSLog.netext,
                    "stale silent-deny boot policy downgraded to alert; explicit deny rules remain active and unanswered asks fail open"
                )
            }
            let status = SharedRuleBridge.SnapshotStatus.ready(for: received)
            snapshotLock.lock()
            let liveSnapshotAlreadyLoaded = snapshotOrigin == .live
            if !liveSnapshotAlreadyLoaded {
                setSnapshotLocked(received)
                snapshotOrigin = .boot
                snapshotStatus = status
            }
            snapshotLock.unlock()

            if liveSnapshotAlreadyLoaded {
                PSLog.info(PSLog.netext, "ignoring boot policy snapshot because a trusted live GUI snapshot is already active")
                return
            }
            PSLog.info(
                PSLog.netext,
                "boot policy snapshot loaded from persisted provider configuration: mode \(received.mode.rawValue), \(received.rules.count) rules"
            )
        } catch {
            let status = SharedRuleBridge.SnapshotStatus.invalid(
                "Network extension persisted boot policy was invalid: \(error.localizedDescription)"
            )
            snapshotLock.lock()
            let liveSnapshotAlreadyLoaded = snapshotOrigin == .live
            if !liveSnapshotAlreadyLoaded {
                setSnapshotLocked(nil)
                snapshotOrigin = .none
                snapshotStatus = status
            }
            snapshotLock.unlock()
            if liveSnapshotAlreadyLoaded {
                PSLog.info(PSLog.netext, "ignoring invalid boot policy snapshot because a trusted live GUI snapshot is already active")
                return
            }
            PSLog.error(PSLog.netext, status.message ?? "Network extension persisted boot policy was invalid.")
        }
    }

    /// Remembers which policy is now enforced, so a later start can refuse an
    /// older saved policy (#213). A failed write is logged and leaves the
    /// previous behaviour: the saved policy loads as before.
    private func recordLiveWatermark(_ accepted: SharedRuleBridge.Snapshot) {
        guard let url = watermarkURL else {
            PSLog.error(PSLog.netext, "live policy watermark has no container location; a failed boot policy save cannot be detected at the next start")
            return
        }
        let watermark = SharedRuleBridge.LivePolicyWatermark(accepted)
        watermarkQueue.async {
            do {
                try watermark.write(to: url)
            } catch {
                PSLog.error(PSLog.netext, "live policy watermark write failed: \(error.localizedDescription); a failed boot policy save cannot be detected at the next start")
            }
        }
    }

    private func receiveSnapshot(_ data: Data) -> SharedRuleBridge.SnapshotStatus {
        do {
            try RuleTransportBoundary.validateSnapshotBytes(data)
            let received = try SharedRuleBridge.decode(data)
            snapshotLock.lock()
            let current = snapshot
            // Ordering is (epoch, generation), never the generation alone.
            // This policy outlives every helper process, so a helper that has
            // restarted arrives with a fresh session and a generation that may
            // legitimately be lower, or zero because nothing had ever written
            // it. Treating that owner as a stale client left the machine in #70
            // unfiltered until a reboot.
            let authority = current.map { SharedRuleBridge.SnapshotAuthority.compare(received: received, against: $0) }

            // Both comparisons run while the policy lock is held and before
            // setSnapshotLocked can assign the candidate. Boot policy is also
            // compared here so a stale live client cannot replace a newer
            // persisted policy during extension startup.
            if let current, authority == .olderSession {
                let status = SharedRuleBridge.SnapshotStatus.invalid(
                    "Network extension rejected a live rule snapshot from an older helper session "
                    + "(session \(received.epoch); current session \(current.epoch)). \(SharedRuleBridge.snapshotRejectionRemediation)",
                    generation: current.generation,
                    epoch: current.epoch,
                    rejection: .olderSession
                )
                snapshotStatus = status
                snapshotLock.unlock()
                PSLog.error(PSLog.netext, status.message ?? "Network extension rejected an older helper session's snapshot.")
                return status
            }
            if let current, received.generation < current.generation {
                // Only inside one helper session is a lower generation a
                // rollback. Across sessions it is the owner restarting, and
                // the epoch above has already ranked it.
                if authority == .sameSession {
                    let status = SharedRuleBridge.SnapshotStatus.invalid(
                        "Network extension rejected an older live rule snapshot (generation \(received.generation); current generation \(current.generation)). \(SharedRuleBridge.snapshotRejectionRemediation)",
                        generation: current.generation,
                        epoch: current.epoch,
                        rejection: .olderGeneration
                    )
                    snapshotStatus = status
                    snapshotLock.unlock()
                    PSLog.error(PSLog.netext, status.message ?? "Network extension rejected an older live rule snapshot.")
                    return status
                }
            }
            let legacyBootGeneration = snapshotOrigin == .boot && current?.generation == 0 && received.generation == 0
            if let current,
               authority == .sameSession,
               received.generation == current.generation,
               (received.mode != current.mode || received.rules != current.rules),
               !legacyBootGeneration {
                let status = SharedRuleBridge.SnapshotStatus.invalid(
                    "Network extension rejected an invalid split-brain snapshot: generation \(received.generation) has different policy content. \(SharedRuleBridge.snapshotRejectionRemediation)",
                    generation: current.generation,
                    epoch: current.epoch,
                    rejection: .conflictingContent
                )
                snapshotStatus = status
                snapshotLock.unlock()
                PSLog.error(PSLog.netext, status.message ?? "Network extension rejected an invalid split-brain snapshot.")
                return status
            }

            // A generation-less boot envelope decodes as generation zero for
            // backward compatibility. The first helper-owned live snapshot is
            // allowed to replace that legacy boot policy; equal-generation
            // conflicts remain invalid once a live snapshot exists.
            var gate = SharedRuleBridge.LiveSnapshotGate(current: legacyBootGeneration ? nil : current)
            let decision = gate.apply(received)
            switch decision {
            case .accepted, .idempotent:
                let accepted = gate.current ?? received
                let status = SharedRuleBridge.SnapshotStatus.ready(for: accepted)
                setSnapshotLocked(accepted)
                snapshotOrigin = .live
                snapshotStatus = status
                // Queued (not written) while the lock is held, so records land
                // in the order the policies were accepted. The write itself
                // runs on its own queue and never delays this reply.
                if decision == .accepted { recordLiveWatermark(accepted) }
                snapshotLock.unlock()

                let allowCount = accepted.rules.filter { $0.action == .allow }.count
                let denyCount = accepted.rules.filter { $0.action == .deny }.count
                let askCount = accepted.rules.filter { $0.action == .ask }.count
                let idempotentNote = decision == .idempotent ? " (idempotent)" : ""
                PSLog.info(PSLog.netext,
                           "filter snapshot received over XPC: session \(accepted.epoch), generation \(accepted.generation), mode \(accepted.mode.rawValue), "
                           + "\(accepted.rules.count) rules (allow \(allowCount), deny \(denyCount), ask \(askCount))\(idempotentNote)")
                // Persistence is owned by the GUI through NEFilterManager. A
                // live XPC update changes only this in-memory policy and never
                // waits on disk, XPC, or another transport.
                return status
            case .rejectedOlder(let currentGeneration), .rejectedConflict(let currentGeneration):
                let status = SharedRuleBridge.SnapshotStatus.invalid(
                    "Network extension rejected an invalid live snapshot at generation \(received.generation); current generation is \(currentGeneration). \(SharedRuleBridge.snapshotRejectionRemediation)",
                    generation: currentGeneration,
                    epoch: current?.epoch,
                    rejection: .olderGeneration
                )
                snapshotStatus = status
                snapshotLock.unlock()
                PSLog.error(PSLog.netext, status.message ?? "Network extension rejected an invalid live snapshot.")
                return status
            case .rejectedOlderSession(let currentEpoch):
                let status = SharedRuleBridge.SnapshotStatus.invalid(
                    "Network extension rejected a live snapshot from helper session \(received.epoch); "
                    + "current session is \(currentEpoch). \(SharedRuleBridge.snapshotRejectionRemediation)",
                    generation: current?.generation,
                    epoch: currentEpoch,
                    rejection: .olderSession
                )
                snapshotStatus = status
                snapshotLock.unlock()
                PSLog.error(PSLog.netext, status.message ?? "Network extension rejected an older helper session's snapshot.")
                return status
            }
        } catch {
            let status = SharedRuleBridge.SnapshotStatus.invalid(
                "Network extension received an invalid rule snapshot: \(error.localizedDescription)"
            )
            snapshotLock.lock()
            snapshotStatus = status
            snapshotLock.unlock()
            PSLog.error(PSLog.netext, status.message ?? "Network extension received an invalid rule snapshot.")
            return status
        }
    }

    private func currentPolicy() -> (snapshot: SharedRuleBridge.Snapshot?, origin: SnapshotOrigin, prepared: PreparedRuleSet) {
        snapshotLock.lock()
        defer { snapshotLock.unlock() }
        return (snapshot, snapshotOrigin, preparedRules)
    }

    private func readSnapshotStatus() -> SharedRuleBridge.SnapshotStatus {
        snapshotLock.lock()
        defer { snapshotLock.unlock() }
        return snapshotStatus
    }
}

/// Bounded executable-path to bundle-identifier cache for the verdict path.
///
/// `cachedMetadata(forExecutablePath:auditToken:)` is memory only apart from
/// one `csops` call into the kernel for the flow's code hash: it holds the lock
/// just long enough for dictionary lookups, and no lock holder ever touches the
/// filesystem. Every signature check and Info.plist read happens on
/// `resolveQueue`, so a cache miss answers nil immediately rather than blocking
/// `handleNewFlow`, and only one resolve is scheduled per path even during a
/// burst of new flows.
///
/// The key is the executable path exactly as `proc_pidpath` reports it, not the
/// enclosing .app, because splitting the path allocates a string and that
/// allocation dominated the lookup. Finding the .app, checking the signature
/// and reading its plist all belong to the background resolve. An executable
/// outside an .app bundle is cached as nil, which is the answer the filter
/// already gives it.
///
/// Two answers per path (#351). The bundle identifier rules may trust comes
/// from the code signature; the version and the identifier the Info.plist
/// claims come from the plist. The claimed identifier is unsigned, so only a
/// deny rule matches it: a fake claim can get a binary blocked, never let
/// through.
///
/// A signed identifier is tied to the code it was checked for, not to the
/// path: it is stored under the code directory hash the kernel reports for the
/// checked process, and a flow only gets it when its own process runs code
/// with that hash. A binary swapped in at a path whose earlier process was
/// checked therefore never inherits that process's identifier; its own code is
/// checked first. A check that could not read the signature at all is not an
/// answer, so it is tried again after `failureRetryInterval`. A signed
/// identifier needs no refresh: code with a given hash keeps the signature it
/// was checked with.
///
/// Bound: at most `capacity` executable paths, and at most `signedPerPath`
/// code hashes per path. When the map is full the path that was resolved
/// longest ago is evicted (first resolved, first out), so this long-lived
/// root-adjacent process cannot grow the map without limit. Eviction runs on
/// `resolveQueue`, never on the verdict path.
///
/// Plist staleness: a path can be reused by a replaced app, so a plist read
/// older than `entryLifetime` is read again in the background while the
/// previous answer is still given from memory. The stale window is therefore
/// bounded by the lifetime plus one background read (two lifetimes while the
/// refresh keeps failing, see below).
///
/// Failed plist reads: an Info.plist that cannot be read or parsed (an app
/// mid-update, a permissions problem) is not an app without a bundle
/// identifier. It is logged once, keeps what the path had before (for at most
/// one more lifetime past its last good read), and is read again after
/// `failureRetryInterval`, doubling up to `entryLifetime` while it keeps
/// failing (#268).
struct AppBundleMetadata: Sendable {
    /// From the plist, as read. In an answer from the cache: the signed
    /// identifier (`CodeSigningIdentity`), never the plist's.
    let bundleIdentifier: String?
    let version: String?
    /// What the unsigned Info.plist claims, when it differs from the signed
    /// identifier. Only ever matched by deny rules.
    var claimedBundleIdentifier: String? = nil
    /// The team that signed `bundleIdentifier` in an answer from the cache
    /// (#364), or `CodeSigningIdentity.appleTeam`. Nil with no signed id.
    var team: String? = nil
    /// Whether the code this flow's process runs has been checked yet. Until
    /// it has, a missing `bundleIdentifier` means "not known yet", not "the
    /// signature does not vouch for it".
    var signatureChecked = false
}

/// The outcome of one Info.plist read. `.read(nil)` is a real answer (the plist
/// names neither an identifier nor a version); `.failed` means nothing is known.
enum AppBundleMetadataRead: Sendable {
    case read(AppBundleMetadata?)
    case failed(String)
}

/// A code directory hash (20 bytes), held without a heap allocation so the
/// verdict path can look one up.
struct CDHash: Hashable, Sendable {
    let head: UInt64
    let middle: UInt64
    let tail: UInt32

    init(_ bytes: (UInt64, UInt64, UInt32)) {
        head = bytes.0
        middle = bytes.1
        tail = bytes.2
    }
}

@_silgen_name("csops_audittoken")
private func csops_audittoken(_ pid: pid_t, _ ops: UInt32, _ useraddr: UnsafeMutableRawPointer?,
                              _ usersize: Int, _ token: UnsafeMutablePointer<audit_token_t>?) -> Int32

final class BundleIdentifierCache: @unchecked Sendable {
    private struct Entry {
        /// The last good plist read (version and claimed identifier).
        var plist: AppBundleMetadata?
        var plistReadAtNanos: UInt64 = 0
        /// When the plist is due for another read. `entryLifetime` after a
        /// good read, much sooner after a failed one.
        var plistRefreshAfterNanos: UInt64 = 0
        /// Failed plist reads in a row since the last good one.
        var plistFailures = 0
        /// Code hashes checked at this path: the signed identifier, or nil
        /// when the code's signature is not one rules may trust.
        var signed: [CDHash: CodeSigningIdentity.SignedBundle?] = [:]
        var signedOrder: [CDHash] = []
        /// The code whose signature could not be read at all, when it may be
        /// checked again, and how many such checks failed in a row. Kept per
        /// code hash: a relaunched app runs new code and is checked at once,
        /// whatever its predecessor's backoff was.
        var unreadableHash: CDHash?
        var signatureRetryAfterNanos: UInt64 = 0
        var signatureFailures = 0
    }

    let capacity: Int
    let entryLifetime: TimeInterval
    let failureRetryInterval: TimeInterval
    let signedPerPath = 4

    private var entries: [String: Entry] = [:]
    private var evictionOrder: [String] = []
    private var pending: Set<String> = []
    /// Set once the kernel failed to give a flow's code hash, so that is
    /// logged once instead of every allow quietly turning into an alert.
    private var codeHashFailureLogged = false
    private let lifetimeNanos: UInt64
    private let failureRetryNanos: UInt64
    /// Stable address for the whole lifetime of the cache. A Swift property of
    /// type `os_unfair_lock_s` gives no such guarantee, and a lock that moves
    /// is not a lock.
    private let lock: UnsafeMutablePointer<os_unfair_lock_s>
    private let resolveQueue = DispatchQueue(label: "io.isaaclins.freesnitch.netext.bundleid", qos: .utility)
    private let read: @Sendable (String) -> AppBundleMetadataRead
    private let identify: @Sendable (String, Data?) -> CodeSigningIdentity.Resolution
    private let codeHash: @Sendable (Data?) -> CDHash?
    /// Monotonic nanoseconds. A test seam, so lifetimes and retries can be
    /// checked without sleeping.
    private let clock: @Sendable () -> UInt64

    init(capacity: Int = 512,
         entryLifetime: TimeInterval = 300,
         failureRetryInterval: TimeInterval = 1,
         read: @escaping @Sendable (String) -> AppBundleMetadataRead = { BundleIdentifierCache.readBundleMetadata(atAppPath: $0) },
         identify: @escaping @Sendable (String, Data?) -> CodeSigningIdentity.Resolution = {
             CodeSigningIdentity.resolve(executablePath: $0, auditToken: $1, pid: 0, fileFallback: false)
         },
         codeHash: @escaping @Sendable (Data?) -> CDHash? = { BundleIdentifierCache.kernelCodeHash(auditToken: $0) },
         clock: @escaping @Sendable () -> UInt64 = { DispatchTime.now().uptimeNanoseconds }) {
        precondition(capacity > 0)
        precondition(entryLifetime > 0)
        precondition(failureRetryInterval > 0)
        self.capacity = capacity
        self.entryLifetime = entryLifetime
        self.failureRetryInterval = min(failureRetryInterval, entryLifetime)
        self.lifetimeNanos = UInt64(entryLifetime * 1_000_000_000)
        self.failureRetryNanos = UInt64(self.failureRetryInterval * 1_000_000_000)
        self.read = read
        self.identify = identify
        self.codeHash = codeHash
        self.clock = clock
        self.lock = .allocate(capacity: 1)
        self.lock.initialize(to: os_unfair_lock_s())
    }

    deinit {
        lock.deinitialize(count: 1)
        lock.deallocate()
    }

    /// The code directory hash of the code the process named by `auditToken`
    /// is running, straight from the kernel: no filesystem access, and it is
    /// what the process executed even if its file was replaced since.
    static func kernelCodeHash(auditToken: Data?) -> CDHash? {
        guard let auditToken, auditToken.count >= MemoryLayout<audit_token_t>.size else { return nil }
        var token = audit_token_t()
        _ = withUnsafeMutableBytes(of: &token) { auditToken.copyBytes(to: $0, count: $0.count) }
        var hash: (UInt64, UInt64, UInt32) = (0, 0, 0)
        let pid = pid_t(bitPattern: token.val.5)
        // CS_OPS_CDHASH is 5; the hash is 20 bytes.
        let status = withUnsafeMutableBytes(of: &hash) { buffer in
            csops_audittoken(pid, 5, buffer.baseAddress, 20, &token)
        }
        return status == 0 ? CDHash(hash) : nil
    }

    /// Verdict path. A first-seen path or code answers nil for the signed
    /// identifier and queues a background check, so a signature check or an
    /// Info.plist read can never block `handleNewFlow`. A temporary nil is
    /// conservative: it may produce an extra ask, never a wrong allow.
    func cachedBundleId(forExecutablePath path: String, auditToken: Data? = nil) -> String? {
        cachedMetadata(forExecutablePath: path, auditToken: auditToken)?.bundleIdentifier
    }

    /// The signed bundle identifier of the flow's own code, and the plist's
    /// version and claimed identifier for its path.
    func cachedMetadata(forExecutablePath path: String, auditToken: Data? = nil) -> AppBundleMetadata? {
        guard !path.isEmpty else { return nil }
        let hash = codeHash(auditToken)
        let now = clock()
        os_unfair_lock_lock(lock)
        let entry = entries[path]
        let known: CodeSigningIdentity.SignedBundle?? = hash.flatMap { entry?.signed[$0] }
        let plistDue = entry.map { now >= $0.plistRefreshAfterNanos } ?? true
        let retryDue = entry.map { hash != $0.unreadableHash || now >= $0.signatureRetryAfterNanos } ?? true
        let checkDue = hash != nil && known == nil && retryDue
        let shouldRefresh = !pending.contains(path) && pending.count < capacity && (plistDue || checkDue)
        if shouldRefresh { pending.insert(path) }
        let reportHashFailure = auditToken != nil && hash == nil && !codeHashFailureLogged
        if reportHashFailure { codeHashFailureLogged = true }
        os_unfair_lock_unlock(lock)
        if reportHashFailure {
            PSLog.error(PSLog.netext,
                        "Could not read the code hash of \(path) from the kernel, so its code signature cannot be checked: allow rules cannot match it by bundle id until this works. Logged once.")
        }
        if shouldRefresh {
            let check = checkDue ? hash : nil
            resolveQueue.async { [weak self] in
                self?.resolve(path, auditToken: auditToken, hash: check, readPlist: plistDue)
            }
        }
        var answer = Self.metadata(known ?? nil, entry?.plist)
        answer?.signatureChecked = known != nil
        return answer
    }

    /// Background only.
    private func resolve(_ path: String, auditToken: Data?, hash: CDHash?, readPlist: Bool) {
        let identity = hash == nil ? nil : identify(path, auditToken)
        var outcome: AppBundleMetadataRead?
        if readPlist {
            if let appPath = Self.appBundlePath(forExecutablePath: path) {
                outcome = read(appPath)
            } else {
                outcome = .read(nil)
            }
        }
        let now = clock()
        os_unfair_lock_lock(lock)
        pending.remove(path)
        let previous = entries[path]
        var entry = previous ?? Entry()
        switch outcome {
        case .read(let metadata)?:
            entry.plist = metadata
            entry.plistReadAtNanos = now
            entry.plistRefreshAfterNanos = now &+ lifetimeNanos
            entry.plistFailures = 0
        case .failed?:
            // Keep the plist read before, for at most one more lifetime, so a
            // path taken over by another app cannot keep the old answer
            // forever; retry soon, backing off.
            entry.plistFailures += 1
            let shift = UInt64(min(entry.plistFailures - 1, 20))
            let delay = min(failureRetryNanos << shift, lifetimeNanos)
            let keep = previous.map { $0.plist != nil && now &- $0.plistReadAtNanos < lifetimeNanos &* 2 } ?? false
            if !keep {
                entry.plist = nil
                entry.plistReadAtNanos = now
            }
            entry.plistRefreshAfterNanos = now &+ delay
        case nil:
            break
        }
        if let hash, let identity {
            switch identity {
            case .unavailable:
                // No signature could be read for this process (it exited, or
                // its app was updated on disk while it ran). That is no
                // answer: try again, backing off like a failed plist read,
                // since an app updated under a running process can only be
                // checked once it is relaunched.
                entry.signatureFailures = entry.unreadableHash == hash ? entry.signatureFailures + 1 : 1
                entry.unreadableHash = hash
                let shift = UInt64(min(entry.signatureFailures - 1, 20))
                entry.signatureRetryAfterNanos = now &+ min(failureRetryNanos << shift, lifetimeNanos)
            case .noBundle, .resolved:
                if entry.signed.updateValue(identity.signed, forKey: hash) == nil {
                    entry.signedOrder.append(hash)
                    if entry.signedOrder.count > signedPerPath {
                        entry.signed.removeValue(forKey: entry.signedOrder.removeFirst())
                    }
                }
                if entry.unreadableHash == hash {
                    entry.unreadableHash = nil
                    entry.signatureFailures = 0
                }
            }
        }
        insertLocked(path, entry: entry)
        os_unfair_lock_unlock(lock)

        // Log outside the lock: once when a path's code starts failing its
        // signature check, and once when a plist starts failing or recovers.
        if case .unavailable? = identity, entry.signatureFailures == 1 {
            PSLog.error(PSLog.netext,
                        "Could not check the code signature of \(path) (the app may have been updated on disk while it runs). Until it can be checked, only deny and ask rules match it by bundle id; checking again with growing gaps.")
        }
        switch outcome {
        case .failed(let reason)? where entry.plistFailures == 1:
            let kept = entry.plist?.bundleIdentifier.map { "keeps answering '\($0)'" }
                ?? "has no bundle identifier from its Info.plist yet"
            PSLog.error(PSLog.netext,
                        "Could not read the app bundle identity for \(path): \(reason). The app \(kept); retrying in \(Int(failureRetryInterval.rounded(.up))) s.")
        case .read(let metadata)? where (previous?.plistFailures ?? 0) > 0:
            PSLog.info(PSLog.netext,
                       "App bundle identity for \(path) readable again after \(previous!.plistFailures) failed reads: \(metadata?.bundleIdentifier ?? "no bundle identifier").")
        default:
            break
        }
    }

    private static func metadata(_ signed: CodeSigningIdentity.SignedBundle?, _ plist: AppBundleMetadata?) -> AppBundleMetadata? {
        let bundleIdentifier = signed?.identifier
        let claimed = plist?.bundleIdentifier.flatMap { $0.isEmpty || $0 == bundleIdentifier ? nil : $0 }
        guard bundleIdentifier != nil || plist?.version != nil || claimed != nil else { return nil }
        return AppBundleMetadata(bundleIdentifier: bundleIdentifier, version: plist?.version,
                                 claimedBundleIdentifier: claimed, team: signed?.team)
    }

    /// Caller must hold the lock.
    private func insertLocked(_ path: String, entry: Entry) {
        if entries[path] == nil {
            if entries.count >= capacity, !evictionOrder.isEmpty {
                entries.removeValue(forKey: evictionOrder.removeFirst())
            }
            evictionOrder.append(path)
        }
        entries[path] = entry
    }

    /// The enclosing .app for an executable path, or nil when there is none.
    static func appBundlePath(forExecutablePath path: String) -> String? {
        guard !path.isEmpty, let r = path.range(of: ".app/", options: .backwards) else { return nil }
        return String(path[..<r.upperBound])
    }

    /// The plist read, reached only from `resolveQueue`. Its bundle identifier
    /// is unsigned: the cache keeps it only as the claimed id, which nothing
    /// but a deny rule matches (#351).
    static func readBundleMetadata(atAppPath appPath: String) -> AppBundleMetadataRead {
        let plist = AppBundleIdentity.infoPlistPath(forAppPath: appPath)
        let data: Data
        do {
            data = try Data(contentsOf: URL(fileURLWithPath: plist))
        } catch {
            return .failed("reading Info.plist failed (\(error.localizedDescription))")
        }
        let dict: [String: Any]
        do {
            guard let parsed = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
                return .failed("Info.plist is not a dictionary")
            }
            dict = parsed
        } catch {
            return .failed("Info.plist could not be parsed (\(error.localizedDescription))")
        }
        let bundleIdentifier = dict["CFBundleIdentifier"] as? String
        let shortVersion = dict["CFBundleShortVersionString"] as? String
        let build = dict["CFBundleVersion"] as? String
        let version: String?
        if let shortVersion, !shortVersion.isEmpty {
            version = build?.isEmpty == false ? "\(shortVersion) (\(build!))" : shortVersion
        } else {
            version = nil
        }
        guard bundleIdentifier != nil || version != nil else { return .read(nil) }
        return .read(AppBundleMetadata(bundleIdentifier: bundleIdentifier, version: version))
    }

    /// Test seam: how many executable paths are currently held.
    var cachedPathCount: Int {
        os_unfair_lock_lock(lock)
        defer { os_unfair_lock_unlock(lock) }
        return entries.count
    }

    /// Test seam: block until the reads scheduled so far have finished.
    func waitForPendingResolves() {
        resolveQueue.sync {}
    }
}
#endif
