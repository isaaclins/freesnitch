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

final class FilterDataProvider: NEFilterDataProvider {
    private enum SnapshotOrigin: Equatable {
        case none
        case boot
        case live
    }

    private let matcher = RuleMatcher()
    private let resolverBypass = ResolverBypass()
    private let bundleIdentifierCache = BundleIdentifierCache()
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
    private let observationQueue = FlowObservationQueue(capacity: 1024)
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
    /// Identifiers of the flows this provider actually asked to hear about.
    ///
    /// The framework delivers reports for flows that were never flagged, so
    /// without this the late-destination tally counts ordinary traffic that had
    /// an address from its first packet and reads as though addresses arrive
    /// late constantly. Only a flow whose verdict carried `shouldReport` may be
    /// counted here.
    private var flaggedFlows: Set<UUID> = []
    /// Insertion order, so a flow whose close report never arrives is evicted
    /// oldest first instead of growing this set without bound.
    private var flaggedFlowOrder: [UUID] = []
    private var flaggedFlowEvictions: UInt64 = 0
    /// Cumulative count of flows flagged, taken under the blocking lock, so it
    /// is exact. The tallies below can only ever be a subset of it.
    private var flaggedFlowsTotal: UInt64 = 0
    private static let maxFlaggedFlows = 4096

    override init() {
        self.observationSignalLock = .allocate(capacity: 1)
        self.observationSignalLock.initialize(to: os_unfair_lock_s())
        self.destinationAccountingLock = .allocate(capacity: 1)
        self.destinationAccountingLock.initialize(to: os_unfair_lock_s())
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
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else { return .allow() }
        let conn = connection(from: socketFlow)
        _ = observationQueue.enqueue(FlowObservation(connection: conn))
        signalObservationDrain()
        // FreeSnitch must never hold up its own traffic. The helper shells out
        // to nettop and lsof to observe connections, and pausing those to ask
        // the user deadlocks the app that is supposed to answer the question.
        if isOwnTraffic(conn) || isLoopback(conn.remoteIP) { return .allow() }
        // Decided once, before any rule is consulted: a flow can reach this
        // point with no destination at all, and that limitation is reported
        // rather than hidden behind a wildcard address.
        let destinationKnown = !conn.remoteIP.isEmpty || !conn.remoteHost.isEmpty
        if !destinationKnown { noteUnknownDestination(socketFlow, port: conn.remotePort) }
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
        switch matcher.decision(for: conn, prepared: policy.prepared, defaultMode: snapshot.mode) {
        case .allow:
            return reportingLateDestination(.allow(), for: flow, destinationKnown: destinationKnown)
        case .deny:
            return reportingLateDestination(.drop(), for: flow, destinationKnown: destinationKnown)
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
                                          destinationKnown: Bool) -> NEFilterNewFlowVerdict {
        guard !destinationKnown else { return verdict }
        verdict.shouldReport = true
        rememberFlaggedFlow(flow.identifier)
        return verdict
    }

    /// Records a flagged flow, evicting the oldest when full. Eviction is
    /// counted rather than silent, because a dropped identifier means a later
    /// arrival for that flow can no longer be recognised and the tally
    /// undercounts.
    private func rememberFlaggedFlow(_ id: UUID) {
        os_unfair_lock_lock(destinationAccountingLock)
        defer { os_unfair_lock_unlock(destinationAccountingLock) }
        guard flaggedFlows.insert(id).inserted else { return }
        flaggedFlowsTotal &+= 1
        flaggedFlowOrder.append(id)
        guard flaggedFlowOrder.count > Self.maxFlaggedFlows else { return }
        let oldest = flaggedFlowOrder.removeFirst()
        flaggedFlows.remove(oldest)
        flaggedFlowEvictions &+= 1
    }

    /// True when the report belongs to a flow this provider flagged. A close
    /// report also retires the identifier, since no further report can follow.
    private func claimFlaggedFlow(_ id: UUID, isClose: Bool) -> Bool {
        os_unfair_lock_lock(destinationAccountingLock)
        defer { os_unfair_lock_unlock(destinationAccountingLock) }
        guard flaggedFlows.contains(id) else { return false }
        if isClose {
            flaggedFlows.remove(id)
            if let index = flaggedFlowOrder.firstIndex(of: id) {
                flaggedFlowOrder.remove(at: index)
            }
        }
        return true
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
        guard claimFlaggedFlow(socketFlow.identifier, isClose: isClose) else { return }
        let destination = FlowDestination.resolve(endpointHost: remoteAddress(of: socketFlow).host,
                                                  remoteHostname: socketFlow.remoteHostname)
        noteLateDestination(arrived: destination.isKnown, isClose: isClose)
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
        let flagged = flaggedFlowsTotal
        let lateAtVerdict = lateDestinationAtVerdictReport
        let lateAtClose = lateDestinationAtFlowClose
        let stillUnknown = stillUnknownAtFlowClose
        let evicted = flaggedFlowEvictions
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

    private func noteLateDestination(arrived: Bool, isClose: Bool) {
        guard os_unfair_lock_trylock(destinationAccountingLock) else { return }
        switch (arrived, isClose) {
        case (true, true): lateDestinationAtFlowClose &+= 1
        case (true, false): lateDestinationAtVerdictReport &+= 1
        case (false, true): stillUnknownAtFlowClose &+= 1
        case (false, false): break
        }
        os_unfair_lock_unlock(destinationAccountingLock)
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
            guard !observations.isEmpty else {
                finishObservationDrainIfIdle()
                return
            }

            var candidate = observations
            var payload: Data?
            repeat {
                payload = try? FreeSnitchWireCodec.encode(FlowObservationBatch(observations: candidate))
                if let payload, payload.count <= InsightsLimits.maxBatchBytes { break }
                candidate.removeLast()
            } while !candidate.isEmpty

            if let payload, payload.count <= InsightsLimits.maxBatchBytes {
                _ = IPCConnection.shared.sendObservationBatch(payload)
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
            self.resumeFlow(flow, with: self.reportingLateDestination(verdict, for: flow, destinationKnown: destinationKnown))
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

    /// DHCP remains exempt for every policy state. Port 53 is exempt only
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
        if conn.remotePort == 67 || conn.remotePort == 68 { return true }
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

    private func connection(from flow: NEFilterSocketFlow) -> Connection {
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
        return Connection(
            pid: Int32(pid),
            processName: name,
            processPath: path,
            processBundleId: bundleIdForApp(atPath: path),
            remoteHost: remoteHost,
            remoteIP: remoteIP,
            remotePort: port,
            direction: flow.direction == .outbound ? .outgoing : .incoming,
            status: .pending
        )
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

    /// Best-effort bundle id from the .app enclosing the executable.
    /// (`NEFilterFlow.sourceAppIdentifier` is unavailable on macOS.)
    ///
    /// Memory only. The verdict path must never wait on a filesystem read, so
    /// an unresolved path answers nil here, exactly like an executable that
    /// lives outside an .app bundle already does, and the Info.plist read runs
    /// on a background queue for the benefit of later flows.
    private func bundleIdForApp(atPath path: String) -> String? {
        bundleIdentifierCache.cachedBundleId(forExecutablePath: path)
    }

    // MARK: - Rule snapshot

    private func loadBootSnapshot(_ data: Data) {
        do {
            let decoded = try SharedRuleBridge.decodeBootSnapshot(data)
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

    private func receiveSnapshot(_ data: Data) -> SharedRuleBridge.SnapshotStatus {
        do {
            let received = try SharedRuleBridge.decode(data)
            let status = SharedRuleBridge.SnapshotStatus.ready(for: received)
            snapshotLock.lock()
            setSnapshotLocked(received)
            snapshotOrigin = .live
            snapshotStatus = status
            snapshotLock.unlock()

            let allowCount = received.rules.filter { $0.action == .allow }.count
            let denyCount = received.rules.filter { $0.action == .deny }.count
            let askCount = received.rules.filter { $0.action == .ask }.count
            PSLog.info(PSLog.netext,
                       "filter snapshot received over XPC: mode \(received.mode.rawValue), "
                       + "\(received.rules.count) rules (allow \(allowCount), deny \(denyCount), ask \(askCount))")
            // Persistence is owned by the GUI through NEFilterManager. A live
            // XPC update changes only this in-memory policy and never waits on
            // disk, XPC, or another transport.
            return status
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
/// `cachedBundleId(forExecutablePath:)` is memory only: it holds the lock just
/// long enough for one dictionary lookup, and no lock holder ever touches the
/// filesystem. Every Info.plist read happens on `resolveQueue`, so a cache
/// miss answers nil immediately rather than blocking `handleNewFlow`, and only
/// one read is scheduled per path even during a burst of new flows.
///
/// The key is the executable path exactly as `proc_pidpath` reports it, not the
/// enclosing .app, because splitting the path allocates a string and that
/// allocation dominated the lookup. Finding the .app and reading its plist both
/// belong to the background resolve. An executable outside an .app bundle is
/// cached as nil, which is the answer the filter already gives it.
///
/// Bound: at most `capacity` executable paths. When the map is full the path
/// that was resolved longest ago is evicted (first resolved, first out), so
/// this long-lived root-adjacent process cannot grow the map without limit.
/// Eviction runs on `resolveQueue`, never on the verdict path.
///
/// Staleness: a path can be reused by a replaced app, so an entry older than
/// `entryLifetime` is re-read in the background while the previous identifier
/// is still answered from memory. The stale window is therefore bounded by the
/// lifetime plus one background read, and an identifier is never invented for
/// a path that has not been read at least once.
final class BundleIdentifierCache: @unchecked Sendable {
    private struct Entry {
        let bundleId: String?
        let resolvedAtNanos: UInt64
    }

    let capacity: Int
    let entryLifetime: TimeInterval

    private var entries: [String: Entry] = [:]
    private var evictionOrder: [String] = []
    private var pending: Set<String> = []
    private let lifetimeNanos: UInt64
    /// Stable address for the whole lifetime of the cache. A Swift property of
    /// type `os_unfair_lock_s` gives no such guarantee, and a lock that moves
    /// is not a lock.
    private let lock: UnsafeMutablePointer<os_unfair_lock_s>
    private let resolveQueue = DispatchQueue(label: "io.isaaclins.freesnitch.netext.bundleid", qos: .utility)
    private let read: @Sendable (String) -> String?

    init(capacity: Int = 512,
         entryLifetime: TimeInterval = 300,
         read: @escaping @Sendable (String) -> String? = { BundleIdentifierCache.readBundleIdentifier(atAppPath: $0) }) {
        precondition(capacity > 0)
        precondition(entryLifetime > 0)
        self.capacity = capacity
        self.entryLifetime = entryLifetime
        self.lifetimeNanos = UInt64(entryLifetime * 1_000_000_000)
        self.read = read
        self.lock = .allocate(capacity: 1)
        self.lock.initialize(to: os_unfair_lock_s())
    }

    deinit {
        lock.deinitialize(count: 1)
        lock.deallocate()
    }

    /// Verdict path. A known path is answered from memory with no I/O. A path
    /// seen for the first time is resolved inline, because `RuleMatcher`
    /// treats a nil bundle identifier as "does not match", so answering nil
    /// here would silently exempt an app's first flows from every
    /// bundle-id-scoped rule. #38 is about reading the plist once per app
    /// rather than once per flow, not about never reading it on this path.
    func cachedBundleId(forExecutablePath path: String) -> String? {
        guard !path.isEmpty else { return nil }
        let now = DispatchTime.now().uptimeNanoseconds
        os_unfair_lock_lock(lock)
        let entry = entries[path]
        let stale = entry.map { now &- $0.resolvedAtNanos >= lifetimeNanos } ?? false
        // A present entry is refreshed in the background, which can never
        // regress an answer to nil. The pending set is bounded by the same
        // capacity, so a flood of distinct paths cannot grow it without limit
        // or schedule the same read twice.
        let shouldRefresh = entry != nil && stale && !pending.contains(path) && pending.count < capacity
        if shouldRefresh { pending.insert(path) }
        os_unfair_lock_unlock(lock)
        if shouldRefresh {
            resolveQueue.async { [weak self] in self?.resolve(path) }
        }
        if let entry { return entry.bundleId }
        return resolveInline(path, now: now)
    }

    /// First sighting of a path. The lock is not held across the filesystem
    /// read, and a concurrent resolver that won the race is preferred.
    private func resolveInline(_ path: String, now: UInt64) -> String? {
        let bundleId = Self.appBundlePath(forExecutablePath: path).flatMap(read)
        os_unfair_lock_lock(lock)
        defer { os_unfair_lock_unlock(lock) }
        if let existing = entries[path] { return existing.bundleId }
        insertLocked(path, entry: Entry(bundleId: bundleId, resolvedAtNanos: now))
        return bundleId
    }

    /// Background only.
    private func resolve(_ path: String) {
        let bundleId = Self.appBundlePath(forExecutablePath: path).flatMap(read)
        let now = DispatchTime.now().uptimeNanoseconds
        os_unfair_lock_lock(lock)
        defer { os_unfair_lock_unlock(lock) }
        pending.remove(path)
        insertLocked(path, entry: Entry(bundleId: bundleId, resolvedAtNanos: now))
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

    /// The one filesystem read, reached only from `resolveQueue`.
    static func readBundleIdentifier(atAppPath appPath: String) -> String? {
        let plist = (appPath as NSString).appendingPathComponent("Contents/Info.plist")
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: plist)),
              let dict = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            return nil
        }
        return dict["CFBundleIdentifier"] as? String
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
