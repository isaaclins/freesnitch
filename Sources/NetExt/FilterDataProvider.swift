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

    override init() {
        self.observationSignalLock = .allocate(capacity: 1)
        self.observationSignalLock.initialize(to: os_unfair_lock_s())
        super.init()
    }

    deinit {
        observationSignalLock.deinitialize(count: 1)
        observationSignalLock.deallocate()
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

    private func clearBootSnapshot(_ message: String) {
        snapshotLock.lock()
        let liveSnapshotAlreadyLoaded = snapshotOrigin == .live
        if !liveSnapshotAlreadyLoaded {
            snapshot = nil
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
        switch matcher.decision(for: conn, rules: snapshot.rules, defaultMode: snapshot.mode) {
        case .allow:
            return .allow()
        case .deny:
            return .drop()
        case .ask:
            promptAndResume(flow: flow, conn: conn)
            return .pause()
        }
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
        let resumeOnce: (NEFilterNewFlowVerdict) -> Void = { [weak self] verdict in
            lock.lock(); defer { lock.unlock() }
            guard let self, !settled else { return }
            settled = true
            self.resumeFlow(flow, with: verdict)
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
    private func isDNSOrDHCP(_ conn: Connection, snapshotOrigin: SnapshotOrigin) -> Bool {
        if conn.remotePort == 67 || conn.remotePort == 68 { return true }
        guard conn.remotePort == 53, snapshotOrigin == .boot else { return false }
        return resolverBypass.allowsDNS(to: conn.remoteIP)
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
        let remoteHost = usableRemoteHost(flow.remoteHostname, address: host)
        let remoteIP = literalRemoteAddress(host, fallback: flow.remoteHostname)
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

    /// `remoteHostname` can contain the result of a reverse lookup. A PTR
    /// query name is not a destination, so discard it and retain the endpoint
    /// address instead. This keeps bad data out of alerts and remembered rules,
    /// rather than relying only on the later PF anchor check.
    private func usableRemoteHost(_ candidate: String?, address: String) -> String {
        if let candidate, !candidate.isEmpty {
            if let kind = PFHostValidator.kind(for: candidate) {
                switch kind {
                case .hostname, .ip:
                    return candidate
                case .cidr:
                    break
                }
            }
            PSLog.error(
                PSLog.netext,
                "Ignoring unusable remote hostname '\(candidate)': \(PFHostValidator.rejectionReason(for: candidate)); using the endpoint address instead."
            )
        }

        guard let kind = PFHostValidator.kind(for: address) else { return "" }
        switch kind {
        case .hostname, .ip:
            return address
        case .cidr:
            return ""
        }
    }

    private func literalRemoteAddress(_ address: String, fallback: String?) -> String {
        if PFHostValidator.kind(for: address) == .ip { return address }
        if let fallback, PFHostValidator.kind(for: fallback) == .ip { return fallback }
        let normalized = address.lowercased().hasSuffix(".")
            ? String(address.dropLast()).lowercased()
            : address.lowercased()
        return normalized == "localhost" ? address : ""
    }

    /// `remoteEndpoint` is deprecated and reports the unspecified address
    /// (0.0.0.0 or ::) on current macOS, which is why alerts showed no
    /// destination. `remoteFlowEndpoint` carries the real one.
    private func remoteAddress(of flow: NEFilterSocketFlow) -> (String, Int) {
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
                snapshot = received
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
                snapshot = nil
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
            snapshot = received
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

    private func currentPolicy() -> (snapshot: SharedRuleBridge.Snapshot?, origin: SnapshotOrigin) {
        snapshotLock.lock()
        defer { snapshotLock.unlock() }
        return (snapshot, snapshotOrigin)
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

    /// Verdict path. Never reads from disk, and answers nil for a path that has
    /// not been resolved yet.
    func cachedBundleId(forExecutablePath path: String) -> String? {
        guard !path.isEmpty else { return nil }
        let now = DispatchTime.now().uptimeNanoseconds
        os_unfair_lock_lock(lock)
        let entry = entries[path]
        let stale = entry.map { now &- $0.resolvedAtNanos >= lifetimeNanos } ?? true
        // The pending set is bounded by the same capacity, so a flood of
        // distinct paths can neither grow it without limit nor schedule the
        // same read twice.
        let shouldResolve = stale && !pending.contains(path) && pending.count < capacity
        if shouldResolve { pending.insert(path) }
        os_unfair_lock_unlock(lock)
        if shouldResolve {
            resolveQueue.async { [weak self] in self?.resolve(path) }
        }
        return entry?.bundleId
    }

    /// Background only.
    private func resolve(_ path: String) {
        let bundleId = Self.appBundlePath(forExecutablePath: path).flatMap(read)
        let now = DispatchTime.now().uptimeNanoseconds
        os_unfair_lock_lock(lock)
        defer { os_unfair_lock_unlock(lock) }
        pending.remove(path)
        if entries[path] == nil {
            if entries.count >= capacity, !evictionOrder.isEmpty {
                entries.removeValue(forKey: evictionOrder.removeFirst())
            }
            evictionOrder.append(path)
        }
        entries[path] = Entry(bundleId: bundleId, resolvedAtNanos: now)
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
