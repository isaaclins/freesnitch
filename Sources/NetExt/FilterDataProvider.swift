//
//  FilterDataProvider.swift
//  FreeSnitch Network System Extension
//
//  A NEFilterDataProvider content filter (the same mechanism Little Snitch
//  uses). Every new socket flow is evaluated against the rule set restored from
//  the helper cache or delivered over XPC by the GUI. Flows with no decisive rule are PAUSED
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
    private let matcher = RuleMatcher()
    private let bootPolicy = BootPolicyClient()
    private let resolverBypass = ResolverBypass()
    private let staleSilentDenyAge: TimeInterval = 24 * 60 * 60
    private let blocklistRefreshInterval: TimeInterval = 30
    private let snapshotLock = NSLock()
    private let blocklistLock = NSLock()
    private var snapshot: SharedRuleBridge.Snapshot?
    private var snapshotStatus = SharedRuleBridge.SnapshotStatus.unavailable(
        "Network extension has not received a rule snapshot from the GUI."
    )
    private var blocklistIndex = BlocklistBridge.Index.empty
    private var blocklistGeneration: String?
    private var blocklistSyncEnabled = false
    private let workQueue = DispatchQueue(label: "io.isaaclins.freesnitch.netext.work")
    private let askTimeout: TimeInterval = 60

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
        PSLog.error(
            PSLog.netext,
            "FILTER NOT READY: no rule snapshot received over XPC; loading the helper boot cache before allowing flows."
        )
        bootPolicy.load { [weak self] data in
            guard let self else {
                completionHandler(nil)
                return
            }
            if let data {
                self.loadBootSnapshot(data)
            } else {
                PSLog.error(
                    PSLog.netext,
                    "boot policy cache missing or unreadable; allowing flows until a trusted GUI snapshot arrives"
                )
            }
            self.startFilterAfterBootSnapshot(completionHandler: completionHandler)
        }
    }

    private func startFilterAfterBootSnapshot(completionHandler: @escaping (Error?) -> Void) {
        IPCConnection.shared.startListener()
        startBlocklistSync()
        // Empty rule list + .filterData default => every flow reaches handleNewFlow.
        // handleNewFlow explicitly allows flows until a valid snapshot exists.
        let settings = NEFilterSettings(rules: [], defaultAction: .filterData)
        apply(settings) { error in completionHandler(error) }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        blocklistLock.lock()
        blocklistSyncEnabled = false
        blocklistIndex = .empty
        blocklistGeneration = nil
        blocklistLock.unlock()
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else { return .allow() }
        let conn = connection(from: socketFlow)
        // FreeSnitch must never hold up its own traffic. The helper shells out
        // to nettop and lsof to observe connections, and pausing those to ask
        // the user deadlocks the app that is supposed to answer the question.
        if isOwnTraffic(conn) || isLoopback(conn.remoteIP) { return .allow() }
        if isDNSOrDHCP(conn) { return .allow() }
        if currentBlocklist().contains(remoteHost: conn.remoteHost, remoteIP: conn.remoteIP) {
            return .drop()
        }
        guard let snapshot = currentSnapshot() else {
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

    /// Keep DHCP available everywhere, but let port 53 bypass policy only for
    /// configured resolvers. If resolver configuration cannot be read, the
    /// resolver helper fails open so names can still be resolved.
    private func isDNSOrDHCP(_ conn: Connection) -> Bool {
        if conn.remotePort == 67 || conn.remotePort == 68 { return true }
        return conn.remotePort == 53 && resolverBypass.allowsDNS(to: conn.remoteIP)
    }

    private func currentBlocklist() -> BlocklistBridge.Index {
        blocklistLock.lock()
        defer { blocklistLock.unlock() }
        return blocklistIndex
    }

    private func startBlocklistSync() {
        blocklistLock.lock()
        blocklistSyncEnabled = true
        blocklistLock.unlock()
        loadBlocklistSnapshot()
    }

    private func loadBlocklistSnapshot() {
        blocklistLock.lock()
        guard blocklistSyncEnabled else {
            blocklistLock.unlock()
            return
        }
        let generation = blocklistGeneration ?? ""
        blocklistLock.unlock()

        bootPolicy.loadBlocklistSnapshot(since: generation) { [weak self] newGeneration, data in
            guard let self else { return }
            self.receiveBlocklistSnapshot(generation: newGeneration, data: data)
            self.scheduleBlocklistSync()
        }
    }

    private func scheduleBlocklistSync() {
        blocklistLock.lock()
        let enabled = blocklistSyncEnabled
        blocklistLock.unlock()
        guard enabled else { return }
        workQueue.asyncAfter(deadline: .now() + blocklistRefreshInterval) { [weak self] in
            self?.loadBlocklistSnapshot()
        }
    }

    private func receiveBlocklistSnapshot(generation: String?, data: Data?) {
        blocklistLock.lock()
        guard blocklistSyncEnabled else {
            blocklistLock.unlock()
            return
        }
        let previousGeneration = blocklistGeneration

        guard let generation, let data else {
            blocklistIndex = .empty
            blocklistGeneration = nil
            blocklistLock.unlock()
            PSLog.error(PSLog.netext, "blocklist snapshot unavailable; blocklist filtering is failing open")
            return
        }

        if data.isEmpty {
            if previousGeneration == generation {
                blocklistLock.unlock()
                return
            }
            blocklistIndex = .empty
            blocklistGeneration = nil
            blocklistLock.unlock()
            PSLog.error(PSLog.netext, "blocklist snapshot changed without a payload; filtering is failing open")
            return
        }

        do {
            let index = try BlocklistBridge.Index(snapshotData: data)
            blocklistIndex = index
            blocklistGeneration = generation
            blocklistLock.unlock()
        } catch {
            blocklistIndex = .empty
            blocklistGeneration = nil
            blocklistLock.unlock()
            PSLog.error(PSLog.netext, "blocklist snapshot rejected; blocklist filtering is failing open: \(error)")
        }
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
    private func bundleIdForApp(atPath path: String) -> String? {
        guard !path.isEmpty, let r = path.range(of: ".app/", options: .backwards) else { return nil }
        let appPath = String(path[..<r.upperBound])
        let plist = (appPath as NSString).appendingPathComponent("Contents/Info.plist")
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: plist)),
              let dict = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            return nil
        }
        return dict["CFBundleIdentifier"] as? String
    }

    // MARK: - Rule snapshot

    private func loadBootSnapshot(_ data: Data) {
        do {
            var received = try SharedRuleBridge.decode(data)
            if received.mode == .silentDeny {
                let age = Date().timeIntervalSince(received.updatedAt)
                if age < 0 || age > staleSilentDenyAge {
                    received.mode = .alert
                    PSLog.error(
                        PSLog.netext,
                        "stale silent-deny boot policy downgraded to alert; explicit deny rules remain active and unanswered asks fail open"
                    )
                }
            }
            let status = SharedRuleBridge.SnapshotStatus.ready(for: received)
            snapshotLock.lock()
            snapshot = received
            snapshotStatus = status
            snapshotLock.unlock()

            PSLog.info(
                PSLog.netext,
                "boot policy snapshot loaded from helper cache: mode \(received.mode.rawValue), \(received.rules.count) rules"
            )
        } catch {
            let status = SharedRuleBridge.SnapshotStatus.invalid(
                "Network extension boot policy cache was invalid: \(error.localizedDescription)"
            )
            snapshotLock.lock()
            snapshot = nil
            snapshotStatus = status
            snapshotLock.unlock()
            PSLog.error(PSLog.netext, status.message ?? "Network extension boot policy cache was invalid.")
        }
    }

    private func receiveSnapshot(_ data: Data) -> SharedRuleBridge.SnapshotStatus {
        do {
            let received = try SharedRuleBridge.decode(data)
            let status = SharedRuleBridge.SnapshotStatus.ready(for: received)
            snapshotLock.lock()
            snapshot = received
            snapshotStatus = status
            snapshotLock.unlock()

            let allowCount = received.rules.filter { $0.action == .allow }.count
            let denyCount = received.rules.filter { $0.action == .deny }.count
            let askCount = received.rules.filter { $0.action == .ask }.count
            PSLog.info(PSLog.netext,
                       "filter snapshot received over XPC: mode \(received.mode.rawValue), "
                       + "\(received.rules.count) rules (allow \(allowCount), deny \(denyCount), ask \(askCount))")
            // The helper validates and atomically stores only this already
            // decoded snapshot. A cache write failure does not affect the
            // currently active policy.
            bootPolicy.store(data)
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

    private func currentSnapshot() -> SharedRuleBridge.Snapshot? {
        snapshotLock.lock()
        defer { snapshotLock.unlock() }
        return snapshot
    }

    private func readSnapshotStatus() -> SharedRuleBridge.SnapshotStatus {
        snapshotLock.lock()
        defer { snapshotLock.unlock() }
        return snapshotStatus
    }
}
#endif
