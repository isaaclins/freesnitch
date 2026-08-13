//
//  FilterDataProvider.swift
//  FreeSnitch Network System Extension
//
//  A NEFilterDataProvider content filter (the same mechanism Little Snitch
//  uses). Every new socket flow is evaluated against the rule set delivered
//  over XPC by the GUI. Flows with no decisive rule are PAUSED
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
    private let snapshotLock = NSLock()
    private var snapshot: SharedRuleBridge.Snapshot?
    private var snapshotStatus = SharedRuleBridge.SnapshotStatus.unavailable(
        "Network extension has not received a rule snapshot from the GUI."
    )
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
        PSLog.error(PSLog.netext,
                    "FILTER NOT READY: no rule snapshot received over XPC; allowing flows until the GUI delivers one.")
        IPCConnection.shared.startListener()
        // Empty rule list + .filterData default => every flow reaches handleNewFlow.
        // handleNewFlow explicitly allows flows until a valid XPC snapshot exists.
        let settings = NEFilterSettings(rules: [], defaultAction: .filterData)
        apply(settings) { error in completionHandler(error) }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else { return .allow() }
        let conn = connection(from: socketFlow)
        // FreeSnitch must never hold up its own traffic. The helper shells out
        // to nettop and lsof to observe connections, and pausing those to ask
        // the user deadlocks the app that is supposed to answer the question.
        if isOwnTraffic(conn) || isLoopback(conn.remoteIP) { return .allow() }
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
        let requirementText = [AppConstants.bundleIdGUI, AppConstants.bundleIdHelper, AppConstants.bundleIdNetExt]
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
