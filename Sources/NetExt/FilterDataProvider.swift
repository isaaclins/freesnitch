//
//  FilterDataProvider.swift
//  PureSnitch Network System Extension
//
//  A NEFilterDataProvider content filter (the same mechanism Little Snitch
//  uses). Every new socket flow is evaluated against the rule set mirrored into
//  the app-group container by the GUI. Flows with no decisive rule are PAUSED
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
    private var snapshot = SharedRuleBridge.Snapshot(mode: .alert, rules: [])
    private var reloadTimer: DispatchSourceTimer?
    private let workQueue = DispatchQueue(label: "io.moamenbasel.puresnitch.netext.work")
    private let askTimeout: TimeInterval = 60

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        IPCConnection.shared.startListener()
        loadRules()
        startReloadTimer()
        // Empty rule list + .filterData default => every flow reaches handleNewFlow.
        let settings = NEFilterSettings(rules: [], defaultAction: .filterData)
        apply(settings) { error in completionHandler(error) }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        reloadTimer?.cancel()
        reloadTimer = nil
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else { return .allow() }
        let conn = connection(from: socketFlow)
        // PureSnitch must never hold up its own traffic. The helper shells out
        // to nettop and lsof to observe connections, and pausing those to ask
        // the user deadlocks the app that is supposed to answer the question.
        if isOwnTraffic(conn) || isLoopback(conn.remoteIP) { return .allow() }
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
        let endpoint = flow.remoteEndpoint as? NWHostEndpoint
        let host = endpoint?.hostname ?? ""
        let port = Int(endpoint?.port ?? "0") ?? 0
        let pid = flow.sourceAppAuditToken.flatMap(auditTokenToPID) ?? 0
        let path = pid > 0 ? pathForPID(pid) : ""
        let name = path.isEmpty ? "Unknown" : (path as NSString).lastPathComponent
        return Connection(
            pid: Int32(pid),
            processName: name,
            processPath: path,
            processBundleId: bundleIdForApp(atPath: path),
            remoteHost: host,
            remoteIP: host,
            remotePort: port,
            direction: flow.direction == .outbound ? .outgoing : .incoming,
            status: .pending
        )
    }

    private func auditTokenToPID(_ data: Data) -> Int? {
        guard data.count >= MemoryLayout<audit_token_t>.size else { return nil }
        var token = audit_token_t()
        _ = withUnsafeMutableBytes(of: &token) { data.copyBytes(to: $0, count: $0.count) }
        // token.val.5 is the pid — avoids linking libbsm for audit_token_to_pid.
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

    // MARK: - Rules

    private func loadRules() { snapshot = SharedRuleBridge.read() }

    private func startReloadTimer() {
        let t = DispatchSource.makeTimerSource(queue: workQueue)
        t.schedule(deadline: .now() + 2, repeating: .seconds(2))
        t.setEventHandler { [weak self] in self?.loadRules() }
        t.resume()
        reloadTimer = t
    }
}
#endif
