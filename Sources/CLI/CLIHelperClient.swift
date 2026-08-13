import Foundation

struct HelperOperationReply: Encodable {
    let succeeded: Bool
    let message: String?
}

private struct AuthoritativeSnapshotReply {
    let supported: Bool
    let data: Data
}

/// Direct client for the root daemon. The connection construction deliberately
/// mirrors GUI/App/HelperClient.swift, including the privileged lookup option.
final class CLIHelperClient: NSObject {
    private var connection: NSXPCConnection?
    private(set) var observedVersion: String?
    private let eventReceiver = CLIEventReceiver()
    private let timeout: TimeInterval = 15

    func prepare(timeout: TimeInterval = 15) async throws -> HelperStatus {
        let version = try await perform(timeout: timeout) { proxy, reply in
            proxy.getVersion(reply: reply)
        }
        observedVersion = version
        guard !version.isEmpty else {
            throw CLIError(.helperUnreachable,
                           message: "The FreeSnitch helper answered with an empty version.",
                           remediation: "Run `freesnitch settings helper recheck`, then approve FreeSnitch in System Settings > General > Login Items & Extensions.")
        }
        guard AppConstants.identityMatches(reported: version, expected: CLIAppBundle.expectedBuildIdentity) else {
            throw CLIError(.helperVersionMismatch,
                           message: "The helper process is running version \(version), but the installed app is version \(CLIAppBundle.expectedBuildIdentity). Helper-side fixes in the installed build are not active.",
                           remediation: "The helper is still running from an earlier build. Do not unregister it. Run `\(AppConstants.helperKickstartCommand)` while launchd still has the service registered, then rerun the command.",
                           observedHelperVersion: version)
        }
        let data: Data = try await perform(timeout: timeout) { proxy, reply in
            proxy.getStatus(reply: reply)
        }
        guard !data.isEmpty else {
            throw CLIError(.helperUnreachable,
                           message: "The helper returned an empty status response.",
                           remediation: "Run `freesnitch settings helper recheck` and inspect the helper logs.")
        }
        do {
            return try FreeSnitchWireCodec.decode(HelperStatus.self, from: data)
        } catch {
            throw CLIError(.operationFailed,
                           message: "The helper returned a status payload this CLI could not decode: \(error.localizedDescription).",
                           remediation: "Use matching FreeSnitch app and helper versions, then run `freesnitch doctor`.")
        }
    }

    func setMode(_ mode: AppMode) async throws {
        try await requireSuccess(timeout: timeout) { proxy, reply in
            proxy.setMode(rawValue: mode.rawValue, reply: reply)
        }
    }

    func listRules(profile: String = "") async throws -> [Rule] {
        let data: Data = try await perform { proxy, reply in
            proxy.listRules(profile: profile, reply: reply)
        }
        return try decode([Rule].self, data: data, what: "rules")
    }

    /// The helper owns policy mode, rules, and generation. A helper that does
    /// not implement this optional getter is too old to participate in a safe
    /// live snapshot sync, so there is deliberately no cached fallback.
    func authoritativeSnapshot() async throws -> SharedRuleBridge.Snapshot {
        let response: AuthoritativeSnapshotReply = try await perform { proxy, reply in
            guard proxy.getAuthoritativeSnapshot != nil else {
                reply(AuthoritativeSnapshotReply(supported: false, data: Data()))
                return
            }
            proxy.getAuthoritativeSnapshot?(reply: { data in
                reply(AuthoritativeSnapshotReply(supported: true, data: data))
            })
        }
        guard response.supported else {
            throw CLIError(.helperVersionMismatch,
                           code: "authoritative_snapshot_unsupported",
                           message: "The running helper does not support authoritative rule snapshots.",
                           remediation: AppConstants.helperKickstartCommand)
        }
        guard !response.data.isEmpty else {
            throw CLIError(.operationFailed,
                           code: "authoritative_snapshot_invalid",
                           message: "The helper returned an empty authoritative rule snapshot.",
                           remediation: "Run `\(AppConstants.helperKickstartCommand)`, then retry.")
        }
        do {
            return try SharedRuleBridge.decode(response.data)
        } catch {
            throw CLIError(.operationFailed,
                           message: "The helper returned invalid authoritative rule snapshot data: \(error.localizedDescription).",
                           remediation: "Run `freesnitch doctor` and check that the app and helper versions match.")
        }
    }

    func addRule(_ rule: Rule) async throws {
        try await requireSuccess(timeout: timeout) { proxy, reply in
            guard let data = try? RuleTransportBoundary.encodeSingleRule(rule) else {
                reply(false, "could not encode rule within the single-rule transport limits")
                return
            }
            proxy.addRule(ruleJSON: data, reply: reply)
        }
    }

    func removeRule(_ id: UUID) async throws {
        try await requireSuccess(timeout: timeout) { proxy, reply in
            proxy.removeRule(idString: id.uuidString, reply: reply)
        }
    }

    func importRules(_ rules: [Rule]) async throws {
        try await requireSuccess(timeout: timeout) { proxy, reply in
            guard let data = try? RuleTransportBoundary.encodeRuleBatch(rules) else {
                reply(false, "could not encode imported rules within the rule-batch transport limits")
                return
            }
            proxy.reloadRules(rulesJSON: data, reply: reply)
        }
    }

    func connections() async throws -> [Connection] {
        let data: Data = try await perform { proxy, reply in
            proxy.currentConnections(reply: reply)
        }
        return try decode([Connection].self, data: data, what: "connections")
    }

    func trafficSamples() async throws -> [TrafficSample] {
        let data: Data = try await perform { proxy, reply in
            proxy.currentTrafficSample(reply: reply)
        }
        if let samples = try? FreeSnitchWireCodec.decode([TrafficSample].self, from: data) {
            return samples
        }
        let sample: TrafficSample = try decode(TrafficSample.self, data: data, what: "traffic sample")
        return [sample]
    }

    func processUsage() async throws -> [ProcessUsage] {
        let data: Data = try await perform { proxy, reply in
            proxy.currentProcessUsage(reply: reply)
        }
        return try decode([ProcessUsage].self, data: data, what: "process usage")
    }

    func blocklists() async throws -> [BlocklistInfo] {
        let data: Data = try await perform { proxy, reply in
            proxy.listBlocklists(reply: reply)
        }
        return try decode([BlocklistInfo].self, data: data, what: "blocklists")
    }

    func setBlocklist(id: String, enabled: Bool) async throws {
        try await requireSuccess(timeout: timeout) { proxy, reply in
            proxy.enableBlocklist(idString: id, enabled: enabled, reply: reply)
        }
    }

    func refreshBlocklists() async throws {
        try await requireSuccess(timeout: 120) { proxy, reply in
            proxy.refreshBlocklists(reply: reply)
        }
    }

    func getDoH() async throws -> String {
        let value: String? = try await perform(timeout: timeout) { proxy, reply in
            guard proxy.getDoHUpstream != nil else {
                reply(nil)
                return
            }
            proxy.getDoHUpstream?(reply: { reply($0) })
        }
        guard let value else {
            throw CLIError(.helperVersionMismatch,
                           message: "The running helper does not support reading the effective DoH upstream.",
                           remediation: "The helper is still running from an earlier build. Run `\(AppConstants.helperKickstartCommand)`, then rerun the command.")
        }
        return value
    }

    func setDoH(url: String) async throws {
        try await requireSuccess(timeout: timeout) { proxy, reply in
            proxy.setDoHUpstream(url: url, reply: reply)
        }
    }

    func setEnforcement(_ enabled: Bool) async throws {
        try await requireSuccess(timeout: timeout) { proxy, reply in
            proxy.setEnforcementEnabled(enabled, reply: reply)
        }
    }

    func installPF() async throws {
        try await requireSuccess(timeout: timeout) { proxy, reply in
            proxy.installPF(reply: reply)
        }
    }

    func uninstallPF() async throws {
        try await requireSuccess(timeout: timeout) { proxy, reply in
            proxy.uninstallPF(reply: reply)
        }
    }

    func flush() async throws {
        try await requireSuccess(timeout: timeout) { proxy, reply in
            proxy.flushAll(reply: reply)
        }
    }

    func recentBlocked(limit: Int) async throws -> [Connection] {
        let data: Data = try await perform { proxy, reply in
            proxy.recentBlocked(limit: limit, reply: reply)
        }
        return try decode([Connection].self, data: data, what: "blocked connections")
    }

    func recentDenied(limit: Int) async throws -> [Connection] {
        let data: Data = try await perform { proxy, reply in
            proxy.recentDenied(limit: limit, reply: reply)
        }
        return try decode([Connection].self, data: data, what: "denied connections")
    }

    private func makeConnection() -> NSXPCConnection {
        let conn = NSXPCConnection(machServiceName: AppConstants.xpcMachServiceName, options: [.privileged])
        conn.remoteObjectInterface = HelperBridge.remoteInterface()
        conn.exportedInterface = HelperBridge.exportedInterface()
        conn.exportedObject = eventReceiver
        conn.invalidationHandler = { }
        conn.interruptionHandler = { }
        conn.resume()
        connection = conn
        return conn
    }

    private func proxy(withErrorHandler handler: @escaping (Error) -> Void) throws -> HelperProtocol {
        let conn = connection ?? makeConnection()
        guard let proxy = conn.remoteObjectProxyWithErrorHandler(handler) as? HelperProtocol else {
            throw CLIError(.helperUnreachable,
                           message: "The helper XPC proxy could not be created.",
                           remediation: "Approve the FreeSnitch helper and use the bundled CLI from the same app.")
        }
        return proxy
    }

    private func perform<T>(timeout: TimeInterval? = nil,
                            _ invoke: @escaping (HelperProtocol, @escaping (T) -> Void) -> Void) async throws -> T {
        let result: Result<T, Error> = await withCheckedContinuation { continuation in
            let lock = NSLock()
            var finished = false
            var timeoutWork: DispatchWorkItem?
            let finish: (Result<T, Error>) -> Void = { result in
                lock.lock()
                guard !finished else {
                    lock.unlock()
                    return
                }
                finished = true
                lock.unlock()
                timeoutWork?.cancel()
                continuation.resume(returning: result)
            }

            do {
                let proxy = try proxy { error in
                    finish(.failure(CLIError(.helperUnreachable,
                                             message: "The helper XPC request failed: \(error.localizedDescription).",
                                             remediation: "Run `freesnitch settings helper recheck` and approve the helper in Login Items.")))
                }
                let work = DispatchWorkItem {
                    finish(.failure(CLIError(.helperUnreachable,
                                             message: "The helper did not answer within \(Int(timeout ?? self.timeout)) seconds.",
                                             remediation: "Run `freesnitch doctor`; the helper may be unapproved, stopped, or from a different build.")))
                }
                timeoutWork = work
                DispatchQueue.global().asyncAfter(deadline: .now() + (timeout ?? self.timeout), execute: work)
                invoke(proxy) { value in finish(.success(value)) }
            } catch {
                finish(.failure(error))
            }
        }
        return try result.get()
    }

    private func requireSuccess(timeout: TimeInterval,
                                _ invoke: @escaping (HelperProtocol, @escaping (Bool, String?) -> Void) -> Void) async throws {
        let reply: HelperOperationReply = try await perform(timeout: timeout) { proxy, completion in
            invoke(proxy) { ok, message in
                completion(HelperOperationReply(succeeded: ok, message: message))
            }
        }
        guard reply.succeeded else {
            throw CLIError(.operationFailed,
                           message: reply.message ?? "The helper refused the operation.",
                           remediation: "Run `freesnitch doctor` for helper and pf diagnostics.")
        }
    }

    private func decode<T: Decodable>(_ type: T.Type, data: Data, what: String) throws -> T {
        do {
            return try FreeSnitchWireCodec.decode(type, from: data)
        } catch {
            throw CLIError(.operationFailed,
                           message: "The helper returned invalid \(what) data: \(error.localizedDescription).",
                           remediation: "Run `freesnitch doctor` and check that the app and helper versions match.")
        }
    }
}

final class CLIEventReceiver: NSObject, HelperClientProtocol {
    func notifyConnection(connectionJSON: Data) {}
    func notifyTraffic(sampleJSON: Data) {}
    func notifyProcessUsage(usageJSON: Data) {}
    func notifyAlert(connectionJSON: Data, reply: @escaping (Bool, Bool) -> Void) {
        // A one-shot CLI has no alert UI. Always answer allow so an incidental
        // helper callback cannot turn the CLI into a network lockout.
        reply(true, false)
    }
    func notifyLog(level: String, message: String) {}
}
