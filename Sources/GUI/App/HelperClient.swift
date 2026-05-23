import Foundation
import ServiceManagement

@MainActor
final class HelperClient: NSObject, ObservableObject {
    @Published var connected: Bool = false
    @Published var status: HelperStatus?

    private var connection: NSXPCConnection?
    weak var state: AppState?

    func connect() {
        let conn = NSXPCConnection(machServiceName: AppConstants.xpcMachServiceName, options: [.privileged])
        conn.remoteObjectInterface = HelperBridge.remoteInterface()
        conn.exportedInterface = HelperBridge.exportedInterface()
        conn.exportedObject = HelperEventReceiver(state: state)
        conn.invalidationHandler = { [weak self] in
            Task { @MainActor in self?.connected = false }
        }
        conn.interruptionHandler = { [weak self] in
            Task { @MainActor in self?.connected = false }
        }
        conn.resume()
        self.connection = conn
        ping()
    }

    var remote: HelperProtocol? {
        connection?.remoteObjectProxyWithErrorHandler { _ in } as? HelperProtocol
    }

    func ping() {
        remote?.getVersion { [weak self] version in
            Task { @MainActor in
                self?.connected = !version.isEmpty
            }
        }
        remote?.getStatus { [weak self] data in
            let status = try? JSONDecoder().decode(HelperStatus.self, from: data)
            Task { @MainActor in self?.status = status }
        }
    }

    func setMode(_ m: AppMode) {
        remote?.setMode(rawValue: m.rawValue) { _, _ in }
    }

    func addRule(_ rule: Rule) {
        guard let data = try? JSONEncoder().encode(rule) else { return }
        remote?.addRule(ruleJSON: data) { _, _ in }
    }

    func removeRule(id: UUID) {
        remote?.removeRule(idString: id.uuidString) { _, _ in }
    }

    func listRules(profile: String = "", completion: @MainActor @escaping ([Rule]) -> Void) {
        remote?.listRules(profile: profile) { data in
            let rules = (try? JSONDecoder().decode([Rule].self, from: data)) ?? []
            Task { @MainActor in completion(rules) }
        }
    }

    func startMonitoring() {
        remote?.startMonitoring { _, _ in }
    }

    func refreshBlocklists() {
        remote?.refreshBlocklists { _, _ in }
    }

    func installPF() {
        remote?.installPF { _, _ in }
    }

    func uninstallPF() {
        remote?.uninstallPF { _, _ in }
    }
}

final class HelperEventReceiver: NSObject, HelperClientProtocol {
    weak var state: AppState?
    init(state: AppState?) { self.state = state }

    func notifyConnection(connectionJSON: Data) {
        guard let conns = try? JSONDecoder().decode([Connection].self, from: connectionJSON) else { return }
        Task { @MainActor in self.state?.updateConnections(conns) }
    }

    func notifyTraffic(sampleJSON: Data) {
        guard let sample = try? JSONDecoder().decode(TrafficSample.self, from: sampleJSON) else { return }
        Task { @MainActor in self.state?.appendSample(sample) }
    }

    func notifyAlert(connectionJSON: Data, reply: @escaping (Bool, Bool) -> Void) {
        guard let conn = try? JSONDecoder().decode(Connection.self, from: connectionJSON) else { reply(true, false); return }
        Task { @MainActor in self.state?.presentAlert(for: conn, reply: reply) }
    }

    func notifyLog(level: String, message: String) {
        Task { @MainActor in self.state?.appendLog(level: level, message: message) }
    }
}
