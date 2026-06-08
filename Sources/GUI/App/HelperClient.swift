import Foundation
import ServiceManagement

@MainActor
final class HelperClient: NSObject, ObservableObject {
    @Published var connected: Bool = false
    @Published var status: HelperStatus?

    private var connection: NSXPCConnection?
    private var didBootstrap = false
    weak var state: AppState?

    /// Registers the privileged helper as a launchd daemon via SMAppService.
    /// Without this the XPC mach service never exists, so every helper call
    /// silently no-ops (the root cause of "no rules / no traffic"). Requires a
    /// signed build; the user approves it in System Settings → Login Items.
    func registerDaemon() {
        guard #available(macOS 13.0, *) else { return }
        let service = SMAppService.daemon(plistName: "io.moamenbasel.puresnitch.helper.plist")
        guard service.status != .enabled else { return }
        do {
            try service.register()
        } catch {
            let message = "Helper registration failed: \(error.localizedDescription). " +
                "Approve PureSnitch in System Settings → General → Login Items."
            Task { @MainActor in self.state?.appendLog(level: "error", message: message) }
        }
    }

    func connect() {
        let conn = NSXPCConnection(machServiceName: AppConstants.xpcMachServiceName, options: [.privileged])
        conn.remoteObjectInterface = HelperBridge.remoteInterface()
        conn.exportedInterface = HelperBridge.exportedInterface()
        conn.exportedObject = HelperEventReceiver(state: state)
        conn.invalidationHandler = { [weak self] in
            Task { @MainActor in self?.setConnected(false) }
        }
        conn.interruptionHandler = { [weak self] in
            Task { @MainActor in self?.setConnected(false) }
        }
        conn.resume()
        self.connection = conn
        ping()
        // The daemon may take a moment to come up (or be approved) after launch;
        // retry a few times so rules/traffic populate without a manual relaunch.
        for delay in [2.0, 5.0, 10.0] {
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in self?.ping() }
        }
    }

    var remote: HelperProtocol? {
        connection?.remoteObjectProxyWithErrorHandler { _ in } as? HelperProtocol
    }

    private func setConnected(_ value: Bool) {
        let wasConnected = connected
        connected = value
        state?.helperConnected = value
        guard value, !wasConnected else { return }
        // First reachable connection runs the full bootstrap; later
        // reconnections only refresh rules so we don't re-run startMonitoring /
        // installPF and duplicate the helper's monitors.
        if didBootstrap {
            state?.refreshRules()
        } else {
            didBootstrap = true
            state?.bootstrap()
        }
    }

    func ping() {
        remote?.getVersion { [weak self] version in
            Task { @MainActor in self?.setConnected(!version.isEmpty) }
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
