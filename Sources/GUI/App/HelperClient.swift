import Foundation
import ServiceManagement
import AppKit

/// Where the privileged helper stands from the user's point of view. macOS
/// registers the daemon on first launch but leaves it *disabled* until the user
/// approves it in System Settings; until then every helper call no-ops and the
/// whole app reads zero. This enum is what the UI shows instead of pretending
/// nothing is wrong.
enum HelperInstallState: Equatable {
    /// Not asked yet.
    case unknown
    /// Registered with launchd but waiting for the user to switch it on in
    /// System Settings under General > Login Items & Extensions.
    case requiresApproval
    /// Approved and running; XPC should be reachable.
    case enabled
    /// Registration was never attempted or was removed.
    case notRegistered
    /// The daemon plist isn't where macOS expects it (broken/unsigned build).
    case notFound
    /// The app is running from the disk image, Downloads, or anywhere else that
    /// isn't an Applications folder. macOS refuses to install background
    /// helpers from there, so registration is not even attempted.
    case wrongLocation
    /// register() itself failed; carries the message from macOS.
    case failed(String)

    var isHealthy: Bool { self == .enabled }
}

enum HelperVersionState: Equatable {
    case unknown
    case matching(String)
    case mismatch(helper: String, app: String)
}

enum HelperRepairState: Equatable {
    case idle
    case inProgress
    case manualRequired(String)
}

enum HelperRecovery {
    static let kickstartCommand = "sudo launchctl kickstart -k system/io.isaaclins.freesnitch.helper"
}

@MainActor
final class HelperClient: NSObject, ObservableObject {
    @Published var connected: Bool = false
    @Published var status: HelperStatus?
    @Published var installState: HelperInstallState = .unknown {
        didSet { state?.helperInstallState = installState }
    }

    private var connection: NSXPCConnection?
    private var pollTimer: Timer?
    private var isRepairing = false
    private var automaticRepairAttemptedVersion: String?
    private var enabledButSilentSince: Date?
    /// Approved but unreachable for long enough that re-registering is worth
    /// offering. Never acted on automatically; see startPolling().
    /// Version string reported by the running daemon, when it answers at all.
    @Published var helperVersion: String?
    @Published var versionState: HelperVersionState = .unknown {
        didSet { state?.helperVersionState = versionState }
    }
    @Published var repairState: HelperRepairState = .idle {
        didSet { state?.helperRepairState = repairState }
    }
    @Published var needsRepair = false {
        didSet { state?.helperNeedsRepair = needsRepair }
    }
    weak var state: AppState?

    private var service: SMAppService? {
        guard #available(macOS 13.0, *) else { return nil }
        return SMAppService.daemon(plistName: "io.isaaclins.freesnitch.helper.plist")
    }

    private var hasVersionMismatch: Bool {
        if case .mismatch = versionState { return true }
        return false
    }

    /// True when the bundle lives somewhere macOS will accept a background
    /// helper from. Launching straight off the mounted DMG is the single most
    /// common way this app ends up looking dead.
    static var isInApplicationsFolder: Bool {
        let path = Bundle.main.bundleURL.resolvingSymlinksInPath().path
        if path.hasPrefix("/Applications/") { return true }
        let userApps = (NSHomeDirectory() as NSString).appendingPathComponent("Applications") + "/"
        return path.hasPrefix(userApps)
    }

    /// Registers the privileged helper as a launchd daemon via SMAppService.
    /// Without this the XPC mach service never exists, so every helper call
    /// silently no-ops (the root cause of "no rules / no traffic"). Requires a
    /// signed build; the user approves it in System Settings under Login Items.
    func registerDaemon() {
        guard Self.isInApplicationsFolder else { installState = .wrongLocation; return }
        guard let service else { installState = .notRegistered; return }
        switch service.status {
        case .enabled:
            installState = .enabled
            return
        case .requiresApproval:
            // Calling register() again here throws EPERM and tells the user
            // nothing useful. The item exists, but it is not switched on yet.
            installState = .requiresApproval
            return
        default:
            break
        }
        do {
            try service.register()
            refreshInstallState()
        } catch {
            let ns = error as NSError
            installState = .failed(ns.localizedFailureReason ?? ns.localizedDescription)
            state?.appendLog(level: "error", message: "Helper registration failed: \(ns.localizedDescription)")
        }
    }

    /// Re-reads the launchd registration so the UI can drop the banner as soon
    /// as the user flips the switch in System Settings.
    func refreshInstallState() {
        guard Self.isInApplicationsFolder else { installState = .wrongLocation; return }
        guard let service else { installState = .notRegistered; return }
        switch service.status {
        case .enabled: installState = .enabled
        case .requiresApproval: installState = .requiresApproval
        case .notRegistered: installState = .notRegistered
        case .notFound: installState = .notFound
        @unknown default: installState = .unknown
        }
    }

    /// Opens the exact System Settings pane where the daemon is approved.
    func openLoginItemsSettings() {
        if #available(macOS 13.0, *) {
            SMAppService.openSystemSettingsLoginItems()
        } else {
            NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension")!)
        }
    }

    /// Removes the launchd registration (used by "Reinstall helper").
    func unregisterDaemon() {
        service?.unregister { [weak self] _ in
            Task { @MainActor in self?.refreshInstallState() }
        }
    }

    /// Re-registers the daemon when SMAppService can manage it. A successful
    /// unregister/register cycle replaces the running process without touching
    /// the pf anchor. If macOS refuses the cycle, the banner gives the user the
    /// privileged launchctl recovery command instead of pretending it worked.
    func repairHelper() {
        repairHelperInternal()
    }

    private func repairHelperInternal() {
        guard !isRepairing else { return }
        repairState = .inProgress
        guard let service else {
            finishRepairFailure("SMAppService cannot manage the helper on this macOS version.")
            return
        }

        switch service.status {
        case .enabled:
            isRepairing = true
            service.unregister { [weak self] error in
                Task { @MainActor in
                    guard let self else { return }
                    if let error {
                        self.finishRepairFailure("SMAppService could not unregister the old helper: \(error.localizedDescription).")
                        return
                    }
                    self.registerReplacement(service: service)
                }
            }
        case .notRegistered:
            registerReplacement(service: service)
        case .requiresApproval:
            refreshInstallState()
            finishRepairFailure("Approve FreeSnitch in System Settings under General > Login Items & Extensions before restarting the helper.")
        case .notFound:
            refreshInstallState()
            finishRepairFailure("The helper is not present in this app bundle.")
        @unknown default:
            refreshInstallState()
            finishRepairFailure("macOS reported an unsupported helper registration state.")
        }
    }

    private func registerReplacement(service: SMAppService) {
        do {
            try service.register()
            refreshInstallState()
            isRepairing = false
            reconnectAndPing(force: true)
        } catch {
            finishRepairFailure("SMAppService could not register the new helper: \(error.localizedDescription). A full root LaunchDaemon restart may require administrator privileges.")
        }
    }

    private func finishRepairFailure(_ message: String) {
        isRepairing = false
        repairState = .manualRequired(message)
        needsRepair = true
    }

    private func makeConnection() -> NSXPCConnection {
        let conn = NSXPCConnection(machServiceName: AppConstants.xpcMachServiceName, options: [.privileged])
        conn.remoteObjectInterface = HelperBridge.remoteInterface()
        conn.exportedInterface = HelperBridge.exportedInterface()
        conn.exportedObject = HelperEventReceiver(state: state)
        let markDisconnected: () -> Void = { [weak self, weak conn] in
            Task { @MainActor in
                guard let self, self.connection === conn else { return }
                self.connection = nil
                self.setConnected(false)
            }
        }
        conn.invalidationHandler = markDisconnected
        conn.interruptionHandler = markDisconnected
        return conn
    }

    func connect() {
        let conn = makeConnection()
        self.connection = conn
        conn.resume()
        ping()
        startPolling()
    }

    /// Keeps checking registration + reachability. Approval happens outside the
    /// app (System Settings), so without polling the user has to relaunch to
    /// see anything change, which reads as "the app does nothing".
    private func startPolling() {
        pollTimer?.invalidate()
        let timer = Timer(timeInterval: 3.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self, !self.isRepairing else { return }
                self.refreshInstallState()
                guard !self.connected else {
                    self.enabledButSilentSince = nil
                    self.needsRepair = false
                    return
                }
                if self.hasVersionMismatch {
                    if self.connection == nil { self.reconnectAndPing() }
                    else { self.ping() }
                    return
                }
                self.reconnectAndPing()

                // Approved but silent (typically after an in-place app update,
                // where the Background Item stays approved but launchd has no
                // job). Surface it after a grace period and let the user decide:
                // repairing means unregister + register, and unregister REVOKES
                // the existing approval, so doing it automatically could throw
                // away a good approval just because XPC was slow to come up.
                guard self.installState == .enabled else {
                    self.enabledButSilentSince = nil
                    self.needsRepair = false
                    return
                }
                let since = self.enabledButSilentSince ?? Date()
                self.enabledButSilentSince = since
                self.needsRepair = Date().timeIntervalSince(since) > 20
            }
        }
        RunLoop.main.add(timer, forMode: .common)
        pollTimer = timer
    }

    private func reconnectAndPing(force: Bool = false) {
        // A connection made before the daemon existed stays invalid forever, so
        // rebuild it rather than pinging a dead proxy.
        if force || connection == nil || installState == .enabled {
            connection?.invalidate()
            let conn = makeConnection()
            connection = conn
            conn.resume()
        }
        ping()
    }

    var remote: HelperProtocol? {
        connection?.remoteObjectProxyWithErrorHandler { _ in } as? HelperProtocol
    }

    private func setConnected(_ value: Bool) {
        let wasConnected = connected
        connected = value
        state?.helperConnected = value
        guard value, !wasConnected else { return }
        // Every fresh connection re-runs the bootstrap. A helper that just
        // restarted (crash, repair, reboot) has no monitor running and no
        // enforcement applied, so only refreshing rules here left the app
        // showing a live-looking UI backed by nothing. NetMonitor.start() and
        // the enforcement call are both idempotent.
        state?.bootstrap()
    }

    private func beginAutomaticRepair(for helperVersion: String) {
        guard !isRepairing else { return }
        guard automaticRepairAttemptedVersion != helperVersion else {
            if case .inProgress = repairState {
                repairState = .manualRequired("The automatic SMAppService repair did not replace the running helper.")
            }
            return
        }
        automaticRepairAttemptedVersion = helperVersion
        repairHelperInternal()
    }

    func ping() {
        remote?.getVersion { [weak self] version in
            Task { @MainActor in
                guard let self else { return }
                guard !version.isEmpty else { self.setConnected(false); return }
                self.helperVersion = version
                guard version == AppConstants.version else {
                    // A helper left over from an older install answers happily,
                    // so keep that fact separate from ordinary reachability.
                    self.versionState = .mismatch(helper: version, app: AppConstants.version)
                    self.needsRepair = true
                    self.setConnected(false)
                    self.beginAutomaticRepair(for: version)
                    return
                }
                self.versionState = .matching(version)
                self.automaticRepairAttemptedVersion = nil
                self.repairState = .idle
                self.needsRepair = false
                self.setConnected(true)
            }
        }
        remote?.getStatus { [weak self] data in
            let status = try? JSONDecoder().decode(HelperStatus.self, from: data)
            Task { @MainActor in
                self?.status = status
                // Adopt the persisted mode instead of leaving the GUI on its
                // pre-connection default, which would then be pushed to the
                // extension and silently undo the user's choice.
                if let mode = status?.mode { self?.state?.adoptPersistedMode(mode) }
            }
        }
    }

    func setMode(_ m: AppMode) {
        remote?.setMode(rawValue: m.rawValue) { _, _ in }
    }

    func addRule(_ rule: Rule) {
        addRule(rule) { _, _ in }
    }

    func addRule(_ rule: Rule, completion: @MainActor @escaping (Bool, String?) -> Void) {
        guard let data = try? JSONEncoder().encode(rule) else {
            completion(false, "Could not encode the rule JSON object.")
            return
        }
        guard let proxy = remote else {
            completion(false, "The FreeSnitch helper is not connected.")
            return
        }
        proxy.addRule(ruleJSON: data) { ok, message in
            Task { @MainActor in completion(ok, message) }
        }
    }

    func reloadRules(_ rules: [Rule], completion: @MainActor @escaping (Bool, String?) -> Void) {
        guard let data = try? JSONEncoder().encode(rules) else {
            completion(false, "Could not encode the rule JSON array.")
            return
        }
        guard let proxy = remote else {
            completion(false, "The FreeSnitch helper is not connected.")
            return
        }
        proxy.reloadRules(rulesJSON: data) { ok, message in
            Task { @MainActor in completion(ok, message) }
        }
    }

    func removeRule(id: UUID) {
        removeRule(id: id) { _, _ in }
    }

    func removeRule(id: UUID, completion: @MainActor @escaping (Bool, String?) -> Void) {
        guard let proxy = remote else {
            completion(false, "The FreeSnitch helper is not connected.")
            return
        }
        proxy.removeRule(idString: id.uuidString) { ok, message in
            Task { @MainActor in completion(ok, message) }
        }
    }

    /// Replaces the helper's stored rules using the existing CRUD protocol.
    /// `reloadRules` upserts its JSON array, so remove the current IDs first
    /// rather than presenting a merge as an import replacement.
    func replaceRules(_ rules: [Rule],
                      existing: [Rule],
                      completion: @MainActor @escaping (Bool, String?) -> Void) {
        guard let proxy = remote else {
            completion(false, "The FreeSnitch helper is not connected.")
            return
        }
        let ids = existing.map(\.id)

        func removeNext(_ index: Int) {
            guard index < ids.count else {
                reloadRules(rules, completion: completion)
                return
            }
            proxy.removeRule(idString: ids[index].uuidString) { ok, message in
                Task { @MainActor in
                    guard ok else {
                        completion(false, message ?? "The helper rejected a rule removal.")
                        return
                    }
                    removeNext(index + 1)
                }
            }
        }

        removeNext(0)
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

    func setBlocklistEnabled(id: UUID,
                             enabled: Bool,
                             completion: @MainActor @escaping (Bool, String?) -> Void) {
        guard let proxy = remote else {
            completion(false, "The FreeSnitch helper is not connected.")
            return
        }
        proxy.enableBlocklist(idString: id.uuidString, enabled: enabled) { ok, message in
            Task { @MainActor in completion(ok, message) }
        }
    }

    func setEnforcementEnabled(_ enabled: Bool) {
        // A transport failure has to roll the UI back too, otherwise the toggle
        // claims enforcement that no daemon ever heard about.
        let proxy = connection?.remoteObjectProxyWithErrorHandler { [weak self] error in
            Task { @MainActor in
                guard let self else { return }
                self.state?.appendLog(level: "error",
                                      message: "Enforcement change never reached the helper: \(error.localizedDescription)")
                self.state?.setEnforcementFlagWithoutApplying(!enabled)
            }
        } as? HelperProtocol
        proxy?.setEnforcementEnabled(enabled) { [weak self] ok, message in
            guard !ok else { return }
            Task { @MainActor in
                guard let self else { return }
                self.state?.appendLog(level: "error",
                                      message: "Enforcement change failed: \(message ?? "unknown error")")
                // The helper rolled back, so the UI must not keep claiming
                // enforcement is on.
                self.state?.setEnforcementFlagWithoutApplying(!enabled)
            }
        }
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

    func notifyProcessUsage(usageJSON: Data) {
        guard let usages = try? JSONDecoder().decode([ProcessUsage].self, from: usageJSON) else { return }
        Task { @MainActor in self.state?.updateProcessUsages(usages) }
    }

    func notifyAlert(connectionJSON: Data, reply: @escaping (Bool, Bool) -> Void) {
        guard let conn = try? JSONDecoder().decode(Connection.self, from: connectionJSON) else { reply(true, false); return }
        Task { @MainActor in self.state?.presentAlert(for: conn, reply: reply) }
    }

    func notifyLog(level: String, message: String) {
        Task { @MainActor in self.state?.appendLog(level: level, message: message) }
    }
}
