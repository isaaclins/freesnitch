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
    /// SMAppService cannot find the registration record or declaration. The
    /// bundle files are checked separately before registration is attempted.
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
    static let kickstartCommand = AppConstants.helperKickstartCommand

    static func staleHelperMessage(helper: String, app: String) -> String {
        "The helper is still running from an earlier build (v\(helper), expected v\(app)). Automatic replacement is disabled because unregistering an enabled helper can remove the service. Run `\(kickstartCommand)` in Terminal. This works while launchd still has the helper service registered."
    }

    static func registrationErrorDetails(_ error: Error) -> String {
        let ns = error as NSError
        return "domain=\(ns.domain), code=\(ns.code), description=\(ns.localizedDescription)"
    }
}

enum HelperLifecycleStatus: Equatable {
    case enabled
    case notRegistered
    case requiresApproval
    case notFound
    case unknown
}

enum HelperLifecycleAction: Equatable {
    case alreadyEnabled
    case register
    case manualKickstart
    case guideApproval
    case unavailable
    case noRegistration
}

enum HelperLifecyclePolicy {
    /// Pure lifecycle policy seam. Registration is only allowed when there is
    /// no existing service to destroy, and repair never unregisters an enabled
    /// service.
    static func action(for status: HelperLifecycleStatus, repairing: Bool = false) -> HelperLifecycleAction {
        switch status {
        case .enabled: return repairing ? .manualKickstart : .alreadyEnabled
        case .notRegistered: return .register
        case .requiresApproval: return .guideApproval
        // A lost SMAppService record is recoverable when the signed bundle
        // still contains the declaration and executable.
        case .notFound: return .register
        case .unknown: return .noRegistration
        }
    }
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
    private var repairConfirmationID = UUID()
    private var enabledButSilentSince: Date?
    /// Approved but unreachable for long enough that non-destructive recovery
    /// is worth offering. Never acted on automatically; see startPolling().
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

    static var hasBundledHelper: Bool {
        let contents = Bundle.main.bundleURL.appendingPathComponent("Contents")
        let declaration = contents
            .appendingPathComponent("Library/LaunchDaemons/io.isaaclins.freesnitch.helper.plist")
        let executable = contents.appendingPathComponent("MacOS/FreeSnitchHelper")
        return FileManager.default.fileExists(atPath: declaration.path)
            && FileManager.default.fileExists(atPath: executable.path)
    }

    /// Registers the privileged helper as a launchd daemon via SMAppService.
    /// Without this the XPC mach service never exists, so every helper call
    /// silently no-ops (the root cause of "no rules / no traffic"). Requires a
    /// signed build; the user approves it in System Settings under Login Items.
    func registerDaemon() {
        guard Self.isInApplicationsFolder else { installState = .wrongLocation; return }
        guard let service else { installState = .notRegistered; return }
        switch HelperLifecyclePolicy.action(for: Self.lifecycleStatus(for: service.status)) {
        case .alreadyEnabled:
            installState = .enabled
        case .register:
            guard Self.hasBundledHelper else {
                installState = .notFound
                return
            }
            do {
                try service.register()
                refreshInstallState()
            } catch {
                let details = HelperRecovery.registrationErrorDetails(error)
                installState = .failed(details)
                state?.appendLog(level: "error", message: "Helper registration failed: \(details)")
            }
        case .guideApproval:
            installState = .requiresApproval
        case .unavailable:
            installState = .notFound
        case .manualKickstart, .noRegistration:
            installState = .unknown
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

    /// Repair never unregisters an enabled helper. A running stale daemon must
    /// be restarted with the privileged launchctl command instead.
    func repairHelper() {
        repairHelperInternal()
    }

    private func repairHelperInternal() {
        guard !isRepairing else { return }
        repairState = .inProgress
        guard Self.isInApplicationsFolder else {
            installState = .wrongLocation
            finishRepairFailure("Move FreeSnitch to /Applications before registering the helper.")
            return
        }
        guard let service else {
            finishRepairFailure("SMAppService cannot manage the helper on this macOS version.")
            return
        }

        switch HelperLifecyclePolicy.action(for: Self.lifecycleStatus(for: service.status), repairing: true) {
        case .manualKickstart:
            refreshInstallState()
            let message: String
            if case .mismatch(let helper, let app) = versionState {
                message = HelperRecovery.staleHelperMessage(helper: helper, app: app)
            } else {
                message = "The helper is enabled but not responding. Automatic replacement is disabled because unregistering an enabled helper can remove the service. Run `\(HelperRecovery.kickstartCommand)` in Terminal. This works while launchd still has the helper service registered."
            }
            finishRepairFailure(message)
        case .register:
            guard Self.hasBundledHelper else {
                refreshInstallState()
                finishRepairFailure("This app copy does not contain both the helper declaration and executable, so registration cannot be attempted.")
                return
            }
            registerAbsentService(service: service)
        case .guideApproval:
            refreshInstallState()
            finishRepairFailure("Approve FreeSnitch in System Settings under General > Login Items & Extensions before starting the helper. Registration exists, but launchd cannot start it until approval.")
        case .unavailable:
            refreshInstallState()
            finishRepairFailure("macOS cannot manage the helper registration on this system.")
        case .alreadyEnabled, .noRegistration:
            refreshInstallState()
            finishRepairFailure("macOS reported an unsupported helper registration state.")
        }
    }

    /// Registration is safe here because SMAppService reports no active
    /// service. It is deliberately separate from stale-helper repair.
    private func registerAbsentService(service: SMAppService) {
        do {
            try service.register()
            refreshInstallState()
            if installState == .requiresApproval {
                finishRepairFailure("macOS registered the helper, but it still needs approval in System Settings under General > Login Items & Extensions. Registration must happen before the kickstart command can work.")
                return
            }
            isRepairing = false
            scheduleRepairConfirmation()
            reconnectAndPing(force: true)
        } catch {
            let details = HelperRecovery.registrationErrorDetails(error)
            state?.appendLog(level: "error", message: "Helper registration failed: \(details)")
            finishRepairFailure("SMAppService could not register the absent helper: \(details). Open System Settings under General > Login Items & Extensions if approval is required, then try again.")
        }
    }

    private func scheduleRepairConfirmation() {
        let confirmationID = UUID()
        repairConfirmationID = confirmationID
        DispatchQueue.main.asyncAfter(deadline: .now() + 8) { [weak self] in
            Task { @MainActor in
                guard let self, self.repairConfirmationID == confirmationID else { return }
                guard case .inProgress = self.repairState else { return }
                if self.hasVersionMismatch {
                    self.repairState = .manualRequired("The registered helper did not reconnect with the expected build. Run `\(HelperRecovery.kickstartCommand)` while launchd still has the service registered.")
                    return
                }
                switch self.installState {
                case .enabled:
                    self.repairState = .manualRequired("SMAppService registered the helper, but it did not reconnect. Registration exists, so run `\(HelperRecovery.kickstartCommand)` in Terminal.")
                case .requiresApproval:
                    self.repairState = .manualRequired("The helper is registered but still requires approval in System Settings under General > Login Items & Extensions. Registration must happen before the kickstart command can work.")
                case .notRegistered, .notFound:
                    self.repairState = .manualRequired("SMAppService did not leave a usable registration record. Do not run the kickstart command yet; run the helper recheck again and report the registration state.")
                case .wrongLocation:
                    self.repairState = .manualRequired("Move FreeSnitch to /Applications before retrying helper registration.")
                case .failed(let message):
                    self.repairState = .manualRequired("Helper registration failed: \(message)")
                case .unknown:
                    self.repairState = .manualRequired("SMAppService registration did not produce a reachable helper. Recheck the registration state before using the kickstart command.")
                }
                self.needsRepair = true
            }
        }
    }

    private func finishRepairFailure(_ message: String) {
        repairConfirmationID = UUID()
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
                // job). Surface it after a grace period and keep recovery
                // non-destructive. An enabled service is restarted with the
                // privileged kickstart command, never unregister/register.
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

    private static func lifecycleStatus(for status: SMAppService.Status) -> HelperLifecycleStatus {
        switch status {
        case .enabled: return .enabled
        case .requiresApproval: return .requiresApproval
        case .notRegistered: return .notRegistered
        case .notFound: return .notFound
        @unknown default: return .unknown
        }
    }

    func ping() {
        remote?.getVersion { [weak self] version in
            Task { @MainActor in
                guard let self else { return }
                guard !version.isEmpty else { self.setConnected(false); return }
                self.helperVersion = version
                guard AppConstants.identityMatches(reported: version, expected: AppConstants.buildIdentity) else {
                    // A helper left over from an older install answers happily,
                    // so keep that fact separate from ordinary reachability.
                    // It is still running, so do not unregister it. The exact
                    // privileged recovery command is surfaced immediately.
                    self.versionState = .mismatch(helper: version, app: AppConstants.buildIdentity)
                    self.needsRepair = true
                    self.repairState = .manualRequired(HelperRecovery.staleHelperMessage(helper: version, app: AppConstants.buildIdentity))
                    self.setConnected(false)
                    return
                }
                self.versionState = .matching(version)
                self.repairConfirmationID = UUID()
                self.repairState = .idle
                self.needsRepair = false
                self.setConnected(true)
            }
        }
        remote?.getStatus { [weak self] data in
            let status = try? FreeSnitchWireCodec.decode(HelperStatus.self, from: data)
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
        guard let data = try? FreeSnitchWireCodec.encode(rule) else {
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
        guard let data = try? FreeSnitchWireCodec.encode(rules) else {
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
            let rules = (try? FreeSnitchWireCodec.decode([Rule].self, from: data)) ?? []
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
        guard let conns = try? FreeSnitchWireCodec.decode([Connection].self, from: connectionJSON) else { return }
        Task { @MainActor in self.state?.updateConnections(conns) }
    }

    func notifyTraffic(sampleJSON: Data) {
        guard let sample = try? FreeSnitchWireCodec.decode(TrafficSample.self, from: sampleJSON) else { return }
        Task { @MainActor in self.state?.appendSample(sample) }
    }

    func notifyProcessUsage(usageJSON: Data) {
        guard let usages = try? FreeSnitchWireCodec.decode([ProcessUsage].self, from: usageJSON) else { return }
        Task { @MainActor in self.state?.updateProcessUsages(usages) }
    }

    func notifyAlert(connectionJSON: Data, reply: @escaping (Bool, Bool) -> Void) {
        guard let conn = try? FreeSnitchWireCodec.decode(Connection.self, from: connectionJSON) else { reply(true, false); return }
        Task { @MainActor in self.state?.presentAlert(for: conn, reply: reply) }
    }

    func notifyLog(level: String, message: String) {
        Task { @MainActor in self.state?.appendLog(level: level, message: message) }
    }
}
