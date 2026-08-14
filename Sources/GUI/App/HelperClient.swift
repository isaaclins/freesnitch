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
    /// `helper` is the build the helper process is running; `app` is the build
    /// installed on disk. They differ after an in-place update that left the
    /// root daemon running the previous binary.
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
        "The helper process is running v\(helper) while the installed app is v\(app). Automatic replacement is disabled because unregistering an enabled helper can remove the service. Run `\(kickstartCommand)` in Terminal. This works while launchd still has the helper service registered."
    }

    /// Shown while the installed app asks the running helper to restart itself.
    static func restartingMessage(helper: String, app: String) -> String {
        "The helper process is running v\(helper) while the installed app is v\(app). FreeSnitch asked it to restart with `\(kickstartCommand)`; the registration is left untouched. If this message stays, run that command in Terminal."
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
    /// One automatic restart attempt per app launch. A helper that comes back
    /// still stale gets the manual command instead of an endless bounce loop.
    private var didRequestUpdateRestart = false
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

    /// Removes the helper's launchd registration, for uninstall only.
    ///
    /// Everywhere else in this class, unregistering an enabled service is
    /// forbidden, because #24 showed that path can destroy a service the user
    /// still wants. During an uninstall that is precisely the goal, and it is
    /// what let the app stop telling people to go turn it off by hand in
    /// System Settings.
    @discardableResult
    func unregisterDaemonForUninstall() -> String? {
        guard let service else { return "SMAppService cannot manage the helper on this macOS version." }
        do {
            try service.unregister()
            return nil
        } catch {
            return HelperRecovery.registrationErrorDetails(error)
        }
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

    /// The build installed on disk right now. Read at call time, because an
    /// in-place update replaces it under a running app as well as under the
    /// helper.
    static var installedIdentity: String {
        AppBundleIdentity.installed ?? AppConstants.buildIdentity
    }

    /// Finishes the update for the user: the installed, signed GUI asks the
    /// running root helper to restart itself with `launchctl kickstart -k`.
    ///
    /// Nothing here unregisters, boots out, or removes the service; #24 showed
    /// that path can delete the helper entirely. A helper from before this
    /// existed has no restart selector, and then the exact privileged command
    /// is shown instead.
    private func requestUpdateRestart(helper: String, installed: String) {
        guard !didRequestUpdateRestart else { return }
        didRequestUpdateRestart = true
        guard let proxy = remote, proxy.restartForUpdate != nil else {
            repairState = .manualRequired(HelperRecovery.staleHelperMessage(helper: helper, app: installed))
            return
        }
        repairState = .manualRequired(HelperRecovery.restartingMessage(helper: helper, app: installed))
        state?.appendLog(level: "info", message: "Helper is running v\(helper) but v\(installed) is installed; asking it to restart with launchctl kickstart -k.")
        proxy.restartForUpdate? { [weak self] ok, message in
            Task { @MainActor in
                guard let self else { return }
                guard ok else {
                    self.repairState = .manualRequired(HelperRecovery.staleHelperMessage(helper: helper, app: installed))
                    self.state?.appendLog(level: "error", message: "The helper refused the update restart: \(message ?? "no reason given").")
                    return
                }
                // Give launchd time to bring the installed binary back, then
                // re-check. Still stale means the manual command is required.
                DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
                    Task { @MainActor in
                        self.reconnectAndPing(force: true)
                        if self.hasVersionMismatch {
                            self.repairState = .manualRequired(HelperRecovery.staleHelperMessage(helper: helper, app: installed))
                        }
                    }
                }
            }
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
            // Actually perform the repair, behind the standard authorization
            // prompt, instead of printing a sudo command and calling that a
            // fix (#69). Falling back to the written command only happens if
            // the privileged restart genuinely could not be carried out.
            performPrivilegedKickstart()
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

    /// Restart the helper as root, prompting for authorization.
    ///
    /// The prompt blocks, so it runs off the main thread; every state change
    /// afterwards hops back. Cancelling is not treated as a failure to shout
    /// about, because the user declining must be a normal outcome.
    private func performPrivilegedKickstart() {
        let previous = versionState
        DispatchQueue.global(qos: .userInitiated).async {
            let outcome = PrivilegedRepair.kickstartHelper()
            Task { @MainActor in
                switch outcome {
                case .success:
                    // launchd needs a moment to bring the replacement up before
                    // asking it for its version is meaningful.
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak self] in
                        guard let self else { return }
                        self.isRepairing = false
                        self.repairState = .idle
                        self.needsRepair = false
                        self.refreshInstallState()
                        self.connect()
                    }
                case .failure(.cancelled):
                    self.isRepairing = false
                    self.repairState = .idle
                    self.needsRepair = true
                case .failure(.failed(let reason)):
                    let fallback: String
                    if case .mismatch(let helper, let app) = previous {
                        fallback = HelperRecovery.staleHelperMessage(helper: helper, app: app)
                    } else {
                        fallback = "The helper is enabled but not responding. Automatic replacement is disabled because unregistering an enabled helper can remove the service, so FreeSnitch only restarts it. Run `\(HelperRecovery.kickstartCommand)` in Terminal if this keeps happening."
                    }
                    self.finishRepairFailure("The privileged restart did not complete: \(reason) \(fallback)")
                }
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
        // Profile state is helper-owned. Hand the view model a transport rather
        // than an XPC connection, so it never owns one of its own.
        // The transport is @Sendable and may be called from any queue, while
        // this client is main-actor isolated, so hop before touching it.
        ProfileClient.shared.setTransport { [weak self] request, completion in
            Task { @MainActor in
                guard let self else {
                    completion(Data(), "The privileged helper is unavailable.")
                    return
                }
                self.sendProfileCommand(request, completion: completion)
            }
        }
        ping()
        startPolling()
    }

    /// One bounded profile command in, one encoded snapshot out. A helper that
    /// predates profiles simply does not implement the selector, and the view
    /// model reports that rather than pretending profiles failed.
    private func sendProfileCommand(_ request: Data,
                                    completion: @escaping (Data, String?) -> Void) {
        guard request.count <= ProfileTransportBoundary.maximumRequestBytes else {
            completion(Data(), "The profile request exceeds the transport limit.")
            return
        }
        guard let proxy = connection?.remoteObjectProxyWithErrorHandler({ error in
            completion(Data(), "Could not reach the privileged helper: \(error.localizedDescription).")
        }) as? HelperProtocol else {
            completion(Data(), "The privileged helper is unavailable.")
            return
        }
        guard proxy.handleProfileCommand != nil else {
            completion(Data(), "The running helper is too old to manage profiles. Run `\(AppConstants.helperKickstartCommand)`, then retry.")
            return
        }
        proxy.handleProfileCommand?(request: request, reply: completion)
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
                // The helper reports the build its process is running; compare
                // it against the build installed on disk, which is what an
                // in-place update just changed.
                let installed = Self.installedIdentity
                guard AppConstants.identityMatches(reported: version, expected: installed) else {
                    // A helper left over from an older install answers happily,
                    // so keep that fact separate from ordinary reachability.
                    // It is still running, so do not unregister it. The exact
                    // privileged recovery command is surfaced immediately.
                    self.versionState = .mismatch(helper: version, app: installed)
                    self.needsRepair = true
                    self.requestUpdateRestart(helper: version, installed: installed)
                    self.setConnected(false)
                    return
                }
                self.versionState = .matching(version)
                self.repairConfirmationID = UUID()
                self.repairState = .idle
                self.needsRepair = false
                self.didRequestUpdateRestart = false
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

    func getDoHUpstream(reply: @escaping (String?, String?) -> Void) {
        let lock = NSLock()
        var finished = false
        var timeoutWork: DispatchWorkItem?
        let finish: (String?, String?) -> Void = { value, error in
            lock.lock()
            guard !finished else {
                lock.unlock()
                return
            }
            finished = true
            lock.unlock()
            timeoutWork?.cancel()
            reply(value, error)
        }
        let work = DispatchWorkItem {
            finish(nil, "Reading the effective DoH upstream timed out. Restart the helper to finish the update.")
        }
        timeoutWork = work
        DispatchQueue.global().asyncAfter(deadline: .now() + 5, execute: work)

        guard let proxy = connection?.remoteObjectProxyWithErrorHandler({ error in
            finish(nil, "Could not read the effective DoH upstream: \(error.localizedDescription)")
        }) as? HelperProtocol else {
            finish(nil, "The privileged helper is unavailable.")
            return
        }
        guard proxy.getDoHUpstream != nil else {
            finish(nil, "The running helper is too old to report the effective DoH upstream. Restart the helper to finish the update.")
            return
        }
        proxy.getDoHUpstream?(reply: { finish($0, nil) })
    }

    func authoritativeSnapshot(completion: @MainActor @escaping (SharedRuleBridge.Snapshot?, String?) -> Void) {
        let lock = NSLock()
        var finished = false
        var timeoutWork: DispatchWorkItem?
        let finish: (SharedRuleBridge.Snapshot?, String?) -> Void = { snapshot, error in
            lock.lock()
            guard !finished else {
                lock.unlock()
                return
            }
            finished = true
            lock.unlock()
            timeoutWork?.cancel()
            Task { @MainActor in completion(snapshot, error) }
        }
        let work = DispatchWorkItem {
            finish(nil, "The helper did not return an authoritative rule snapshot within 5 seconds. Run `\(AppConstants.helperKickstartCommand)`, then retry.")
        }
        timeoutWork = work
        DispatchQueue.global().asyncAfter(deadline: .now() + 5, execute: work)

        guard let proxy = connection?.remoteObjectProxyWithErrorHandler({ error in
            finish(nil, "Could not read the authoritative rule snapshot: \(error.localizedDescription). Run `\(AppConstants.helperKickstartCommand)`, then retry.")
        }) as? HelperProtocol else {
            finish(nil, "The privileged helper is unavailable. Run `\(AppConstants.helperKickstartCommand)`, then retry.")
            return
        }
        guard proxy.getAuthoritativeSnapshot != nil else {
            finish(nil, "The running helper does not support authoritative rule snapshots. Run `\(AppConstants.helperKickstartCommand)`, then retry.")
            return
        }
        proxy.getAuthoritativeSnapshot?(reply: { data in
            guard !data.isEmpty else {
                finish(nil, "The helper returned an empty authoritative rule snapshot. Run `\(AppConstants.helperKickstartCommand)`, then retry.")
                return
            }
            do {
                try RuleTransportBoundary.validateSnapshotBytes(data)
                finish(try SharedRuleBridge.decode(data), nil)
            } catch {
                finish(nil, "The helper returned an invalid authoritative rule snapshot: \(error.localizedDescription). Run `\(AppConstants.helperKickstartCommand)`, then retry.")
            }
        })
    }

    func setMode(_ m: AppMode) {
        setMode(m) { _, _ in }
    }

    func setMode(_ m: AppMode, completion: @MainActor @escaping (Bool, String?) -> Void) {
        guard let proxy = remote else {
            completion(false, "The FreeSnitch helper is not connected.")
            return
        }
        proxy.setMode(rawValue: m.rawValue) { ok, message in
            Task { @MainActor in completion(ok, message) }
        }
    }

    @discardableResult
    func ingestObservationBatch(_ data: Data) -> Bool {
        guard data.count <= InsightsLimits.maxBatchBytes else {
            state?.appendLog(level: "error", message: "Insights batch exceeded the transport limit and was dropped by the GUI.")
            return false
        }
        let proxy = connection?.remoteObjectProxyWithErrorHandler { [weak self] error in
            Task { @MainActor in
                self?.state?.appendLog(level: "error",
                                       message: "Insights batch transport failed: \(error.localizedDescription).")
            }
        } as? HelperProtocol
        guard let proxy else {
            state?.appendLog(level: "error", message: "Insights batch dropped because the privileged helper is unavailable.")
            return false
        }
        proxy.ingestObservationBatch(observationBatch: data) { [weak self] ok, message in
            guard !ok else { return }
            Task { @MainActor in
                self?.state?.appendLog(level: "error",
                                       message: "The helper rejected an insights batch: \(message ?? "unknown error").")
            }
        }
        return true
    }

    /// Fetches the helper-prepared contact set. This is deliberately a
    /// snapshot read, not a per-flow database query. A missing or stale set is
    /// returned as nil so Alert mode retains its existing ask behavior.
    func insightsContactSnapshot(completion: @MainActor @escaping (InsightsContactSnapshot?) -> Void) {
        guard let proxy = connection?.remoteObjectProxyWithErrorHandler({ _ in
            Task { @MainActor in completion(nil) }
        }) as? HelperProtocol else {
            completion(nil)
            return
        }
        guard proxy.getInsightsContactSnapshot != nil else {
            completion(nil)
            return
        }
        proxy.getInsightsContactSnapshot? { data, message in
            guard message == nil, !data.isEmpty,
                  let snapshot = try? FreeSnitchWireCodec.decode(InsightsContactSnapshot.self, from: data),
                  (try? snapshot.validate()) != nil else {
                Task { @MainActor in completion(nil) }
                return
            }
            Task { @MainActor in completion(snapshot) }
        }
    }

    func queryInsightsRecordingEnabled(completion: @MainActor @escaping (Bool) -> Void) {
        guard let proxy = remote else {
            completion(false)
            return
        }
        proxy.getInsightsRecordingEnabled { enabled in
            Task { @MainActor in completion(enabled) }
        }
    }

    func setInsightsRecordingEnabled(_ enabled: Bool,
                                     completion: @MainActor @escaping (Bool, String?) -> Void) {
        guard let proxy = remote else {
            completion(false, "The FreeSnitch helper is not connected.")
            return
        }
        proxy.setInsightsRecordingEnabled(enabled) { ok, message in
            Task { @MainActor in completion(ok, message) }
        }
    }

    /// Bounded Insights read. The request is encoded through the shared wire
    /// codec and byte-capped on both sides; the reply is bounds-checked before
    /// it is decoded and never re-judged for content.
    func insightsReport(_ query: InsightsQuery,
                        completion: @MainActor @escaping (InsightsReport?, String?) -> Void) {
        let lock = NSLock()
        var finished = false
        var timeoutWork: DispatchWorkItem?
        let finish: (InsightsReport?, String?) -> Void = { report, error in
            lock.lock()
            guard !finished else {
                lock.unlock()
                return
            }
            finished = true
            lock.unlock()
            timeoutWork?.cancel()
            Task { @MainActor in completion(report, error) }
        }
        let work = DispatchWorkItem {
            finish(nil, "The helper did not answer the Insights query within 10 seconds.")
        }
        timeoutWork = work
        DispatchQueue.global().asyncAfter(deadline: .now() + 10, execute: work)

        guard let data = try? FreeSnitchWireCodec.encode(query), data.count <= InsightsLimits.maxQueryRequestBytes else {
            finish(nil, "Could not encode the Insights query within the transport limit.")
            return
        }
        guard let proxy = connection?.remoteObjectProxyWithErrorHandler({ error in
            finish(nil, "Could not read Insights: \(error.localizedDescription).")
        }) as? HelperProtocol else {
            finish(nil, "The privileged helper is unavailable.")
            return
        }
        guard proxy.queryInsights != nil else {
            finish(nil, "The running helper is too old to answer Insights queries. Run `\(AppConstants.helperKickstartCommand)`, then retry.")
            return
        }
        proxy.queryInsights?(request: data, reply: { payload, message in
            if let message, !message.isEmpty {
                finish(nil, message)
                return
            }
            guard !payload.isEmpty else {
                finish(nil, "The helper returned an empty Insights report.")
                return
            }
            guard payload.count <= InsightsLimits.maxReportBytes else {
                finish(nil, "The helper returned an oversized Insights report: \(payload.count) bytes.")
                return
            }
            do {
                let report = try FreeSnitchWireCodec.decode(InsightsReport.self, from: payload)
                try report.validateBounds(payloadBytes: payload.count)
                finish(report, nil)
            } catch {
                finish(nil, "The helper returned an unreadable Insights report: \(error.localizedDescription).")
            }
        })
    }

    func purgeInsights(completion: @MainActor @escaping (Bool, String?) -> Void) {
        guard let proxy = remote else {
            completion(false, "The FreeSnitch helper is not connected.")
            return
        }
        proxy.purgeInsights { ok, message in
            Task { @MainActor in completion(ok, message) }
        }
    }

    func addRule(_ rule: Rule) {
        addRule(rule) { _, _ in }
    }

    func addRule(_ rule: Rule, completion: @MainActor @escaping (Bool, String?) -> Void) {
        guard let data = try? RuleTransportBoundary.encodeSingleRule(rule) else {
            completion(false, "Could not encode the rule within the single-rule transport limits.")
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
        guard let data = try? RuleTransportBoundary.encodeRuleBatch(rules) else {
            completion(false, "Could not encode the rule batch within the transport limits.")
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

    /// Replaces the helper's stored rules in one transaction. There is no
    /// fallback to cached GUI rules or to a sequence of removals.
    func replaceRules(_ rules: [Rule],
                      existing _: [Rule],
                      completion: @MainActor @escaping (Bool, String?) -> Void) {
        guard let data = try? RuleTransportBoundary.encodeRuleBatch(rules) else {
            completion(false, "Could not encode the rule batch within the transport limits.")
            return
        }
        guard let proxy = remote else {
            completion(false, "The FreeSnitch helper is not connected.")
            return
        }
        guard proxy.replaceRules != nil else {
            completion(false, "The running helper does not support atomic rule replacement. Run `\(AppConstants.helperKickstartCommand)`, then retry.")
            return
        }
        proxy.replaceRules?(rulesJSON: data) { ok, message in
            Task { @MainActor in completion(ok, message) }
        }
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
        Task { @MainActor in
            self.state?.appendLog(level: level, message: message)
            // A profile switch changes which rules are enforced. Refresh from
            // the helper-owned snapshot instead of assuming the cached set is
            // still correct, and refresh the profile view model with it.
            if message == AppConstants.profilePolicyChangedLogMessage {
                self.state?.syncSharedRules()
                ProfileClient.shared.refresh()
            }
        }
    }
}
