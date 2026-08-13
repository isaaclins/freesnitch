import Foundation
import AppKit
import SystemExtensions
import NetworkExtension
import os.log

/// Drives the per-process firewall: activates the embedded Network System
/// Extension, enables the content filter via NEFilterManager, and opens the XPC
/// channel so the extension can prompt the user (reusing the connection-alert
/// UI). Mirrors Apple's "SimpleFirewall" sample.
@MainActor
final class SystemExtensionManager: NSObject, ObservableObject {
    enum Status: Equatable {
        case idle
        case activating
        case needsApproval
        case active
        case unsupported
        case failed(String)
    }

    /// What macOS actually reported about removing the extension.
    ///
    /// Deactivation is a deliberate, user-initiated uninstall, never a repair
    /// (see #24), and it commonly finishes only after a reboot. Accepting the
    /// request is not success, so there is no state for "we asked": the value
    /// only moves past `.deactivating` when the system answers.
    enum UninstallState: Equatable {
        case idle
        case deactivating
        case notInstalled
        case pendingReboot
        case removed
        case failed(String)
    }

    private enum RequestKind {
        case activation
        case deactivation
        case properties
    }

    @Published var status: Status = .idle
    @Published var uninstallState: UninstallState = .idle
    @Published var snapshotStatus = SharedRuleBridge.SnapshotStatus.unavailable(
        "Network extension IPC is not connected."
    )

    private weak var state: AppState?
    private let extensionIdentifier = AppConstants.bundleIdNetExt
    private let log = OSLog(subsystem: AppConstants.bundleIdGUI, category: "sysext")
    private var bridge: AppCommunicationBridge?
    private var requestKind: RequestKind = .activation
    private var filterConfigurationActive = false
    private var persistenceQueue = SharedRuleBridge.NewestWriteWinsQueue()
    private var persistenceInFlight = false
    private var persistenceWorkItem: DispatchWorkItem?
    private var enableFilterRequested = false

    init(state: AppState) {
        self.state = state
        super.init()
        state.filterSnapshotStatusHandler = { [weak self] snapshotStatus in
            self?.recordSnapshotStatus(snapshotStatus)
        }
        state.filterSnapshotPersistenceHandler = { [weak self] snapshot in
            self?.requestPersistedSnapshot(snapshot)
        }
    }

    private var hasEmbeddedExtension: Bool {
        let dir = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/SystemExtensions")
        guard let urls = try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) else { return false }
        return urls.contains { $0.pathExtension == "systemextension" }
    }

    /// Activate the extension (no-op if this build doesn't embed one).
    func activate() {
        guard hasEmbeddedExtension else {
            status = .unsupported
            return
        }
        status = .activating
        requestKind = .activation
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: extensionIdentifier, queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func deactivate() {
        disableFilter()
        guard hasEmbeddedExtension else { return }
        requestKind = .deactivation
        let request = OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: extensionIdentifier, queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Entry point for the uninstall flow in Settings. Under SIP the app is the
    /// only component macOS allows to deactivate this extension, so this is the
    /// real removal path, not a convenience wrapper.
    ///
    /// It touches the extension and the content filter only. It never
    /// unregisters, boots out, or kickstarts the privileged helper: removing
    /// that service is the user's own action in System Settings, and doing it
    /// silently is exactly the failure #24 was filed for.
    func deactivateForUninstall() {
        uninstallState = .deactivating
        guard hasEmbeddedExtension else {
            // Nothing was ever staged from this bundle, so there is no OS
            // answer to wait for. Still drop the filter configuration.
            disableFilter()
            uninstallState = .notInstalled
            return
        }
        deactivate()
    }

    /// Asks the system whether a record for the extension still exists, so the
    /// UI can report what macOS holds rather than what we requested.
    private func checkExtensionPresence() {
        requestKind = .properties
        let request = OSSystemExtensionRequest.propertiesRequest(forExtensionWithIdentifier: extensionIdentifier, queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Opens the System Settings location where a staged system extension is
    /// approved. The query selects Network Extensions on current macOS; the
    /// parent pane remains the fallback for releases that do not understand it.
    func openNetworkExtensionsSettings() {
        let networkExtensionsURL = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension?NetworkExtensions")
        let loginItemsURL = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension")
        if let networkExtensionsURL, NSWorkspace.shared.open(networkExtensionsURL) { return }
        if let loginItemsURL { NSWorkspace.shared.open(loginItemsURL) }
    }

    // MARK: - Content filter configuration

    private func enableFilter() {
        enableFilterRequested = true
        // AppState fetches the helper-owned snapshot and invokes the
        // persistence callback only after it has updated its display cache.
        // There is no cached-rule fallback during activation.
        state?.syncSharedRules()
    }

    /// Queue the newest policy for NEFilterManager.providerConfiguration. The
    /// manager is the sole persistence owner. Saves are serialized because
    /// NEFilterManager's load/save callbacks are asynchronous, and a newer
    /// request always remains pending until the older save completes.
    private func requestPersistedSnapshot(_ snapshot: SharedRuleBridge.Snapshot,
                                          immediate: Bool = false) {
        do {
            persistenceQueue.enqueue(try SharedRuleBridge.encodeBootSnapshot(snapshot))
            schedulePersistence(immediate: immediate || enableFilterRequested)
        } catch {
            recordPersistenceFailure("encode", error: error)
            if immediate {
                enableFilterRequested = true
                schedulePersistence(immediate: true)
            }
        }
    }

    private func schedulePersistence(immediate: Bool) {
        persistenceWorkItem?.cancel()
        let work = DispatchWorkItem { [weak self] in
            Task { @MainActor [weak self] in
                self?.flushPersistence()
            }
        }
        persistenceWorkItem = work
        let delay = immediate ? 0 : 0.2
        DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: work)
    }

    private func flushPersistence() {
        guard !persistenceInFlight else { return }
        // Activation waits for a successful helper getter before it can save
        // or enable the filter. An enable request without a pending snapshot
        // is a fetch failure, not permission to persist stale GUI state.
        guard persistenceQueue.hasPending else { return }
        persistenceInFlight = true
        let generationAtLoad = persistenceQueue.generation
        let mgr = NEFilterManager.shared()
        mgr.loadFromPreferences { [weak self] loadError in
            DispatchQueue.main.async {
                guard let self else { return }
                if let loadError {
                    self.persistenceInFlight = false
                    self.recordPersistenceFailure("load", error: loadError)
                    if self.enableFilterRequested {
                        self.fail("filter load: \(loadError.localizedDescription)")
                    }
                    let hasNewerSnapshot = self.persistenceQueue.hasNewerWork(since: generationAtLoad)
                    self.persistenceQueue.discardThrough(generationAtLoad)
                    if hasNewerSnapshot {
                        self.schedulePersistence(immediate: true)
                    }
                    return
                }

                let snapshotData = self.persistenceQueue.takeNewest()?.data
                let shouldEnable = self.enableFilterRequested
                self.enableFilterRequested = false
                let configuration = mgr.providerConfiguration ?? NEFilterProviderConfiguration()
                configuration.filterSockets = true
                configuration.filterPackets = false
                if let snapshotData {
                    var vendorConfiguration = configuration.vendorConfiguration ?? [:]
                    vendorConfiguration[SharedRuleBridge.bootSnapshotVendorConfigurationKey] = snapshotData
                    configuration.vendorConfiguration = vendorConfiguration
                }
                mgr.providerConfiguration = configuration
                if shouldEnable {
                    mgr.localizedDescription = "FreeSnitch"
                    mgr.isEnabled = true
                }
                mgr.saveToPreferences { saveError in
                    DispatchQueue.main.async {
                        self.persistenceInFlight = false
                        if let saveError {
                            self.recordPersistenceFailure("save", error: saveError)
                            if shouldEnable {
                                self.fail("filter save: \(saveError.localizedDescription)")
                            }
                        } else {
                            if snapshotData != nil {
                                self.state?.clearFilterPersistenceFailure()
                                if shouldEnable || self.filterConfigurationActive {
                                    self.recordFilterDiagnostic(state: "installed-enabled", detail: "The content filter configuration is installed and enabled.")
                                }
                            } else if shouldEnable {
                                self.recordFilterDiagnostic(state: "degraded", detail: "The content filter is enabled, but no valid boot policy could be persisted. Future starts will fail open.")
                            }
                            if shouldEnable {
                                self.filterConfigurationActive = true
                                self.status = .active
                                // Deliberately does NOT touch `helperConnected`: the
                                // content filter and privileged helper are separate.
                                self.state?.appendLog(level: "info", message: "Per-process firewall active.")
                                self.registerIPC()
                            }
                        }

                        // A request that arrived while load/save was in flight
                        // cannot be folded into the completed system write.
                        // Start another serialized cycle for that newer data.
                        if self.persistenceQueue.hasNewerWork(since: generationAtLoad)
                            || self.enableFilterRequested {
                            self.schedulePersistence(immediate: true)
                        }
                    }
                }
            }
        }
    }

    private func recordPersistenceFailure(_ operation: String, error: Error) {
        let detail = "Persisted boot policy \(operation) failed: \(error.localizedDescription). Live filtering remains unchanged; a future extension start will fail open."
        recordFilterDiagnostic(state: "degraded", detail: detail)
        state?.recordFilterPersistenceFailure(detail)
        os_log("%{public}@", log: log, type: .error, detail)
    }

    private func disableFilter() {
        let mgr = NEFilterManager.shared()
        mgr.loadFromPreferences { [weak self] error in
            guard let self else { return }
            guard error == nil else {
                self.recordFilterDiagnostic(state: "unknown", detail: "Could not read the content filter preferences while disabling them.")
                return
            }
            mgr.isEnabled = false
            mgr.saveToPreferences { saveError in
                if let saveError {
                    self.recordFilterDiagnostic(state: "unknown", detail: "The content filter could not be disabled: \(saveError.localizedDescription).")
                } else {
                    self.recordFilterDiagnostic(state: "installed-disabled", detail: "The content filter configuration is installed but disabled.")
                }
            }
        }
    }

    private func recordFilterDiagnostic(state: String, detail: String) {
        AppPreferences.set(state, forKey: AppPreferences.Key.filterConfigurationState, notify: false)
        AppPreferences.set(detail, forKey: AppPreferences.Key.filterConfigurationDetail, notify: false)
    }

    private func registerIPC() {
        guard let state else { return }
        let bridge = AppCommunicationBridge(state: state)
        self.bridge = bridge
        IPCConnection.shared.register(delegate: bridge) { [weak self] ok, remoteStatus in
            DispatchQueue.main.async {
                guard let self else { return }
                state.appendLog(level: ok ? "info" : "error",
                                message: ok ? "Connected to network extension." : "Extension IPC unavailable.")
                self.recordSnapshotStatus(remoteStatus)
                // The extension starts with no in-memory snapshot, so hand the
                // current one over as soon as the link is up, not only after a
                // later rule or mode change.
                if ok { state.syncSharedRules() }
            }
        }
    }

    private func recordSnapshotStatus(_ snapshotStatus: SharedRuleBridge.SnapshotStatus) {
        self.snapshotStatus = snapshotStatus
        if !snapshotStatus.isReady,
           enableFilterRequested,
           !persistenceQueue.hasPending,
           !persistenceInFlight {
            enableFilterRequested = false
            fail("filter snapshot unavailable: \(snapshotStatus.message ?? "the helper returned no authoritative policy")")
            return
        }
        guard filterConfigurationActive else { return }
        if snapshotStatus.isReady {
            status = .active
            return
        }
        let detail = snapshotStatus.message ?? "no snapshot has been received"
        status = .failed("filter snapshot unavailable: \(detail)")
    }

    private func fail(_ message: String) {
        status = .failed(message)
        state?.appendLog(level: "error", message: message)
        os_log("%{public}@", log: log, type: .error, message)
    }
}

extension SystemExtensionManager: OSSystemExtensionRequestDelegate {
    nonisolated func request(_ request: OSSystemExtensionRequest,
                             didFinishWithResult result: OSSystemExtensionRequest.Result) {
        Task { @MainActor in
            if self.requestKind == .properties { return }
            guard self.requestKind == .activation else {
                if result == .completed {
                    self.filterConfigurationActive = false
                    self.status = .idle
                    // A completed deactivation is the system's answer, but the
                    // record can still be present and only drop at reboot. Ask
                    // before telling the user it is gone.
                    self.uninstallState = .deactivating
                    self.checkExtensionPresence()
                } else {
                    self.state?.appendLog(level: "info", message: "Network extension deactivation finishes after reboot.")
                    self.uninstallState = .pendingReboot
                }
                return
            }
            guard result == .completed else {
                self.state?.appendLog(level: "info", message: "Network extension activation finishes after reboot.")
                return
            }
            // The request remains pending while approval is outstanding. A
            // completed activation is the first point at which saving the
            // content-filter preferences is permitted.
            self.state?.appendLog(level: "info", message: "Network extension approved and active; installing filter configuration.")
            self.enableFilter()
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        Task { @MainActor in
            let missing = (error as? OSSystemExtensionError)?.code == .extensionNotFound
            switch self.requestKind {
            case .activation:
                self.fail("Extension activation failed: \(error.localizedDescription)")
            case .deactivation:
                if missing {
                    self.uninstallState = .notInstalled
                } else {
                    self.uninstallState = .failed(error.localizedDescription)
                }
                self.state?.appendLog(level: "info",
                                      message: "Network extension deactivation returned: \(error.localizedDescription)")
            case .properties:
                // The system has no record left to describe. That is the only
                // evidence available that the extension is actually gone.
                self.uninstallState = missing ? .removed : .pendingReboot
            }
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest,
                             foundProperties properties: [OSSystemExtensionProperties]) {
        Task { @MainActor in
            guard self.requestKind == .properties else { return }
            let records = properties.filter { $0.bundleIdentifier == self.extensionIdentifier }
            if records.isEmpty {
                self.uninstallState = .removed
            } else {
                self.uninstallState = .pendingReboot
            }
        }
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in
            guard self.requestKind != .deactivation else {
                // Removal can need approval too. Do not repaint the firewall
                // status as "waiting to be switched on" while the user is
                // switching it off.
                self.state?.appendLog(level: "info",
                                      message: "macOS is asking you to approve removing the FreeSnitch network extension. Approve it in System Settings > General > Login Items & Extensions > Network Extensions.")
                return
            }
            self.status = .needsApproval
            self.state?.appendLog(level: "info",
                                  message: "Approve FreeSnitch in System Settings > General > Login Items & Extensions > Network Extensions, then it will start filtering.")
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest,
                             actionForReplacingExtension existing: OSSystemExtensionProperties,
                             withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        return .replace
    }
}

/// App-side XPC object the extension calls to ask the user about a paused flow.
/// Bridges into the existing connection-alert UI via AppState.
final class AppCommunicationBridge: NSObject, AppCommunication {
    private weak var state: AppState?
    init(state: AppState) { self.state = state }

    func promptUser(flowJSON: Data, responseHandler: @escaping (Bool, Bool) -> Void) {
        guard let conn = try? JSONDecoder().decode(Connection.self, from: flowJSON) else {
            responseHandler(true, false); return
        }
        Task { @MainActor in
            guard let state = self.state else { responseHandler(true, false); return }
            state.presentAlert(for: conn, reply: responseHandler)
        }
    }

    func recordObservationBatch(observationBatch: Data, responseHandler: @escaping (Bool) -> Void) {
        guard observationBatch.count <= InsightsLimits.maxBatchBytes else {
            responseHandler(false)
            return
        }
        guard let state else {
            responseHandler(false)
            return
        }
        Task { @MainActor in
            responseHandler(state.helper.ingestObservationBatch(observationBatch))
        }
    }
}
