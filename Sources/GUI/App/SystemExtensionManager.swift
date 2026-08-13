import Foundation
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

    private enum RequestKind {
        case activation
        case deactivation
    }

    @Published var status: Status = .idle
    @Published var snapshotStatus = SharedRuleBridge.SnapshotStatus.unavailable(
        "Network extension IPC is not connected."
    )

    private weak var state: AppState?
    private let extensionIdentifier = AppConstants.bundleIdNetExt
    private let log = OSLog(subsystem: AppConstants.bundleIdGUI, category: "sysext")
    private var bridge: AppCommunicationBridge?
    private var requestKind: RequestKind = .activation
    private var filterConfigurationActive = false

    init(state: AppState) {
        self.state = state
        super.init()
        state.filterSnapshotStatusHandler = { [weak self] snapshotStatus in
            self?.recordSnapshotStatus(snapshotStatus)
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

    // MARK: - Content filter configuration

    private func enableFilter() {
        let mgr = NEFilterManager.shared()
        mgr.loadFromPreferences { [weak self] loadError in
            DispatchQueue.main.async {
                guard let self else { return }
                if let loadError { self.fail("filter load: \(loadError.localizedDescription)"); return }
                if mgr.providerConfiguration == nil {
                    let cfg = NEFilterProviderConfiguration()
                    cfg.filterSockets = true
                    cfg.filterPackets = false
                    mgr.providerConfiguration = cfg
                    mgr.localizedDescription = "FreeSnitch"
                }
                mgr.isEnabled = true
                mgr.saveToPreferences { saveError in
                    DispatchQueue.main.async {
                        if let saveError {
                            self.fail("filter save: \(saveError.localizedDescription)")
                            return
                        }
                        self.filterConfigurationActive = true
                        self.status = .active
                        // Deliberately does NOT touch `helperConnected`: the
                        // content filter and the privileged helper are separate
                        // subsystems, and claiming the helper is up here made
                        // the UI report "connected" while XPC was dead.
                        self.state?.appendLog(level: "info", message: "Per-process firewall active.")
                        self.registerIPC()
                    }
                }
            }
        }
    }

    private func disableFilter() {
        let mgr = NEFilterManager.shared()
        mgr.loadFromPreferences { error in
            guard error == nil else { return }
            mgr.isEnabled = false
            mgr.saveToPreferences { _ in }
        }
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
            guard self.requestKind == .activation else {
                if result == .completed {
                    self.filterConfigurationActive = false
                    self.status = .idle
                } else {
                    self.state?.appendLog(level: "info", message: "Network extension deactivation finishes after reboot.")
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
        Task { @MainActor in self.fail("Extension activation failed: \(error.localizedDescription)") }
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in
            self.status = .needsApproval
            self.state?.appendLog(level: "info",
                                  message: "Approve FreeSnitch in System Settings > Privacy & Security, then it will start filtering.")
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
}
