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
        let mgr = NEFilterManager.shared()
        mgr.loadFromPreferences { [weak self] loadError in
            DispatchQueue.main.async {
                guard let self else { return }
                if let loadError {
                    self.recordFilterDiagnostic(state: "unknown", detail: "Could not read the content filter preferences: \(loadError.localizedDescription).")
                    self.fail("filter load: \(loadError.localizedDescription)")
                    return
                }
                if mgr.providerConfiguration == nil {
                    self.recordFilterDiagnostic(state: "missing", detail: "No FreeSnitch content filter configuration is installed.")
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
                            self.recordFilterDiagnostic(state: "unknown", detail: "The content filter configuration could not be saved: \(saveError.localizedDescription).")
                            self.fail("filter save: \(saveError.localizedDescription)")
                            return
                        }
                        self.recordFilterDiagnostic(state: "installed-enabled", detail: "The content filter configuration is installed and enabled.")
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
}
