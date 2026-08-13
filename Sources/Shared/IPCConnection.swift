import Foundation

/// Implemented by the GUI app; called by the system extension when a flow needs
/// an interactive decision. `responseHandler(allow, remember)`.
@objc public protocol AppCommunication {
    func promptUser(flowJSON: Data, responseHandler: @escaping (Bool, Bool) -> Void)
    func recordObservationBatch(observationBatch: Data, responseHandler: @escaping (Bool) -> Void)
}

/// Implemented by the system extension; called by the app to establish the link
/// and to hand over the active rule set.
@objc public protocol ProviderCommunication {
    func register(_ completionHandler: @escaping (Bool, Data) -> Void)
    /// The app pushes mode and rules here. The app group container cannot be
    /// used for this: the extension runs as root, so its container resolves to
    /// /var/root/Library/Group Containers while the app writes to the user's
    /// home, and the two never meet.
    func updateSnapshot(snapshotJSON: Data, completionHandler: @escaping (Data) -> Void)
}

/// App <-> Network System Extension XPC, modelled on Apple's "SimpleFirewall"
/// sample. The extension vends an `NSXPCListener` on a mach service whose name
/// is prefixed by the team identifier / app group; the app connects to it. The
/// extension then calls back into the app (`promptUser`) over the same
/// connection to drive the connection-alert UI.
public final class IPCConnection: NSObject, @unchecked Sendable {
    public static let shared = IPCConnection()

    private var listener: NSXPCListener?
    private var currentConnection: NSXPCConnection?
    private weak var delegate: AppCommunication?
    /// Extension side: invoked when the app pushes a rule set. It returns the
    /// provider's resulting status synchronously so the app can publish it.
    public var onSnapshot: ((Data) -> SharedRuleBridge.SnapshotStatus)?
    /// Extension side: supplies the current status during registration.
    public var snapshotStatus: (() -> SharedRuleBridge.SnapshotStatus)?

    private override init() { super.init() }

    private static func encodeStatus(_ status: SharedRuleBridge.SnapshotStatus) -> Data {
        (try? SharedRuleBridge.encode(status)) ?? Data()
    }

    private static func decodeStatus(_ data: Data) -> SharedRuleBridge.SnapshotStatus {
        (try? SharedRuleBridge.decodeStatus(data))
            ?? .unavailable("Network extension returned an unreadable snapshot status.")
    }

    private static func unavailableStatus(_ detail: String) -> SharedRuleBridge.SnapshotStatus {
        .unavailable("\(detail) No rule snapshot was delivered; filtering remains fail-open.")
    }

    // MARK: - Extension side

    /// Called from the provider's `startFilter`. Vends the mach service the app
    /// connects to.
    public func startListener() {
        let newListener = NSXPCListener(machServiceName: AppConstants.ipcMachServiceName)
        newListener.delegate = self
        newListener.resume()
        listener = newListener
    }

    /// Called from the provider to ask the app about a flow. Returns false if no
    /// app is currently connected (caller should then fail open).
    @discardableResult
    public func promptUser(flowJSON: Data, responseHandler: @escaping (Bool, Bool) -> Void) -> Bool {
        guard let connection = currentConnection else { return false }
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ [weak self, weak connection] _ in
            self?.clearCurrentConnection(connection)
        }) as? AppCommunication else {
            return false
        }
        proxy.promptUser(flowJSON: flowJSON, responseHandler: responseHandler)
        return true
    }

    /// Extension side: hand a bounded observation batch to the connected GUI.
    /// A missing GUI or transport error drops the batch. The extension never
    /// waits for the acknowledgement and never retries an individual flow.
    @discardableResult
    public func sendObservationBatch(_ data: Data) -> Bool {
        guard data.count <= InsightsLimits.maxBatchBytes else { return false }
        guard let connection = currentConnection,
              let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in }) as? AppCommunication else {
            return false
        }
        proxy.recordObservationBatch(observationBatch: data) { _ in }
        return true
    }

    /// App side: hand the current mode and rules to the extension. Silently
    /// reports an unavailable status when the extension is not running, which
    /// is the normal case for builds without one.
    public func sendSnapshot(
        _ snapshotJSON: Data,
        completionHandler: @escaping (SharedRuleBridge.SnapshotStatus) -> Void = { _ in }
    ) {
        var completed = false
        let completionLock = NSLock()
        let finish: (SharedRuleBridge.SnapshotStatus) -> Void = { status in
            completionLock.lock()
            guard !completed else {
                completionLock.unlock()
                return
            }
            completed = true
            completionLock.unlock()
            completionHandler(status)
        }

        guard let connection = currentConnection else {
            finish(Self.unavailableStatus("Network extension IPC is not connected."))
            return
        }
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
            finish(Self.unavailableStatus("Network extension IPC failed: \(error.localizedDescription)."))
        }) as? ProviderCommunication else {
            finish(Self.unavailableStatus("Network extension IPC proxy is unavailable."))
            return
        }
        proxy.updateSnapshot(snapshotJSON: snapshotJSON) { statusJSON in
            finish(Self.decodeStatus(statusJSON))
        }
    }

    // MARK: - App side

    /// Called from the app once the extension is active. Connects to the
    /// extension's mach service and registers `delegate` to receive prompts.
    public func register(
        delegate: AppCommunication,
        completionHandler: @escaping (Bool, SharedRuleBridge.SnapshotStatus) -> Void
    ) {
        self.delegate = delegate

        var completed = false
        let completionLock = NSLock()
        let finish: (Bool, SharedRuleBridge.SnapshotStatus) -> Void = { ok, status in
            completionLock.lock()
            guard !completed else {
                completionLock.unlock()
                return
            }
            completed = true
            completionLock.unlock()
            completionHandler(ok, status)
        }

        // The extension runs as root, so its listener is registered in the
        // system domain. Without .privileged launchd searches the per-user GUI
        // domain instead and every lookup fails with "No such process", which
        // silently left the filter with no rules and no way to raise alerts.
        // HelperClient already talks to the root helper this way.
        let newConnection = NSXPCConnection(machServiceName: AppConstants.ipcMachServiceName,
                                            options: [.privileged])
        newConnection.exportedInterface = NSXPCInterface(with: AppCommunication.self)
        newConnection.exportedObject = delegate
        newConnection.remoteObjectInterface = NSXPCInterface(with: ProviderCommunication.self)
        newConnection.invalidationHandler = { [weak self] in
            self?.currentConnection = nil
            finish(false, Self.unavailableStatus("Network extension rejected or invalidated the GUI XPC peer."))
        }
        newConnection.interruptionHandler = { [weak self] in self?.currentConnection = nil }
        currentConnection = newConnection
        newConnection.resume()

        guard let proxy = newConnection.remoteObjectProxyWithErrorHandler({ error in
            finish(false, Self.unavailableStatus("Network extension IPC rejected the GUI peer or failed: \(error.localizedDescription)."))
        }) as? ProviderCommunication else {
            finish(false, Self.unavailableStatus("Network extension IPC proxy is unavailable."))
            return
        }
        proxy.register { ok, statusJSON in
            finish(ok, Self.decodeStatus(statusJSON))
        }
    }
}

extension IPCConnection: NSXPCListenerDelegate {
    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        guard XPCPeerValidator.isTrustedGUI(newConnection) else {
            PSLog.error(PSLog.netext,
                        "SECURITY: rejected XPC peer failing the FreeSnitch GUI code requirement "
                        + "(pid \(newConnection.processIdentifier)); no snapshot was accepted and "
                        + "filtering will fail open if no trusted GUI is connected.")
            return false
        }
        // Extension side: the signed GUI connected. Export ProviderCommunication
        // and keep the connection so we can call promptUser on it later.
        newConnection.exportedInterface = NSXPCInterface(with: ProviderCommunication.self)
        newConnection.exportedObject = self
        newConnection.remoteObjectInterface = NSXPCInterface(with: AppCommunication.self)
        newConnection.invalidationHandler = { [weak self, weak newConnection] in
            self?.clearCurrentConnection(newConnection)
        }
        newConnection.interruptionHandler = { [weak self, weak newConnection] in
            self?.clearCurrentConnection(newConnection)
        }
        // A CLI connection is allowed to inspect and update snapshots, but it
        // must not replace the GUI connection that answers interactive alerts.
        if !XPCPeerValidator.isCLI(newConnection) {
            currentConnection = newConnection
        }
        newConnection.resume()
        return true
    }

    private func clearCurrentConnection(_ connection: NSXPCConnection?) {
        guard let connection, currentConnection === connection else { return }
        currentConnection = nil
    }
}

extension IPCConnection: ProviderCommunication {
    public func register(_ completionHandler: @escaping (Bool, Data) -> Void) {
        let status = snapshotStatus?()
            ?? .unavailable("Network extension has not received a rule snapshot from the GUI.")
        completionHandler(true, Self.encodeStatus(status))
    }

    public func updateSnapshot(
        snapshotJSON: Data,
        completionHandler: @escaping (Data) -> Void
    ) {
        let status = onSnapshot?(snapshotJSON)
            ?? .unavailable("Network extension is not ready to receive rule snapshots.")
        completionHandler(Self.encodeStatus(status))
    }
}
