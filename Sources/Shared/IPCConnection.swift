import Foundation

/// Implemented by the GUI app; called by the system extension when a flow needs
/// an interactive decision. `responseHandler(allow, remember)`.
@objc public protocol AppCommunication {
    func promptUser(flowJSON: Data, responseHandler: @escaping (Bool, Bool) -> Void)
}

/// Implemented by the system extension; called by the app to establish the link.
@objc public protocol ProviderCommunication {
    func register(_ completionHandler: @escaping (Bool) -> Void)
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

    private override init() { super.init() }

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
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
            self.currentConnection = nil
        }) as? AppCommunication else {
            return false
        }
        proxy.promptUser(flowJSON: flowJSON, responseHandler: responseHandler)
        return true
    }

    // MARK: - App side

    /// Called from the app once the extension is active. Connects to the
    /// extension's mach service and registers `delegate` to receive prompts.
    public func register(delegate: AppCommunication, completionHandler: @escaping (Bool) -> Void) {
        self.delegate = delegate

        let newConnection = NSXPCConnection(machServiceName: AppConstants.ipcMachServiceName, options: [])
        newConnection.exportedInterface = NSXPCInterface(with: AppCommunication.self)
        newConnection.exportedObject = delegate
        newConnection.remoteObjectInterface = NSXPCInterface(with: ProviderCommunication.self)
        newConnection.invalidationHandler = { [weak self] in self?.currentConnection = nil }
        newConnection.interruptionHandler = { [weak self] in self?.currentConnection = nil }
        currentConnection = newConnection
        newConnection.resume()

        guard let proxy = newConnection.remoteObjectProxyWithErrorHandler({ _ in
            completionHandler(false)
        }) as? ProviderCommunication else {
            completionHandler(false)
            return
        }
        proxy.register(completionHandler)
    }
}

extension IPCConnection: NSXPCListenerDelegate {
    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        // Extension side: the app connected. Export ProviderCommunication and
        // keep the connection so we can call promptUser on it later.
        newConnection.exportedInterface = NSXPCInterface(with: ProviderCommunication.self)
        newConnection.exportedObject = self
        newConnection.remoteObjectInterface = NSXPCInterface(with: AppCommunication.self)
        newConnection.invalidationHandler = { [weak self] in self?.currentConnection = nil }
        newConnection.interruptionHandler = { [weak self] in self?.currentConnection = nil }
        currentConnection = newConnection
        newConnection.resume()
        return true
    }
}

extension IPCConnection: ProviderCommunication {
    public func register(_ completionHandler: @escaping (Bool) -> Void) {
        completionHandler(true)
    }
}
