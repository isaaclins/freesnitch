import Foundation

/// Vends only the boot-policy cache to the sandboxed Network Extension.
final class BootPolicyListener: NSObject, NSXPCListenerDelegate {
    private let service: HelperService

    init(service: HelperService) {
        self.service = service
        super.init()
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        guard XPCPeerValidator.isTrustedNetExt(newConnection) else {
            PSLog.error(
                PSLog.helper,
                "SECURITY: rejected boot-policy peer failing the FreeSnitch Network Extension code requirement (pid \(newConnection.processIdentifier))"
            )
            return false
        }
        newConnection.exportedInterface = HelperBridge.bootPolicyInterface()
        newConnection.exportedObject = service
        newConnection.invalidationHandler = { }
        newConnection.interruptionHandler = { }
        newConnection.resume()
        return true
    }
}
