import Foundation

enum ExtensionClientError: Error {
    case transport(String)
    case invalidResponse(String)
    case rejected(String)

    var message: String {
        switch self {
        case .transport(let value), .invalidResponse(let value), .rejected(let value): return value
        }
    }
}

/// XPC client for the extension's existing app-extension channel. It is used
/// only for delivering a CLI rule/mode change. The extension validator accepts
/// this client identifier, but the extension deliberately keeps the GUI as the
/// interactive alert owner. Status does not use this channel because the bare
/// CLI cannot reliably inspect the live app-group service.
final class CLIExtensionClient: NSObject {
    private var connection: NSXPCConnection?
    private let appCommunication = CLIAppCommunication()

    func updateSnapshot(_ data: Data) async throws -> SnapshotReport {
        let status: SharedRuleBridge.SnapshotStatus = try await perform { proxy, completion in
            proxy.updateSnapshot(snapshotJSON: data) { response in
                guard let status = try? SharedRuleBridge.decodeStatus(response) else {
                    completion(.failure(ExtensionClientError.invalidResponse("The network extension returned an unreadable snapshot acknowledgement.")))
                    return
                }
                completion(.success(status))
            }
        }
        return Self.report(for: status)
    }

    private static func report(for status: SharedRuleBridge.SnapshotStatus) -> SnapshotReport {
        SnapshotReport(state: status.state.rawValue,
                       mode: status.mode.map(canonicalMode),
                       ruleCount: status.isReady ? status.ruleCount : nil,
                       updatedAt: status.updatedAt,
                       generation: status.generation,
                       message: status.message)
    }

    private func makeConnection() -> NSXPCConnection {
        let conn = NSXPCConnection(machServiceName: AppConstants.ipcMachServiceName, options: [.privileged])
        conn.exportedInterface = NSXPCInterface(with: AppCommunication.self)
        conn.exportedObject = appCommunication
        conn.remoteObjectInterface = NSXPCInterface(with: ProviderCommunication.self)
        conn.invalidationHandler = { }
        conn.interruptionHandler = { }
        conn.resume()
        connection = conn
        return conn
    }

    private func perform<T>(
        _ invoke: @escaping (ProviderCommunication, @escaping (Result<T, Error>) -> Void) -> Void
    ) async throws -> T {
        let result: Result<T, Error> = await withCheckedContinuation { continuation in
            let lock = NSLock()
            var finished = false
            var timeoutWork: DispatchWorkItem?
            let finish: (Result<T, Error>) -> Void = { result in
                lock.lock()
                guard !finished else {
                    lock.unlock()
                    return
                }
                finished = true
                lock.unlock()
                timeoutWork?.cancel()
                continuation.resume(returning: result)
            }

            let conn = connection ?? makeConnection()
            guard let proxy = conn.remoteObjectProxyWithErrorHandler({ error in
                finish(.failure(ExtensionClientError.transport("Network extension XPC failed: \(error.localizedDescription).")))
            }) as? ProviderCommunication else {
                finish(.failure(ExtensionClientError.transport("The network extension XPC proxy could not be created.")))
                return
            }
            let work = DispatchWorkItem {
                finish(.failure(ExtensionClientError.transport("The network extension did not answer within 8 seconds.")))
            }
            timeoutWork = work
            DispatchQueue.global().asyncAfter(deadline: .now() + 8, execute: work)
            invoke(proxy) { result in finish(result) }
        }
        return try result.get()
    }
}

final class CLIAppCommunication: NSObject, AppCommunication {
    func promptUser(flowJSON: Data, responseHandler: @escaping (Bool, Bool) -> Void) {
        // The CLI has no interactive alert window. Preserve the extension's
        // fail-open guarantee if a flow arrives while this diagnostic channel
        // is connected.
        responseHandler(true, false)
    }
}
