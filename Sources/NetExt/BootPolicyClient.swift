import Foundation

/// Connects to the helper's narrow boot-policy listener. The extension is
/// sandboxed, so it asks the root helper for the root-owned cache rather than
/// opening a path outside its app group.
final class BootPolicyClient: @unchecked Sendable {
    private let timeout: TimeInterval = 3

    func load(completion: @escaping (Data?) -> Void) {
        let connection = makeConnection()
        var finished = false
        let lock = NSLock()
        var timeoutWork: DispatchWorkItem?
        let finish: (Data?) -> Void = { data in
            lock.lock()
            guard !finished else {
                lock.unlock()
                return
            }
            finished = true
            lock.unlock()
            timeoutWork?.cancel()
            connection.invalidate()
            completion(data)
        }

        connection.invalidationHandler = { finish(nil) }
        connection.interruptionHandler = { finish(nil) }
        connection.resume()
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
            PSLog.error(PSLog.netext, "boot policy XPC load failed: \(error.localizedDescription)")
            finish(nil)
        }) as? BootPolicyProtocol else {
            finish(nil)
            return
        }

        let work = DispatchWorkItem {
            PSLog.error(PSLog.netext, "boot policy XPC load timed out; filtering will fail open")
            finish(nil)
        }
        timeoutWork = work
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: work)
        proxy.loadBootSnapshot { data in
            finish(data.isEmpty ? nil : data)
        }
    }

    func loadBlocklistSnapshot(
        since generation: String,
        completion: @escaping (String?, Data?) -> Void
    ) {
        let connection = makeConnection()
        var finished = false
        let lock = NSLock()
        var timeoutWork: DispatchWorkItem?
        let finish: (String?, Data?) -> Void = { newGeneration, data in
            lock.lock()
            guard !finished else {
                lock.unlock()
                return
            }
            finished = true
            lock.unlock()
            timeoutWork?.cancel()
            connection.invalidate()
            completion(newGeneration, data)
        }

        connection.invalidationHandler = { finish(nil, nil) }
        connection.interruptionHandler = { finish(nil, nil) }
        connection.resume()
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
            PSLog.error(PSLog.netext, "blocklist XPC load failed: \(error.localizedDescription)")
            finish(nil, nil)
        }) as? BootPolicyProtocol else {
            finish(nil, nil)
            return
        }

        let work = DispatchWorkItem {
            PSLog.error(PSLog.netext, "blocklist XPC load timed out; blocklist filtering will fail open")
            finish(nil, nil)
        }
        timeoutWork = work
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: work)
        proxy.loadBlocklistSnapshot(generation: generation) { newGeneration, data in
            finish(newGeneration, data)
        }
    }

    func store(_ snapshotJSON: Data) {
        let connection = makeConnection()
        var finished = false
        let lock = NSLock()
        var timeoutWork: DispatchWorkItem?
        let finish: (Bool, String?) -> Void = { ok, message in
            lock.lock()
            guard !finished else {
                lock.unlock()
                return
            }
            finished = true
            lock.unlock()
            timeoutWork?.cancel()
            connection.invalidate()
            if !ok {
                PSLog.error(
                    PSLog.netext,
                    message ?? "boot policy cache was not stored; future starts will fail open"
                )
            }
        }

        connection.invalidationHandler = {
            finish(false, "boot policy XPC store connection was invalidated; future starts will fail open")
        }
        connection.interruptionHandler = {
            finish(false, "boot policy XPC store connection was interrupted; future starts will fail open")
        }
        connection.resume()
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
            PSLog.error(PSLog.netext, "boot policy XPC store failed: \(error.localizedDescription)")
            finish(false, nil)
        }) as? BootPolicyProtocol else {
            finish(false, "boot policy XPC store proxy was unavailable; future starts will fail open")
            return
        }

        let work = DispatchWorkItem {
            finish(false, "boot policy XPC store timed out; future starts will fail open")
        }
        timeoutWork = work
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: work)
        proxy.storeBootSnapshot(snapshotJSON: snapshotJSON) { ok, message in
            finish(ok, message)
        }
    }

    private func makeConnection() -> NSXPCConnection {
        let connection = NSXPCConnection(
            machServiceName: AppConstants.bootPolicyMachServiceName,
            options: [.privileged]
        )
        connection.remoteObjectInterface = HelperBridge.bootPolicyInterface()
        return connection
    }
}
