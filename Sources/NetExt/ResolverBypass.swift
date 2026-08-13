#if canImport(NetworkExtension)
import Foundation
import NetworkExtension
import SystemConfiguration

/// Tracks the system DNS servers without consulting them on the flow path.
/// If the configuration cannot be read, every port-53 destination remains
/// allowed so a resolver configuration failure cannot become a lockout.
final class ResolverBypass: @unchecked Sendable {
    private let lock = NSLock()
    private var addresses: Set<String> = []
    private var hasConfiguration = false
    private let refreshQueue = DispatchQueue(label: "io.isaaclins.freesnitch.netext.resolvers")
    private let timer: DispatchSourceTimer

    init() {
        timer = DispatchSource.makeTimerSource(queue: refreshQueue)
        timer.schedule(deadline: .now(), repeating: 30)
        timer.setEventHandler { [weak self] in self?.refresh() }
        timer.resume()
    }

    deinit {
        timer.cancel()
    }

    /// Returns true for DHCP, local stubs handled by the caller, or a
    /// configured resolver. An unknown address fails open for DNS safety.
    func allowsDNS(to remoteIP: String) -> Bool {
        guard !remoteIP.isEmpty else { return true }
        let normalized = remoteIP.lowercased().split(separator: "%").first.map(String.init) ?? remoteIP
        lock.lock()
        defer { lock.unlock() }
        return !hasConfiguration || addresses.contains(normalized)
    }

    private func refresh() {
        let store = SCDynamicStoreCreate(nil, "FreeSnitchResolverBypass" as CFString, nil, nil)
        var found: Set<String> = []
        if let store {
            collect(SCDynamicStoreCopyValue(store, "State:/Network/Global/DNS" as CFString), into: &found)
            let patterns = ["State:/Network/Service/.*/DNS"] as CFArray
            if let values = SCDynamicStoreCopyMultiple(store, nil, patterns) as? [String: Any] {
                for value in values.values {
                    collect(value, into: &found)
                }
            }
        }

        lock.lock()
        addresses = found
        hasConfiguration = !found.isEmpty
        lock.unlock()
        if found.isEmpty {
            PSLog.error(
                PSLog.netext,
                "system DNS resolver configuration unavailable; allowing port-53 destinations to preserve name resolution"
            )
        }
    }

    private func collect(_ value: Any?, into result: inout Set<String>) {
        guard let dictionary = value as? [String: Any],
              let serverAddresses = dictionary["ServerAddresses"] as? [String] else { return }
        for address in serverAddresses {
            let normalized = address.lowercased().split(separator: "%").first.map(String.init) ?? address
            guard PFHostValidator.kind(for: normalized) == .ip else { continue }
            result.insert(normalized)
        }
    }
}
#endif
