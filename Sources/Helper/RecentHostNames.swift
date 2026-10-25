import Foundation

/// Names the helper has recently seen an address under: the local DNS
/// proxy's answers and the hostnames the content filter reports with flows.
/// The Network Monitor's list comes from lsof, which knows only addresses, so
/// without this every row was a bare IP even when the name was known (#168).
///
/// Display only. A name from here is put on `Connection.resolvedName` and
/// never into `remoteHost`, so the rule a Monitor row writes stays exactly the
/// address it wrote before.
final class RecentHostNames: @unchecked Sendable {
    private struct Entry {
        let name: String
        let seen: Date
    }

    private let lock = NSLock()
    private var names: [String: Entry] = [:]
    private let capacity: Int
    private let lifetime: TimeInterval

    init(capacity: Int = 4096, lifetime: TimeInterval = 60 * 60) {
        self.capacity = capacity
        self.lifetime = lifetime
    }

    func note(name rawName: String, for rawIP: String, at date: Date = Date()) {
        let name = rawName.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let ip = rawIP.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard PFHostValidator.kind(for: name) == .hostname,
              let kind = PFHostValidator.kind(for: ip), kind != .hostname else { return }
        lock.lock()
        defer { lock.unlock() }
        names[ip] = Entry(name: name, seen: date)
        if names.count > capacity { evictLocked(now: date) }
    }

    /// The hostnames carried by the filter's observations. A port-53 flow's
    /// hostname is the name being looked up and its address is the resolver,
    /// so it says nothing about where that name lives (#167).
    func note(_ observations: [FlowObservation]) {
        for observation in observations where observation.remotePort != 53 {
            note(name: observation.remoteHost, for: observation.remoteIP, at: observation.observedAt)
        }
    }

    func name(for rawIP: String, now: Date = Date()) -> String? {
        let ip = rawIP.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        lock.lock()
        defer { lock.unlock() }
        guard let entry = names[ip], now.timeIntervalSince(entry.seen) <= lifetime else { return nil }
        return entry.name
    }

    /// Fills in a name for connections that carry only an address.
    func annotate(_ connections: [Connection], now: Date = Date()) -> [Connection] {
        connections.map { connection in
            let host = connection.remoteHost
            guard connection.resolvedName == nil,
                  host.isEmpty || host == connection.remoteIP,
                  let name = name(for: connection.remoteIP, now: now) else { return connection }
            var named = connection
            named.resolvedName = name
            return named
        }
    }

    private func evictLocked(now: Date) {
        names = names.filter { now.timeIntervalSince($0.value.seen) <= lifetime }
        guard names.count > capacity else { return }
        // Still full of live names: keep the newest three quarters.
        let keep = capacity * 3 / 4
        let newest = names.sorted { $0.value.seen > $1.value.seen }.prefix(keep)
        names = Dictionary(uniqueKeysWithValues: newest.map { ($0.key, $0.value) })
    }
}
