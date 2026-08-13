import Foundation

final class BlocklistManager: @unchecked Sendable {
    private let store: RuleStore
    private(set) var domains: Set<String> = []
    private let queue = DispatchQueue(label: "io.isaaclins.freesnitch.blocklists")
    var onUpdate: ((Int) -> Void)?

    private static let publicationLock = NSLock()
    private static var publicationGeneration = UUID().uuidString
    private static var publicationData = BlocklistBridge.emptySnapshotData
    private static let maxListBytes = 32 * 1024 * 1024

    init(store: RuleStore) {
        self.store = store
        Self.publish(BlocklistBridge.emptySnapshotData)
    }

    /// The privileged helper serves the current compact payload through the
    /// existing, peer-validated boot-policy listener. An empty Data response
    /// means that the caller already has this generation.
    static func blocklistSnapshot(since generation: String) -> (generation: String, data: Data) {
        publicationLock.lock()
        defer { publicationLock.unlock() }
        guard generation != publicationGeneration else {
            return (publicationGeneration, Data())
        }
        return (publicationGeneration, publicationData)
    }

    private static func publish(_ data: Data) {
        publicationLock.lock()
        publicationGeneration = UUID().uuidString
        publicationData = data
        publicationLock.unlock()
    }

    func refresh() async {
        let lists = store.allBlocklists().filter { $0.enabled }
        var merged: Set<String> = []
        await withTaskGroup(of: (BlocklistInfo, Set<String>?).self) { group in
            for list in lists {
                group.addTask { (list, await self.fetch(list)) }
            }
            for await (list, set) in group {
                // A list that failed to download must not be recorded as a
                // successful empty one, or Settings reports "0 entries,
                // updated just now" for a source that is simply gone.
                guard let set else { continue }
                merged.formUnion(set)
                var updated = list
                updated.entryCount = set.count
                updated.lastUpdated = Date()
                try? self.store.updateBlocklist(updated)
            }
        }

        let snapshotData: Data
        do {
            snapshotData = try BlocklistBridge.encode(entries: merged)
        } catch {
            // Do not let either enforcement layer use a partial or oversized
            // publication. A rejected payload is an explicit fail-open state.
            PSLog.error(PSLog.dns, "blocklist snapshot rejected: \(error)")
            queue.sync { self.domains = [] }
            Self.publish(BlocklistBridge.emptySnapshotData)
            onUpdate?(0)
            return
        }

        queue.sync { self.domains = merged }
        Self.publish(snapshotData)
        onUpdate?(merged.count)
    }

    /// `nil` means the download failed; an empty set means the source really
    /// carried no entries.
    private func fetch(_ list: BlocklistInfo) async -> Set<String>? {
        guard let url = URL(string: list.url) else { return nil }
        var req = URLRequest(url: url, timeoutInterval: 15)
        req.setValue("FreeSnitch/0.1", forHTTPHeaderField: "User-Agent")
        do {
            let (data, response) = try await URLSession.shared.data(for: req)
            // Without this check an error page parses into junk "domains":
            // GitHub's 404 body alone yields an entry called "Found".
            if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
                PSLog.error(PSLog.dns, "blocklist \(list.name) returned HTTP \(http.statusCode)")
                return nil
            }
            guard data.count <= Self.maxListBytes else {
                PSLog.error(PSLog.dns, "blocklist \(list.name) exceeded the \(Self.maxListBytes)-byte safety limit")
                return nil
            }
            guard let text = String(data: data, encoding: .utf8) else { return nil }
            return parse(text)
        } catch {
            PSLog.error(PSLog.dns, "blocklist fetch failed: \(list.name) - \(error)")
            return nil
        }
    }

    private func parse(_ text: String) -> Set<String>? {
        var out: Set<String> = []
        out.reserveCapacity(50_000)
        for raw in text.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            // "[Adblock Plus]" heads every Adblock-syntax list.
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix("!") || line.hasPrefix("[") { continue }
            var parts = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            if parts.isEmpty { continue }
            var host = parts.last ?? ""
            if parts.count >= 2, (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1" || parts[0] == "::1") {
                host = parts[1]
            }
            if host.hasPrefix("||") {
                let idx = host.firstIndex(of: "^") ?? host.endIndex
                host = String(host[host.index(host.startIndex, offsetBy: 2)..<idx])
            }
            host = host.lowercased()
            if host.hasSuffix(".") { host.removeLast() }
            if host == "localhost" || host == "0.0.0.0" || host == "broadcasthost" { continue }
            guard let kind = PFHostValidator.kind(for: host), kind != .cidr else { continue }
            guard kind == .hostname || kind == .ip else { continue }
            out.insert(host)
            if out.count > BlocklistBridge.maxEntries {
                PSLog.error(PSLog.dns, "blocklist source exceeded the \(BlocklistBridge.maxEntries)-entry safety limit")
                return nil
            }
        }
        return out
    }
}

extension HelperService {
    func loadBlocklistSnapshot(generation: String, reply: @escaping (String, Data) -> Void) {
        let snapshot = BlocklistManager.blocklistSnapshot(since: generation)
        reply(snapshot.generation, snapshot.data)
    }
}
