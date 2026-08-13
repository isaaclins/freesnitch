import Foundation

final class BlocklistManager: @unchecked Sendable {
    /// The result of reading one IP feed. A failure is a reason, never an
    /// empty body: a feed that could not be fetched has not become empty.
    enum IPFeedFetchResult: Sendable {
        case body(String)
        case failure(String)
    }

    private let store: RuleStore
    private(set) var domains: Set<String> = []
    private let queue = DispatchQueue(label: "io.isaaclins.freesnitch.blocklists")
    var onUpdate: ((Int) -> Void)?

    /// Address feeds are a separate kind of list with a separate storage key,
    /// a separate matcher, and a separate enforcement point. Nothing here ever
    /// touches `domains`, and nothing in the domain path ever reads these.
    static let ipFeedsSettingKey = "ip_blocklists"
    private var ipSet: IPBlocklistSet = .empty
    private var ipFeedsCache: [IPBlocklistFeed]?

    /// Called after every IP feed refresh with the newly built set. Wiring
    /// this is what pushes address blocking into pf.
    var onIPBlocklistUpdate: ((IPBlocklistSet, [IPBlocklistFeed]) -> Void)?

    /// Test seam. When set, feeds are read through this instead of the
    /// network, so feed handling can be exercised deterministically.
    var ipFeedFetcher: (@Sendable (IPBlocklistFeed) async -> IPFeedFetchResult)?

    init(store: RuleStore) {
        self.store = store
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
        queue.sync { self.domains = merged }
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
            guard let text = String(data: data, encoding: .utf8) else { return nil }
            return parse(text)
        } catch {
            PSLog.error(PSLog.dns, "blocklist fetch failed: \(list.name) - \(error)")
            return nil
        }
    }

    private func parse(_ text: String) -> Set<String> {
        var out: Set<String> = []
        out.reserveCapacity(50_000)
        for raw in text.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            // "[Adblock Plus]" heads every Adblock-syntax list.
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix("!") || line.hasPrefix("[") { continue }
            let parts = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
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
            if host.contains("/") { continue }
            if host == "localhost" || host == "0.0.0.0" || host == "broadcasthost" { continue }
            if host.isEmpty { continue }
            out.insert(host)
        }
        return out
    }

    // MARK: - IP and CIDR feeds

    /// The configured address feeds, seeded from the catalog the first time.
    /// Persisted next to, never inside, the domain blocklist table.
    func ipFeeds() -> [IPBlocklistFeed] {
        if let cached = queue.sync(execute: { ipFeedsCache }) { return cached }
        let stored = store.getSetting(BlocklistManager.ipFeedsSettingKey)
            .flatMap { $0.data(using: .utf8) }
            .flatMap { try? JSONDecoder().decode([IPBlocklistFeed].self, from: $0) }
        let feeds = stored ?? IPBlocklistCatalog.defaults
        queue.sync { ipFeedsCache = feeds }
        return feeds
    }

    /// Enables or disables one address feed. Returns false when the id is
    /// unknown, so a caller can answer honestly instead of silently doing
    /// nothing.
    @discardableResult
    func setIPFeedEnabled(idString: String, enabled: Bool) -> Bool {
        var feeds = ipFeeds()
        guard let index = feeds.firstIndex(where: { $0.id.uuidString == idString }) else { return false }
        feeds[index].enabled = enabled
        persistIPFeeds(feeds)
        return true
    }

    /// Downloads every enabled address feed and rebuilds the matcher.
    ///
    /// Fail open, in both directions: a feed that cannot be fetched, is too
    /// large, or parses to nothing usable contributes no entries and records
    /// why, and a refresh where every feed fails leaves an empty set that
    /// blocks nothing. An address feed must never be able to take the machine
    /// off the network, least of all by failing.
    func refreshIPBlocklists() async {
        var feeds = ipFeeds()
        let enabled = feeds.enumerated().filter { $0.element.enabled }
        guard !enabled.isEmpty else {
            applyIPEntries([], to: &feeds)
            return
        }

        var bodies: [Int: IPFeedFetchResult] = [:]
        await withTaskGroup(of: (Int, IPFeedFetchResult).self) { group in
            for (index, feed) in enabled {
                group.addTask { (index, await self.fetchIPFeed(feed)) }
            }
            for await (index, result) in group { bodies[index] = result }
        }

        var entries: [String] = []
        entries.reserveCapacity(IPBlocklistLimits.maxRanges)
        for (index, _) in enabled {
            switch bodies[index] {
            case .some(.body(let text)):
                let parsed = IPBlocklistFeedParser.entries(from: text)
                // Counting happens on the built set, not on the raw lines, so
                // the number the UI shows is the number that can actually
                // match.
                let built = IPBlocklistSet(entries: parsed)
                feeds[index].entryCount = built.acceptedEntryCount
                feeds[index].rejectedCount = built.rejectedEntryCount
                feeds[index].lastUpdated = Date()
                feeds[index].lastError = nil
                let remaining = IPBlocklistLimits.maxRanges - entries.count
                if remaining > 0 {
                    entries.append(contentsOf: built.acceptedEntries.prefix(remaining))
                }
                if built.acceptedEntries.count > remaining {
                    feeds[index].lastError = "combined IP blocklist range limit reached; feed tail was not loaded"
                }
            case .some(.failure(let reason)):
                feeds[index].lastError = reason
                PSLog.error(PSLog.pf, "IP blocklist \(feeds[index].name) unavailable: \(reason); it is enforcing nothing")
            case .none:
                feeds[index].lastError = "feed was not read"
                PSLog.error(PSLog.pf, "IP blocklist \(feeds[index].name) was not read; it is enforcing nothing")
            }
        }

        applyIPEntries(entries, to: &feeds)
    }

    /// The current address matcher. Immutable, so a caller can hold it across
    /// a verdict without locking.
    func currentIPBlocklist() -> IPBlocklistSet {
        queue.sync { ipSet }
    }

    /// One immutable value carrying the set, the bypasses that outrank it, and
    /// whether enforcement is on at all.
    func ipBlocklistPolicy(enforcementEnabled: Bool, resolverAddresses: [String] = []) -> IPBlocklistPolicy {
        IPBlocklistPolicy(
            enforcementEnabled: enforcementEnabled,
            blocked: currentIPBlocklist(),
            resolverAddresses: resolverAddresses,
            feeds: ipFeeds()
        )
    }

    private func applyIPEntries(_ entries: [String], to feeds: inout [IPBlocklistFeed]) {
        let set = IPBlocklistSet(entries: entries)
        queue.sync { ipSet = set }
        persistIPFeeds(feeds)
        onIPBlocklistUpdate?(set, feeds)
    }

    private func persistIPFeeds(_ feeds: [IPBlocklistFeed]) {
        queue.sync { ipFeedsCache = feeds }
        guard let data = try? JSONEncoder().encode(feeds),
              let text = String(data: data, encoding: .utf8) else { return }
        try? store.setSetting(BlocklistManager.ipFeedsSettingKey, text)
    }

    private func fetchIPFeed(_ feed: IPBlocklistFeed) async -> IPFeedFetchResult {
        if let ipFeedFetcher { return await ipFeedFetcher(feed) }
        guard let url = URL(string: feed.url), url.scheme == "https" else {
            return .failure("feed URL is not an https URL")
        }
        var request = URLRequest(url: url, timeoutInterval: 30)
        request.setValue("FreeSnitch/0.1", forHTTPHeaderField: "User-Agent")
        do {
            // `data(for:)` waits for and allocates the complete response before
            // this code can inspect its size. AsyncBytes lets us stop at the
            // hard byte ceiling, so a hostile or accidentally huge feed never
            // becomes an unbounded allocation.
            let (bytes, response) = try await URLSession.shared.bytes(for: request)
            if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
                return .failure("HTTP \(http.statusCode)")
            }
            var data = Data()
            data.reserveCapacity(min(IPBlocklistLimits.maxFeedBytes, 1 * 1024 * 1024))
            for try await byte in bytes {
                guard data.count < IPBlocklistLimits.maxFeedBytes else {
                    return .failure("feed is larger than the \(IPBlocklistLimits.maxFeedBytes) byte limit")
                }
                data.append(byte)
            }
            guard let text = String(data: data, encoding: .utf8) else {
                return .failure("feed body is not UTF-8")
            }
            return .body(text)
        } catch {
            return .failure("\(error.localizedDescription)")
        }
    }
}
