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
    /// Bumped by every IP feed refresh and every toggle. A refresh whose
    /// number is no longer the latest drops its result instead of publishing
    /// it, so a slow download that started before the user flipped a feed can
    /// neither undo the flip nor push an older set to pf after a newer one
    /// (#209).
    private var ipRefreshGeneration = 0
    /// Held while a refresh result is stored and handed to pf, so two results
    /// are never published out of order.
    private let ipPublishLock = NSLock()
    /// The number of the last refresh whose result was published, and the
    /// toggles waiting for a refresh newer than their own change to publish.
    private var ipPublishedGeneration = 0
    private var ipPublishWaiters: [(after: Int, resume: CheckedContinuation<Void, Never>)] = []

    /// Called after every IP feed refresh with the newly built set. Wiring
    /// this is what pushes address blocking into pf.
    var onIPBlocklistUpdate: ((IPBlocklistSet, [IPBlocklistFeed]) -> Void)?

    /// Test seam. When set, feeds are read through this instead of the
    /// network, so feed handling can be exercised deterministically.
    var ipFeedFetcher: (@Sendable (IPBlocklistFeed) async -> IPFeedFetchResult)?

    /// How long the helper waits before downloading every enabled list and
    /// address feed again (#491). Without this a helper that runs for weeks
    /// keeps whatever it fetched at start.
    static let scheduledRefreshInterval: TimeInterval = 24 * 60 * 60
    /// How soon a scheduled download that failed is tried again. A failed feed
    /// enforces nothing (fail open), so waiting a whole day to recover from a
    /// network that was briefly down would leave the user unprotected for it.
    /// The wait doubles with every failure in a row, up to the normal day, so
    /// one source that is gone for good does not make the helper download
    /// everything every hour. Domain lists and address feeds keep their own
    /// count, so a dead domain list never stretches a feed's retry.
    static let failedRefreshRetryInterval: TimeInterval = 60 * 60

    /// Test seam for the schedule, so it can be exercised without waiting.
    var clock: @Sendable () -> Date = { Date() }

    private struct DownloadSchedule {
        var last: Date?
        var failuresInARow = 0
        var running = false

        func isDue(at now: Date) -> Bool {
            guard !running else { return false }
            guard let last else { return true }
            let elapsed = now.timeIntervalSince(last)
            // A clock set back makes `elapsed` negative; that is treated as
            // due rather than as "wait until the clock catches up".
            return elapsed < 0 || elapsed >= BlocklistManager.scheduledWait(afterFailuresInARow: failuresInARow)
        }

        mutating func finish(at now: Date, succeeded: Bool) {
            last = now
            failuresInARow = succeeded ? 0 : failuresInARow + 1
            running = false
        }
    }
    private var domainSchedule = DownloadSchedule()
    private var feedSchedule = DownloadSchedule()

    static func scheduledWait(afterFailuresInARow failures: Int) -> TimeInterval {
        guard failures > 0 else { return scheduledRefreshInterval }
        let doubled = failedRefreshRetryInterval * pow(2, Double(min(failures - 1, 16)))
        return min(doubled, scheduledRefreshInterval)
    }

    init(store: RuleStore) {
        self.store = store
    }

    /// Downloads the domain lists and the address feeds side by side. This is
    /// what "Refresh Lists", `freesnitch blocklists refresh` and a profile's
    /// blocklist change all mean: both kinds of list (#491). The answer is the
    /// domain lists' result; a feed's failure is shown on the feed itself.
    @discardableResult
    func refreshAll() async -> DomainRefreshResult {
        await refresh(domains: true, feeds: true).domains ?? DomainRefreshResult(failedLists: [])
    }

    /// Downloads whichever kind is due: a day after its last clean download,
    /// an hour after a first failure and twice as long after each further
    /// one, never longer than a day. Meant to be called on a short tick;
    /// wall-clock time is compared rather than a timer relied on, because a
    /// timer does not count while the Mac sleeps. Returns whether anything
    /// was downloaded.
    @discardableResult
    func refreshIfDue() async -> Bool {
        let now = clock()
        // Checked and claimed in one step, so two ticks can't both start.
        let (domainsDue, feedsDue): (Bool, Bool) = queue.sync {
            let due = (domainSchedule.isDue(at: now), feedSchedule.isDue(at: now))
            if due.0 { domainSchedule.running = true }
            if due.1 { feedSchedule.running = true }
            return due
        }
        guard domainsDue || feedsDue else { return false }
        await refresh(domains: domainsDue, feeds: feedsDue)
        return true
    }

    @discardableResult
    private func refresh(domains: Bool, feeds: Bool) async -> (domains: DomainRefreshResult?, feedsRead: Bool) {
        queue.sync {
            if domains { domainSchedule.running = true }
            if feeds { feedSchedule.running = true }
        }
        async let domainResult: DomainRefreshResult? = domains ? refresh() : nil
        async let feedsRead = feeds ? downloadIPFeeds().allRead : true
        let (domainDone, feedsDone) = await (domainResult, feedsRead)
        let finished = clock()
        queue.sync {
            if domains { domainSchedule.finish(at: finished, succeeded: domainDone?.isComplete ?? true) }
            if feeds { feedSchedule.finish(at: finished, succeeded: feedsDone) }
        }
        return (domainDone, feedsDone)
    }

    /// What one download round did. A list whose source could not be read
    /// is named here, so a caller never reports a partial refresh as done.
    struct DomainRefreshResult: Sendable, Equatable {
        /// Enabled lists whose download failed. Their last saved entries are
        /// still what blocks for them.
        var failedLists: [String]

        var isComplete: Bool { failedLists.isEmpty }

        /// One sentence for the app and the command-line tool, or nil when
        /// every enabled list downloaded.
        var failureMessage: String? {
            guard !failedLists.isEmpty else { return nil }
            let names = failedLists.sorted().joined(separator: ", ")
            return failedLists.count == 1
                ? "Could not download \(names). Its last saved entries are still blocked."
                : "Could not download \(names). Their last saved entries are still blocked."
        }
    }

    /// Test seam. When set, domain lists are read through this instead of the
    /// network; `nil` means the download failed.
    var domainListFetcher: (@Sendable (BlocklistInfo) async -> Set<String>?)?

    @discardableResult
    func refresh() async -> DomainRefreshResult {
        let lists = store.allBlocklists().filter { $0.enabled }
        var downloadedSets: [UUID: Set<String>] = [:]
        var failed: [String] = []
        await withTaskGroup(of: (BlocklistInfo, Set<String>?).self) { group in
            for list in lists {
                group.addTask { (list, await self.fetch(list)) }
            }
            for await (list, downloaded) in group {
                // A list that failed to download must not be recorded as a
                // successful empty one, or Settings reports "0 entries,
                // updated just now" for a source that is simply gone. Nor may
                // it stop blocking: an outage or a helper restart while the
                // source is unreachable would otherwise silently drop every
                // name it carried (#252). What is stored for it, hand edits
                // included, keeps blocking until a download succeeds.
                guard var set = downloaded else {
                    failed.append(list.name)
                    PSLog.error(PSLog.dns,
                                "blocklist \(list.name) was not refreshed; its saved entries stay in effect")
                    continue
                }
                // Hand edits are reapplied after every download, which is the
                // whole reason they are stored apart from the entries (#97).
                let edits = store.blocklistEdits(id: list.id)
                set.formUnion(edits.added)
                set.subtract(edits.removed)
                downloadedSets[list.id] = set
                // Only the download's own fields are written, never `enabled`:
                // with downloads on a schedule (#491) the user may switch the
                // list off while one runs, and a stale copy would switch it
                // back on. A list deleted meanwhile is left alone.
                guard (try? self.store.recordBlocklistDownload(id: list.id, entryCount: set.count, at: Date())) == true else {
                    continue
                }
                // Kept per list, on disk, so the GUI can ask what is on a list
                // without anyone holding one in memory (#79). A failure here
                // costs the browsable copy, never the blocking itself, which
                // works off the merged set below.
                do {
                    try self.store.replaceBlocklistEntries(blocklistID: list.id, domains: Array(set))
                } catch {
                    PSLog.error(PSLog.helper,
                                "blocklist entries for \(list.name) could not be stored: \(error.localizedDescription)")
                }
            }
        }
        // Built from the lists that are on now, for the same reason. A list
        // that failed, or was switched on during the download, blocks from
        // its saved copy until its own download lands.
        var merged: Set<String> = []
        for list in store.allBlocklists() where list.enabled {
            merged.formUnion(downloadedSets[list.id] ?? storedEntries(of: list))
        }
        queue.sync { self.domains = merged }
        onUpdate?(merged.count)
        return DomainRefreshResult(failedLists: failed)
    }

    /// Rebuilds the matching set from what is already stored, without touching
    /// the network. A hand edit changes what should be blocked immediately;
    /// waiting for the next scheduled download would leave a name the user just
    /// removed blocked for hours (#97).
    func rebuildFromStore() {
        var merged: Set<String> = []
        for list in store.allBlocklists() where list.enabled {
            merged.formUnion(storedEntries(of: list))
        }
        queue.sync { self.domains = merged }
        onUpdate?(merged.count)
    }

    /// Everything stored for one list, read in bounded pages.
    private func storedEntries(of list: BlocklistInfo) -> Set<String> {
        var entries: Set<String> = []
        var offset = 0
        while true {
            let page = store.blocklistEntries(blocklistID: list.id,
                                              search: "",
                                              offset: offset,
                                              limit: BlocklistEntryQuery.maximumLimit)
            entries.formUnion(page.entries)
            offset += page.entries.count
            if page.entries.isEmpty || offset >= page.total { break }
        }
        return entries
    }

    /// `nil` means the download failed; an empty set means the source really
    /// carried no entries.
    private func fetch(_ list: BlocklistInfo) async -> Set<String>? {
        if let domainListFetcher { return await domainListFetcher(list) }
        // A hand-written list has no source. It has not failed to download;
        // there is nothing to download, and its entries are its edits (#97).
        if list.url.trimmingCharacters(in: .whitespaces).isEmpty { return [] }
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
        _ = ipFeeds()
        ipPublishLock.lock()
        defer { ipPublishLock.unlock() }
        let changed: [IPBlocklistFeed]? = queue.sync {
            guard var feeds = ipFeedsCache,
                  let index = feeds.firstIndex(where: {
                      $0.id.uuidString.caseInsensitiveCompare(idString) == .orderedSame
                  }) else { return nil }
            feeds[index].enabled = enabled
            ipFeedsCache = feeds
            // Whatever refresh is in flight was planned without this change.
            ipRefreshGeneration += 1
            return feeds
        }
        guard let changed else { return false }
        storeIPFeeds(changed)
        return true
    }

    /// The feeds and what they block, for the app and the command-line tool.
    func ipFeedsReport(enforcementEnabled: Bool,
                       addressTableRefused: Bool = false,
                       resolverAddresses: [String] = []) -> IPFeedsReport {
        let refused = enforcementEnabled && addressTableRefused && !currentIPBlocklist().isEmpty
        let policy = ipBlocklistPolicy(enforcementEnabled: enforcementEnabled && !refused,
                                       resolverAddresses: resolverAddresses)
        return IPFeedsReport(feeds: policy.feeds, status: policy.status, addressTableRefused: refused)
    }

    /// Downloads every enabled address feed and rebuilds the matcher.
    ///
    /// Fail open, in both directions: a feed that cannot be fetched, is too
    /// large, or parses to nothing usable contributes no entries and records
    /// why, and a refresh where every feed fails leaves an empty set that
    /// blocks nothing. An address feed must never be able to take the machine
    /// off the network, least of all by failing.
    /// Returns false when a newer refresh or a toggle overtook this one, so
    /// its result was dropped rather than published.
    @discardableResult
    func refreshIPBlocklists() async -> Bool {
        await downloadIPFeeds().published
    }

    /// The feed download itself. Besides whether its result was published, it
    /// says whether every enabled feed could be read, which the download
    /// schedule backs off on (#491) even when a toggle overtook it.
    private func downloadIPFeeds() async -> (published: Bool, allRead: Bool) {
        _ = ipFeeds()
        let (generation, snapshot): (Int, [IPBlocklistFeed]) = queue.sync {
            ipRefreshGeneration += 1
            return (ipRefreshGeneration, ipFeedsCache ?? IPBlocklistCatalog.defaults)
        }
        var feeds = snapshot
        let enabled = feeds.enumerated().filter { $0.element.enabled }
        guard !enabled.isEmpty else {
            return (applyIPEntries([], to: feeds, generation: generation), true)
        }

        var allRead = true
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
                let remaining = max(0, IPBlocklistLimits.maxRanges - entries.count)
                let loaded = min(remaining, built.acceptedEntries.count)
                entries.append(contentsOf: built.acceptedEntries.prefix(loaded))
                feeds[index].loadedEntryCount = loaded
                if built.acceptedEntries.count > remaining {
                    feeds[index].lastError = loaded == 0
                        ? "combined IP blocklist range limit reached by earlier feeds; this feed was not loaded"
                        : "combined IP blocklist range limit reached; feed tail was not loaded"
                }
            case .some(.failure(let reason)):
                allRead = false
                feeds[index].lastError = reason
                feeds[index].loadedEntryCount = 0
                PSLog.error(PSLog.pf, "IP blocklist \(feeds[index].name) unavailable: \(reason); it is enforcing nothing")
            case .none:
                allRead = false
                feeds[index].lastError = "feed was not read"
                feeds[index].loadedEntryCount = 0
                PSLog.error(PSLog.pf, "IP blocklist \(feeds[index].name) was not read; it is enforcing nothing")
            }
        }

        return (applyIPEntries(entries, to: feeds, generation: generation), allRead)
    }

    /// A toggle, then a refresh, returning once a refresh that started after
    /// the toggle has been published, so the caller answers with counts from
    /// a download that already includes the change (#493).
    ///
    /// When another refresh overtakes this one, this one is dropped and the
    /// newer one carries the change, because it read the feeds after the
    /// toggle. So this waits for that one instead of downloading again, which
    /// let two switches flipped close together keep cancelling each other's
    /// downloads. Every toggle is followed by a refresh, and the newest
    /// refresh always publishes, so the wait always ends.
    func setIPFeedEnabledAndRefresh(idString: String, enabled: Bool) async -> Bool {
        guard setIPFeedEnabled(idString: idString, enabled: enabled) else { return false }
        let toggleGeneration = queue.sync { ipRefreshGeneration }
        if await refreshIPBlocklists() { return true }
        await waitForIPPublish(after: toggleGeneration)
        return true
    }

    private func waitForIPPublish(after generation: Int) async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let alreadyPublished: Bool = queue.sync {
                if ipPublishedGeneration > generation { return true }
                ipPublishWaiters.append((generation, continuation))
                return false
            }
            if alreadyPublished { continuation.resume() }
        }
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

    @discardableResult
    private func applyIPEntries(_ entries: [String], to feeds: [IPBlocklistFeed], generation: Int) -> Bool {
        let set = IPBlocklistSet(entries: entries)
        ipPublishLock.lock()
        defer { ipPublishLock.unlock() }
        let published: [IPBlocklistFeed]? = queue.sync {
            // A newer refresh or a toggle happened while this one downloaded.
            // The newer refresh publishes; this result is already out of date.
            guard generation == ipRefreshGeneration else { return nil }
            ipSet = set
            ipFeedsCache = feeds
            ipPublishedGeneration = generation
            return feeds
        }
        guard let published else { return false }
        storeIPFeeds(published)
        onIPBlocklistUpdate?(set, published)
        // Released once pf has the set, so a waiting toggle answers with what
        // is enforced.
        let ready: [CheckedContinuation<Void, Never>] = queue.sync {
            let due = ipPublishWaiters.filter { $0.after < generation }.map(\.resume)
            ipPublishWaiters.removeAll { $0.after < generation }
            return due
        }
        ready.forEach { $0.resume() }
        return true
    }

    private func storeIPFeeds(_ feeds: [IPBlocklistFeed]) {
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
