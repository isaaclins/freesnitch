import Foundation

/// Blocklist entries live in the helper, so in demo mode this screen would be
/// nothing but "the helper is not connected" and could not be reviewed before
/// shipping. This answers the same query the helper answers, with synthetic
/// names, and is inert unless FREESNITCH_DEMO is set.
enum BlocklistEntriesDemo {
    static func page(for blocklist: BlocklistInfo,
                     search: String,
                     offset: Int,
                     limit: Int) -> BlocklistEntryPage? {
        guard ProcessInfo.processInfo.environment["FREESNITCH_DEMO"] == "1" else { return nil }
        let all = entries(for: blocklist).filter { !(removed[blocklist.id]?.names.contains($0) ?? false) }
        let needle = search.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let matching = needle.isEmpty ? all : all.filter { $0.contains(needle) }
        let start = min(max(0, offset), matching.count)
        let end = min(start + limit, matching.count)
        return BlocklistEntryPage(entries: Array(matching[start..<end]),
                                  total: matching.count,
                                  offset: start)
    }

    /// Names taken off a list in demo mode, and the list's count before the
    /// first one. The names are generated from that count, so a removal drops
    /// the name the user picked instead of whichever sorted last.
    private static var removed: [UUID: (seeded: Int, names: Set<String>)] = [:]

    static func remove(_ domains: [String], from blocklist: BlocklistInfo) {
        guard ProcessInfo.processInfo.environment["FREESNITCH_DEMO"] == "1" else { return }
        removed[blocklist.id, default: (blocklist.entryCount, [])].names.formUnion(domains)
    }

    private static func entries(for blocklist: BlocklistInfo) -> [String] {
        let count = removed[blocklist.id]?.seeded ?? blocklist.entryCount
        let stems = ["ads", "track", "metrics", "telemetry", "pixel", "beacon", "analytics", "collect"]
        let domains = ["doubleclick.net", "adnxs.com", "criteo.com", "scorecardresearch.com",
                       "adsrvr.org", "taboola.com", "outbrain.com", "branch.io"]
        // Every name distinct, the way a real list is: a generator that
        // repeats itself makes the pane look broken rather than full.
        return (0..<count).map { i in
            "\(stems[i % stems.count])\(i).\(domains[i % domains.count])"
        }
        .sorted()
    }
}
