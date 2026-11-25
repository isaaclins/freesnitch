import Foundation

/// The decisions the blocklist entries pane makes about which page to ask the
/// helper for. Kept apart from the view so a harness can drive them against the
/// real store (#220).
enum BlocklistEntryPaging {
    /// What the helper changes on a list whenever its names change: a removal,
    /// names added in the editor, or a download. A download that brings back
    /// the same names still moves the time, which costs one extra page query
    /// and nothing else.
    struct ContentVersion: Equatable {
        let entryCount: Int
        let lastUpdated: Date?

        init(_ blocklist: BlocklistInfo) {
            entryCount = blocklist.entryCount
            lastUpdated = blocklist.lastUpdated
        }
    }

    /// The offset to ask for instead, when a page came back empty although the
    /// list still has names: removing the only name on the last page leaves an
    /// offset past the end. Nil when the page should be shown as it is.
    static func offsetToRetry(emptyPage entries: [String],
                              total: Int,
                              offset: Int,
                              pageSize: Int) -> Int? {
        guard entries.isEmpty, total > 0, pageSize > 0 else { return nil }
        let lastPage = (total - 1) / pageSize * pageSize
        return lastPage < offset ? lastPage : nil
    }
}
