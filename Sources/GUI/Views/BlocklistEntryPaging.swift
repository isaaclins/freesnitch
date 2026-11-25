import Foundation

/// Which page the blocklist entries pane asks the helper for, apart from the
/// view so Scripts/test_blocklist_entry_removal.sh can drive it (#220).
enum BlocklistEntryPaging {
    /// What the helper changes whenever the names on a list change. A download
    /// that brings back the same names still moves the time: one extra query.
    struct ContentVersion: Equatable {
        let entryCount: Int
        let lastUpdated: Date?

        init(_ blocklist: BlocklistInfo) {
            entryCount = blocklist.entryCount
            lastUpdated = blocklist.lastUpdated
        }
    }

    /// Removing the only name on the last page leaves an offset past the end.
    /// Returns the last page to ask for instead, or nil to show the page as is.
    static func offsetToRetry(_ page: BlocklistEntryPage, offset: Int, pageSize: Int) -> Int? {
        guard page.entries.isEmpty, page.total > 0 else { return nil }
        let lastPage = (page.total - 1) / pageSize * pageSize
        return lastPage < offset ? lastPage : nil
    }
}
