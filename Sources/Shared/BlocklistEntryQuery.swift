import Foundation

/// Asking the helper what is on a blocklist, one bounded page at a time.
///
/// The bundled lists run to hundreds of thousands of names, so the GUI never
/// receives a whole list: it asks for a window of it, and the search runs in
/// the helper where the data already is (#79).
public struct BlocklistEntryQuery: Codable, Sendable {
    /// The most entries one reply may carry. Chosen so a page is a screenful
    /// and change, not a download.
    public static let maximumLimit = 200
    /// Longer needles are not a search, they are a payload.
    public static let maximumSearchLength = 200

    public var blocklistID: UUID
    public var search: String
    public var offset: Int
    public var limit: Int

    public init(blocklistID: UUID, search: String = "", offset: Int = 0, limit: Int = 100) {
        self.blocklistID = blocklistID
        self.search = String(search.prefix(Self.maximumSearchLength))
        self.offset = max(0, offset)
        self.limit = min(max(1, limit), Self.maximumLimit)
    }

    /// Applied again on the helper side: a caller is not trusted to have
    /// bounded itself.
    public func bounded() -> BlocklistEntryQuery {
        BlocklistEntryQuery(blocklistID: blocklistID, search: search, offset: offset, limit: limit)
    }
}

public struct BlocklistEntryPage: Codable, Sendable {
    public var entries: [String]
    /// How many entries match the query in total, which is what lets the GUI
    /// show "1 to 100 of 301675" without ever holding them.
    public var total: Int
    public var offset: Int

    public init(entries: [String], total: Int, offset: Int) {
        self.entries = entries
        self.total = total
        self.offset = offset
    }
}
