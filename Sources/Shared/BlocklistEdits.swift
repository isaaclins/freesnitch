import Foundation

/// What a user changed about a blocklist, kept apart from what the source says.
///
/// A downloaded list is replaced wholesale on every refresh, so an edit written
/// into the downloaded copy would live until the next refresh and then vanish
/// without a word. The edits are therefore stored beside the list and reapplied
/// after every download: effective = downloaded, plus `added`, minus `removed`
/// (#97). That also makes "reset to what shipped" a single deletion rather than
/// a second download of the original.
///
/// A list with no source URL is entirely `added`: that is what a hand-written
/// list is.
public struct BlocklistEdits: Codable, Sendable, Equatable {
    public var added: [String]
    public var removed: [String]

    /// A hand-edited list is a hand-sized thing. The cap is what keeps one
    /// command inside the transport's byte limit and one list out of the
    /// territory where this feature would need a different design.
    public static let maximumEntries = 2_000

    public init(added: [String] = [], removed: [String] = []) {
        self.added = added
        self.removed = removed
    }

    public var isEmpty: Bool { added.isEmpty && removed.isEmpty }
}

/// One place that decides what a blocklist entry is.
///
/// The helper's parser accepts whole hosts files; this accepts one name typed
/// by a person, and rejects anything that would silently never match: a URL, a
/// path, a port, a wildcard, an address.
public enum BlocklistDomain {
    public static let maximumLength = 253

    /// Returns the normalised name, or nil when it is not one.
    public static func normalise(_ raw: String) -> String? {
        var host = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !host.isEmpty else { return nil }
        // A pasted URL is a common and harmless mistake, so the host is taken
        // out of it rather than refused.
        if let range = host.range(of: "://") { host = String(host[range.upperBound...]) }
        if let slash = host.firstIndex(of: "/") { host = String(host[..<slash]) }
        if let colon = host.firstIndex(of: ":") { host = String(host[..<colon]) }
        while host.hasPrefix(".") { host.removeFirst() }
        while host.hasSuffix(".") { host.removeLast() }
        guard !host.isEmpty, host.utf8.count <= maximumLength else { return nil }
        guard host.contains(".") else { return nil }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789.-_")
        guard host.unicodeScalars.allSatisfy({ allowed.contains($0) }) else { return nil }
        guard host != "localhost", host != "broadcasthost" else { return nil }
        return host
    }

    /// Normalises a block of typed or pasted text into distinct names, keeping
    /// the order they were written in.
    public static func normaliseAll<S: Sequence>(_ raw: S) -> [String] where S.Element == String {
        var seen: Set<String> = []
        var out: [String] = []
        for line in raw {
            guard let host = normalise(line) else { continue }
            guard seen.insert(host).inserted else { continue }
            out.append(host)
        }
        return out
    }

    public static func normaliseText(_ text: String) -> [String] {
        normaliseAll(text.split(whereSeparator: { $0 == "\n" || $0 == "," || $0 == " " }).map(String.init))
    }
}
