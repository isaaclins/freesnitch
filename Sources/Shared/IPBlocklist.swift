import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// IP and CIDR blocklists (issue #51).
//
// These feeds are a different product from the domain blocklists. Domain lists
// are names matched by the DNS proxy; these are addresses, matched where
// addresses are actually seen: the pf anchor and the extension's per-flow path.
// The two are never merged, so "blocklists filter DNS names only" stays true
// for the thing it describes.
//
// Three properties are load bearing here:
//
//   * Validity is decided by `PFHostValidator`, and by nothing else. It is the
//     same authority the rule ingest paths use, so a feed can never introduce
//     an address shape the rest of the firewall would refuse. In particular the
//     prefix-length bounds established by #37 and #41 (0...32 for IPv4, 0...128
//     for IPv6) are enforced there, before this file ever sees a number.
//   * Safety is decided before matching, not by the feed. Loopback, the app's
//     own traffic, DHCP, and the configured resolvers can never be blocked, no
//     matter what a feed lists.
//   * Cost is paid once, when a feed is loaded. Ranges are normalized, sorted
//     and merged at load time; a lookup is a binary search over contiguous
//     storage and allocates nothing, so #38's removal of per-flow work stays
//     removed.

// MARK: - Limits

/// Explicit bounds for a data source that is large by nature and comes from
/// the network. Nothing here grows with traffic, only with a feed, and every
/// growth has a ceiling.
public enum IPBlocklistLimits {
    /// Largest feed body accepted from the network. A larger response is
    /// treated as a failed download, which is fail-open.
    public static let maxFeedBytes = 32 * 1024 * 1024
    /// Largest number of usable entries taken from one feed.
    public static let maxEntriesPerFeed = 500_000
    /// Largest number of merged ranges held in memory across all feeds.
    public static let maxRanges = 1_000_000
    /// Largest number of table entries rendered into the pf anchor. The table
    /// is bounded independently of the in-memory set, but it is large enough
    /// that a normal 100k-entry feed is not silently enforced only halfway.
    public static let maxPFTableEntries = 1_000_000
    /// Longest accepted line. Feed lines are addresses, not documents.
    public static let maxLineLength = 128
}

// MARK: - Feed model

/// One IP or CIDR feed. Deliberately a separate type from `BlocklistInfo`, so
/// an IP feed can never be listed, counted, or persisted as a domain list.
public struct IPBlocklistFeed: Codable, Sendable, Identifiable, Hashable {
    public var id: UUID
    public var name: String
    public var url: String
    public var enabled: Bool
    public var lastUpdated: Date?
    /// Entries accepted into the matcher at the last successful load.
    public var entryCount: Int
    /// Entries the validator or the safety filter refused at the last
    /// successful load. Reported rather than hidden: a feed that is mostly
    /// rejected is a feed the user should stop trusting.
    public var rejectedCount: Int
    /// Why the last refresh failed, or nil when it succeeded. A failure keeps
    /// the previous counts, because a feed that could not be fetched has not
    /// become empty.
    public var lastError: String?

    public init(
        id: UUID = UUID(),
        name: String,
        url: String,
        enabled: Bool = false,
        lastUpdated: Date? = nil,
        entryCount: Int = 0,
        rejectedCount: Int = 0,
        lastError: String? = nil
    ) {
        self.id = id
        self.name = name
        self.url = url
        self.enabled = enabled
        self.lastUpdated = lastUpdated
        self.entryCount = entryCount
        self.rejectedCount = rejectedCount
        self.lastError = lastError
    }
}

/// The feeds offered out of the box. Every one of them ships disabled: a wrong
/// CIDR can break the network path that would carry the fix, so turning an
/// address feed on is a decision the user makes, not a default.
public enum IPBlocklistCatalog {
    public static let defaults: [IPBlocklistFeed] = [
        IPBlocklistFeed(
            id: UUID(uuidString: "5B3B2F52-1F3C-4C2E-9E1E-2C0E0B6A0001")!,
            name: "FireHOL Level 1",
            url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
        ),
        IPBlocklistFeed(
            id: UUID(uuidString: "5B3B2F52-1F3C-4C2E-9E1E-2C0E0B6A0002")!,
            name: "Spamhaus DROP",
            url: "https://www.spamhaus.org/drop/drop.txt"
        ),
        IPBlocklistFeed(
            id: UUID(uuidString: "5B3B2F52-1F3C-4C2E-9E1E-2C0E0B6A0003")!,
            name: "Emerging Threats compromised hosts",
            url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
        )
    ]
}

// MARK: - Feed text parsing

/// Turns a downloaded feed body into candidate entries. This step only strips
/// syntax; it decides nothing about validity or safety.
public enum IPBlocklistFeedParser {
    public static func entries(from text: String, limit: Int = IPBlocklistLimits.maxEntriesPerFeed) -> [String] {
        var out: [String] = []
        out.reserveCapacity(min(limit, 50_000))
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            if out.count >= limit { break }
            var line = rawLine
            if line.hasSuffix("\r") { line = line.dropLast() }
            guard line.count <= IPBlocklistLimits.maxLineLength else { continue }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }
            if trimmed.hasPrefix("#") || trimmed.hasPrefix(";") || trimmed.hasPrefix("!")
                || trimmed.hasPrefix("//") || trimmed.hasPrefix("[") { continue }
            // Spamhaus writes "1.2.3.0/24 ; SBL123", FireHOL writes bare
            // networks. The address is the first token either way.
            guard let token = trimmed.split(whereSeparator: { $0 == " " || $0 == "\t" }).first else { continue }
            out.append(String(token))
        }
        return out
    }
}

// MARK: - Address values

/// A 128 bit address value. IPv4 keeps its own 32 bit space; the two families
/// are never compared against each other.
public struct IPv6Value: Comparable, Hashable, Sendable {
    public let upper: UInt64
    public let lower: UInt64

    public init(upper: UInt64, lower: UInt64) {
        self.upper = upper
        self.lower = lower
    }

    public static func < (lhs: IPv6Value, rhs: IPv6Value) -> Bool {
        lhs.upper == rhs.upper ? lhs.lower < rhs.lower : lhs.upper < rhs.upper
    }
}

/// Numeric conversion for text `PFHostValidator` has already accepted.
///
/// This is not a second parser: it never decides whether a value is a valid
/// address or whether a prefix length is in range. It calls the same
/// `inet_pton` the validator and the rule matcher call, and it re-asserts the
/// prefix bounds only as a local guard, so that no mask can ever be built from
/// an unbounded value even if a caller forgets the validator.
public enum IPBlocklistAddress {
    /// A parsed destination carried into the verdict path. Once this value is
    /// made, membership checks below touch only integers and contiguous arrays.
    /// The extension can create one alongside its existing flow destination
    /// parsing and reuse it for every address-feed check.
    public struct Value: Sendable, Equatable {
        public let ipv4: UInt32?
        public let ipv6: IPv6Value?

        public init(ipv4: UInt32) {
            self.ipv4 = ipv4
            ipv6 = nil
        }

        public init(ipv6: IPv6Value) {
            ipv4 = nil
            self.ipv6 = ipv6
        }
    }

    public static func parse(_ raw: String) -> Value? {
        if raw.contains(":") {
            return ipv6(raw).map(Value.init(ipv6:))
        }
        return ipv4(raw).map(Value.init(ipv4:))
    }

    public static func ipv4(_ raw: String) -> UInt32? {
        var address = in_addr()
        guard raw.withCString({ inet_pton(AF_INET, $0, &address) }) == 1 else { return nil }
        return UInt32(bigEndian: address.s_addr)
    }

    public static func ipv6(_ raw: String) -> IPv6Value? {
        // A link-local address arrives carrying an interface zone. The zone
        // names an interface, not a different address.
        let literal = raw.prefix { $0 != "%" }
        guard !literal.isEmpty else { return nil }
        var address = in6_addr()
        guard String(literal).withCString({ inet_pton(AF_INET6, $0, &address) }) == 1 else { return nil }
        return withUnsafeBytes(of: &address) { bytes in
            var upper: UInt64 = 0
            var lower: UInt64 = 0
            for index in 0..<8 { upper = (upper << 8) | UInt64(bytes[index]) }
            for index in 8..<16 { lower = (lower << 8) | UInt64(bytes[index]) }
            return IPv6Value(upper: upper, lower: lower)
        }
    }

    /// Splits "network/prefix" into its two already-validated halves.
    static func components(_ raw: String) -> (network: String, prefix: Int)? {
        let parts = raw.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty,
              parts[1].utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
              let prefix = Int(parts[1]) else { return nil }
        return (String(parts[0]), prefix)
    }

    static func ipv4Range(network: UInt32, prefix bits: Int) -> (UInt32, UInt32)? {
        // The mask is never built before the prefix is bounded. Swift's `<<` is
        // the non-trapping smart shift, so an out-of-range prefix would produce
        // mask 0, and mask 0 matches every address.
        guard (0...32).contains(bits) else { return nil }
        let mask: UInt32 = bits == 0 ? 0 : UInt32.max << (32 - bits)
        return (network & mask, (network & mask) | ~mask)
    }

    static func ipv6Range(network: IPv6Value, prefix bits: Int) -> (IPv6Value, IPv6Value)? {
        guard (0...128).contains(bits) else { return nil }
        let upperMask: UInt64
        let lowerMask: UInt64
        if bits == 0 {
            upperMask = 0
            lowerMask = 0
        } else if bits < 64 {
            upperMask = UInt64.max << (64 - bits)
            lowerMask = 0
        } else if bits == 64 {
            upperMask = UInt64.max
            lowerMask = 0
        } else if bits == 128 {
            upperMask = UInt64.max
            lowerMask = UInt64.max
        } else {
            upperMask = UInt64.max
            lowerMask = UInt64.max << (128 - bits)
        }
        let start = IPv6Value(upper: network.upper & upperMask, lower: network.lower & lowerMask)
        let end = IPv6Value(upper: start.upper | ~upperMask, lower: start.lower | ~lowerMask)
        return (start, end)
    }
}

// MARK: - The bounded set

/// An immutable, bounded set of addresses and networks.
///
/// Built once per refresh: every entry is validated, converted, sorted and
/// merged here. A lookup touches two contiguous arrays and allocates nothing.
public struct IPBlocklistSet: Sendable {
    private let v4Starts: ContiguousArray<UInt32>
    private let v4Ends: ContiguousArray<UInt32>
    private let v6Starts: ContiguousArray<IPv6Value>
    private let v6Ends: ContiguousArray<IPv6Value>

    /// Entries accepted into the set.
    public let acceptedEntryCount: Int
    /// Entries refused because the validator rejected them or because they
    /// touched a protected network.
    public let rejectedEntryCount: Int
    /// True when the input was larger than `IPBlocklistLimits.maxRanges` and
    /// the tail was dropped. Reported so the state stays honest.
    public let truncated: Bool
    /// The accepted entry text, in the order it was accepted, for renderers
    /// such as the pf anchor. Already validated and already safe.
    public let acceptedEntries: [String]

    public static let empty = IPBlocklistSet()

    private init() {
        v4Starts = []
        v4Ends = []
        v6Starts = []
        v6Ends = []
        acceptedEntryCount = 0
        rejectedEntryCount = 0
        truncated = false
        acceptedEntries = []
    }

    /// - Parameters:
    ///   - entries: candidate address or CIDR text.
    ///   - dropProtectedDestinations: true for a blocking set, where loopback,
    ///     local networks, link-local, multicast, unspecified and broadcast
    ///     must never enter. False only for exemption sets, where those
    ///     addresses are exactly what has to be representable.
    ///   - limit: hard ceiling on retained ranges.
    public init(
        entries: [String],
        dropProtectedDestinations: Bool = true,
        limit: Int = IPBlocklistLimits.maxRanges
    ) {
        let rangeLimit = min(max(0, limit), IPBlocklistLimits.maxRanges)
        var v4: [(UInt32, UInt32)] = []
        var v6: [(IPv6Value, IPv6Value)] = []
        var accepted: [String] = []
        var rejected = 0
        var truncatedInput = false
        v4.reserveCapacity(min(rangeLimit, entries.count))
        accepted.reserveCapacity(min(rangeLimit, entries.count))

        for entry in entries {
            if v4.count + v6.count >= rangeLimit {
                truncatedInput = true
                break
            }
            // PFHostValidator is the single authority on what an address may
            // look like, including the CIDR prefix bounds from #37 and #41.
            guard let kind = PFHostValidator.kind(for: entry), kind != .hostname else {
                rejected += 1
                continue
            }
            // A feed must never be able to reach loopback, a local network,
            // link-local, multicast, the unspecified address, or broadcast.
            // An entry that merely overlaps one of those is dropped whole
            // rather than trimmed: a partially applied CIDR is a surprise, and
            // erring towards not blocking is the safe direction.
            if dropProtectedDestinations, PFHostValidator.protectedDestinationReason(for: entry) != nil {
                rejected += 1
                continue
            }

            if let range = Self.range(for: entry, kind: kind) {
                switch range {
                case .v4(let start, let end): v4.append((start, end))
                case .v6(let start, let end): v6.append((start, end))
                }
                accepted.append(entry)
            } else {
                rejected += 1
            }
        }

        // Sorting and merging happen here, once, and never on a lookup.
        v4.sort { $0.0 == $1.0 ? $0.1 < $1.1 : $0.0 < $1.0 }
        v6.sort { $0.0 == $1.0 ? $0.1 < $1.1 : $0.0 < $1.0 }

        var mergedV4Starts = ContiguousArray<UInt32>()
        var mergedV4Ends = ContiguousArray<UInt32>()
        mergedV4Starts.reserveCapacity(v4.count)
        mergedV4Ends.reserveCapacity(v4.count)
        for (start, end) in v4 {
            if let last = mergedV4Ends.last, start <= (last == UInt32.max ? last : last + 1) {
                if end > last { mergedV4Ends[mergedV4Ends.count - 1] = end }
                continue
            }
            mergedV4Starts.append(start)
            mergedV4Ends.append(end)
        }

        var mergedV6Starts = ContiguousArray<IPv6Value>()
        var mergedV6Ends = ContiguousArray<IPv6Value>()
        mergedV6Starts.reserveCapacity(v6.count)
        mergedV6Ends.reserveCapacity(v6.count)
        for (start, end) in v6 {
            if let last = mergedV6Ends.last, start <= last || start == Self.successor(of: last) {
                if end > last { mergedV6Ends[mergedV6Ends.count - 1] = end }
                continue
            }
            mergedV6Starts.append(start)
            mergedV6Ends.append(end)
        }

        v4Starts = mergedV4Starts
        v4Ends = mergedV4Ends
        v6Starts = mergedV6Starts
        v6Ends = mergedV6Ends
        acceptedEntryCount = accepted.count
        rejectedEntryCount = rejected
        truncated = truncatedInput
        acceptedEntries = accepted
    }

    private enum ParsedRange {
        case v4(UInt32, UInt32)
        case v6(IPv6Value, IPv6Value)
    }

    private static func range(for entry: String, kind: PFHostSpecificationKind) -> ParsedRange? {
        switch kind {
        case .hostname:
            return nil
        case .ip:
            if entry.contains(":") {
                guard let address = IPBlocklistAddress.ipv6(entry) else { return nil }
                return .v6(address, address)
            }
            guard let address = IPBlocklistAddress.ipv4(entry) else { return nil }
            return .v4(address, address)
        case .cidr:
            guard let parts = IPBlocklistAddress.components(entry) else { return nil }
            if parts.network.contains(":") {
                guard let network = IPBlocklistAddress.ipv6(parts.network),
                      let range = IPBlocklistAddress.ipv6Range(network: network, prefix: parts.prefix) else { return nil }
                return .v6(range.0, range.1)
            }
            guard let network = IPBlocklistAddress.ipv4(parts.network),
                  let range = IPBlocklistAddress.ipv4Range(network: network, prefix: parts.prefix) else { return nil }
            return .v4(range.0, range.1)
        }
    }

    private static func successor(of value: IPv6Value) -> IPv6Value {
        if value.lower == UInt64.max {
            if value.upper == UInt64.max { return value }
            return IPv6Value(upper: value.upper + 1, lower: 0)
        }
        return IPv6Value(upper: value.upper, lower: value.lower + 1)
    }

    public var isEmpty: Bool { v4Starts.isEmpty && v6Starts.isEmpty }
    public var rangeCount: Int { v4Starts.count + v6Starts.count }

    /// Membership for a textual address. Parses once, then binary searches.
    public func contains(_ ip: String) -> Bool {
        guard let address = IPBlocklistAddress.parse(ip) else { return false }
        return contains(address)
    }

    /// Allocation-free membership after the caller has parsed the flow's
    /// destination. This is the API intended for the extension verdict path.
    public func contains(_ address: IPBlocklistAddress.Value) -> Bool {
        if let ipv4 = address.ipv4 { return contains(ipv4: ipv4) }
        if let ipv6 = address.ipv6 { return contains(ipv6: ipv6) }
        return false
    }

    public func contains(ipv4 address: UInt32) -> Bool {
        var low = 0
        var high = v4Starts.count - 1
        var candidate = -1
        while low <= high {
            let mid = (low + high) / 2
            if v4Starts[mid] <= address {
                candidate = mid
                low = mid + 1
            } else {
                high = mid - 1
            }
        }
        guard candidate >= 0 else { return false }
        return address <= v4Ends[candidate]
    }

    public func contains(ipv6 address: IPv6Value) -> Bool {
        var low = 0
        var high = v6Starts.count - 1
        var candidate = -1
        while low <= high {
            let mid = (low + high) / 2
            if v6Starts[mid] <= address {
                candidate = mid
                low = mid + 1
            } else {
                high = mid - 1
            }
        }
        guard candidate >= 0 else { return false }
        return address <= v6Ends[candidate]
    }

    /// Entries for the pf anchor table, bounded independently of the in-memory
    /// set because pfctl reparses the anchor on every apply.
    public func pfTableEntries(limit: Int = IPBlocklistLimits.maxPFTableEntries) -> [String] {
        let boundedLimit = max(0, min(limit, IPBlocklistLimits.maxPFTableEntries))
        return acceptedEntries.count <= boundedLimit
            ? acceptedEntries
            : Array(acceptedEntries.prefix(boundedLimit))
    }
}

// MARK: - Enforcement policy

/// Why a lookup answered the way it did. The exempt cases are not "not found":
/// they are guarantees, and naming them keeps them testable.
public enum IPBlocklistVerdict: String, Sendable, Equatable {
    case notEnforced
    case exemptOwnTraffic
    case exemptLoopback
    case exemptInfrastructurePort
    case exemptResolver
    case blocked
    case allowed

    public var isBlocked: Bool { self == .blocked }
}

/// An immutable pairing of a loaded set with the bypasses that outrank it.
///
/// The bypasses are evaluated before the set, always, so no feed can block
/// loopback, FreeSnitch's own traffic, DHCP, or a configured resolver. They are
/// not a filter applied to the feed, which could be forgotten; they are the
/// first branches of the lookup.
public struct IPBlocklistPolicy: Sendable {
    /// Ports that carry the machine's ability to be on a network at all.
    public static let infrastructurePorts: Set<Int> = [53, 67, 68, 546, 547]

    public let enforcementEnabled: Bool
    public let blocked: IPBlocklistSet
    /// Configured DNS resolvers, exempt regardless of port.
    public let resolvers: IPBlocklistSet
    public let feeds: [IPBlocklistFeed]

    public static let disabled = IPBlocklistPolicy(
        enforcementEnabled: false,
        blocked: .empty,
        resolvers: .empty,
        feeds: []
    )

    public init(
        enforcementEnabled: Bool,
        blocked: IPBlocklistSet,
        resolvers: IPBlocklistSet,
        feeds: [IPBlocklistFeed]
    ) {
        self.enforcementEnabled = enforcementEnabled
        self.blocked = blocked
        self.resolvers = resolvers
        self.feeds = feeds
    }

    public init(
        enforcementEnabled: Bool,
        blocked: IPBlocklistSet,
        resolverAddresses: [String] = [],
        feeds: [IPBlocklistFeed] = []
    ) {
        self.init(
            enforcementEnabled: enforcementEnabled,
            blocked: blocked,
            // An exemption set keeps protected addresses on purpose: a resolver
            // is very often on a local network.
            resolvers: resolverAddresses.isEmpty
                ? .empty
                : IPBlocklistSet(entries: resolverAddresses, dropProtectedDestinations: false, limit: 256),
            feeds: feeds
        )
    }

    public func withEnforcement(_ enabled: Bool) -> IPBlocklistPolicy {
        IPBlocklistPolicy(enforcementEnabled: enabled, blocked: blocked, resolvers: resolvers, feeds: feeds)
    }

    public func withResolverAddresses(_ addresses: [String]) -> IPBlocklistPolicy {
        IPBlocklistPolicy(
            enforcementEnabled: enforcementEnabled,
            blocked: blocked,
            resolverAddresses: addresses,
            feeds: feeds
        )
    }

    /// The whole verdict path. Pure, allocation-free, and safe to call from a
    /// per-flow context.
    public func verdict(remoteIP: String, remotePort: Int, isOwnTraffic: Bool) -> IPBlocklistVerdict {
        guard let address = IPBlocklistAddress.parse(remoteIP) else {
            return enforcementEnabled && Self.infrastructurePorts.contains(remotePort)
                ? .exemptInfrastructurePort
                : (enforcementEnabled ? .allowed : .notEnforced)
        }
        return verdict(address: address, remotePort: remotePort, isOwnTraffic: isOwnTraffic)
    }

    /// Allocation-free verdict overload for the per-flow path. The caller
    /// should pass the already parsed flow destination rather than asking the
    /// extension to parse the same text a second time.
    public func verdict(
        address: IPBlocklistAddress.Value,
        remotePort: Int,
        isOwnTraffic: Bool
    ) -> IPBlocklistVerdict {
        guard enforcementEnabled else { return .notEnforced }
        if isOwnTraffic { return .exemptOwnTraffic }
        if Self.isLoopback(address) { return .exemptLoopback }
        if Self.infrastructurePorts.contains(remotePort) { return .exemptInfrastructurePort }
        if resolvers.contains(address) { return .exemptResolver }
        return blocked.contains(address) ? .blocked : .allowed
    }

    public func isBlocked(remoteIP: String, remotePort: Int, isOwnTraffic: Bool) -> Bool {
        verdict(remoteIP: remoteIP, remotePort: remotePort, isOwnTraffic: isOwnTraffic).isBlocked
    }

    public static func isLoopback(_ ip: String) -> Bool {
        guard let address = IPBlocklistAddress.parse(ip) else {
            return ip == "localhost"
        }
        return isLoopback(address)
    }

    public static func isLoopback(_ address: IPBlocklistAddress.Value) -> Bool {
        if let ipv4 = address.ipv4 {
            return (0x7F00_0000...0x7FFF_FFFF).contains(ipv4)
        }
        return address.ipv6?.upper == 0 && address.ipv6?.lower == 1
    }

    /// What the UI is allowed to claim. With enforcement off the answer is
    /// zero, because that is what the list is blocking.
    public var status: IPBlocklistStatus {
        IPBlocklistStatus(
            enforcementEnabled: enforcementEnabled,
            loadedEntryCount: blocked.acceptedEntryCount,
            loadedRangeCount: blocked.rangeCount,
            rejectedEntryCount: blocked.rejectedEntryCount,
            truncated: blocked.truncated,
            enabledFeedCount: feeds.filter { $0.enabled }.count,
            failedFeedCount: feeds.filter { $0.enabled && $0.lastError != nil }.count
        )
    }
}

/// Honest state, per #22 and #12: what is loaded, and what is actually being
/// blocked right now, which are not the same number.
public struct IPBlocklistStatus: Codable, Sendable, Equatable {
    public var enforcementEnabled: Bool
    public var loadedEntryCount: Int
    public var loadedRangeCount: Int
    public var rejectedEntryCount: Int
    public var truncated: Bool
    public var enabledFeedCount: Int
    public var failedFeedCount: Int

    public init(
        enforcementEnabled: Bool,
        loadedEntryCount: Int,
        loadedRangeCount: Int,
        rejectedEntryCount: Int,
        truncated: Bool,
        enabledFeedCount: Int,
        failedFeedCount: Int
    ) {
        self.enforcementEnabled = enforcementEnabled
        self.loadedEntryCount = loadedEntryCount
        self.loadedRangeCount = loadedRangeCount
        self.rejectedEntryCount = rejectedEntryCount
        self.truncated = truncated
        self.enabledFeedCount = enabledFeedCount
        self.failedFeedCount = failedFeedCount
    }

    /// Entries that can block a flow at this moment.
    public var blockingEntryCount: Int { enforcementEnabled ? loadedEntryCount : 0 }

    public var summary: String {
        guard enabledFeedCount > 0 else {
            return "No IP or CIDR feeds are enabled. Nothing is blocked by address."
        }
        guard enforcementEnabled else {
            return "Enforcement is off, so these \(loadedEntryCount) address entries are blocking nothing."
        }
        if loadedEntryCount == 0 {
            return failedFeedCount > 0
                ? "No IP or CIDR entries are loaded, because \(failedFeedCount) enabled feed(s) could not be fetched. Nothing is blocked by address."
                : "No IP or CIDR entries are loaded. Nothing is blocked by address."
        }
        var text = "Blocking \(loadedEntryCount) address entries (\(loadedRangeCount) ranges)."
        if failedFeedCount > 0 {
            text += " \(failedFeedCount) enabled feed(s) could not be fetched and are not being enforced."
        }
        if truncated {
            text += " The set hit its size limit and was truncated."
        }
        return text
    }
}
