import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

fileprivate struct PreparedIPv6Address: Equatable, Sendable {
    let upper: UInt64
    let lower: UInt64
}

fileprivate struct PreparedIPv6Network: Sendable {
    let upper: UInt64
    let lower: UInt64
    let upperMask: UInt64
    let lowerMask: UInt64

    init(address: PreparedIPv6Address, prefix: Int) {
        if prefix == 0 {
            upperMask = 0
            lowerMask = 0
        } else if prefix < 64 {
            upperMask = UInt64.max << (64 - prefix)
            lowerMask = 0
        } else if prefix == 64 {
            upperMask = UInt64.max
            lowerMask = 0
        } else {
            upperMask = UInt64.max
            lowerMask = UInt64.max << (128 - prefix)
        }
        upper = address.upper & upperMask
        lower = address.lower & lowerMask
    }

    func contains(_ address: PreparedIPv6Address) -> Bool {
        address.upper & upperMask == upper && address.lower & lowerMask == lower
    }
}

fileprivate func parsePreparedIPv6Address(_ raw: String) -> PreparedIPv6Address? {
    let literal = raw.prefix { $0 != "%" }
    guard !literal.isEmpty else { return nil }
    var address = in6_addr()
    guard String(literal).withCString({ inet_pton(AF_INET6, $0, &address) }) == 1 else { return nil }
    return withUnsafeBytes(of: &address) { bytes in
        var upper: UInt64 = 0
        var lower: UInt64 = 0
        for index in 0..<8 { upper = (upper << 8) | UInt64(bytes[index]) }
        for index in 8..<16 { lower = (lower << 8) | UInt64(bytes[index]) }
        return PreparedIPv6Address(upper: upper, lower: lower)
    }
}

fileprivate func parsePreparedIPv4Address(_ raw: String) -> UInt32? {
    let octets = raw.split(separator: ".", omittingEmptySubsequences: false)
    guard octets.count == 4 else { return nil }
    var address: UInt32 = 0
    for octet in octets {
        guard !octet.isEmpty,
              octet.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
              octet.count == 1 || octet.first != "0",
              let value = UInt32(octet), value < 256 else { return nil }
        address = (address << 8) | value
    }
    return address
}

fileprivate struct PreparedConnectionAddress: Sendable {
    let ipv4: UInt32?
    let ipv6: PreparedIPv6Address?

    init(_ raw: String, needsIPv4: Bool, needsIPv6: Bool) {
        ipv4 = needsIPv4 && !raw.contains(":") ? parsePreparedIPv4Address(raw) : nil
        ipv6 = needsIPv6 && raw.contains(":") ? parsePreparedIPv6Address(raw) : nil
    }
}

fileprivate enum PreparedHostPattern: Sendable {
    case exact(String)
    case wildcard(base: String, dottedSuffix: String)
    case suffix(String)

    init(_ raw: String) {
        if raw.hasPrefix("*.") {
            let base = String(raw.dropFirst(2))
            self = .wildcard(base: base, dottedSuffix: "." + base)
        } else if raw.hasPrefix(".") {
            self = .suffix(String(raw.dropFirst()))
        } else {
            self = .exact(raw)
        }
    }

    func matches(_ host: String) -> Bool {
        switch self {
        case .exact(let value):
            return host == value
        case .wildcard(let base, let dottedSuffix):
            return host == base || host.hasSuffix(dottedSuffix)
        case .suffix(let value):
            return host.hasSuffix(value)
        }
    }
}

fileprivate struct PreparedIPPattern: Sendable {
    fileprivate enum Comparison: Sendable {
        case exactOnly
        case wildcard(String)
        case ipv6Literal(PreparedIPv6Address)
        case ipv4CIDR(network: UInt32, mask: UInt32)
        case ipv6CIDR(PreparedIPv6Network)
    }

    let raw: String
    let comparison: Comparison

    init(_ raw: String) {
        self.raw = raw

        if raw.contains("/") {
            let parts = raw.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty,
                  parts[1].utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else {
                comparison = .exactOnly
                return
            }
            let network = String(parts[0])
            if network.contains(":") {
                guard let bits = Int(parts[1]), (0...128).contains(bits),
                      let address = parsePreparedIPv6Address(network) else {
                    comparison = .exactOnly
                    return
                }
                comparison = .ipv6CIDR(PreparedIPv6Network(address: address, prefix: bits))
            } else {
                guard let bits = Int(parts[1]), (0...32).contains(bits),
                      let address = parsePreparedIPv4Address(network) else {
                    comparison = .exactOnly
                    return
                }
                let mask: UInt32 = bits == 0 ? 0 : UInt32.max << (32 - bits)
                comparison = .ipv4CIDR(network: address & mask, mask: mask)
            }
            return
        }

        if raw.contains(":") {
            comparison = parsePreparedIPv6Address(raw).map(Comparison.ipv6Literal) ?? .exactOnly
        } else if raw.hasSuffix(".*") {
            comparison = .wildcard(String(raw.dropLast(2)) + ".")
        } else {
            comparison = .exactOnly
        }
    }

    var needsIPv4: Bool {
        if case .ipv4CIDR = comparison { return true }
        return false
    }

    var needsIPv6: Bool {
        switch comparison {
        case .ipv6Literal, .ipv6CIDR: return true
        default: return false
        }
    }

    func matches(rawIP: String, parsed: PreparedConnectionAddress) -> Bool {
        if raw == rawIP { return true }
        switch comparison {
        case .exactOnly:
            return false
        case .wildcard(let prefix):
            return rawIP.hasPrefix(prefix)
        case .ipv6Literal(let expected):
            return parsed.ipv6 == expected
        case .ipv4CIDR(let network, let mask):
            guard let address = parsed.ipv4 else { return false }
            return address & mask == network
        case .ipv6CIDR(let network):
            guard let address = parsed.ipv6 else { return false }
            return network.contains(address)
        }
    }
}

fileprivate struct PreparedRule: Sendable {
    let action: RuleAction
    let expiresAt: Date?
    let direction: RuleDirection?
    let processBundleId: String?
    let processPath: String?
    let remotePort: Int?
    let remoteHost: PreparedHostPattern?
    let remoteIP: PreparedIPPattern?

    init(_ rule: Rule) {
        action = rule.action
        expiresAt = rule.expiresAt
        direction = rule.direction == .any ? nil : rule.direction
        processBundleId = rule.processBundleId.flatMap { $0.isEmpty ? nil : $0 }
        processPath = rule.processPath.flatMap { $0.isEmpty ? nil : $0 }
        remotePort = rule.remotePort.flatMap { $0 == 0 ? nil : $0 }
        remoteHost = rule.remoteHost.flatMap { $0.isEmpty ? nil : PreparedHostPattern($0) }
        remoteIP = rule.remoteIP.flatMap { $0.isEmpty ? nil : PreparedIPPattern($0) }
    }

    var needsIPv4: Bool { remoteIP?.needsIPv4 ?? false }
    var needsIPv6: Bool { remoteIP?.needsIPv6 ?? false }

    func matches(connection: Connection, address: PreparedConnectionAddress) -> Bool {
        if let direction, direction != connection.direction { return false }
        if let processBundleId, (connection.processBundleId ?? "") != processBundleId { return false }
        if let processPath, !connection.processPath.hasPrefix(processPath) { return false }
        if let remotePort, connection.remotePort != remotePort { return false }
        if let remoteHost, !remoteHost.matches(connection.remoteHost) { return false }
        if let remoteIP, !remoteIP.matches(rawIP: connection.remoteIP, parsed: address) { return false }
        return true
    }
}

/// The enabled rules of one policy snapshot, already in the order the matcher
/// consults them.
///
/// Ordering a rule set is O(n log n) and belongs to the moment a snapshot is
/// applied, not to a verdict. Every new socket flow used to pay two filtered
/// array copies and a full sort before the filter could answer, and that cost
/// grew with the rule count, so a burst of new connections was also the most
/// expensive moment.
public struct PreparedRuleSet: Sendable {
    /// Enabled rules, highest priority first.
    public let ordered: [Rule]
    fileprivate let compiled: [PreparedRule]
    fileprivate let needsIPv4: Bool
    fileprivate let needsIPv6: Bool

    public init(rules: [Rule]) {
        // Which rule wins must never depend on a sort algorithm's tie
        // handling, so equal priorities keep the order the snapshot delivered
        // them in.
        ordered = rules.enumerated()
            .filter { $0.element.enabled }
            .sorted { lhs, rhs in
                lhs.element.priority == rhs.element.priority
                    ? lhs.offset < rhs.offset
                    : lhs.element.priority > rhs.element.priority
            }
            .map { $0.element }
        compiled = ordered.map(PreparedRule.init)
        needsIPv4 = compiled.contains(where: \.needsIPv4)
        needsIPv6 = compiled.contains(where: \.needsIPv6)
    }
}

public struct RuleMatcher: Sendable {
    public init() {}

    /// Orders the rule set on every call. A verdict path should hold a
    /// `PreparedRuleSet` and use the overload below instead.
    public func decision(for c: Connection, rules: [Rule], defaultMode: AppMode) -> RuleAction {
        decision(for: c, prepared: PreparedRuleSet(rules: rules), defaultMode: defaultMode)
    }

    public func decision(for c: Connection, prepared: PreparedRuleSet, defaultMode: AppMode) -> RuleAction {
        // Expiry is the one predicate that cannot be precomputed, because it
        // depends on when the flow arrives rather than on the snapshot. It
        // stays a test inside the scan, which allocates nothing.
        let now = Date()
        let address = PreparedConnectionAddress(
            c.remoteIP,
            needsIPv4: prepared.needsIPv4,
            needsIPv6: prepared.needsIPv6
        )
        for r in prepared.compiled {
            if let exp = r.expiresAt, exp < now { continue }
            if r.matches(connection: c, address: address) { return r.action }
        }

        switch defaultMode {
        case .alert: return .ask
        case .silentAllow: return .allow
        case .silentDeny: return .deny
        }
    }

    public func matches(rule r: Rule, connection c: Connection) -> Bool {
        if r.direction != .any && r.direction != c.direction { return false }
        if let bid = r.processBundleId, !bid.isEmpty {
            if (c.processBundleId ?? "") != bid { return false }
        }
        if let path = r.processPath, !path.isEmpty {
            if c.processPath != path && !c.processPath.hasPrefix(path) { return false }
        }
        if let port = r.remotePort, port != 0 {
            if c.remotePort != port { return false }
        }
        if let host = r.remoteHost, !host.isEmpty {
            if !hostMatches(pattern: host, host: c.remoteHost) { return false }
        }
        if let ip = r.remoteIP, !ip.isEmpty {
            if !ipMatches(pattern: ip, ip: c.remoteIP) { return false }
        }
        return true
    }

    public func hostMatches(pattern: String, host: String) -> Bool {
        if pattern == host { return true }
        if pattern.hasPrefix("*.") {
            let suf = String(pattern.dropFirst(2))
            return host == suf || host.hasSuffix("." + suf)
        }
        if pattern.hasPrefix(".") {
            let suf = String(pattern.dropFirst())
            return host.hasSuffix(suf)
        }
        return false
    }

    public func ipMatches(pattern: String, ip: String) -> Bool {
        if pattern == ip { return true }
        if pattern.contains("/") { return cidrContains(cidr: pattern, ip: ip) }
        // One IPv6 address has many spellings. A rule written as 2001:db8::1
        // means the same host as the expanded form the flow reports, and a
        // link-local address arrives carrying an interface zone, so an IPv6
        // literal is compared as bytes rather than as text.
        if pattern.contains(":") {
            guard let a = ipv6Bytes(pattern), let b = ipv6Bytes(ip) else { return false }
            return a == b
        }
        if pattern.hasSuffix(".*") {
            let prefix = String(pattern.dropLast(2))
            return ip.hasPrefix(prefix + ".")
        }
        return false
    }

    // A matcher must never widen a rule. Swift's `<<` is the non-trapping
    // smart shift, so an out-of-range prefix silently produced mask 0 here and
    // mask 0 matches every address: a malformed deny rule denied everything and
    // a malformed allow rule was a silent bypass. The prefix is therefore
    // bounded before it is ever turned into a mask, independently of whatever
    // validation the ingest paths perform.
    private func cidrContains(cidr: String, ip: String) -> Bool {
        let parts = cidr.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty else { return false }
        guard parts[1].utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else { return false }
        let net = String(parts[0])
        // The two families are separate address spaces. A colon in the network
        // decides which one this rule speaks about, and neither parser accepts
        // the other's text, so an IPv4 CIDR can never cover an IPv6 flow or the
        // reverse.
        if net.contains(":") { return ipv6CidrContains(network: net, prefix: parts[1], ip: ip) }
        guard let bits = Int(parts[1]), (0...32).contains(bits) else { return false }
        guard let a = ipv4ToUInt32(net), let b = ipv4ToUInt32(ip) else { return false }
        let mask: UInt32 = bits == 0 ? 0 : UInt32.max << (32 - bits)
        return (a & mask) == (b & mask)
    }

    /// Compares the leading `prefix` bits of two 16 byte addresses.
    ///
    /// Ingest accepted IPv6 CIDRs long before anything could match one, so an
    /// enabled `2001:db8::/32` rule was inert. The prefix is bounded to
    /// 0...128 before any mask exists, for the same reason the IPv4 path bounds
    /// its own: a mask of zero matches every address.
    private func ipv6CidrContains(network: String, prefix: Substring, ip: String) -> Bool {
        guard let bits = Int(prefix), (0...128).contains(bits) else { return false }
        guard let net = ipv6Bytes(network), let addr = ipv6Bytes(ip) else { return false }
        let wholeBytes = bits / 8
        for i in 0..<wholeBytes where net[i] != addr[i] { return false }
        let remainingBits = bits % 8
        if remainingBits == 0 { return true }
        let mask = UInt8(0xFF) << (8 - remainingBits)
        return (net[wholeBytes] & mask) == (addr[wholeBytes] & mask)
    }

    /// Parses an IPv6 literal into its 16 bytes, or nil for anything else.
    ///
    /// `inet_pton` is the same parser `PFHostValidator` validates with, so the
    /// matcher accepts exactly what ingest stored. It rejects a zone id, and
    /// the filter sees link-local addresses as fe80::1%en0, so the zone is cut
    /// first: it names an interface, not a different address.
    private func ipv6Bytes(_ raw: String) -> [UInt8]? {
        let literal = raw.prefix { $0 != "%" }
        guard !literal.isEmpty else { return nil }
        var v6 = in6_addr()
        guard String(literal).withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 else { return nil }
        return withUnsafeBytes(of: &v6) { Array($0) }
    }

    private func ipv4ToUInt32(_ s: String) -> UInt32? {
        let octs = s.split(separator: ".", omittingEmptySubsequences: false)
        guard octs.count == 4 else { return nil }
        var v: UInt32 = 0
        for o in octs {
            // A leading zero is ambiguous: inet_pton rejects it and other
            // parsers read it as octal. Ingest validation already refuses it,
            // so the matcher agrees rather than inventing a third reading of
            // the same text.
            guard !o.isEmpty, o.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
                  o.count == 1 || o.first != "0",
                  let n = UInt32(o), n < 256 else { return nil }
            v = (v << 8) | n
        }
        return v
    }
}

/// Validates the address pattern a rule may carry, at every ingest boundary.
///
/// The matcher already refuses to evaluate anything this rejects, so ingest
/// validation exists to fail loudly at the point of entry instead of storing a
/// rule that can never do what its author meant.
public enum RuleAddressValidator {
    public static let remediation = "Use a literal IP address such as 1.2.3.4, a CIDR whose prefix length is 0 through 32 for IPv4 or 0 through 128 for IPv6, or an octet wildcard such as 10.1.*."

    /// Returns nil when the value is usable as a rule address, otherwise a
    /// short reason. An absent or empty value is not an address constraint at
    /// all and stays accepted.
    public static func rejectionReason(forRemoteIP raw: String?) -> String? {
        guard let value = raw, !value.isEmpty else { return nil }
        if value != value.trimmingCharacters(in: .whitespacesAndNewlines) {
            return "the address has leading or trailing whitespace"
        }
        if value.hasSuffix(".*") {
            return isOctetWildcard(value)
                ? nil
                : "an octet wildcard must be one to three numeric octets followed by .*"
        }
        switch PFHostValidator.kind(for: value) {
        case .ip, .cidr:
            return nil
        case .hostname:
            return "a hostname belongs in the host field, not the IP field"
        case .none:
            return PFHostValidator.rejectionReason(for: value)
        }
    }

    private static func isOctetWildcard(_ value: String) -> Bool {
        let octets = value.dropLast(2).split(separator: ".", omittingEmptySubsequences: false)
        guard (1...3).contains(octets.count) else { return false }
        return octets.allSatisfy { octet in
            !octet.isEmpty
                && octet.utf8.allSatisfy { $0 >= 48 && $0 <= 57 }
                && (UInt32(octet).map { $0 < 256 } ?? false)
        }
    }
}
