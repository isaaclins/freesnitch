import Foundation

public struct RuleMatcher: Sendable {
    public init() {}

    public func decision(for c: Connection, rules: [Rule], defaultMode: AppMode) -> RuleAction {
        let sorted = rules.filter { $0.enabled }.filter { rule in
            if let exp = rule.expiresAt, exp < Date() { return false }
            return true
        }.sorted { $0.priority > $1.priority }

        for r in sorted where matches(rule: r, connection: c) {
            return r.action
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
        guard let bits = Int(parts[1]), (0...32).contains(bits) else { return false }
        let net = String(parts[0])
        guard let a = ipv4ToUInt32(net), let b = ipv4ToUInt32(ip) else { return false }
        let mask: UInt32 = bits == 0 ? 0 : UInt32.max << (32 - bits)
        return (a & mask) == (b & mask)
    }

    private func ipv4ToUInt32(_ s: String) -> UInt32? {
        let octs = s.split(separator: ".", omittingEmptySubsequences: false)
        guard octs.count == 4 else { return nil }
        var v: UInt32 = 0
        for o in octs {
            guard !o.isEmpty, o.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
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
