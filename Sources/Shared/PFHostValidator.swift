import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

public enum PFHostSpecificationKind: String, Equatable, Sendable {
    case ip
    case cidr
    case hostname
}

/// Validates values before they become PF host specifications.
///
/// This intentionally accepts only literal IP addresses, CIDRs, and DNS
/// hostnames that can be represented as one PF token. DNS reverse-lookup names
/// are queries, not destinations, and are never accepted here.
public enum PFHostValidator {
    public static func kind(for raw: String) -> PFHostSpecificationKind? {
        guard !raw.isEmpty,
              raw == raw.trimmingCharacters(in: .whitespacesAndNewlines),
              !isReverseDNSName(raw) else { return nil }

        if raw.contains("/") {
            return cidrBits(for: raw) == nil ? nil : .cidr
        }
        if parseAddress(raw) != nil { return .ip }
        if looksLikeIPv4Literal(raw) { return nil }
        return isHostname(raw) ? .hostname : nil
    }

    public static func rejectionReason(for raw: String) -> String {
        if raw.isEmpty || raw.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return "host specification is empty"
        }
        if raw != raw.trimmingCharacters(in: .whitespacesAndNewlines) {
            return "host specification contains leading or trailing whitespace"
        }
        if isReverseDNSName(raw) {
            return "reverse-DNS query names ending in .in-addr.arpa or .ip6.arpa are not destinations"
        }
        if raw.contains("/") {
            return "CIDR does not contain a valid IP address and prefix length"
        }
        return "value is not a valid IP address or plausible hostname"
    }

    /// Returns a reason when a destination must not be used by a blocking PF
    /// rule. Allow rules are unaffected by this safety check.
    public static func protectedDestinationReason(for raw: String) -> String? {
        let normalized = raw.lowercased().hasSuffix(".")
            ? String(raw.dropLast()).lowercased()
            : raw.lowercased()
        if normalized == "localhost" || normalized.hasSuffix(".localhost") || normalized.hasSuffix(".local") {
            return "loopback or local-link hostname"
        }

        guard let range = addressRange(for: raw) else { return nil }
        if protectedRanges.contains(where: { rangesOverlap(range, $0) }) {
            return "loopback, local-network, link-local, multicast, unspecified, or broadcast network"
        }
        return nil
    }

    private enum AddressFamily {
        case ipv4
        case ipv6
    }

    private struct ParsedAddress {
        let family: AddressFamily
        let bitLength: Int
        let bytes: [UInt8]
    }

    private struct AddressRange {
        let family: AddressFamily
        let prefixLength: Int
        let bytes: [UInt8]
    }

    private static var protectedRanges: [AddressRange] {
        [
            addressRange(for: "0.0.0.0/8"),
            addressRange(for: "10.0.0.0/8"),
            addressRange(for: "127.0.0.0/8"),
            addressRange(for: "169.254.0.0/16"),
            addressRange(for: "172.16.0.0/12"),
            addressRange(for: "192.168.0.0/16"),
            addressRange(for: "224.0.0.0/4"),
            addressRange(for: "255.255.255.255/32"),
            addressRange(for: "::/128"),
            addressRange(for: "::1/128"),
            addressRange(for: "fc00::/7"),
            addressRange(for: "fe80::/10"),
            addressRange(for: "ff00::/8")
        ].compactMap { $0 }
    }

    private static func isReverseDNSName(_ raw: String) -> Bool {
        var value = raw.lowercased()
        if value.hasSuffix(".") { value.removeLast() }
        return value == "in-addr.arpa"
            || value.hasSuffix(".in-addr.arpa")
            || value == "ip6.arpa"
            || value.hasSuffix(".ip6.arpa")
    }

    private static func looksLikeIPv4Literal(_ raw: String) -> Bool {
        let parts = raw.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 4 && parts.allSatisfy { part in
            !part.isEmpty && part.utf8.allSatisfy { $0 >= 48 && $0 <= 57 }
        }
    }

    private static func isHostname(_ raw: String) -> Bool {
        var value = raw
        if value.hasSuffix(".") { value.removeLast() }
        guard !value.isEmpty, value.utf8.count <= 253 else { return false }

        let labels = value.split(separator: ".", omittingEmptySubsequences: false)
        guard !labels.isEmpty else { return false }
        for label in labels {
            let bytes = Array(label.utf8)
            guard (1...63).contains(bytes.count),
                  isASCIIAlphaNumeric(bytes[0]),
                  isASCIIAlphaNumeric(bytes[bytes.count - 1]) else { return false }
            guard bytes.allSatisfy({ isASCIIAlphaNumeric($0) || $0 == 45 }) else { return false }
        }
        return true
    }

    private static func isASCIIAlphaNumeric(_ byte: UInt8) -> Bool {
        (byte >= 48 && byte <= 57)
            || (byte >= 65 && byte <= 90)
            || (byte >= 97 && byte <= 122)
    }

    private static func cidrBits(for raw: String) -> Int? {
        let parts = raw.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2,
              !parts[0].isEmpty,
              !parts[1].isEmpty,
              parts[1].utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
              let address = parseAddress(String(parts[0])),
              let prefix = Int(parts[1]),
              (0...address.bitLength).contains(prefix) else { return nil }
        return prefix
    }

    private static func parseAddress(_ raw: String) -> ParsedAddress? {
        var v4 = in_addr()
        if raw.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            let bytes = withUnsafeBytes(of: &v4) { Array($0) }
            return ParsedAddress(family: .ipv4, bitLength: 32, bytes: bytes)
        }

        var v6 = in6_addr()
        if raw.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
            let bytes = withUnsafeBytes(of: &v6) { Array($0) }
            return ParsedAddress(family: .ipv6, bitLength: 128, bytes: bytes)
        }
        return nil
    }

    private static func addressRange(for raw: String) -> AddressRange? {
        let address: String
        let prefix: Int?
        if raw.contains("/") {
            let parts = raw.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { return nil }
            address = String(parts[0])
            prefix = Int(parts[1])
        } else {
            address = raw
            prefix = nil
        }

        guard let parsed = parseAddress(address) else { return nil }
        let length = prefix ?? parsed.bitLength
        guard (0...parsed.bitLength).contains(length) else { return nil }
        return AddressRange(family: parsed.family, prefixLength: length, bytes: parsed.bytes)
    }

    private static func rangesOverlap(_ lhs: AddressRange, _ rhs: AddressRange) -> Bool {
        guard lhs.family == rhs.family else { return false }
        let commonBits = min(lhs.prefixLength, rhs.prefixLength)
        guard commonBits > 0 else { return true }
        for bit in 0..<commonBits {
            let byte = bit / 8
            let mask = UInt8(1 << (7 - (bit % 8)))
            if (lhs.bytes[byte] & mask) != (rhs.bytes[byte] & mask) { return false }
        }
        return true
    }
}
