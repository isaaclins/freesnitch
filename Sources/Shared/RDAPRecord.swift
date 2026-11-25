import Foundation

/// The parts of an RDAP IP network record (RFC 9083) the Network Monitor
/// shows when the user asks who owns an address (#194).
///
/// Parsing only. Nothing in this file touches the network: the GUI fetches
/// the record when the user clicks, and only then.
public struct RDAPNetworkRecord: Equatable, Sendable {
    /// The registered network name, e.g. "HELIUM-NET".
    public let name: String?
    /// The registry's handle for the network, e.g. "NET-130-12-92-0-1".
    public let handle: String?
    /// The registrant's name from the first registrant entity's vCard.
    public let owner: String?
    public let country: String?
    public let startAddress: String?
    public let endAddress: String?
    /// The record's CIDR prefixes when the registry lists them (cidr0).
    public let prefixes: [String]

    /// What to show as the registered range.
    public var rangeText: String? {
        if !prefixes.isEmpty { return prefixes.prefix(3).joined(separator: ", ") }
        guard let startAddress, let endAddress else { return nil }
        return "\(startAddress) – \(endAddress)"
    }

    public var isEmpty: Bool {
        name == nil && handle == nil && owner == nil && country == nil && rangeText == nil
    }

    /// RDAP answers are small. A larger body is refused rather than parsed.
    public static let maxBodyBytes = 1024 * 1024

    public static func parse(_ data: Data) -> RDAPNetworkRecord? {
        guard data.count <= maxBodyBytes,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        if let objectClass = object["objectClassName"] as? String, objectClass != "ip network" { return nil }

        var prefixes: [String] = []
        for case let cidr as [String: Any] in (object["cidr0_cidrs"] as? [Any]) ?? [] {
            guard let length = cidr["length"] as? Int else { continue }
            if let prefix = text(cidr["v4prefix"]) ?? text(cidr["v6prefix"]) {
                prefixes.append("\(prefix)/\(length)")
            }
        }

        let record = RDAPNetworkRecord(name: text(object["name"]),
                                       handle: text(object["handle"]),
                                       owner: owner(in: object["entities"]),
                                       country: text(object["country"])?.uppercased(),
                                       startAddress: text(object["startAddress"]),
                                       endAddress: text(object["endAddress"]),
                                       prefixes: prefixes)
        return record.isEmpty ? nil : record
    }

    /// Who the network is registered to: the first registrant, else the
    /// administrative contact. RIPE lists its maintainer objects
    /// ("MNT-GOOG-PROD") under the registrant role, and those name an access
    /// key, not an owner, so they are skipped. Nested entities are searched
    /// too, where some registries put the registrant.
    private static func owner(in value: Any?) -> String? {
        for role in ["registrant", "administrative"] {
            if let name = entityName(in: value, role: role, depth: 0) { return name }
        }
        return nil
    }

    private static func entityName(in value: Any?, role: String, depth: Int) -> String? {
        guard depth < 3, let entities = value as? [Any] else { return nil }
        for case let entity as [String: Any] in entities {
            let roles = (entity["roles"] as? [Any])?.compactMap { $0 as? String } ?? []
            guard roles.contains(role), !isMaintainer(entity), let name = formattedName(entity["vcardArray"]) else { continue }
            return name
        }
        for case let entity as [String: Any] in entities {
            if let nested = entityName(in: entity["entities"], role: role, depth: depth + 1) { return nested }
        }
        return nil
    }

    private static func isMaintainer(_ entity: [String: Any]) -> Bool {
        let handle = (text(entity["handle"]) ?? "").uppercased()
        return handle.hasPrefix("MNT-") || handle.hasSuffix("-MNT")
    }

    /// `["vcard", [["fn", {}, "text", "Example Inc."], ...]]`
    private static func formattedName(_ value: Any?) -> String? {
        guard let card = value as? [Any], card.count >= 2, let properties = card[1] as? [Any] else { return nil }
        for case let property as [Any] in properties where property.count >= 4 {
            if (property[0] as? String)?.lowercased() == "fn", let name = text(property[3]) {
                return name
            }
        }
        return nil
    }

    /// A trimmed, bounded, single-line string, or nil.
    private static func text(_ value: Any?) -> String? {
        guard let raw = value as? String else { return nil }
        let line = raw.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
            .joined(separator: " ")
        guard !line.isEmpty else { return nil }
        return line.count > 200 ? String(line.prefix(200)) + "…" : line
    }

    /// The public bootstrap service: it redirects to the registry (ARIN,
    /// RIPE, APNIC, LACNIC, AFRINIC) that holds the address.
    public static func lookupURL(for ip: String) -> URL? {
        let trimmed = ip.trimmingCharacters(in: .whitespacesAndNewlines)
        guard IPGeoCache.parseIPv4(trimmed) != nil || IPGeoCache.parseIPv6(trimmed) != nil else { return nil }
        return URL(string: "https://rdap.org/ip/\(trimmed)")
    }
}
