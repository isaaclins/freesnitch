import Foundation

public struct InternetAccessPolicy: Hashable, Sendable {
    public struct Connection: Hashable, Sendable {
        public let host: String
        public let purpose: String
        public let denyConsequences: String?
        public let relevance: String
        public let isIncoming: Bool
        public let networkProtocol: String?
        public let port: String?

        public init(
            host: String,
            purpose: String,
            denyConsequences: String? = nil,
            relevance: String = "Default",
            isIncoming: Bool = false,
            networkProtocol: String? = nil,
            port: String? = nil
        ) {
            self.host = host
            self.purpose = purpose
            self.denyConsequences = denyConsequences
            self.relevance = relevance
            self.isIncoming = isIncoming
            self.networkProtocol = networkProtocol
            self.port = port
        }
    }

    public struct Service: Hashable, Sendable {
        public let name: String
        public let purpose: String
        public let identifier: String?

        public init(name: String, purpose: String, identifier: String? = nil) {
            self.name = name
            self.purpose = purpose
            self.identifier = identifier
        }
    }

    public let developerName: String?
    public let applicationDescription: String
    public let website: String?
    public let connections: [Connection]
    public let services: [Service]

    public init(
        developerName: String? = nil,
        applicationDescription: String,
        website: String? = nil,
        connections: [Connection] = [],
        services: [Service] = []
    ) {
        self.developerName = developerName
        self.applicationDescription = applicationDescription
        self.website = website
        self.connections = connections
        self.services = services
    }

    public func matchingConnections(for remoteHost: String?) -> [Connection] {
        guard let host = Self.normalizedHost(remoteHost) else {
            let exactDomainMatches = connections.filter { connection in
                Self.hostValues(for: connection.host).contains(where: Self.isUnscopedExactMatch)
            }
            if !exactDomainMatches.isEmpty {
                return Self.ordered(exactDomainMatches)
            }
            return Self.ordered(connections.filter { connection in
                Self.hostValues(for: connection.host).contains { $0 == "*" }
            })
        }

        let exactMatches = connections.filter { connection in
            Self.hostValues(for: connection.host).contains { token in
                Self.isExactHostMatch(token, host: host)
            }
        }
        if !exactMatches.isEmpty {
            return exactMatches
        }

        let domainMatches = connections.filter { connection in
            Self.hostValues(for: connection.host).contains { token in
                Self.isDomainMatch(token, host: host)
            }
        }
        if !domainMatches.isEmpty {
            return Self.ordered(domainMatches)
        }

        return Self.ordered(connections.filter { connection in
            Self.hostValues(for: connection.host).contains { $0 == "*" }
        })
    }

    private static func normalizedHost(_ value: String?) -> String? {
        guard let value else { return nil }
        let host = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return host.isEmpty ? nil : host
    }

    private static func hostValues(for value: String) -> [String] {
        value.split(separator: ",").map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        }.filter { !$0.isEmpty }
    }

    private static func isUnscopedExactMatch(_ token: String) -> Bool {
        token == "=*" || token.hasPrefix("=*.")
    }

    private static func isExactHostMatch(_ token: String, host: String) -> Bool {
        guard token != "*", !token.hasPrefix("*."), !token.hasPrefix("="), !token.contains("/") else { return false }
        return token == host
    }

    private static func isDomainMatch(_ token: String, host: String) -> Bool {
        if token.hasPrefix("*.") {
            let domain = String(token.dropFirst(2))
            return !domain.isEmpty && (host == domain || host.hasSuffix("." + domain))
        }
        return token.contains("/") && matchesIPv4CIDR(token, host: host)
    }

    private static func matchesIPv4CIDR(_ value: String, host: String) -> Bool {
        let parts = value.split(separator: "/", maxSplits: 1).map(String.init)
        guard parts.count == 2,
              let prefixLength = Int(parts[1]),
              (0...32).contains(prefixLength),
              let network = ipv4Value(parts[0]),
              let address = ipv4Value(host) else { return false }
        let mask: UInt32 = prefixLength == 0 ? 0 : UInt32.max << UInt32(32 - prefixLength)
        return network & mask == address & mask
    }

    private static func ipv4Value(_ value: String) -> UInt32? {
        let components = value.split(separator: ".")
        guard components.count == 4 else { return nil }
        var result: UInt32 = 0
        for component in components {
            guard let octet = UInt32(component), octet <= 255 else { return nil }
            result = (result << 8) | octet
        }
        return result
    }

    private static func ordered(_ values: [Connection]) -> [Connection] {
        values.enumerated().sorted { lhs, rhs in
            let lhsRank = lhs.element.relevance.caseInsensitiveCompare("Essential") == .orderedSame ? 0 : 1
            let rhsRank = rhs.element.relevance.caseInsensitiveCompare("Essential") == .orderedSame ? 0 : 1
            return lhsRank == rhsRank ? lhs.offset < rhs.offset : lhsRank < rhsRank
        }.map { $0.element }
    }
}

public final class InternetAccessPolicyLoader: @unchecked Sendable {
    public static let shared = InternetAccessPolicyLoader()

    private enum FileFormat {
        case plist
        case json
    }

    private struct CacheEntry {
        let policy: InternetAccessPolicy?
    }

    private let lock = NSLock()
    private var cache: [String: CacheEntry] = [:]

    private init() {}

    public func policy(forProcessPath processPath: String?) -> InternetAccessPolicy? {
        guard let processPath, let bundlePath = Self.enclosingBundlePath(for: processPath) else { return nil }

        lock.lock()
        defer { lock.unlock() }
        if let cached = cache[bundlePath] {
            return cached.policy
        }

        let policy = Self.readPolicy(fromBundlePath: bundlePath)
        cache[bundlePath] = CacheEntry(policy: policy)
        return policy
    }

    private static func enclosingBundlePath(for processPath: String) -> String? {
        let path = URL(fileURLWithPath: processPath).standardizedFileURL.path
        if path.hasSuffix(".app") {
            return path
        }
        guard let range = path.range(of: ".app/", options: .backwards) else { return nil }
        return URL(fileURLWithPath: String(path[..<range.upperBound]), isDirectory: true).standardizedFileURL.path
    }

    private static func readPolicy(fromBundlePath bundlePath: String) -> InternetAccessPolicy? {
        let resourcesURL = URL(fileURLWithPath: bundlePath, isDirectory: true)
            .appendingPathComponent("Contents/Resources", isDirectory: true)
        let files: [(String, FileFormat)] = [
            ("InternetAccessPolicy.plist", .plist),
            ("InternetAccessPolicy.json", .json)
        ]

        for (name, format) in files {
            let url = resourcesURL.appendingPathComponent(name)
            guard let data = try? Data(contentsOf: url),
                  let policy = parse(data, format: format) else { continue }
            return policy
        }
        return nil
    }

    private static func parse(_ data: Data, format: FileFormat) -> InternetAccessPolicy? {
        let object: Any
        do {
            switch format {
            case .plist:
                object = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
            case .json:
                object = try JSONSerialization.jsonObject(with: data, options: [])
            }
        } catch {
            return nil
        }

        guard let dictionary = object as? [String: Any],
              let applicationDescription = dictionary["ApplicationDescription"] as? String else { return nil }

        return InternetAccessPolicy(
            developerName: dictionary["DeveloperName"] as? String,
            applicationDescription: applicationDescription,
            website: dictionary["Website"] as? String,
            connections: parseConnections(dictionary["Connections"]),
            services: parseServices(dictionary["Services"])
        )
    }

    private static func parseConnections(_ value: Any?) -> [InternetAccessPolicy.Connection] {
        guard let entries = value as? [Any] else { return [] }
        return entries.compactMap { value in
            guard let entry = value as? [String: Any],
                  let host = entry["Host"] as? String,
                  let purpose = entry["Purpose"] as? String else { return nil }
            let relevance = (entry["Relevance"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
            return InternetAccessPolicy.Connection(
                host: host,
                purpose: purpose,
                denyConsequences: entry["DenyConsequences"] as? String,
                relevance: relevance?.caseInsensitiveCompare("Essential") == .orderedSame ? "Essential" : "Default",
                isIncoming: boolValue(entry["IsIncoming"]),
                networkProtocol: entry["NetworkProtocol"] as? String,
                port: entry["Port"] as? String
            )
        }
    }

    private static func parseServices(_ value: Any?) -> [InternetAccessPolicy.Service] {
        guard let entries = value as? [Any] else { return [] }
        return entries.compactMap { value in
            guard let entry = value as? [String: Any],
                  let name = entry["Name"] as? String,
                  let purpose = entry["Purpose"] as? String else { return nil }
            return InternetAccessPolicy.Service(
                name: name,
                purpose: purpose,
                identifier: entry["Identifier"] as? String
            )
        }
    }

    private static func boolValue(_ value: Any?) -> Bool {
        if let value = value as? Bool {
            return value
        }
        if let value = value as? NSNumber {
            return value.boolValue
        }
        return false
    }
}
