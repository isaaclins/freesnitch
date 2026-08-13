import Foundation

public enum InsightsValidationError: Error, LocalizedError, Sendable {
    case unsupportedVersion(Int)
    case tooManyObservations(Int)
    case tooManyMappings(Int)
    case oversizedPayload(Int)
    case invalidField(String)

    public var errorDescription: String? {
        switch self {
        case .unsupportedVersion(let version): return "unsupported insights schema version \(version)"
        case .tooManyObservations(let count): return "too many insights observations: \(count)"
        case .tooManyMappings(let count): return "too many insights DNS mappings: \(count)"
        case .oversizedPayload(let count): return "insights payload is too large: \(count) bytes"
        case .invalidField(let field): return "invalid insights field: \(field)"
        }
    }
}

public enum InsightsLimits {
    public static let schemaVersion = 1
    public static let maxBatchCount = 256
    public static let maxDNSMappingCount = 256
    public static let maxBatchBytes = 256 * 1024
    public static let maxBundleIDLength = 256
    public static let maxPathLength = 4096
    public static let maxNameLength = 256
    public static let maxHostLength = 253
    public static let maxIPAddressLength = 45
    public static let maxProtocolLength = 32
    public static let rawRetention: TimeInterval = 14 * 24 * 60 * 60
    public static let rollupRetentionDays = 365
    public static let maxDNSMappingLifetime: TimeInterval = 7 * 24 * 60 * 60
}

public struct FlowObservation: Codable, Hashable, Sendable {
    public let schemaVersion: Int
    public let id: UUID
    public let observedAt: Date
    public let pid: Int32
    public let processBundleId: String?
    public let processPath: String
    public let processName: String
    public let remoteHost: String
    public let remoteIP: String
    public let remotePort: Int
    public let direction: RuleDirection
    public let protocolName: String
    public let bytesIn: Int64?
    public let bytesOut: Int64?

    public init(connection: Connection, observedAt: Date = Date()) {
        self.schemaVersion = InsightsLimits.schemaVersion
        self.id = connection.id
        self.observedAt = observedAt
        self.pid = connection.pid
        self.processBundleId = connection.processBundleId
        self.processPath = connection.processPath
        self.processName = connection.processName
        self.remoteHost = connection.remoteHost
        self.remoteIP = connection.remoteIP
        self.remotePort = connection.remotePort
        self.direction = connection.direction
        self.protocolName = connection.protocolName
        self.bytesIn = connection.bytesIn >= 0 ? connection.bytesIn : nil
        self.bytesOut = connection.bytesOut >= 0 ? connection.bytesOut : nil
    }

    public func validate(now: Date = Date()) throws {
        guard schemaVersion == InsightsLimits.schemaVersion else {
            throw InsightsValidationError.unsupportedVersion(schemaVersion)
        }
        guard observedAt.timeIntervalSince1970.isFinite,
              observedAt <= now.addingTimeInterval(5 * 60),
              observedAt >= now.addingTimeInterval(-InsightsLimits.rawRetention) else {
            throw InsightsValidationError.invalidField("observedAt")
        }
        guard pid >= 0 else { throw InsightsValidationError.invalidField("pid") }
        try validateLength(processBundleId, InsightsLimits.maxBundleIDLength, "processBundleId")
        try validateLength(processPath, InsightsLimits.maxPathLength, "processPath")
        try validateLength(processName, InsightsLimits.maxNameLength, "processName")
        try validateLength(remoteHost, InsightsLimits.maxHostLength, "remoteHost")
        try validateLength(remoteIP, InsightsLimits.maxIPAddressLength, "remoteIP")
        try validateLength(protocolName, InsightsLimits.maxProtocolLength, "protocolName")
        guard remotePort >= 0 && remotePort <= 65535 else {
            throw InsightsValidationError.invalidField("remotePort")
        }
        guard remoteHost.isEmpty || PFHostValidator.kind(for: remoteHost) == .hostname || PFHostValidator.kind(for: remoteHost) == .ip else {
            throw InsightsValidationError.invalidField("remoteHost")
        }
        guard remoteIP.isEmpty || PFHostValidator.kind(for: remoteIP) == .ip else {
            throw InsightsValidationError.invalidField("remoteIP")
        }
        if let bytesIn { guard bytesIn >= 0 else { throw InsightsValidationError.invalidField("bytesIn") } }
        if let bytesOut { guard bytesOut >= 0 else { throw InsightsValidationError.invalidField("bytesOut") } }
    }

    private func validateLength(_ value: String?, _ maximum: Int, _ name: String) throws {
        guard (value?.utf8.count ?? 0) <= maximum else {
            throw InsightsValidationError.invalidField(name)
        }
    }
}

public struct FlowObservationBatch: Codable, Sendable {
    public let schemaVersion: Int
    public let observations: [FlowObservation]

    public init(observations: [FlowObservation]) {
        self.schemaVersion = InsightsLimits.schemaVersion
        self.observations = observations
    }

    public func validate(payloadBytes: Int, now: Date = Date()) throws {
        guard payloadBytes >= 0 && payloadBytes <= InsightsLimits.maxBatchBytes else {
            throw InsightsValidationError.oversizedPayload(payloadBytes)
        }
        guard schemaVersion == InsightsLimits.schemaVersion else {
            throw InsightsValidationError.unsupportedVersion(schemaVersion)
        }
        guard observations.count <= InsightsLimits.maxBatchCount else {
            throw InsightsValidationError.tooManyObservations(observations.count)
        }
        for observation in observations { try observation.validate(now: now) }
    }
}

public struct DNSMapping: Codable, Hashable, Sendable {
    public let schemaVersion: Int
    public let domain: String
    public let ip: String
    public let observedAt: Date
    public let expiresAt: Date

    public init(domain: String, ip: String, observedAt: Date = Date(), expiresAt: Date? = nil) {
        self.schemaVersion = InsightsLimits.schemaVersion
        self.domain = domain.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        self.ip = ip
        self.observedAt = observedAt
        self.expiresAt = expiresAt ?? observedAt.addingTimeInterval(5 * 60)
    }

    public func validate(now: Date = Date()) throws {
        guard schemaVersion == InsightsLimits.schemaVersion else {
            throw InsightsValidationError.unsupportedVersion(schemaVersion)
        }
        guard domain.utf8.count > 0 && domain.utf8.count <= InsightsLimits.maxHostLength,
              PFHostValidator.kind(for: domain) == .hostname else {
            throw InsightsValidationError.invalidField("domain")
        }
        guard ip.utf8.count > 0 && ip.utf8.count <= InsightsLimits.maxIPAddressLength,
              PFHostValidator.kind(for: ip) == .ip else {
            throw InsightsValidationError.invalidField("ip")
        }
        guard observedAt.timeIntervalSince1970.isFinite,
              expiresAt.timeIntervalSince1970.isFinite,
              observedAt <= now.addingTimeInterval(5 * 60),
              observedAt >= now.addingTimeInterval(-InsightsLimits.rawRetention),
              expiresAt >= observedAt,
              expiresAt <= observedAt.addingTimeInterval(InsightsLimits.maxDNSMappingLifetime) else {
            throw InsightsValidationError.invalidField("DNS timestamps")
        }
    }
}

public struct DNSMappingBatch: Codable, Sendable {
    public let schemaVersion: Int
    public let mappings: [DNSMapping]

    public init(mappings: [DNSMapping]) {
        self.schemaVersion = InsightsLimits.schemaVersion
        self.mappings = mappings
    }

    public func validate(payloadBytes: Int, now: Date = Date()) throws {
        guard payloadBytes >= 0 && payloadBytes <= InsightsLimits.maxBatchBytes else {
            throw InsightsValidationError.oversizedPayload(payloadBytes)
        }
        guard schemaVersion == InsightsLimits.schemaVersion else {
            throw InsightsValidationError.unsupportedVersion(schemaVersion)
        }
        guard mappings.count <= InsightsLimits.maxDNSMappingCount else {
            throw InsightsValidationError.tooManyMappings(mappings.count)
        }
        for mapping in mappings { try mapping.validate(now: now) }
    }
}
