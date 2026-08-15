import Foundation

public enum InsightsValidationError: Error, LocalizedError, Sendable {
    case unsupportedVersion(Int)
    case tooManyObservations(Int)
    case tooManyMappings(Int)
    case oversizedPayload(Int)
    case invalidField(String)
    case tooManyRows(Int)
    case tooManyContacts(Int)
    case invalidContactSnapshot(String)

    public var errorDescription: String? {
        switch self {
        case .unsupportedVersion(let version): return "unsupported insights schema version \(version)"
        case .tooManyObservations(let count): return "too many insights observations: \(count)"
        case .tooManyMappings(let count): return "too many insights DNS mappings: \(count)"
        case .oversizedPayload(let count): return "insights payload is too large: \(count) bytes"
        case .invalidField(let field): return "invalid insights field: \(field)"
        case .tooManyRows(let count): return "insights report contains too many rows: \(count)"
        case .tooManyContacts(let count): return "insights contact snapshot contains too many contacts: \(count)"
        case .invalidContactSnapshot(let field): return "invalid insights contact snapshot: \(field)"
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

    /// Read-side bounds. A year of rollups must never be materialised at once,
    /// so every query carries a page size and the store refuses anything above
    /// this. These are transport bounds, not content judgements: they are
    /// applied to the request and to the encoded byte count, never to the
    /// stored values coming back out. See #57.
    public static let maxQueryPageSize = 200
    public static let maxQueryOffset = 100_000
    public static let maxQueryRangeDays = 366
    public static let maxQueryRequestBytes = 8 * 1024
    public static let maxReportBytes = 1024 * 1024
    public static let maxReportRowCount = maxQueryPageSize + 1
    /// A prepared contact set is deliberately bounded. A contact omitted from
    /// a bounded set is treated as new, never as known, so this bound can only
    /// cause an extra prompt and can never silently allow unknown traffic.
    public static let maxContactCount = 10_000
    public static let maxContactSnapshotAge: TimeInterval = 5 * 60
    public static let maxVersionLength = 256
    /// How many distinct process names an unresolved-IP row may name inline.
    public static let maxUnresolvedAppNames = 5
}

/// A stable identifier derived from text, so the same app and destination keep
/// the same proposal id across queries and the UI does not reshuffle rows.
public enum InsightsIdentity {
    public static func deterministicUUID(_ value: String) -> UUID {
        var bytes = [UInt8](repeating: 0, count: 16)
        let low = fnv1a(value)
        let high = fnv1a("freesnitch-insights:" + value)
        for index in 0..<8 {
            bytes[index] = UInt8truncating(low >> (UInt64(index) * 8))
            bytes[index + 8] = UInt8truncating(high >> (UInt64(index) * 8))
        }
        return UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                           bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
    }

    private static func UInt8truncating(_ value: UInt64) -> UInt8 {
        UInt8(truncatingIfNeeded: value)
    }

    private static func fnv1a(_ value: String) -> UInt64 {
        var hash: UInt64 = 0xcbf29ce484222325
        for byte in value.utf8 {
            hash ^= UInt64(byte)
            hash = hash &* 0x100000001b3
        }
        return hash
    }
}

public struct FlowObservation: Codable, Hashable, Sendable {
    public let schemaVersion: Int
    public let id: UUID
    public let observedAt: Date
    public let pid: Int32
    public let processBundleId: String?
    public let processPath: String
    public let processName: String
    /// Marketing version plus build from the containing app's Info.plist.
    /// Nil means no reliable containing app/version was available.
    public let processVersion: String?
    public let remoteHost: String
    public let remoteIP: String
    public let remotePort: Int
    public let direction: RuleDirection
    public let protocolName: String
    public let bytesIn: Int64?
    public let bytesOut: Int64?

    public init(connection: Connection, observedAt: Date = Date(), processVersion: String? = nil) {
        self.schemaVersion = InsightsLimits.schemaVersion
        self.id = connection.id
        self.observedAt = observedAt
        self.pid = connection.pid
        self.processBundleId = connection.processBundleId
        self.processPath = connection.processPath
        self.processName = connection.processName
        self.processVersion = AppVersionIdentity(processVersion)?.value
        self.remoteHost = connection.remoteHost
        self.remoteIP = connection.remoteIP
        self.remotePort = connection.remotePort
        self.direction = connection.direction
        self.protocolName = connection.protocolName
        self.bytesIn = connection.bytesIn >= 0 ? connection.bytesIn : nil
        self.bytesOut = connection.bytesOut >= 0 ? connection.bytesOut : nil
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion, id, observedAt, pid, processBundleId, processPath, processName,
             processVersion, remoteHost, remoteIP, remotePort, direction, protocolName, bytesIn, bytesOut
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try c.decode(Int.self, forKey: .schemaVersion)
        id = try c.decode(UUID.self, forKey: .id)
        observedAt = try c.decode(Date.self, forKey: .observedAt)
        pid = try c.decode(Int32.self, forKey: .pid)
        processBundleId = try c.decodeIfPresent(String.self, forKey: .processBundleId)
        processPath = try c.decode(String.self, forKey: .processPath)
        processName = try c.decode(String.self, forKey: .processName)
        processVersion = try c.decodeIfPresent(String.self, forKey: .processVersion)
        remoteHost = try c.decode(String.self, forKey: .remoteHost)
        remoteIP = try c.decode(String.self, forKey: .remoteIP)
        remotePort = try c.decode(Int.self, forKey: .remotePort)
        direction = try c.decode(RuleDirection.self, forKey: .direction)
        protocolName = try c.decode(String.self, forKey: .protocolName)
        bytesIn = try c.decodeIfPresent(Int64.self, forKey: .bytesIn)
        bytesOut = try c.decodeIfPresent(Int64.self, forKey: .bytesOut)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(schemaVersion, forKey: .schemaVersion)
        try c.encode(id, forKey: .id)
        try c.encode(observedAt, forKey: .observedAt)
        try c.encode(pid, forKey: .pid)
        try c.encodeIfPresent(processBundleId, forKey: .processBundleId)
        try c.encode(processPath, forKey: .processPath)
        try c.encode(processName, forKey: .processName)
        try c.encodeIfPresent(processVersion, forKey: .processVersion)
        try c.encode(remoteHost, forKey: .remoteHost)
        try c.encode(remoteIP, forKey: .remoteIP)
        try c.encode(remotePort, forKey: .remotePort)
        try c.encode(direction, forKey: .direction)
        try c.encode(protocolName, forKey: .protocolName)
        try c.encodeIfPresent(bytesIn, forKey: .bytesIn)
        try c.encodeIfPresent(bytesOut, forKey: .bytesOut)
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
        try validateLength(processVersion, InsightsLimits.maxVersionLength, "processVersion")
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

/// The offline identity of the containing app at observation time. A value is
/// only reliable when it came from an enclosing .app's Info.plist. System
/// binaries and standalone executables intentionally remain nil.
public struct AppVersionIdentity: Codable, Hashable, Sendable {
    public let value: String

    public init?(_ value: String?) {
        guard let value, !value.isEmpty, value.utf8.count <= InsightsLimits.maxVersionLength else { return nil }
        self.value = value
    }

    public var label: String { value }
}

/// A pair used by both first-contact suppression and update findings. Keeping
/// the key in shared code prevents the two policies from disagreeing about
/// whether a hostname or address represents the destination.
public struct InsightsContact: Codable, Hashable, Sendable {
    public let appIdentity: String
    public let destination: String

    public init(appIdentity: String, destination: String) {
        self.appIdentity = appIdentity
        self.destination = PFHostValidator.kind(for: destination) == .hostname
            ? destination.lowercased()
            : destination
    }

    public init?(observation: FlowObservation) {
        let app = observation.processBundleId?.isEmpty == false
            ? observation.processBundleId!
            : observation.processPath
        let destination = Self.destination(for: observation.remoteHost, ip: observation.remoteIP)
        guard !app.isEmpty, !destination.isEmpty else { return nil }
        self.init(appIdentity: app, destination: destination)
    }

    public static func destination(for host: String, ip: String) -> String {
        PFHostValidator.kind(for: host) == .hostname ? host.lowercased() : ip
    }
}

/// This is prepared by the root helper away from the verdict path and handed
/// to the GUI. `unavailable` is represented by a missing snapshot, not by an
/// empty ready set: an empty set is evidence that the retained store was
/// successfully inspected and therefore means every contact is new.
public struct InsightsContactSnapshot: Codable, Sendable {
    public let schemaVersion: Int
    public let preparedAt: Date
    public let contacts: [InsightsContact]
    public let truncated: Bool

    public init(contacts: [InsightsContact], preparedAt: Date = Date(), truncated: Bool = false) {
        self.schemaVersion = InsightsLimits.schemaVersion
        self.preparedAt = preparedAt
        self.contacts = contacts
        self.truncated = truncated
    }

    public func validate(now: Date = Date()) throws {
        guard schemaVersion == InsightsLimits.schemaVersion else {
            throw InsightsValidationError.unsupportedVersion(schemaVersion)
        }
        guard preparedAt.timeIntervalSince1970.isFinite,
              preparedAt <= now.addingTimeInterval(5 * 60),
              now.timeIntervalSince(preparedAt) <= InsightsLimits.maxContactSnapshotAge else {
            throw InsightsValidationError.invalidContactSnapshot("preparedAt")
        }
        guard contacts.count <= InsightsLimits.maxContactCount else {
            throw InsightsValidationError.tooManyContacts(contacts.count)
        }
        for contact in contacts {
            guard !contact.appIdentity.isEmpty,
                  contact.appIdentity.utf8.count <= InsightsLimits.maxPathLength,
                  !contact.destination.isEmpty,
                  contact.destination.utf8.count <= InsightsLimits.maxHostLength || contact.destination.utf8.count <= InsightsLimits.maxIPAddressLength,
                  PFHostValidator.kind(for: contact.destination) == .hostname || PFHostValidator.kind(for: contact.destination) == .ip else {
                throw InsightsValidationError.invalidContactSnapshot("contact")
            }
        }
    }

    public func contains(_ contact: InsightsContact) -> Bool {
        contacts.contains(contact)
    }
}

public enum InsightsContactDecision: String, Codable, Sendable {
    case firstContact
    case knownContact
    /// No conclusion is safe. Alert mode keeps its existing ask behavior.
    case askHistoryUnavailable
}

public struct InsightsContactClassifier: Sendable {
    private let contacts: Set<InsightsContact>?

    public init(snapshot: InsightsContactSnapshot?, now: Date = Date()) {
        guard let snapshot, (try? snapshot.validate(now: now)) != nil else {
            self.contacts = nil
            return
        }
        self.contacts = Set(snapshot.contacts)
    }

    public var isAvailable: Bool { contacts != nil }

    public func decision(for observation: FlowObservation) -> InsightsContactDecision {
        guard let contacts else { return .askHistoryUnavailable }
        guard let contact = InsightsContact(observation: observation) else { return .firstContact }
        return contacts.contains(contact) ? .knownContact : .firstContact
    }

    public func decision(for connection: Connection) -> InsightsContactDecision {
        decision(for: FlowObservation(connection: connection))
    }

    public func knownDestinationCount(for connection: Connection) -> Int? {
        guard let contacts else { return nil }
        let app = connection.processBundleId?.isEmpty == false
            ? connection.processBundleId!
            : connection.processPath
        guard !app.isEmpty else { return 0 }
        return contacts.reduce(into: 0) { count, contact in
            if contact.appIdentity == app { count += 1 }
        }
    }
}

/// A finding is an observed destination difference, not a malware or causation
/// claim. Missing version identities are displayed as unknown and never filled
/// with a guessed marketing version.
public struct InsightsBehaviourFinding: Codable, Sendable, Hashable, Identifiable {
    public var id: String { appIdentity + "\\u{1F}" + destination + "\\u{1F}" + (newVersion ?? "unknown") }
    public let appIdentity: String
    public let displayName: String
    public let oldVersion: String?
    public let newVersion: String?
    public let destination: String
    public let firstSeen: Date
    public let connectionCount: Int
    public let versionKnown: Bool

    public init(appIdentity: String, displayName: String, oldVersion: String?, newVersion: String?,
                destination: String, firstSeen: Date, connectionCount: Int, versionKnown: Bool) {
        self.appIdentity = appIdentity
        self.displayName = displayName
        self.oldVersion = oldVersion
        self.newVersion = newVersion
        self.destination = destination
        self.firstSeen = firstSeen
        self.connectionCount = connectionCount
        self.versionKnown = versionKnown
    }

    /// A sentence, not a diff. This used to print "0.0.312 -> 0.0.318" in a
    /// monospaced font, which reads as developer output rather than as a fact
    /// about an app (#125).
    public var versionLabel: String {
        guard versionKnown else { return "Version not known" }
        guard let old = oldVersion, let new = newVersion else {
            return "Version \(newVersion ?? oldVersion ?? "not known")"
        }
        return "Version \(old) to \(new)"
    }

    public var wording: String {
        versionKnown ? "New after update" : "New destination, app version not known"
    }

    /// The count is already on the row as a chip, so the sentence carries only
    /// what the chip cannot: since when.
    public var evidence: String {
        "First seen \(firstSeen.formatted(date: .abbreviated, time: .shortened))."
    }

    public func proposedRule(processBundleId: String? = nil, processPath: String? = nil) -> InsightsProposedRule? {
        guard PFHostValidator.kind(for: destination) == .hostname || PFHostValidator.kind(for: destination) == .ip else { return nil }
        let domain = PFHostValidator.kind(for: destination) == .hostname ? destination : nil
        let ip = domain == nil ? destination : nil
        return InsightsProposedRule(appIdentity: appIdentity, appDisplayName: displayName,
                                    processBundleId: processBundleId, processPath: processPath,
                                    domain: domain, remoteIP: ip, connectionCount: connectionCount,
                                    otherAppCount: 0, lastSeen: firstSeen)
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

// MARK: - Read side

public enum InsightsQueryKind: String, Codable, Sendable {
    /// The default axis: which apps talked, per D6.
    case apps
    /// The destinations one app reached, with the inline correlation note.
    case destinations
    /// Destinations that never appeared in a DNS answer, per D10.
    case unresolved
    /// Proposed, never enforced, rules per D2 and D7.
    case proposals
    /// Offline observations of destinations first seen after a reliable app build change.
    case findings
    /// Store-wide counters used to describe the quality of the picture.
    case overview
}

/// Which storage answered a query. Raw events keep byte counts, ports and
/// timestamps for 14 days; older ranges can only be answered from daily
/// rollups, which are per day and never carry per-flow detail.
public enum InsightsDataSource: String, Codable, Sendable {
    case rawEvents
    case dailyRollups

    public var explanation: String {
        switch self {
        case .rawEvents:
            return "Raw events, kept for 14 days."
        case .dailyRollups:
            return "Daily rollups, kept for a year. Counts and bytes per day, no per-connection detail."
        }
    }
}

public struct InsightsQuery: Codable, Sendable, Hashable {
    public let schemaVersion: Int
    public let kind: InsightsQueryKind
    /// Bundle identifier when known, otherwise the executable path. Required
    /// for `.destinations`.
    public let appIdentity: String?
    public let since: Date
    public let until: Date
    public let limit: Int
    public let offset: Int

    public init(kind: InsightsQueryKind,
                appIdentity: String? = nil,
                since: Date,
                until: Date = Date(),
                limit: Int = 50,
                offset: Int = 0) {
        self.schemaVersion = InsightsLimits.schemaVersion
        self.kind = kind
        self.appIdentity = appIdentity
        self.since = since
        self.until = until
        self.limit = limit
        self.offset = offset
    }

    public func validate(payloadBytes: Int = 0, now: Date = Date()) throws {
        guard payloadBytes >= 0 && payloadBytes <= InsightsLimits.maxQueryRequestBytes else {
            throw InsightsValidationError.oversizedPayload(payloadBytes)
        }
        guard schemaVersion == InsightsLimits.schemaVersion else {
            throw InsightsValidationError.unsupportedVersion(schemaVersion)
        }
        guard since.timeIntervalSince1970.isFinite, until.timeIntervalSince1970.isFinite else {
            throw InsightsValidationError.invalidField("range")
        }
        guard since < until else { throw InsightsValidationError.invalidField("range") }
        guard until <= now.addingTimeInterval(5 * 60) else {
            throw InsightsValidationError.invalidField("until")
        }
        let maximumRange = Double(InsightsLimits.maxQueryRangeDays) * 24 * 60 * 60
        guard until.timeIntervalSince(since) <= maximumRange else {
            throw InsightsValidationError.invalidField("range")
        }
        guard limit >= 1 && limit <= InsightsLimits.maxQueryPageSize else {
            throw InsightsValidationError.invalidField("limit")
        }
        guard offset >= 0 && offset <= InsightsLimits.maxQueryOffset else {
            throw InsightsValidationError.invalidField("offset")
        }
        if let appIdentity {
            guard !appIdentity.isEmpty, appIdentity.utf8.count <= InsightsLimits.maxPathLength else {
                throw InsightsValidationError.invalidField("appIdentity")
            }
        }
        if kind == .destinations {
            guard let appIdentity, !appIdentity.isEmpty else {
                throw InsightsValidationError.invalidField("appIdentity")
            }
        }
    }
}

public struct InsightsAppSummary: Codable, Sendable, Hashable, Identifiable {
    public var id: String { appIdentity }
    public let appIdentity: String
    public let displayName: String
    public let processBundleId: String?
    public let processPath: String?
    public let destinationCount: Int
    public let connectionCount: Int
    public let bytesIn: Int64
    public let bytesOut: Int64
    public let lastSeen: Date?

    public init(appIdentity: String, displayName: String, processBundleId: String?, processPath: String?,
                destinationCount: Int, connectionCount: Int, bytesIn: Int64, bytesOut: Int64, lastSeen: Date?) {
        self.appIdentity = appIdentity
        self.displayName = displayName
        self.processBundleId = processBundleId
        self.processPath = processPath
        self.destinationCount = destinationCount
        self.connectionCount = connectionCount
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
        self.lastSeen = lastSeen
    }
}

public struct InsightsDestinationSummary: Codable, Sendable, Hashable, Identifiable {
    public var id: String { appIdentity + "\u{1F}" + destinationKey }
    public let appIdentity: String
    /// The hostname the app asked for when one was seen, otherwise the address.
    public let destinationKey: String
    /// Only ever from the local DNS answer map. Never a reverse lookup, never
    /// an online lookup. Nil means no name is known, and the UI says so.
    public let resolvedDomain: String?
    public let remoteIP: String?
    public let connectionCount: Int
    public let bytesIn: Int64
    public let bytesOut: Int64
    /// How many OTHER apps reached the same destination in the same range.
    /// Co-occurrence only: it says nothing about why.
    public let otherAppCount: Int
    public let lastSeen: Date?

    public init(appIdentity: String, destinationKey: String, resolvedDomain: String?, remoteIP: String?,
                connectionCount: Int, bytesIn: Int64, bytesOut: Int64, otherAppCount: Int, lastSeen: Date?) {
        self.appIdentity = appIdentity
        self.destinationKey = destinationKey
        self.resolvedDomain = resolvedDomain
        self.remoteIP = remoteIP
        self.connectionCount = connectionCount
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
        self.otherAppCount = otherAppCount
        self.lastSeen = lastSeen
    }

    public var isNameKnown: Bool { resolvedDomain != nil }
    public var displayName: String { resolvedDomain ?? destinationKey }

    /// The inline correlation note from D6. States co-occurrence and nothing
    /// else: no shared cause is observable from socket flows.
    public var correlationNote: String? {
        guard otherAppCount > 0 else { return nil }
        return otherAppCount == 1
            ? "also contacted by 1 other app"
            : "also contacted by \(otherAppCount) other apps"
    }
}

public struct InsightsUnresolvedDestination: Codable, Sendable, Hashable, Identifiable {
    public var id: String { remoteIP }
    public let remoteIP: String
    public let connectionCount: Int
    public let appCount: Int
    /// Bounded sample of the processes that reached this address.
    public let appNames: [String]
    public let bytesIn: Int64
    public let bytesOut: Int64
    public let lastSeen: Date?

    public init(remoteIP: String, connectionCount: Int, appCount: Int, appNames: [String],
                bytesIn: Int64, bytesOut: Int64, lastSeen: Date?) {
        self.remoteIP = remoteIP
        self.connectionCount = connectionCount
        self.appCount = appCount
        self.appNames = appNames
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
        self.lastSeen = lastSeen
    }

    /// D10 is explicit that this is a signal to look at, not a verdict. VPNs,
    /// Tailscale, NTP and plenty of ordinary software connect to bare
    /// addresses, and the DNS map is only as complete as the DNS proxy.
    public static let signalWording =
        "No DNS answer for this address was seen while recording. That is worth a look, not a verdict: VPNs, Tailscale, NTP and apps that resolve names themselves all reach addresses directly."
}

/// A proposal. Nothing here is in force. A human accepts each one, per D2.
public struct InsightsProposedRule: Codable, Sendable, Hashable, Identifiable {
    public let id: UUID
    public let appIdentity: String
    public let appDisplayName: String
    public let processBundleId: String?
    public let processPath: String?
    /// The name the app asked for. When this is nil no name is known, and the
    /// UI must say so before the user accepts an address-pinned rule (D7).
    public let domain: String?
    public let remoteIP: String?
    public let connectionCount: Int
    public let otherAppCount: Int
    public let lastSeen: Date?

    public init(appIdentity: String, appDisplayName: String, processBundleId: String?, processPath: String?,
                domain: String?, remoteIP: String?, connectionCount: Int, otherAppCount: Int, lastSeen: Date?) {
        self.id = InsightsIdentity.deterministicUUID(appIdentity + "\u{1F}" + (domain ?? remoteIP ?? ""))
        self.appIdentity = appIdentity
        self.appDisplayName = appDisplayName
        self.processBundleId = processBundleId
        self.processPath = processPath
        self.domain = domain
        self.remoteIP = remoteIP
        self.connectionCount = connectionCount
        self.otherAppCount = otherAppCount
        self.lastSeen = lastSeen
    }

    public var isDomainScoped: Bool { domain != nil }
    /// True when no name was ever seen for the destination. An address-pinned
    /// rule goes stale as CDN addresses rotate, so the user must choose it
    /// knowingly rather than have one written silently.
    public var requiresExplicitIPChoice: Bool { domain == nil }

    public var destinationLabel: String { domain ?? remoteIP ?? "" }

    /// Observed facts only.
    public var evidence: String {
        var text = "\(appDisplayName) reached \(destinationLabel) \(connectionCount) time"
        if connectionCount != 1 { text += "s" }
        if otherAppCount > 0 {
            text += "; also contacted by \(otherAppCount) other app"
            if otherAppCount != 1 { text += "s" }
        }
        return text + "."
    }

    /// App-specific and domain-scoped whenever a name is known (D7).
    public func rule(action: RuleAction = .deny, profile: String = "default") -> Rule {
        if let domain {
            return Rule(processBundleId: processBundleId,
                        processPath: processPath,
                        processName: appDisplayName,
                        remoteHost: domain,
                        remoteIP: nil,
                        remotePort: nil,
                        direction: .outgoing,
                        action: action,
                        scope: .domain,
                        priority: 100,
                        profile: profile,
                        groupName: "Insights",
                        notes: "Proposed by Insights. \(evidence)")
        }
        return Rule(processBundleId: processBundleId,
                    processPath: processPath,
                    processName: appDisplayName,
                    remoteHost: remoteIP,
                    remoteIP: remoteIP,
                    remotePort: nil,
                    direction: .outgoing,
                    action: action,
                    scope: .ip,
                    priority: 100,
                    profile: profile,
                    groupName: "Insights",
                    notes: "Proposed by Insights, pinned to an address because no DNS name was ever seen for it. \(evidence)")
    }

    /// The one extra click from the correlation view: the same destination for
    /// every app. Only offered when a name is known.
    public func widenedRule(action: RuleAction = .deny, profile: String = "default") -> Rule? {
        guard let domain else { return nil }
        return Rule(processBundleId: nil,
                    processPath: nil,
                    processName: nil,
                    remoteHost: domain,
                    remoteIP: nil,
                    remotePort: nil,
                    direction: .outgoing,
                    action: action,
                    scope: .domain,
                    priority: 100,
                    profile: profile,
                    groupName: "Insights",
                    notes: "Proposed by Insights, widened to every app. \(evidence)")
    }
}

public struct InsightsOverview: Codable, Sendable, Hashable {
    public let recordingEnabled: Bool
    public let rawObservationCount: Int
    public let dnsMappingCount: Int
    public let rollupRowCount: Int
    public let appCount: Int
    public let oldestObservation: Date?
    public let newestObservation: Date?

    public init(recordingEnabled: Bool, rawObservationCount: Int, dnsMappingCount: Int, rollupRowCount: Int,
                appCount: Int, oldestObservation: Date?, newestObservation: Date?) {
        self.recordingEnabled = recordingEnabled
        self.rawObservationCount = rawObservationCount
        self.dnsMappingCount = dnsMappingCount
        self.rollupRowCount = rollupRowCount
        self.appCount = appCount
        self.oldestObservation = oldestObservation
        self.newestObservation = newestObservation
    }

    /// D5's known limits, stated rather than hidden behind bare addresses.
    public var namingNote: String {
        dnsMappingCount == 0
            ? "No DNS answers have been recorded, so destinations are shown as raw addresses. FreeSnitch only learns names from the DNS proxy, which runs when enforcement is on, and apps that resolve names themselves bypass it."
            : "Names come from DNS answers seen on this Mac. Apps that resolve names themselves are shown as raw addresses."
    }
}

public struct InsightsReport: Codable, Sendable {
    public let schemaVersion: Int
    public let kind: InsightsQueryKind
    public let generatedAt: Date
    public let rangeStart: Date
    public let rangeEnd: Date
    public let source: InsightsDataSource
    public let recordingEnabled: Bool
    public let limit: Int
    public let offset: Int
    public let hasMore: Bool
    public let apps: [InsightsAppSummary]
    public let destinations: [InsightsDestinationSummary]
    public let unresolved: [InsightsUnresolvedDestination]
    public let proposals: [InsightsProposedRule]
    public let findings: [InsightsBehaviourFinding]
    public let overview: InsightsOverview?

    private enum CodingKeys: String, CodingKey {
        case schemaVersion, kind, generatedAt, rangeStart, rangeEnd, source, recordingEnabled,
             limit, offset, hasMore, apps, destinations, unresolved, proposals, findings, overview
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try c.decode(Int.self, forKey: .schemaVersion)
        kind = try c.decode(InsightsQueryKind.self, forKey: .kind)
        generatedAt = try c.decode(Date.self, forKey: .generatedAt)
        rangeStart = try c.decode(Date.self, forKey: .rangeStart)
        rangeEnd = try c.decode(Date.self, forKey: .rangeEnd)
        source = try c.decode(InsightsDataSource.self, forKey: .source)
        recordingEnabled = try c.decode(Bool.self, forKey: .recordingEnabled)
        limit = try c.decode(Int.self, forKey: .limit)
        offset = try c.decode(Int.self, forKey: .offset)
        hasMore = try c.decode(Bool.self, forKey: .hasMore)
        apps = try c.decode([InsightsAppSummary].self, forKey: .apps)
        destinations = try c.decode([InsightsDestinationSummary].self, forKey: .destinations)
        unresolved = try c.decode([InsightsUnresolvedDestination].self, forKey: .unresolved)
        proposals = try c.decode([InsightsProposedRule].self, forKey: .proposals)
        findings = try c.decodeIfPresent([InsightsBehaviourFinding].self, forKey: .findings) ?? []
        overview = try c.decodeIfPresent(InsightsOverview.self, forKey: .overview)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(schemaVersion, forKey: .schemaVersion)
        try c.encode(kind, forKey: .kind)
        try c.encode(generatedAt, forKey: .generatedAt)
        try c.encode(rangeStart, forKey: .rangeStart)
        try c.encode(rangeEnd, forKey: .rangeEnd)
        try c.encode(source, forKey: .source)
        try c.encode(recordingEnabled, forKey: .recordingEnabled)
        try c.encode(limit, forKey: .limit)
        try c.encode(offset, forKey: .offset)
        try c.encode(hasMore, forKey: .hasMore)
        try c.encode(apps, forKey: .apps)
        try c.encode(destinations, forKey: .destinations)
        try c.encode(unresolved, forKey: .unresolved)
        try c.encode(proposals, forKey: .proposals)
        try c.encode(findings, forKey: .findings)
        try c.encodeIfPresent(overview, forKey: .overview)
    }

    public init(kind: InsightsQueryKind,
                generatedAt: Date = Date(),
                rangeStart: Date,
                rangeEnd: Date,
                source: InsightsDataSource,
                recordingEnabled: Bool,
                limit: Int,
                offset: Int,
                hasMore: Bool,
                apps: [InsightsAppSummary] = [],
                destinations: [InsightsDestinationSummary] = [],
                unresolved: [InsightsUnresolvedDestination] = [],
                proposals: [InsightsProposedRule] = [],
                findings: [InsightsBehaviourFinding] = [],
                overview: InsightsOverview? = nil) {
        self.schemaVersion = InsightsLimits.schemaVersion
        self.kind = kind
        self.generatedAt = generatedAt
        self.rangeStart = rangeStart
        self.rangeEnd = rangeEnd
        self.source = source
        self.recordingEnabled = recordingEnabled
        self.limit = limit
        self.offset = offset
        self.hasMore = hasMore
        self.apps = apps
        self.destinations = destinations
        self.unresolved = unresolved
        self.proposals = proposals
        self.findings = findings
        self.overview = overview
    }

    /// Bounds only. Reading our own store back out must never re-judge the
    /// CONTENT of what was stored: a single odd legacy row would otherwise hide
    /// the whole picture from the user, which is exactly what happened in #57.
    public func validateBounds(payloadBytes: Int) throws {
        guard payloadBytes >= 0 && payloadBytes <= InsightsLimits.maxReportBytes else {
            throw InsightsValidationError.oversizedPayload(payloadBytes)
        }
        guard schemaVersion == InsightsLimits.schemaVersion else {
            throw InsightsValidationError.unsupportedVersion(schemaVersion)
        }
        let rows = apps.count + destinations.count + unresolved.count + proposals.count + findings.count
        guard rows <= InsightsLimits.maxReportRowCount else {
            throw InsightsValidationError.tooManyRows(rows)
        }
    }
}
