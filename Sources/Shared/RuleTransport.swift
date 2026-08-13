import Foundation

/// The single policy boundary for rule payloads crossing process boundaries.
/// Every caller validates the encoded byte count before asking JSON to decode,
/// then validates the complete decoded value before it can be committed.
public enum RuleTransportBoundary {
    public static let maximumEncodedSnapshotBytes = 512 * 1024
    public static let maximumEncodedRuleBatchBytes = maximumEncodedSnapshotBytes
    public static let maximumEncodedSingleRuleBytes = 32 * 1024
    public static let maximumDecodedRuleCount = 4096

    public static let maximumProcessBundleIDBytes = 256
    public static let maximumProcessPathBytes = 4096
    public static let maximumProcessNameBytes = 256
    public static let maximumRemoteHostBytes = 255
    public static let maximumRemoteIPBytes = 45
    public static let maximumProfileBytes = 256
    public static let maximumGroupNameBytes = 256
    public static let maximumNotesBytes = 8192

    public enum PayloadKind: String, Sendable {
        case snapshot
        case ruleBatch
        case singleRule

        fileprivate var label: String {
            switch self {
            case .snapshot: return "rule snapshot"
            case .ruleBatch: return "rule batch"
            case .singleRule: return "single rule"
            }
        }
    }

    public enum ValidationError: Error, LocalizedError, Equatable, Sendable {
        case oversized(kind: PayloadKind, actualBytes: Int, maximumBytes: Int)
        case tooManyRules(actualCount: Int, maximumCount: Int)
        case fieldTooLong(field: String, actualBytes: Int, maximumBytes: Int)
        case invalidField(field: String, reason: String)

        public var errorDescription: String? {
            switch self {
            case .oversized(let kind, let actualBytes, let maximumBytes):
                return "\(kind.label) payload is oversized: \(actualBytes) bytes (maximum \(maximumBytes))."
            case .tooManyRules(let actualCount, let maximumCount):
                return "rule payload contains too many rules: \(actualCount) (maximum \(maximumCount))."
            case .fieldTooLong(let field, let actualBytes, let maximumBytes):
                return "rule field \(field) is too long: \(actualBytes) UTF-8 bytes (maximum \(maximumBytes))."
            case .invalidField(let field, let reason):
                return "invalid rule field \(field): \(reason)."
            }
        }
    }

    /// These checks intentionally inspect only `Data.count`. They are the
    /// pre-decode half of the boundary and must stay free of JSON decoding.
    public static func validateSnapshotBytes(_ data: Data) throws {
        try validateEncodedBytes(data, kind: .snapshot, maximum: maximumEncodedSnapshotBytes)
    }

    public static func validateBootSnapshotBytes(_ data: Data) throws {
        try validateEncodedBytes(data, kind: .snapshot, maximum: maximumEncodedSnapshotBytes)
    }

    public static func validateRuleBatchBytes(_ data: Data) throws {
        try validateEncodedBytes(data, kind: .ruleBatch, maximum: maximumEncodedRuleBatchBytes)
    }

    public static func validateSingleRuleBytes(_ data: Data) throws {
        try validateEncodedBytes(data, kind: .singleRule, maximum: maximumEncodedSingleRuleBytes)
    }

    public static func validate(snapshot: SharedRuleBridge.Snapshot) throws {
        try validate(rules: snapshot.rules)
    }

    /// Validates the whole array. No prefix or subset is ever accepted.
    public static func validate(rules: [Rule]) throws {
        guard rules.count <= maximumDecodedRuleCount else {
            throw ValidationError.tooManyRules(actualCount: rules.count,
                                               maximumCount: maximumDecodedRuleCount)
        }
        for rule in rules {
            try validate(rule: rule)
        }
    }

    public static func validate(rule: Rule) throws {
        try validateLength(rule.processBundleId, field: "processBundleId", maximum: maximumProcessBundleIDBytes)
        try validateLength(rule.processPath, field: "processPath", maximum: maximumProcessPathBytes)
        try validateLength(rule.processName, field: "processName", maximum: maximumProcessNameBytes)
        try validateLength(rule.remoteHost, field: "remoteHost", maximum: maximumRemoteHostBytes)
        try validateLength(rule.remoteIP, field: "remoteIP", maximum: maximumRemoteIPBytes)
        try validateLength(rule.profile, field: "profile", maximum: maximumProfileBytes)
        try validateLength(rule.groupName, field: "groupName", maximum: maximumGroupNameBytes)
        try validateLength(rule.notes, field: "notes", maximum: maximumNotesBytes)

        if let reason = RuleAddressValidator.rejectionReason(forRemoteIP: rule.remoteIP) {
            throw ValidationError.invalidField(field: "remoteIP", reason: reason)
        }
        if let reason = rejectionReason(forRemoteHost: rule.remoteHost) {
            throw ValidationError.invalidField(field: "remoteHost", reason: reason)
        }
        if let remotePort = rule.remotePort, !(0...65535).contains(remotePort) {
            throw ValidationError.invalidField(field: "remotePort", reason: "expected a value from 0 through 65535")
        }
    }

    public static func encodeSnapshot(_ snapshot: SharedRuleBridge.Snapshot) throws -> Data {
        try validate(snapshot: snapshot)
        let data = try FreeSnitchWireCodec.encode(snapshot)
        try validateSnapshotBytes(data)
        return data
    }

    public static func encodeRuleBatch(_ rules: [Rule]) throws -> Data {
        try validate(rules: rules)
        let data = try FreeSnitchWireCodec.encode(rules)
        try validateRuleBatchBytes(data)
        return data
    }

    public static func encodeSingleRule(_ rule: Rule) throws -> Data {
        try validate(rule: rule)
        let data = try FreeSnitchWireCodec.encode(rule)
        try validateSingleRuleBytes(data)
        return data
    }

    private static func rejectionReason(forRemoteHost raw: String?) -> String? {
        guard let value = raw, !value.isEmpty else { return nil }
        let base: String
        if value.hasPrefix("*.") {
            base = String(value.dropFirst(2))
        } else if value.hasPrefix(".") {
            base = String(value.dropFirst())
        } else {
            base = value
        }
        guard !base.isEmpty, PFHostValidator.kind(for: base) != nil else {
            return PFHostValidator.rejectionReason(for: base)
        }
        if value.hasPrefix("*.") && PFHostValidator.kind(for: base) != .hostname {
            return "wildcard remoteHost patterns must target a hostname"
        }
        return nil
    }

    private static func validateEncodedBytes(_ data: Data,
                                             kind: PayloadKind,
                                             maximum: Int) throws {
        guard data.count <= maximum else {
            throw ValidationError.oversized(kind: kind,
                                            actualBytes: data.count,
                                            maximumBytes: maximum)
        }
    }

    private static func validateLength(_ value: String?,
                                       field: String,
                                       maximum: Int) throws {
        let bytes = value?.utf8.count ?? 0
        guard bytes <= maximum else {
            throw ValidationError.fieldTooLong(field: field,
                                               actualBytes: bytes,
                                               maximumBytes: maximum)
        }
    }
}
