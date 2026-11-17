import Foundation

/// The one on-disk contract for rule backups, shared by the CLI and the GUI.
///
/// Both clients write `freesnitch.rules.v1` and both clients read it, so a file
/// produced by `freesnitch rules export` restores through the GUI and a file
/// exported from the GUI restores through the CLI.
public struct RuleExportDocument: Codable, Sendable {
    /// Stable name of the canonical document. A file whose `format` differs is
    /// rejected instead of being decoded because it happens to have a `rules`
    /// key.
    public static let formatIdentifier = "freesnitch.rules.v1"
    /// Version written by this build.
    public static let currentVersion = 1
    /// Versions this build can read. A newer document is refused with its
    /// version named, never silently downgraded.
    public static let supportedVersions: ClosedRange<Int> = 1...1

    public let format: String
    public let version: Int
    public let exportedAt: Date
    public let rules: [Rule]

    public init(rules: [Rule], exportedAt: Date = Date()) {
        self.format = Self.formatIdentifier
        self.version = Self.currentVersion
        self.exportedAt = exportedAt
        self.rules = rules
    }
}

/// Which accepted input shape a file used.
public enum RuleExportSource: String, Sendable {
    /// The canonical versioned document.
    case canonical
    /// The bare `[Rule]` array written by FreeSnitch builds before the
    /// canonical document existed. This is a compatibility path only: it is
    /// still read so existing GUI backups keep working, and it is never
    /// written again.
    case legacyRuleArray
}

public struct RuleImport: Sendable {
    public let rules: [Rule]
    public let source: RuleExportSource
    /// Present only for the canonical document.
    public let exportedAt: Date?

    public init(rules: [Rule], source: RuleExportSource, exportedAt: Date?) {
        self.rules = rules
        self.source = source
        self.exportedAt = exportedAt
    }
}

public enum RuleExportError: Error, LocalizedError, Equatable {
    case empty
    case oversized(bytes: Int, limit: Int)
    case tooManyRules(count: Int, limit: Int)
    case notRuleJSON
    case unsupportedFormat(String)
    case unsupportedVersion(Int)
    case malformed(String)
    case invalidRule(id: String, reason: String)
    case duplicateRuleID(String)

    public var errorDescription: String? {
        switch self {
        case .empty:
            return "The rule file is empty."
        case .oversized(let bytes, let limit):
            return "The rule file is \(bytes) bytes, above the \(limit)-byte import limit."
        case .tooManyRules(let count, let limit):
            return "The rule file declares \(count) rules, above the \(limit)-rule import limit."
        case .notRuleJSON:
            return "The file is not a FreeSnitch rule export: it is neither a \(RuleExportDocument.formatIdentifier) document nor a JSON array of rules."
        case .unsupportedFormat(let format):
            return "Unsupported rule export format `\(format)`. This build reads `\(RuleExportDocument.formatIdentifier)`."
        case .unsupportedVersion(let version):
            return "Unsupported rule export version \(version). This build reads versions \(RuleExportDocument.supportedVersions.lowerBound) through \(RuleExportDocument.supportedVersions.upperBound)."
        case .malformed(let detail):
            return "The rule file could not be decoded: \(detail)."
        case .invalidRule(let id, let reason):
            return "Rule \(id) is invalid: \(reason)."
        case .duplicateRuleID(let id):
            return "Rule \(id) appears more than once in the file."
        }
    }

    /// A concrete next step for the user, mirrored by the CLI error envelope
    /// and the GUI alert.
    public var remediation: String {
        switch self {
        case .empty, .notRuleJSON, .malformed:
            return "Create the file with `freesnitch rules export` or the GUI export button."
        case .oversized, .tooManyRules:
            return "Split the backup into smaller files and import them one after another."
        case .unsupportedFormat, .unsupportedVersion:
            return "Export the file again with this version of FreeSnitch, or update FreeSnitch to a build that knows this format."
        case .invalidRule, .duplicateRuleID:
            return "Fix the named rule in the file and import it again. Nothing was imported."
        }
    }
}

/// Reads and writes the rule export contract.
///
/// Every import goes through `decode`, which validates the complete batch
/// before any caller shows a confirmation or writes anything: an import is
/// all-or-nothing.
public enum RuleExportCodec {
    /// Bound the payload before it is parsed. A rule export is small; anything
    /// larger is a mistake or an attack, not a backup.
    public static let maximumEncodedBytes = 16 * 1024 * 1024
    /// Bound the batch before any `Rule` is allocated.
    ///
    /// This is deliberately the same limit the live rule transport can carry.
    /// Accepting a larger file would let a user import and persist a policy
    /// that could never be delivered to the network extension, which fails
    /// open, so the rules would be listed in the app while nothing enforced
    /// them.
    public static let maximumRuleCount = RuleTransportBoundary.maximumDecodedRuleCount
    /// Bound each stored string so one rule cannot carry a megabyte of text.
    public static let maximumFieldLength = 4096

    public static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }

    /// Accepts ISO 8601 dates written by this contract and the bare numeric
    /// reference-date values written by legacy GUI backups.
    public static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            if let seconds = try? container.decode(Double.self) {
                return Date(timeIntervalSinceReferenceDate: seconds)
            }
            let string = try container.decode(String.self)
            let fractional = ISO8601DateFormatter()
            fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let date = fractional.date(from: string) { return date }
            let plain = ISO8601DateFormatter()
            plain.formatOptions = [.withInternetDateTime]
            if let date = plain.date(from: string) { return date }
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "invalid ISO 8601 date")
        }
        return decoder
    }

    /// Encodes the canonical document. Both clients export through here.
    public static func encode(_ rules: [Rule], exportedAt: Date = Date()) throws -> Data {
        try validate(rules)
        return try encoder().encode(RuleExportDocument(rules: rules, exportedAt: exportedAt))
    }

    /// Rejects a payload by size before it is read into memory.
    public static func validateEncodedSize(_ bytes: Int) throws {
        guard bytes > 0 else { throw RuleExportError.empty }
        guard bytes <= maximumEncodedBytes else {
            throw RuleExportError.oversized(bytes: bytes, limit: maximumEncodedBytes)
        }
    }

    /// Decodes either accepted input shape and validates the whole batch.
    ///
    /// Throws `RuleExportError` and never returns a partially usable batch.
    public static func decode(_ data: Data) throws -> RuleImport {
        try validateEncodedSize(data.count)
        switch try shape(of: data) {
        case .canonical:
            let header = try decodeHeader(data)
            guard header.format == RuleExportDocument.formatIdentifier else {
                throw RuleExportError.unsupportedFormat(header.format)
            }
            guard RuleExportDocument.supportedVersions.contains(header.version) else {
                throw RuleExportError.unsupportedVersion(header.version)
            }
            try checkRuleCount(header.rules.count)
            let document: RuleExportDocument
            do { document = try decoder().decode(RuleExportDocument.self, from: data) }
            catch { throw RuleExportError.malformed(readable(error)) }
            try validate(document.rules)
            return RuleImport(rules: document.rules, source: .canonical, exportedAt: document.exportedAt)
        case .legacyArray:
            let probes: [RuleProbe]
            do { probes = try decoder().decode([RuleProbe].self, from: data) }
            catch { throw RuleExportError.notRuleJSON }
            try checkRuleCount(probes.count)
            let rules: [Rule]
            do { rules = try decoder().decode([Rule].self, from: data) }
            catch { throw RuleExportError.malformed(readable(error)) }
            try validate(rules)
            return RuleImport(rules: rules, source: .legacyRuleArray, exportedAt: nil)
        }
    }

    /// Validates the complete batch. Callers run this before a confirmation
    /// prompt and before any write, so a bad file changes nothing.
    public static func validate(_ rules: [Rule]) throws {
        try checkRuleCount(rules.count)
        var seen = Set<UUID>()
        for rule in rules {
            let id = rule.id.uuidString
            guard seen.insert(rule.id).inserted else {
                throw RuleExportError.duplicateRuleID(id)
            }
            if let reason = RuleAddressValidator.rejectionReason(forRemoteIP: rule.remoteIP) {
                throw RuleExportError.invalidRule(id: id, reason: "\(reason). \(RuleAddressValidator.remediation)")
            }
            if let port = rule.remotePort, !(1...65535).contains(port) {
                throw RuleExportError.invalidRule(id: id, reason: "remote port \(port) is outside 1 through 65535")
            }
            if rule.profile.isEmpty {
                throw RuleExportError.invalidRule(id: id, reason: "the profile name is empty")
            }
            if let reason = rule.nameOnlyRejectionReason {
                throw RuleExportError.invalidRule(
                    id: id,
                    reason: reason + ". In the file, set its \"enabled\" to false, or give it a \"processPath\" or \"processBundleId\"")
            }
            for (label, value) in [("profile", rule.profile as String?),
                                   ("process bundle id", rule.processBundleId),
                                   ("process path", rule.processPath),
                                   ("process name", rule.processName),
                                   ("remote host", rule.remoteHost),
                                   ("remote IP", rule.remoteIP),
                                   ("group name", rule.groupName),
                                   ("notes", rule.notes)] {
                guard let value, value.utf8.count > maximumFieldLength else { continue }
                throw RuleExportError.invalidRule(id: id, reason: "the \(label) field is longer than \(maximumFieldLength) bytes")
            }
        }
    }

    private enum Shape {
        case canonical
        case legacyArray
    }

    /// Decides the shape from the first structural byte so an object that is
    /// not a FreeSnitch document is never coerced into one.
    private static func shape(of data: Data) throws -> Shape {
        for byte in data {
            switch byte {
            case 0x20, 0x09, 0x0A, 0x0D:
                continue
            case UInt8(ascii: "{"):
                return .canonical
            case UInt8(ascii: "["):
                return .legacyArray
            default:
                throw RuleExportError.notRuleJSON
            }
        }
        throw RuleExportError.empty
    }

    /// Only the envelope fields plus a count probe, so format, version and
    /// rule count are checked before any `Rule` is built.
    private struct Header: Decodable {
        let format: String
        let version: Int
        let rules: [RuleProbe]
    }

    /// Consumes one array element without materialising it.
    private struct RuleProbe: Decodable {
        init(from decoder: Decoder) throws {
            _ = try decoder.singleValueContainer()
        }
    }

    private static func decodeHeader(_ data: Data) throws -> Header {
        do { return try decoder().decode(Header.self, from: data) }
        catch let error as DecodingError {
            switch error {
            case .keyNotFound, .typeMismatch, .valueNotFound:
                throw RuleExportError.notRuleJSON
            default:
                throw RuleExportError.malformed(readable(error))
            }
        } catch {
            throw RuleExportError.malformed(readable(error))
        }
    }

    private static func checkRuleCount(_ count: Int) throws {
        guard count <= maximumRuleCount else {
            throw RuleExportError.tooManyRules(count: count, limit: maximumRuleCount)
        }
    }

    private static func readable(_ error: Error) -> String {
        guard let decoding = error as? DecodingError else { return "\(error)" }
        switch decoding {
        case .keyNotFound(let key, let context):
            return "missing field `\(key.stringValue)` at \(path(context))"
        case .typeMismatch(let type, let context):
            return "field at \(path(context)) is not a \(type)"
        case .valueNotFound(let type, let context):
            return "field at \(path(context)) is null but a \(type) is required"
        case .dataCorrupted(let context):
            return "\(context.debugDescription) at \(path(context))"
        @unknown default:
            return "\(decoding)"
        }
    }

    private static func path(_ context: DecodingError.Context) -> String {
        let joined = context.codingPath.map(\.stringValue).joined(separator: ".")
        return joined.isEmpty ? "the top level" : "`\(joined)`"
    }
}

/// What importing a rule file does to the rules already stored (#247).
///
/// An import replaces the rules of the profiles the file carries rules for,
/// and only those. A profile the file says nothing about was not given, so its
/// rules are kept. A backup made while one profile was active therefore can no
/// longer wipe the other profiles' rules. The helper applies this plan inside
/// its transaction, and the app shows the same plan before the user confirms,
/// so what the dialog promises is what the helper does.
public struct RuleImportPlan: Sendable {
    /// Profiles the file carries rules for, sorted. Their stored rules are replaced.
    public let replacedProfiles: [String]
    /// Stored rules in a replaced profile that the file does not contain.
    /// These are the only rules an import deletes.
    public let removed: [Rule]
    /// Stored rules in profiles the file does not mention. They stay as they are.
    public let kept: [Rule]
    /// Stored rules the file also carries, by ID, under a different profile.
    /// They leave their old profile, so the dialog and the log name them.
    public let moved: [Rule]
    /// The complete rule table after the import: the kept rules, then the file's rules.
    public let resulting: [Rule]

    public init(current: [Rule], imported: [Rule]) {
        let profiles = Set(imported.map(\.profile))
        let importedIDs = Set(imported.map(\.id))
        // Always first, as the Rules window lists it, then the rest by name.
        replacedProfiles = profiles.sorted { lhs, rhs in
            if lhs == Profile.alwaysName || rhs == Profile.alwaysName { return lhs == Profile.alwaysName && rhs != Profile.alwaysName }
            return lhs < rhs
        }
        // A stored rule the file also carries, by ID, is replaced by the
        // file's copy wherever it lived, so it is neither kept nor lost.
        kept = current.filter { !profiles.contains($0.profile) && !importedIDs.contains($0.id) }
        removed = current.filter { profiles.contains($0.profile) && !importedIDs.contains($0.id) }
        let importedProfileByID = Dictionary(imported.map { ($0.id, $0.profile) }, uniquingKeysWith: { first, _ in first })
        moved = current.filter { stored in
            importedProfileByID[stored.id].map { $0 != stored.profile } ?? false
        }
        resulting = kept + imported
    }

    /// Every rule the import takes out of a profile: deleted or moved away.
    /// The app shows these to the user and sends exactly these IDs with the
    /// import, so the helper can check it is doing what was confirmed.
    public var confirmedIDs: [UUID] {
        (removed + moved).map(\.id)
    }

    /// The import the helper runs inside its policy transaction. If the stored
    /// rules changed since the user confirmed (an alert answered while the
    /// dialog was open, a CLI edit), the rules it would delete or move differ
    /// from `confirmedIDs` and the import is refused, so it can never take
    /// away a rule the user was not shown.
    public static func apply(imported: [Rule],
                             confirmedIDs: Set<UUID>,
                             to draft: inout RuleStore.PolicyDraft) throws -> RuleImportPlan {
        // The app's file reader refuses duplicate IDs; a direct caller could
        // send them, and then the plan and the stored table would disagree.
        guard Set(imported.map(\.id)).count == imported.count else {
            throw RuleExportError.duplicateRuleID("in the imported rules")
        }
        let plan = RuleImportPlan(current: draft.rules, imported: imported)
        guard Set(plan.confirmedIDs) == confirmedIDs else {
            throw RuleImportConflict()
        }
        try RuleTransportBoundary.validate(rules: plan.resulting)
        draft.rules = plan.resulting
        return plan
    }

    /// What the log keeps of an import: the summary, then one line per rule it
    /// deleted or moved, so a large import is not one line the log truncates.
    public var logLines: [String] {
        let kept = keptByProfile.map { "\($0.profile)=\($0.count)" }.joined(separator: ", ")
        return ["rule import: \(resulting.count - self.kept.count) rules imported into profiles [\(replacedProfiles.joined(separator: ", "))]; "
                + "\(removed.count) removed, \(moved.count) moved to another profile, \(self.kept.count) kept in other profiles [\(kept)]"]
            + removed.map { "rule import removed: \(Self.describe($0)) in \($0.profile) (\($0.id.uuidString))" }
            + moved.map { "rule import moved: \(Self.describe($0)) from \($0.profile) (\($0.id.uuidString))" }
    }

    /// Kept rules counted per profile, sorted by profile name.
    public var keptByProfile: [(profile: String, count: Int)] {
        Dictionary(grouping: kept, by: \.profile)
            .map { (profile: $0.key, count: $0.value.count) }
            .sorted { $0.profile < $1.profile }
    }

    /// A rule the way a person reads it: what it does, to which app and
    /// destination. The ID is kept so the log line can be matched exactly.
    public static func describe(_ rule: Rule) -> String {
        let process = rule.processName ?? rule.processBundleId ?? rule.processPath ?? "any process"
        var destination = rule.remoteHost ?? rule.remoteIP ?? "any destination"
        if let port = rule.remotePort { destination += ":\(port)" }
        return "\(rule.action.rawValue) \(process) to \(destination)"
    }

    /// One line for the log, naming every rule the import deletes or moves.
    public var logSummary: String {
        let kept = keptByProfile.map { "\($0.profile)=\($0.count)" }.joined(separator: ", ")
        let removedIDs = removed.map { "\(Self.describe($0)) in \($0.profile) \($0.id.uuidString)" }.joined(separator: ", ")
        let movedIDs = moved.map { "\(Self.describe($0)) from \($0.profile) \($0.id.uuidString)" }.joined(separator: ", ")
        return "rule import: \(resulting.count - self.kept.count) rules imported into profiles [\(replacedProfiles.joined(separator: ", "))]; "
            + "\(removed.count) stored rules removed [\(removedIDs)]; "
            + "\(moved.count) rules moved to another profile [\(movedIDs)]; "
            + "\(self.kept.count) rules in other profiles kept [\(kept)]"
    }
}

/// The stored rules changed between the confirmation and the import.
public struct RuleImportConflict: Error, LocalizedError, Equatable {
    public init() {}

    public var errorDescription: String? {
        "The rules changed while the import was waiting for confirmation, so it would no longer delete or move exactly the rules you confirmed. Nothing was imported. Import the file again to review the current changes."
    }
}
