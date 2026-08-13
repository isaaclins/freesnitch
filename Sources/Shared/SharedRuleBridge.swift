import Foundation

/// The rule snapshot exchanged between the GUI and the Network System
/// Extension. The extension runs in a sandbox, so an app-group file would
/// resolve to the wrong home for the root process. Live snapshots cross the
/// existing app-extension XPC connection; the GUI persists the same
/// versioned envelope in the filter provider configuration for extension startup.
public enum SharedRuleBridge {
    /// Version the persisted provider-configuration envelope separately from
    /// the live XPC payload. A future build must reject an unknown snapshot
    /// instead of guessing its policy.
    public static let bootSnapshotVersion = 1
    /// Stable key in NEFilterProviderConfiguration.vendorConfiguration.
    public static let bootSnapshotVendorConfigurationKey = "io.isaaclins.freesnitch.bootSnapshot"
    /// Keep provider preferences bounded because they are persisted by the
    /// system, not streamed like the live XPC payload.
    public static let maximumBootSnapshotEncodedBytes = 512 * 1024
    public static let maximumBootSnapshotRuleCount = 4096

    public struct Snapshot: Codable, Sendable {
        public var mode: AppMode
        public var rules: [Rule]
        public var updatedAt: Date

        public init(mode: AppMode, rules: [Rule], updatedAt: Date = Date()) {
            self.mode = mode
            self.rules = rules
            self.updatedAt = updatedAt
        }
    }

    public struct BootSnapshot: Codable, Sendable {
        public let version: Int
        public let snapshot: Snapshot

        public init(snapshot: Snapshot, version: Int = SharedRuleBridge.bootSnapshotVersion) {
            self.version = version
            self.snapshot = snapshot
        }
    }

    public struct SnapshotStatus: Codable, Equatable, Sendable {
        public enum State: String, Codable, Sendable {
            case unavailable
            case invalid
            case ready
        }

        public var state: State
        public var mode: AppMode?
        public var ruleCount: Int
        public var updatedAt: Date?
        public var message: String?

        public init(state: State,
                    mode: AppMode? = nil,
                    ruleCount: Int = 0,
                    updatedAt: Date? = nil,
                    message: String? = nil) {
            self.state = state
            self.mode = mode
            self.ruleCount = ruleCount
            self.updatedAt = updatedAt
            self.message = message
        }

        public static func ready(for snapshot: Snapshot) -> Self {
            Self(state: .ready,
                 mode: snapshot.mode,
                 ruleCount: snapshot.rules.count,
                 updatedAt: snapshot.updatedAt)
        }

        public static func unavailable(_ message: String) -> Self {
            Self(state: .unavailable, message: message)
        }

        public static func invalid(_ message: String) -> Self {
            Self(state: .invalid, message: message)
        }

        public var isReady: Bool { state == .ready }
    }

    public static func encode(_ snapshot: Snapshot) throws -> Data {
        try JSONEncoder().encode(snapshot)
    }

    public static func decode(_ data: Data) throws -> Snapshot {
        try JSONDecoder().decode(Snapshot.self, from: data)
    }

    public static func encodeBootSnapshot(_ snapshot: Snapshot, now: Date = Date()) throws -> Data {
        let stored = BootSnapshot(snapshot: snapshot)
        try validateBootSnapshot(stored, now: now)
        let data = try JSONEncoder().encode(stored)
        guard data.count <= maximumBootSnapshotEncodedBytes else {
            throw validationError("Boot snapshot exceeds the \(maximumBootSnapshotEncodedBytes)-byte limit.")
        }
        return data
    }

    public static func decodeBootSnapshot(_ data: Data, now: Date = Date()) throws -> Snapshot {
        guard !data.isEmpty else { throw validationError("Boot snapshot is missing.") }
        guard data.count <= maximumBootSnapshotEncodedBytes else {
            throw validationError("Boot snapshot exceeds the \(maximumBootSnapshotEncodedBytes)-byte limit.")
        }
        let stored = try JSONDecoder().decode(BootSnapshot.self, from: data)
        try validateBootSnapshot(stored, now: now)
        return stored.snapshot
    }

    private static func validateBootSnapshot(_ stored: BootSnapshot, now: Date) throws {
        guard stored.version == bootSnapshotVersion else {
            throw validationError("Unsupported boot snapshot version \(stored.version).")
        }
        guard stored.snapshot.rules.count <= maximumBootSnapshotRuleCount else {
            throw validationError("Boot snapshot contains too many rules.")
        }
        guard stored.snapshot.updatedAt <= now else {
            throw validationError("Boot snapshot is dated in the future.")
        }
    }

    private static func validationError(_ message: String) -> NSError {
        NSError(
            domain: "SharedRuleBridge",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }

    public static func encode(_ status: SnapshotStatus) throws -> Data {
        try JSONEncoder().encode(status)
    }

    public static func decodeStatus(_ data: Data) throws -> SnapshotStatus {
        try JSONDecoder().decode(SnapshotStatus.self, from: data)
    }
}
