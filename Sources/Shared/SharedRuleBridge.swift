import Foundation

/// The rule snapshot exchanged between the GUI and the Network System
/// Extension. The extension runs as root, so an app-group file would resolve
/// to root's home rather than the logged-in user's home. Snapshots therefore
/// stay in memory and cross the existing app-extension XPC connection.
public enum SharedRuleBridge {
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

    public static func encode(_ status: SnapshotStatus) throws -> Data {
        try JSONEncoder().encode(status)
    }

    public static func decodeStatus(_ data: Data) throws -> SnapshotStatus {
        try JSONDecoder().decode(SnapshotStatus.self, from: data)
    }
}
