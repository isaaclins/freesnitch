import Foundation

/// Shared bridge between the GUI/helper and the Network System Extension.
///
/// The extension runs in its own (restricted) process and cannot read the
/// helper's `/Library/Application Support` database, so the active rule set and
/// mode are mirrored into the app-group container as JSON. The GUI writes the
/// snapshot whenever rules/mode change; the extension reads it (on start and on
/// a short poll) to drive its verdicts.
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

    public static var containerURL: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: AppConstants.appGroup)
    }

    private static var fileURL: URL? {
        containerURL?.appendingPathComponent("filter-rules.json")
    }

    public static func write(mode: AppMode, rules: [Rule]) {
        guard let url = fileURL else { return }
        let snap = Snapshot(mode: mode, rules: rules)
        guard let data = try? JSONEncoder().encode(snap) else { return }
        try? data.write(to: url, options: .atomic)
    }

    public static func read() -> Snapshot {
        guard let url = fileURL,
              let data = try? Data(contentsOf: url),
              let snap = try? JSONDecoder().decode(Snapshot.self, from: data) else {
            return Snapshot(mode: .alert, rules: [])
        }
        return snap
    }
}
