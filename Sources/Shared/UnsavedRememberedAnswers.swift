import Foundation

/// An alert answered with "Remember this decision" whose rule the helper did
/// not save. The connection itself was answered; only the rule is missing, so
/// the next connection like it is asked about again or left to the mode (#246).
public struct UnsavedRememberedAnswer: Identifiable, Equatable, Sendable {
    public let id: UUID
    public let processName: String
    public let destination: String
    public let allow: Bool
    /// The rule exactly as it was sent, so trying again saves the same thing.
    public let rule: Rule
    /// What the helper, or the connection to it, said went wrong.
    public let reason: String

    public init(id: UUID = UUID(), processName: String, destination: String,
                allow: Bool, rule: Rule, reason: String) {
        self.id = id
        self.processName = processName
        self.destination = destination
        self.allow = allow
        self.rule = rule
        self.reason = reason
    }
}

/// The answers that could not be remembered, shown where they were given:
/// in the alert window, until each is retried or dismissed (#246).
///
/// Bounded, because a helper that is down refuses every save and a busy Mac
/// can answer many alerts in that time. Only the newest are kept.
public struct UnsavedRememberedAnswers: Sendable {
    public static let limit = 5

    public private(set) var items: [UnsavedRememberedAnswer] = []

    public init() {}

    /// The one the alert window shows: the oldest that is still kept, so they
    /// are seen in the order they were answered.
    public var current: UnsavedRememberedAnswer? { items.first }

    public var isEmpty: Bool { items.isEmpty }

    /// Records a failed save. The same rule failing again (a retry that was
    /// refused too) replaces its earlier entry instead of adding a second.
    public mutating func record(_ answer: UnsavedRememberedAnswer) {
        items.removeAll { $0.rule.id == answer.rule.id }
        items.append(answer)
        if items.count > Self.limit {
            items.removeFirst(items.count - Self.limit)
        }
    }

    /// Removes one and hands it back, for a retry or a dismissal. Nil when it
    /// is already gone, so a double click does nothing the second time.
    @discardableResult
    public mutating func take(id: UUID) -> UnsavedRememberedAnswer? {
        guard let index = items.firstIndex(where: { $0.id == id }) else { return nil }
        return items.remove(at: index)
    }
}
