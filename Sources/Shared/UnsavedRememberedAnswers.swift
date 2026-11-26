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

    /// Answers whose rule is being sent again right now. They stay on screen
    /// while the retry is in flight, so the window does not close and reopen,
    /// and a second click sends nothing.
    public private(set) var retrying: Set<UUID> = []

    public func isRetrying(_ id: UUID) -> Bool { retrying.contains(id) }

    /// Records a failed save. The same rule failing again (a retry that was
    /// refused too) replaces its earlier entry in place, so the notice just
    /// retried stays the one on screen instead of a second being added.
    public mutating func record(_ answer: UnsavedRememberedAnswer) {
        if let index = items.firstIndex(where: { $0.rule.id == answer.rule.id }) {
            retrying.remove(items[index].id)
            items[index] = answer
            return
        }
        items.append(answer)
        if items.count > Self.limit {
            for dropped in items.prefix(items.count - Self.limit) { retrying.remove(dropped.id) }
            items.removeFirst(items.count - Self.limit)
        }
    }

    /// Marks one as being retried and hands it back to send. Nil when it is
    /// gone or already being retried, so a double click sends one save.
    public mutating func beginRetry(id: UUID) -> UnsavedRememberedAnswer? {
        guard !retrying.contains(id), let answer = items.first(where: { $0.id == id }) else { return nil }
        retrying.insert(id)
        return answer
    }

    /// Gives the buttons back when a retry has had no answer for too long,
    /// so a helper that takes the call and never replies cannot leave a
    /// notice nobody can close. A late answer still clears or replaces it.
    public mutating func endRetry(id: UUID) {
        retrying.remove(id)
    }

    /// How long a retry may wait for the helper before the buttons come back.
    public static let retryPatience: TimeInterval = 15

    /// Removes one: dismissed, or its rule was saved. Nil when it is already
    /// gone.
    @discardableResult
    public mutating func take(id: UUID) -> UnsavedRememberedAnswer? {
        retrying.remove(id)
        guard let index = items.firstIndex(where: { $0.id == id }) else { return nil }
        return items.remove(at: index)
    }
}
