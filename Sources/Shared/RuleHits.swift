import Foundation
import Darwin

/// How often one rule decided a flow since the last report, and when it last
/// did (#434). The network extension counts these on the verdict path and
/// sends them with its observation batches; the helper adds them to the
/// rule's `hitCount` and `lastUsedAt`.
public struct RuleHit: Codable, Hashable, Sendable {
    public let ruleID: UUID
    public let count: Int
    public let lastMatchedAt: Date

    public init(ruleID: UUID, count: Int, lastMatchedAt: Date) {
        self.ruleID = ruleID
        self.count = count
        self.lastMatchedAt = lastMatchedAt
    }

    /// One report never carries more than this many matches for a rule. Far
    /// above what one rule can see between two batches, low enough that a
    /// stored count can never overflow from a single report.
    public static let maxCountPerReport = 1_000_000

    public func validate(now: Date = Date()) throws {
        guard count > 0 && count <= Self.maxCountPerReport else {
            throw InsightsValidationError.invalidField("ruleHits.count")
        }
        guard lastMatchedAt.timeIntervalSince1970.isFinite,
              lastMatchedAt <= now.addingTimeInterval(5 * 60),
              lastMatchedAt >= now.addingTimeInterval(-InsightsLimits.rawRetention) else {
            throw InsightsValidationError.invalidField("ruleHits.lastMatchedAt")
        }
    }
}

/// The extension's running count of rule matches. Counting is trylock-only,
/// like the observation queue, so it can never delay a verdict: a match that
/// arrives while the tally is being read or written is not counted. The
/// counts are a usage indicator, not an audit log, and never decide anything.
final class RuleHitTally: @unchecked Sendable {
    private struct Entry {
        var count: Int
        var last: Date
    }

    /// The tally stops taking new rules at this size until the next drain.
    /// Matches for rules it already holds are still counted.
    let capacity: Int
    private var entries: [UUID: Entry] = [:]
    private let lock: UnsafeMutablePointer<os_unfair_lock_s>

    init(capacity: Int = 4096) {
        precondition(capacity > 0)
        self.capacity = capacity
        self.entries.reserveCapacity(min(capacity, 256))
        self.lock = .allocate(capacity: 1)
        self.lock.initialize(to: os_unfair_lock_s())
    }

    deinit {
        lock.deinitialize(count: 1)
        lock.deallocate()
    }

    /// Returns false when the match was not counted (contended or full).
    @discardableResult
    func record(_ ruleID: UUID, at date: Date = Date()) -> Bool {
        guard os_unfair_lock_trylock(lock) else { return false }
        defer { os_unfair_lock_unlock(lock) }
        if var entry = entries[ruleID] {
            if entry.count < RuleHit.maxCountPerReport { entry.count += 1 }
            if date > entry.last { entry.last = date }
            entries[ruleID] = entry
            return true
        }
        guard entries.count < capacity else { return false }
        entries[ruleID] = Entry(count: 1, last: date)
        return true
    }

    /// Takes up to `maximum` rules' counts out of the tally. The rest stay for
    /// the next drain. Called off the verdict path, so it may wait.
    func drain(maximum: Int) -> [RuleHit] {
        guard maximum > 0 else { return [] }
        os_unfair_lock_lock(lock)
        defer { os_unfair_lock_unlock(lock) }
        var taken: [RuleHit] = []
        taken.reserveCapacity(min(maximum, entries.count))
        for (id, entry) in entries {
            guard taken.count < maximum else { break }
            taken.append(RuleHit(ruleID: id, count: entry.count, lastMatchedAt: entry.last))
        }
        for hit in taken { entries.removeValue(forKey: hit.ruleID) }
        return taken
    }

    /// Puts counts back after a batch that could not be sent, adding to
    /// anything counted since. Off the verdict path.
    func restore(_ hits: [RuleHit]) {
        os_unfair_lock_lock(lock)
        defer { os_unfair_lock_unlock(lock) }
        for hit in hits {
            if var entry = entries[hit.ruleID] {
                entry.count = min(entry.count + hit.count, RuleHit.maxCountPerReport)
                if hit.lastMatchedAt > entry.last { entry.last = hit.lastMatchedAt }
                entries[hit.ruleID] = entry
            } else if entries.count < capacity {
                entries[hit.ruleID] = Entry(count: hit.count, last: hit.lastMatchedAt)
            }
        }
    }
}
