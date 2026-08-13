import Foundation
import Darwin

/// A fixed-capacity ring for the extension hot path. Enqueue uses trylock:
/// contention and a full ring both drop immediately, so observation can never
/// delay a filtering verdict.
final class FlowObservationQueue: @unchecked Sendable {
    enum EnqueueResult {
        case enqueued
        case full
        case contended
    }

    let capacity: Int
    private var values: [FlowObservation?]
    private var head = 0
    private var tail = 0
    private var count = 0
    private var fullDrops = 0
    private let lock: UnsafeMutablePointer<os_unfair_lock_s>

    init(capacity: Int = 1024) {
        precondition(capacity > 0)
        self.capacity = capacity
        self.values = Array(repeating: nil, count: capacity)
        self.lock = .allocate(capacity: 1)
        self.lock.initialize(to: os_unfair_lock_s())
    }

    deinit {
        lock.deinitialize(count: 1)
        lock.deallocate()
    }

    func enqueue(_ observation: FlowObservation) -> EnqueueResult {
        guard os_unfair_lock_trylock(lock) else { return .contended }
        defer { os_unfair_lock_unlock(lock) }
        guard count < capacity else {
            fullDrops += 1
            return .full
        }
        values[tail] = observation
        tail = (tail + 1) % capacity
        count += 1
        return .enqueued
    }

    /// Drain is only called on the background sender queue. It may briefly
    /// wait for the hot path while moving at most the requested bound.
    func drain(maximum: Int) -> [FlowObservation] {
        guard maximum > 0 else { return [] }
        os_unfair_lock_lock(lock)
        defer { os_unfair_lock_unlock(lock) }
        let amount = min(maximum, count)
        var result: [FlowObservation] = []
        result.reserveCapacity(amount)
        for _ in 0..<amount {
            if let value = values[head] { result.append(value) }
            values[head] = nil
            head = (head + 1) % capacity
            count -= 1
        }
        return result
    }

    var isEmpty: Bool {
        os_unfair_lock_lock(lock)
        defer { os_unfair_lock_unlock(lock) }
        return count == 0
    }

    func takeFullDropCount() -> Int {
        os_unfair_lock_lock(lock)
        defer { os_unfair_lock_unlock(lock) }
        defer { fullDrops = 0 }
        return fullDrops
    }
}
