import Foundation

/// The rule snapshot exchanged between the GUI and the Network System
/// Extension. Live snapshots cross the existing app-extension XPC connection;
/// the versioned boot envelope is persisted in the provider configuration for
/// extension startup.
public enum SharedRuleBridge {
    /// Version the persisted provider-configuration envelope separately from
    /// the live XPC payload. A future build must reject an unknown snapshot
    /// instead of guessing its policy.
    public static let bootSnapshotVersion = 1
    /// Stable key in NEFilterProviderConfiguration.vendorConfiguration.
    public static let bootSnapshotVendorConfigurationKey = "io.isaaclins.freesnitch.bootSnapshot"
    /// Keep provider preferences bounded because they are persisted by the
    /// system, not streamed like the live XPC payload.
    public static let maximumBootSnapshotEncodedBytes = RuleTransportBoundary.maximumEncodedBootSnapshotBytes
    public static let maximumBootSnapshotRuleCount = RuleTransportBoundary.maximumBootSnapshotRuleCount
    public static let staleSilentDenyAge: TimeInterval = 24 * 60 * 60
    /// Printed with every ordering rejection. The extension's in-memory policy
    /// is the only state involved, and restarting the filter provider clears
    /// it, so no rejection may ever be reported as "reboot to fix".
    public static let snapshotRejectionRemediation =
        "FreeSnitch can recover by restarting the network extension filter; restarting the Mac is not required."
    /// Said once the automatic restarts are used up, so the user is never left
    /// with a firewall that is off and no next step.
    public static let snapshotRecoveryExhaustedRemediation =
        "FreeSnitch restarted the network extension filter and the extension still rejected the helper policy. "
        + "Turn the per-process firewall off and on again in FreeSnitch settings; restarting the Mac is not required."

    /// Pure state for the asynchronous provider-preference writer. A caller
    /// may take only the newest pending payload after a load completes; any
    /// request arriving during a save remains visible as newer work.
    public struct NewestWriteWinsQueue: Sendable {
        public struct Pending: Sendable {
            public let generation: Int
            public let data: Data
        }

        private(set) public var generation = 0
        private var pendingData: Data?

        public init() {}

        public var hasPending: Bool { pendingData != nil }

        @discardableResult
        public mutating func enqueue(_ data: Data) -> Int {
            generation += 1
            pendingData = data
            return generation
        }

        public mutating func takeNewest() -> Pending? {
            guard let pendingData else { return nil }
            self.pendingData = nil
            return Pending(generation: generation, data: pendingData)
        }

        public func hasNewerWork(since generation: Int) -> Bool {
            self.generation > generation
        }

        /// Drop the attempted generation after a failed preference load. A
        /// request enqueued during that load has a larger generation and is
        /// deliberately retained for one fresh attempt.
        public mutating func discardThrough(_ generation: Int) {
            guard self.generation <= generation else { return }
            pendingData = nil
        }
    }

    public struct Snapshot: Codable, Sendable {
        public var mode: AppMode
        public var rules: [Rule]
        public var updatedAt: Date
        /// Assigned by the helper and persisted with the policy. A missing
        /// field decodes as zero so snapshots written by older builds remain
        /// readable, but clients never use their own clock as this value.
        public var generation: UInt64
        /// The helper session that produced this snapshot, from
        /// `PolicyEpoch`. A missing field decodes as `PolicyEpoch.unknown`,
        /// which is what every pre-epoch build effectively published, so the
        /// first epoch-aware helper outranks them without a reboot (#70).
        public var epoch: UInt64

        private enum CodingKeys: String, CodingKey {
            case mode
            case rules
            case updatedAt
            case generation
            case epoch
        }

        public init(mode: AppMode,
                    rules: [Rule],
                    updatedAt: Date = Date(),
                    generation: UInt64 = 0,
                    epoch: UInt64 = PolicyEpoch.unknown) {
            self.mode = mode
            self.rules = rules
            self.updatedAt = updatedAt
            self.generation = generation
            self.epoch = epoch
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            mode = try container.decode(AppMode.self, forKey: .mode)
            rules = try container.decode([Rule].self, forKey: .rules)
            updatedAt = try container.decode(Date.self, forKey: .updatedAt)
            generation = try container.decodeIfPresent(UInt64.self, forKey: .generation) ?? 0
            epoch = try container.decodeIfPresent(UInt64.self, forKey: .epoch) ?? PolicyEpoch.unknown
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(mode, forKey: .mode)
            try container.encode(rules, forKey: .rules)
            try container.encode(updatedAt, forKey: .updatedAt)
            try container.encode(generation, forKey: .generation)
            try container.encode(epoch, forKey: .epoch)
        }
    }

    /// Which helper session a received snapshot belongs to, relative to the
    /// policy the extension already holds.
    ///
    /// The helper owns policy, so a helper that has restarted is not a stale
    /// client: it is the owner speaking again, and its generation may legally
    /// be lower than the one the extension learned from the previous session.
    /// Ordering is therefore lexicographic on `(epoch, generation)`, and the
    /// generation comparison only means anything inside one session.
    public enum SnapshotAuthority: Equatable, Sendable {
        /// A newer helper session. Authoritative regardless of generation.
        case newerSession
        /// The same helper session, where the generation ordering applies.
        case sameSession
        /// An older helper session: a stale client from a previous session.
        case olderSession

        public static func compare(received: Snapshot, against current: Snapshot) -> SnapshotAuthority {
            if received.epoch > current.epoch { return .newerSession }
            if received.epoch < current.epoch { return .olderSession }
            return .sameSession
        }
    }

    /// Pure live-snapshot sequencing used by the extension and by the
    /// production-source harness. Policy content excludes `updatedAt`: a
    /// helper can construct an idempotent snapshot for the same generation at
    /// a later wall-clock time without creating split brain.
    public enum LiveSnapshotDecision: Equatable, Sendable {
        case accepted
        case idempotent
        case rejectedOlder(currentGeneration: UInt64)
        case rejectedConflict(currentGeneration: UInt64)
        case rejectedOlderSession(currentEpoch: UInt64)
    }

    public struct LiveSnapshotGate: Sendable {
        public private(set) var current: Snapshot?

        public init(current: Snapshot? = nil) {
            self.current = current
        }

        @discardableResult
        public mutating func apply(_ received: Snapshot) -> LiveSnapshotDecision {
            if let current {
                switch SnapshotAuthority.compare(received: received, against: current) {
                case .olderSession:
                    return .rejectedOlderSession(currentEpoch: current.epoch)
                case .newerSession:
                    // The helper restarted. Its persisted generation may be
                    // lower, or absent and therefore zero, and it is still the
                    // authority on policy. Rejecting it here is what left #70's
                    // machine unfiltered until a reboot.
                    break
                case .sameSession:
                    if received.generation < current.generation {
                        return .rejectedOlder(currentGeneration: current.generation)
                    }
                    if received.generation == current.generation {
                        guard current.mode == received.mode, current.rules == received.rules else {
                            return .rejectedConflict(currentGeneration: current.generation)
                        }
                        self.current = received
                        return .idempotent
                    }
                }
            }
            current = received
            return .accepted
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

        /// Why a snapshot was refused, in a form the app can act on without
        /// parsing an English sentence.
        public enum RejectionReason: String, Codable, Sendable {
            /// The sender belongs to an older helper session.
            case olderSession
            /// A lower generation inside the current helper session.
            case olderGeneration
            /// The same generation carrying different policy content.
            case conflictingContent

            /// True when the extension's retained policy, not the payload, is
            /// what refused the snapshot. Only these are cleared by restarting
            /// the filter provider; a malformed payload would come back.
            public var isClearedByRestartingFilter: Bool { true }
        }

        public var state: State
        public var mode: AppMode?
        public var ruleCount: Int
        public var updatedAt: Date?
        public var generation: UInt64?
        public var epoch: UInt64?
        public var rejection: RejectionReason?
        public var message: String?

        public init(state: State,
                    mode: AppMode? = nil,
                    ruleCount: Int = 0,
                    updatedAt: Date? = nil,
                    generation: UInt64? = nil,
                    epoch: UInt64? = nil,
                    rejection: RejectionReason? = nil,
                    message: String? = nil) {
            self.state = state
            self.mode = mode
            self.ruleCount = ruleCount
            self.updatedAt = updatedAt
            self.generation = generation
            self.epoch = epoch
            self.rejection = rejection
            self.message = message
        }

        public static func ready(for snapshot: Snapshot) -> Self {
            Self(state: .ready,
                 mode: snapshot.mode,
                 ruleCount: snapshot.rules.count,
                 updatedAt: snapshot.updatedAt,
                 generation: snapshot.generation,
                 epoch: snapshot.epoch)
        }

        public static func unavailable(_ message: String) -> Self {
            Self(state: .unavailable, message: message)
        }

        public static func invalid(_ message: String,
                                   generation: UInt64? = nil,
                                   epoch: UInt64? = nil,
                                   rejection: RejectionReason? = nil) -> Self {
            Self(state: .invalid,
                 generation: generation,
                 epoch: epoch,
                 rejection: rejection,
                 message: message)
        }

        public var isReady: Bool { state == .ready }

        /// True when the extension refused the helper because of policy it is
        /// still holding in memory. That state must never need a reboot.
        public var needsFilterRestart: Bool {
            state == .invalid && rejection?.isClearedByRestartingFilter == true
        }
    }

    public static func encode(_ snapshot: Snapshot) throws -> Data {
        try RuleTransportBoundary.encodeSnapshot(snapshot)
    }

    public static func decode(_ data: Data) throws -> Snapshot {
        // Bounds only. Rejecting a delivered policy because one persisted rule
        // predates a later content rule would stop the extension receiving any
        // policy at all, and the filter fails open. Content is judged where
        // rules enter the store, not where an existing policy is delivered.
        try RuleTransportBoundary.validateSnapshotBytes(data)
        let snapshot = try FreeSnitchWireCodec.decode(Snapshot.self, from: data)
        try RuleTransportBoundary.validateBounds(rules: snapshot.rules)
        return snapshot
    }

    public static func encodeBootSnapshot(_ snapshot: Snapshot, now: Date = Date()) throws -> Data {
        let stored = BootSnapshot(snapshot: snapshot)
        try validateBootSnapshot(stored, now: now)
        let data = try FreeSnitchWireCodec.encode(stored)
        try RuleTransportBoundary.validateBootSnapshotBytes(data)
        return data
    }

    public static func decodeBootSnapshot(_ data: Data, now: Date = Date()) throws -> Snapshot {
        guard !data.isEmpty else { throw validationError("Boot snapshot is missing.") }
        try RuleTransportBoundary.validateBootSnapshotBytes(data)
        let stored = try FreeSnitchWireCodec.decode(BootSnapshot.self, from: data)
        try validateBootSnapshot(stored, now: now)
        return stored.snapshot
    }

    public static func applyingBootPolicySafety(_ snapshot: Snapshot, now: Date = Date()) -> Snapshot {
        guard snapshot.mode == .silentDeny else { return snapshot }
        let age = now.timeIntervalSince(snapshot.updatedAt)
        guard age < 0 || age > staleSilentDenyAge else { return snapshot }
        var downgraded = snapshot
        downgraded.mode = .alert
        return downgraded
    }

    private static func validateBootSnapshot(_ stored: BootSnapshot, now: Date) throws {
        guard stored.version == bootSnapshotVersion else {
            throw validationError("Unsupported boot snapshot version \(stored.version).")
        }
        try RuleTransportBoundary.validateBounds(rules: stored.snapshot.rules)
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
        try FreeSnitchWireCodec.encode(status)
    }

    public static func decodeStatus(_ data: Data) throws -> SnapshotStatus {
        try FreeSnitchWireCodec.decode(SnapshotStatus.self, from: data)
    }
}
