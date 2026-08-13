import Foundation

/// The pending-alert registry: the only path by which a process that does not
/// own the network extension's callback connection can see and answer a paused
/// flow.
///
/// The shape of the problem, which the rest of this file exists to respect:
/// `FilterDataProvider` pauses a flow and asks the *GUI* over the app-group
/// channel. The helper never sees that flow, and the CLI is deliberately not a
/// notification client (`XPCPeerValidator.isCLI` in `HelperService.listener`).
/// So the GUI registers the alert it is already showing with the helper, the
/// CLI lists and answers through the helper, and the verdict travels back to
/// the GUI, which is the only process that can answer the extension.
///
/// Three properties matter, and each one is a bug this type exists to prevent:
/// - an alert resolves exactly once, so a CLI answer racing the GUI answer
///   cannot decide the same flow twice
/// - a registry entry expires strictly before the flow's own budget, so the
///   CLI can never become a way to pause traffic for longer than the extension
///   already allows
/// - the table is bounded, exactly like the DNS ask table, so a wedged client
///   cannot grow it forever
public enum PendingAlertLimits {
    /// The budget `FilterDataProvider` gives a paused flow, and the same one
    /// `DNSAskCoordinator.askTimeout` uses. Both resume with the fail-open
    /// default when it runs out.
    public static let flowAskTimeout: TimeInterval = 60

    /// Subtracted from the flow budget so a registry entry always dies before
    /// the flow it describes. Answering an alert whose flow already resumed is
    /// pointless, and pretending otherwise would be a lie to the CLI user.
    public static let answerGrace: TimeInterval = 5

    /// The longest a registered alert can stay answerable. Strictly shorter
    /// than `flowAskTimeout`; `Scripts/test_pending_alerts.sh` asserts that
    /// against the real extension and helper sources.
    public static let maxLifetime: TimeInterval = flowAskTimeout - answerGrace

    /// Hard bound on registered alerts. Past this, do not queue: the
    /// registration resolves immediately with the fail-open default, which is
    /// what the GUI and the DNS ask table already do on overflow.
    public static let capacity = 12

    /// Bounded memory of alerts that already finished, so an id that timed out
    /// or was answered gets a specific answer instead of "not found".
    public static let historyCapacity = 64

    public static let maxDescriptorBytes = 8 * 1024
    public static let maxRequestBytes = 8 * 1024
    public static let maxListingBytes = 256 * 1024

    /// Bounds for `--remember <duration>`.
    public static let minRememberDuration: TimeInterval = 60
    public static let maxRememberDuration: TimeInterval = 30 * 24 * 60 * 60
    /// What `--temporary` means when no duration is given.
    public static let temporaryRememberDuration: TimeInterval = 60 * 60
}

public enum PendingAlertError: LocalizedError, Equatable {
    case invalidDescriptor(String)
    case unsupportedScope(String)
    case invalidDuration(String)

    public var errorDescription: String? {
        switch self {
        case .invalidDescriptor(let reason): return "invalid pending alert: \(reason)"
        case .unsupportedScope(let reason): return reason
        case .invalidDuration(let reason): return reason
        }
    }
}

/// The remember scopes the GUI alert offers, in CLI spelling.
public enum PendingAlertScope: String, Codable, Sendable, CaseIterable {
    case process
    case domain
    case ip
    case port

    public var ruleScope: RuleScope {
        switch self {
        case .process: return .process
        case .domain: return .domain
        case .ip: return .ip
        case .port: return .port
        }
    }

    public static func parse(_ value: String) -> PendingAlertScope? {
        PendingAlertScope(rawValue: value.lowercased())
    }
}

/// How long a remembered decision lives. `.no` is the CLI default: answer the
/// flow and store nothing, which is the alert panel with "Remember" unchecked.
public struct PendingAlertRemember: Codable, Sendable, Equatable {
    public enum Kind: String, Codable, Sendable {
        case no
        case forever
        case duration
    }

    public let kind: Kind
    /// Seconds, only for `.duration`.
    public let seconds: TimeInterval?

    public static let no = PendingAlertRemember(kind: .no, seconds: nil)
    public static let forever = PendingAlertRemember(kind: .forever, seconds: nil)

    public static func duration(_ seconds: TimeInterval) -> PendingAlertRemember {
        PendingAlertRemember(kind: .duration, seconds: seconds)
    }

    public var storesRule: Bool { kind != .no }

    public func expiration(from now: Date) -> Date? {
        guard kind == .duration, let seconds else { return nil }
        return now.addingTimeInterval(seconds)
    }

    public var describedValue: String {
        switch kind {
        case .no: return "no"
        case .forever: return "forever"
        case .duration: return PendingAlertDuration.describe(seconds ?? 0)
        }
    }

    public func validate() throws {
        guard kind == .duration else { return }
        guard let seconds else {
            throw PendingAlertError.invalidDuration("a remembered duration is missing its length")
        }
        try PendingAlertDuration.validate(seconds)
    }
}

/// Parses `5m`, `90s`, `2h`, `7d`, and `forever`. Kept here rather than in the
/// CLI parser so the helper validates the same bounds it is told about.
public enum PendingAlertDuration {
    public static func parse(_ value: String) throws -> PendingAlertRemember {
        let text = value.trimmingCharacters(in: .whitespaces).lowercased()
        guard !text.isEmpty else {
            throw PendingAlertError.invalidDuration("a remembered duration cannot be empty")
        }
        if text == "forever" || text == "permanent" || text == "always" {
            return .forever
        }
        let unit = text.last!
        let multiplier: TimeInterval
        switch unit {
        case "s": multiplier = 1
        case "m": multiplier = 60
        case "h": multiplier = 3600
        case "d": multiplier = 86400
        default:
            throw PendingAlertError.invalidDuration(
                "`\(value)` is not a duration; use forever or a number followed by s, m, h, or d, for example 30m")
        }
        let amount = text.dropLast()
        guard let count = Double(amount), count > 0 else {
            throw PendingAlertError.invalidDuration(
                "`\(value)` is not a duration; use forever or a number followed by s, m, h, or d, for example 30m")
        }
        let seconds = count * multiplier
        try validate(seconds)
        return .duration(seconds)
    }

    public static func validate(_ seconds: TimeInterval) throws {
        guard seconds >= PendingAlertLimits.minRememberDuration else {
            throw PendingAlertError.invalidDuration(
                "a remembered decision must last at least \(Int(PendingAlertLimits.minRememberDuration)) seconds")
        }
        guard seconds <= PendingAlertLimits.maxRememberDuration else {
            throw PendingAlertError.invalidDuration(
                "a remembered decision cannot last longer than \(Int(PendingAlertLimits.maxRememberDuration / 86400)) days; use forever for a permanent rule")
        }
    }

    public static func describe(_ seconds: TimeInterval) -> String {
        if seconds >= 86400, seconds.truncatingRemainder(dividingBy: 86400) == 0 {
            return "\(Int(seconds / 86400))d"
        }
        if seconds >= 3600, seconds.truncatingRemainder(dividingBy: 3600) == 0 {
            return "\(Int(seconds / 3600))h"
        }
        if seconds >= 60, seconds.truncatingRemainder(dividingBy: 60) == 0 {
            return "\(Int(seconds / 60))m"
        }
        return "\(Int(seconds))s"
    }
}

/// What the CLI is shown about a paused flow. This is a copy, not a handle:
/// the flow itself stays with the GUI and the extension.
public struct PendingAlertDescriptor: Codable, Sendable, Equatable, Identifiable {
    public let id: UUID
    public let processName: String
    public let processPath: String
    public let processBundleId: String?
    public let remoteHost: String
    public let remoteIP: String
    public let remotePort: Int
    public let direction: RuleDirection
    public let protocolName: String
    public let askedAt: Date
    public let expiresAt: Date

    public init(id: UUID,
                processName: String,
                processPath: String,
                processBundleId: String?,
                remoteHost: String,
                remoteIP: String,
                remotePort: Int,
                direction: RuleDirection,
                protocolName: String,
                askedAt: Date,
                expiresAt: Date) {
        self.id = id
        self.processName = processName
        self.processPath = processPath
        self.processBundleId = processBundleId
        self.remoteHost = remoteHost
        self.remoteIP = remoteIP
        self.remotePort = remotePort
        self.direction = direction
        self.protocolName = protocolName
        self.askedAt = askedAt
        self.expiresAt = expiresAt
    }

    public init(id: UUID, connection: Connection, askedAt: Date = Date(), expiresAt: Date) {
        self.init(id: id,
                  processName: connection.processName,
                  processPath: connection.processPath,
                  processBundleId: connection.processBundleId,
                  remoteHost: connection.remoteHost,
                  remoteIP: connection.remoteIP,
                  remotePort: connection.remotePort,
                  direction: connection.direction,
                  protocolName: connection.protocolName,
                  askedAt: askedAt,
                  expiresAt: expiresAt)
    }

    /// The name if one is known, otherwise the address. Never invented.
    public var destination: String {
        remoteHost.isEmpty ? remoteIP : remoteHost
    }

    public var hasHostname: Bool {
        !remoteHost.isEmpty && PFHostValidator.kind(for: remoteHost) == .hostname
    }

    public func secondsRemaining(now: Date = Date()) -> Int {
        max(0, Int(expiresAt.timeIntervalSince(now).rounded()))
    }

    public func withExpiration(_ date: Date) -> PendingAlertDescriptor {
        PendingAlertDescriptor(id: id,
                               processName: processName,
                               processPath: processPath,
                               processBundleId: processBundleId,
                               remoteHost: remoteHost,
                               remoteIP: remoteIP,
                               remotePort: remotePort,
                               direction: direction,
                               protocolName: protocolName,
                               askedAt: askedAt,
                               expiresAt: date)
    }

    public func validate() throws {
        guard remotePort >= 0, remotePort <= 65535 else {
            throw PendingAlertError.invalidDescriptor("remote port \(remotePort) is out of range")
        }
        guard processName.count <= 512, processPath.count <= 1024,
              remoteHost.count <= 512, remoteIP.count <= 128,
              (processBundleId?.count ?? 0) <= 512, protocolName.count <= 32 else {
            throw PendingAlertError.invalidDescriptor("a descriptor field exceeds its length bound")
        }
    }
}

/// Who answered. The registry records this so the loser of a race is told what
/// beat it instead of a generic failure.
public enum PendingAlertAnswerer: String, Codable, Sendable {
    case cli
    case gui
}

/// Delivered to whoever registered the alert (the GUI) when it finishes. This
/// is the value that lets the GUI answer the extension.
public struct PendingAlertResolution: Codable, Sendable, Equatable {
    public enum Kind: String, Codable, Sendable {
        /// A human answered, through the GUI or through the CLI.
        case answered
        /// The registrant answered it itself and took the entry back.
        case withdrawn
        /// Nobody answered inside the registry's budget. The flow still
        /// resumes on its own timeout with the fail-open default.
        case expired
        /// The registry was full. Nothing was queued.
        case overflow
    }

    public let kind: Kind
    public let allow: Bool?
    public let answeredBy: PendingAlertAnswerer?
    public let at: Date

    public init(kind: Kind, allow: Bool?, answeredBy: PendingAlertAnswerer?, at: Date) {
        self.kind = kind
        self.allow = allow
        self.answeredBy = answeredBy
        self.at = at
    }

    public static func answered(allow: Bool, by answerer: PendingAlertAnswerer, at: Date = Date()) -> Self {
        Self(kind: .answered, allow: allow, answeredBy: answerer, at: at)
    }

    public static func withdrawn(at: Date = Date()) -> Self {
        Self(kind: .withdrawn, allow: nil, answeredBy: .gui, at: at)
    }

    public static func expired(at: Date = Date()) -> Self {
        Self(kind: .expired, allow: nil, answeredBy: nil, at: at)
    }

    public static func overflow(at: Date = Date()) -> Self {
        Self(kind: .overflow, allow: nil, answeredBy: nil, at: at)
    }

    /// The verdict to apply to the flow, or nil when this resolution carries no
    /// human decision. A nil here is never a deny: the caller falls back to the
    /// same fail-open default the extension uses on timeout.
    public var flowVerdict: Bool? {
        kind == .answered ? allow : nil
    }
}

/// The answer a caller sends for one alert.
public struct PendingAlertAnswer: Codable, Sendable, Equatable {
    public let allow: Bool
    public let scope: PendingAlertScope?
    public let remember: PendingAlertRemember

    public init(allow: Bool, scope: PendingAlertScope? = nil, remember: PendingAlertRemember = .no) {
        self.allow = allow
        self.scope = scope
        self.remember = remember
    }

    public func validate() throws {
        try remember.validate()
        if scope != nil, !remember.storesRule {
            throw PendingAlertError.unsupportedScope(
                "a scope only applies to a remembered decision; add --remember or --temporary")
        }
    }
}

public struct PendingAlertAnswerRequest: Codable, Sendable {
    public let id: UUID
    public let answer: PendingAlertAnswer

    public init(id: UUID, answer: PendingAlertAnswer) {
        self.id = id
        self.answer = answer
    }
}

/// The reply to `alerts answer`, including the specific reason an id could not
/// be answered.
public struct PendingAlertAnswerResponse: Codable, Sendable {
    public enum State: String, Codable, Sendable {
        case answered
        case alreadyAnswered = "already-answered"
        case expired
        case unknown
    }

    public let id: UUID
    public let state: State
    public let allow: Bool?
    public let answeredBy: PendingAlertAnswerer?
    public let resolvedAt: Date?
    public let descriptor: PendingAlertDescriptor?
    public let ruleStored: Bool
    public let ruleID: UUID?
    public let ruleMessage: String?
    public let message: String

    public init(id: UUID,
                state: State,
                allow: Bool? = nil,
                answeredBy: PendingAlertAnswerer? = nil,
                resolvedAt: Date? = nil,
                descriptor: PendingAlertDescriptor? = nil,
                ruleStored: Bool = false,
                ruleID: UUID? = nil,
                ruleMessage: String? = nil,
                message: String) {
        self.id = id
        self.state = state
        self.allow = allow
        self.answeredBy = answeredBy
        self.resolvedAt = resolvedAt
        self.descriptor = descriptor
        self.ruleStored = ruleStored
        self.ruleID = ruleID
        self.ruleMessage = ruleMessage
        self.message = message
    }
}

/// What `alerts list` returns. An empty list is never presented as a failure,
/// and never without saying why it is empty.
public struct PendingAlertListing: Codable, Sendable {
    public let alerts: [PendingAlertDescriptor]
    public let guiAttached: Bool
    public let capacity: Int
    public let reason: String?

    public static let noGUIReason = """
        No FreeSnitch app is connected to the helper. Connection alerts are raised by the network \
        extension against the running app, so none can exist and none can be answered while the app \
        is not running. Flows still resume with the fail-open default when their ask timeout expires.
        """

    public static let noneReason = "No connection alert is waiting for an answer."

    public init(alerts: [PendingAlertDescriptor], guiAttached: Bool, capacity: Int = PendingAlertLimits.capacity) {
        self.alerts = alerts
        self.guiAttached = guiAttached
        self.capacity = capacity
        if !alerts.isEmpty {
            self.reason = nil
        } else if guiAttached {
            self.reason = Self.noneReason
        } else {
            self.reason = Self.noGUIReason
        }
    }
}

/// Turns an answered alert into the rule the user asked to remember. The
/// helper owns this so a CLI answer stores exactly the same shape of rule the
/// GUI alert panel stores.
public enum PendingAlertRuleFactory {
    /// The scope the GUI would pick: the name when one is known, the address
    /// otherwise. Never a rule that matches nothing.
    public static func defaultScope(for descriptor: PendingAlertDescriptor) -> PendingAlertScope {
        descriptor.hasHostname ? .domain : .ip
    }

    public static func rule(for descriptor: PendingAlertDescriptor,
                            answer: PendingAlertAnswer,
                            profile: String = "default",
                            now: Date = Date()) throws -> Rule? {
        guard answer.remember.storesRule else { return nil }
        let scope = answer.scope ?? defaultScope(for: descriptor)
        let action: RuleAction = answer.allow ? .allow : .deny
        let expiresAt = answer.remember.expiration(from: now)
        let temporary = expiresAt != nil
        let notes = "Created from `freesnitch alerts answer`"

        switch scope {
        case .process:
            guard descriptor.processBundleId != nil || !descriptor.processPath.isEmpty else {
                throw PendingAlertError.unsupportedScope(
                    "this alert carries no application identity, so a process-scoped rule would match nothing")
            }
            return Rule(processBundleId: descriptor.processBundleId,
                        processPath: descriptor.processPath.isEmpty ? nil : descriptor.processPath,
                        processName: descriptor.processName.isEmpty ? nil : descriptor.processName,
                        direction: descriptor.direction,
                        action: action,
                        scope: .process,
                        profile: profile,
                        notes: notes,
                        temporary: temporary,
                        expiresAt: expiresAt)
        case .domain:
            guard descriptor.hasHostname else {
                throw PendingAlertError.unsupportedScope(
                    "this alert has no resolvable host name, so a domain-scoped rule would match nothing; use --scope ip")
            }
            return Rule(processBundleId: descriptor.processBundleId,
                        processPath: descriptor.processPath.isEmpty ? nil : descriptor.processPath,
                        processName: descriptor.processName.isEmpty ? nil : descriptor.processName,
                        remoteHost: descriptor.remoteHost,
                        direction: descriptor.direction,
                        action: action,
                        scope: .domain,
                        profile: profile,
                        notes: notes,
                        temporary: temporary,
                        expiresAt: expiresAt)
        case .ip:
            guard !descriptor.remoteIP.isEmpty,
                  RuleAddressValidator.rejectionReason(forRemoteIP: descriptor.remoteIP) == nil else {
                throw PendingAlertError.unsupportedScope(
                    "this alert has no usable remote address, so an address-scoped rule would match nothing")
            }
            return Rule(processBundleId: descriptor.processBundleId,
                        processPath: descriptor.processPath.isEmpty ? nil : descriptor.processPath,
                        processName: descriptor.processName.isEmpty ? nil : descriptor.processName,
                        remoteIP: descriptor.remoteIP,
                        direction: descriptor.direction,
                        action: action,
                        scope: .ip,
                        profile: profile,
                        notes: notes,
                        temporary: temporary,
                        expiresAt: expiresAt)
        case .port:
            guard descriptor.remotePort > 0 else {
                throw PendingAlertError.unsupportedScope(
                    "this alert carries no remote port, so a port-scoped rule would match nothing")
            }
            return Rule(processBundleId: descriptor.processBundleId,
                        processPath: descriptor.processPath.isEmpty ? nil : descriptor.processPath,
                        processName: descriptor.processName.isEmpty ? nil : descriptor.processName,
                        remotePort: descriptor.remotePort,
                        direction: descriptor.direction,
                        action: action,
                        scope: .port,
                        profile: profile,
                        notes: notes,
                        temporary: temporary,
                        expiresAt: expiresAt)
        }
    }
}

/// The bounded table of alerts that can currently be answered from outside the
/// process that owns the flow.
///
/// Every rule here mirrors `DNSAskCoordinator`: no completion runs while the
/// lock is held, every entry has one exit, and the table cannot grow past its
/// capacity.
public final class PendingAlertRegistry: @unchecked Sendable {
    /// Fail open, exactly like the extension's no-GUI path and the DNS ask
    /// table. A registration that cannot be queued, or an alert nobody
    /// answers, must never turn into a block.
    public static let defaultDecision = true

    public enum Admission: Equatable {
        /// Queued; the resolution callback will run exactly once, later.
        case registered
        /// Nothing was queued. The callback already ran with this resolution.
        case resolvedImmediately(PendingAlertResolution)
    }

    /// Why an id cannot be answered. Each case is a distinct, specific answer;
    /// none of them is a generic failure.
    public enum AnswerOutcome: Equatable {
        case answered(PendingAlertDescriptor)
        case alreadyAnswered(by: PendingAlertAnswerer, at: Date)
        case expired(at: Date)
        case unknown
    }

    private struct Entry {
        let descriptor: PendingAlertDescriptor
        let ownerKey: ObjectIdentifier?
        let resolve: (PendingAlertResolution) -> Void
    }

    private enum HistoryOutcome: Equatable {
        case answered(by: PendingAlertAnswerer)
        case expired
    }

    private var entries: [UUID: Entry] = [:]
    private var history: [UUID: (outcome: HistoryOutcome, at: Date)] = [:]
    private var historyOrder: [UUID] = []
    private let lock = NSLock()
    /// Expiry runs on its own utility queue. It must never share a queue with
    /// XPC handling, because an expiry that waits behind a request is the same
    /// hang it exists to break.
    private let expiryQueue = DispatchQueue(label: "io.isaaclins.freesnitch.pending-alert-expiry", qos: .utility)

    public init() {}

    /// Number of alerts currently answerable. Test seam and diagnostics.
    public var count: Int {
        lock.lock()
        let value = entries.count
        lock.unlock()
        return value
    }

    /// Registers an alert the caller is already showing.
    ///
    /// The deadline is clamped to `PendingAlertLimits.maxLifetime`, so a caller
    /// cannot ask the helper to hold an answerable entry for longer than the
    /// flow's own budget however wrong its clock or its arithmetic is.
    @discardableResult
    public func register(_ descriptor: PendingAlertDescriptor,
                         ownerKey: ObjectIdentifier? = nil,
                         now: Date = Date(),
                         onResolve: @escaping (PendingAlertResolution) -> Void) -> Admission {
        let ceiling = now.addingTimeInterval(PendingAlertLimits.maxLifetime)
        let deadline = min(descriptor.expiresAt, ceiling)
        guard deadline > now else {
            let resolution = PendingAlertResolution.expired(at: now)
            onResolve(resolution)
            return .resolvedImmediately(resolution)
        }
        let clamped = descriptor.withExpiration(deadline)

        lock.lock()
        if entries.count >= PendingAlertLimits.capacity || entries[clamped.id] != nil {
            lock.unlock()
            // Do not queue past the bound, and never replace a live entry: the
            // caller resumes the flow with the fail-open default instead, which
            // is what the GUI and the DNS ask table already do here.
            let resolution = PendingAlertResolution.overflow(at: now)
            onResolve(resolution)
            return .resolvedImmediately(resolution)
        }
        entries[clamped.id] = Entry(descriptor: clamped, ownerKey: ownerKey, resolve: onResolve)
        lock.unlock()

        let budget = deadline.timeIntervalSince(now)
        expiryQueue.asyncAfter(deadline: .now() + budget) { [weak self] in
            self?.expire(id: clamped.id)
        }
        return .registered
    }

    /// Answers one alert. The entry is removed under the lock, so exactly one
    /// caller can ever win; every later caller is told what beat it.
    public func answer(id: UUID,
                       allow: Bool,
                       by answerer: PendingAlertAnswerer,
                       now: Date = Date()) -> AnswerOutcome {
        lock.lock()
        guard let entry = entries.removeValue(forKey: id) else {
            let recorded = history[id]
            lock.unlock()
            return Self.outcome(for: recorded)
        }
        record(id: id, outcome: .answered(by: answerer), at: now)
        lock.unlock()
        entry.resolve(.answered(allow: allow, by: answerer, at: now))
        return .answered(entry.descriptor)
    }

    /// The registrant took the alert back because a human answered it there.
    /// This is a claim, not a cancellation: it closes the entry so a CLI answer
    /// arriving afterwards is told the GUI already answered.
    public func withdraw(id: UUID, now: Date = Date()) -> AnswerOutcome {
        lock.lock()
        guard let entry = entries.removeValue(forKey: id) else {
            let recorded = history[id]
            lock.unlock()
            return Self.outcome(for: recorded)
        }
        record(id: id, outcome: .answered(by: .gui), at: now)
        lock.unlock()
        entry.resolve(.withdrawn(at: now))
        return .answered(entry.descriptor)
    }

    /// Drops every entry registered over a connection that went away. Their
    /// flows are still resumed by the extension's own timeout.
    public func withdrawAll(ownerKey: ObjectIdentifier, now: Date = Date()) {
        lock.lock()
        let doomed = entries.filter { $0.value.ownerKey == ownerKey }
        for id in doomed.keys {
            entries.removeValue(forKey: id)
            record(id: id, outcome: .expired, at: now)
        }
        lock.unlock()
        for entry in doomed.values { entry.resolve(.withdrawn(at: now)) }
    }

    /// The alerts that can be answered right now, oldest first. Due entries are
    /// expired first, so a caller can never be shown an alert it cannot answer.
    public func pending(now: Date = Date()) -> [PendingAlertDescriptor] {
        expireDueEntries(now: now)
        lock.lock()
        let descriptors = entries.values.map(\.descriptor)
        lock.unlock()
        return descriptors.sorted { $0.askedAt < $1.askedAt }
    }

    /// Expires everything whose budget has run out. The scheduled timer calls
    /// the same path; this exists so a read, or a test, cannot observe an entry
    /// that is already past its deadline.
    public func expireDueEntries(now: Date = Date()) {
        lock.lock()
        let due = entries.filter { $0.value.descriptor.expiresAt <= now }
        for id in due.keys {
            entries.removeValue(forKey: id)
            record(id: id, outcome: .expired, at: now)
        }
        lock.unlock()
        for entry in due.values { entry.resolve(.expired(at: now)) }
    }

    private func expire(id: UUID, now: Date = Date()) {
        lock.lock()
        guard let entry = entries.removeValue(forKey: id) else {
            lock.unlock()
            return
        }
        record(id: id, outcome: .expired, at: now)
        lock.unlock()
        entry.resolve(.expired(at: now))
    }

    /// Caller holds the lock.
    private func record(id: UUID, outcome: HistoryOutcome, at: Date) {
        if history[id] == nil { historyOrder.append(id) }
        history[id] = (outcome, at)
        while historyOrder.count > PendingAlertLimits.historyCapacity {
            let oldest = historyOrder.removeFirst()
            history.removeValue(forKey: oldest)
        }
    }

    private static func outcome(for recorded: (outcome: HistoryOutcome, at: Date)?) -> AnswerOutcome {
        guard let recorded else { return .unknown }
        switch recorded.outcome {
        case .answered(let answerer): return .alreadyAnswered(by: answerer, at: recorded.at)
        case .expired: return .expired(at: recorded.at)
        }
    }
}
