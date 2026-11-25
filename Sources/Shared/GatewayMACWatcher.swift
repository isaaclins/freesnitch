import Foundation

/// A small injectable seam around the system route and ARP tools. Tests can
/// provide a fixed value without invoking a shell or any Wi-Fi API.
public protocol GatewayMACProviding: Sendable {
    func currentGatewayMAC() -> String?
    /// The same reading, but a failed read says why instead of looking like a
    /// network without a gateway (#269). Providers that cannot fail keep the
    /// default, which is `currentGatewayMAC()`.
    func readGatewayMAC() throws -> String?
}

public extension GatewayMACProviding {
    func readGatewayMAC() throws -> String? { currentGatewayMAC() }
}

/// Why the system tools gave no gateway MAC. Each case names the step that
/// failed, so a log line or the Profiles screen can say more than "unknown".
public enum GatewayMACReadError: Error, LocalizedError, Equatable, Sendable {
    case launchFailed(tool: String, reason: String)
    case exitStatus(tool: String, status: Int32)
    case outputTooLarge(tool: String, maximum: Int)
    case unreadableOutput(tool: String)
    /// `route` found no default route. Mapped to "no gateway", never shown.
    case noRoute
    case noMACForGateway(String)

    /// The code the helper sends on, or nil for `noRoute`, which is no
    /// gateway rather than a failure.
    public var problem: ProfileProblem? {
        switch self {
        case .launchFailed(let tool, let reason): return .toolLaunchFailed(tool: tool, detail: reason)
        case .exitStatus(let tool, let status): return .toolExitStatus(tool: tool, status: status)
        case .outputTooLarge(let tool, let maximum): return .toolOutputTooLarge(tool: tool, maximum: maximum)
        case .unreadableOutput(let tool): return .toolOutputNotText(tool: tool)
        case .noRoute: return nil
        case .noMACForGateway(let gateway): return .noMACForGateway(gateway)
        }
    }

    public var errorDescription: String? {
        problem?.message ?? "no default route"
    }
}

public struct SystemGatewayMACProvider: GatewayMACProviding, Sendable {
    public static let maximumCommandOutputBytes = 64 * 1024

    public init() {}

    public func currentGatewayMAC() -> String? {
        try? readGatewayMAC()
    }

    public func readGatewayMAC() throws -> String? {
        let route: String
        do {
            route = try run(executable: "/sbin/route", arguments: ["-n", "get", "-inet", "default"])
        } catch GatewayMACReadError.noRoute {
            // Offline: there is no gateway, which is not a failure to read one.
            return nil
        }
        // Offline, macOS's route prints "not in table" to stderr, exits 0 and
        // writes nothing here. A default route through an interface (a
        // full-tunnel VPN) has no gateway line either. Both are simply no
        // gateway.
        guard let gateway = Self.gatewayAddress(in: route) else { return nil }
        let arp: String
        do {
            arp = try run(executable: "/usr/sbin/arp", arguments: ["-n", gateway])
        } catch GatewayMACReadError.exitStatus {
            // arp says "-- no entry" and exits 1 when the gateway is not in
            // the ARP table yet (just after joining) or never will be (a
            // tunnel gateway). Said in plain words, not as an exit status.
            throw GatewayMACReadError.noMACForGateway(gateway)
        }
        guard let mac = Self.gatewayMAC(inARPOutput: arp) else {
            throw GatewayMACReadError.noMACForGateway(gateway)
        }
        return mac
    }

    /// The hardware address in `arp -n <gateway>` output, or nil when there is
    /// none (an incomplete entry, or "-- no entry").
    public static func gatewayMAC(inARPOutput output: String) -> String? {
        output.split(whereSeparator: { $0.isWhitespace || $0 == "(" || $0 == ")" })
            .prefix(512)
            .compactMap { GatewayMAC.normalized(String($0)) }
            .first
    }

    /// The IPv4 gateway in `route -n get` output, or nil when there is none.
    public static func gatewayAddress(in output: String) -> String? {
        for line in output.split(whereSeparator: \.isNewline).prefix(512) {
            let fields = line.split(whereSeparator: \.isWhitespace)
            guard fields.count >= 2, fields[0].lowercased() == "gateway:" else { continue }
            let candidate = String(fields[1])
            guard candidate.utf8.count <= 64,
                  candidate.split(separator: ".", omittingEmptySubsequences: false).count == 4,
                  candidate.allSatisfy({ $0.isNumber || $0 == "." }) else { continue }
            return candidate
        }
        return nil
    }

    private func run(executable: String, arguments: [String]) throws -> String {
        let tool = URL(fileURLWithPath: executable).lastPathComponent
        let task = Process()
        task.executableURL = URL(fileURLWithPath: executable)
        task.arguments = arguments
        let pipe = Pipe()
        task.standardOutput = pipe
        let errorPipe = Pipe()
        task.standardError = errorPipe
        do {
            try task.run()
        } catch {
            throw GatewayMACReadError.launchFailed(tool: tool, reason: error.localizedDescription)
        }
        // Read before waiting: a tool that fills the pipe would otherwise
        // block on its write while we block on its exit.
        let data = pipe.fileHandleForReading.readData(ofLength: Self.maximumCommandOutputBytes + 1)
        guard data.count <= Self.maximumCommandOutputBytes else {
            task.terminate()
            task.waitUntilExit()
            throw GatewayMACReadError.outputTooLarge(tool: tool, maximum: Self.maximumCommandOutputBytes)
        }
        let message = errorPipe.fileHandleForReading.readData(ofLength: 4096)
        task.waitUntilExit()
        guard task.terminationStatus == 0 else {
            if tool == "route", String(decoding: message, as: UTF8.self).contains("not in table") {
                throw GatewayMACReadError.noRoute
            }
            throw GatewayMACReadError.exitStatus(tool: tool, status: task.terminationStatus)
        }
        guard let text = String(data: data, encoding: .utf8) else {
            throw GatewayMACReadError.unreadableOutput(tool: tool)
        }
        return text
    }
}

/// Polls the default gateway without ever binding a profile that the user has
/// not explicitly associated with that gateway MAC. The watcher reports only
/// a changed canonical MAC; policy selection belongs to ProfileCoordinator.
///
/// A change counts as delivered only when the handler says it was handled.
/// Until then every poll hands the same MAC over again, so a profile switch
/// that failed is retried instead of being lost until the gateway changes
/// (#269).
public final class GatewayMACWatcher: @unchecked Sendable {
    /// Returns true when the change was fully acted on, false to have it
    /// delivered again on the next poll.
    public typealias ChangeHandler = (String?) -> Bool

    private let provider: GatewayMACProviding
    private let queue: DispatchQueue
    private let lock = NSLock()
    private var timer: DispatchSourceTimer?
    private var lastMAC: String?
    private var undelivered = false
    private var delivering = false
    private var readProblem: ProfileProblem?
    private var handler: ChangeHandler?

    public init(
        provider: GatewayMACProviding = SystemGatewayMACProvider(),
        queue: DispatchQueue = DispatchQueue(label: "io.isaaclins.freesnitch.gateway-mac", qos: .utility)
    ) {
        self.provider = provider
        self.queue = queue
    }

    public var onChange: ChangeHandler? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return handler
        }
        set {
            lock.lock()
            handler = newValue
            lock.unlock()
        }
    }

    /// Starts polling. The initial read is delivered only when it differs from
    /// the empty state, and no binding is created as a side effect.
    public func start(every interval: TimeInterval = 5) {
        stop()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        let boundedInterval = max(1, min(interval, 24 * 60 * 60))
        timer.schedule(deadline: .now(), repeating: boundedInterval)
        timer.setEventHandler { [weak self] in _ = self?.refresh() }
        timer.resume()
        lock.lock()
        self.timer = timer
        lock.unlock()
    }

    public func stop() {
        lock.lock()
        let current = timer
        timer = nil
        lock.unlock()
        current?.cancel()
    }

    /// Why the last read gave no gateway MAC, or nil when it gave one or the
    /// network simply has none to give.
    public var lastReadProblem: ProfileProblem? {
        lock.lock()
        defer { lock.unlock() }
        return readProblem
    }

    /// Forgets a change the handler has not managed to act on yet, so the next
    /// poll does not deliver it again. For when the user decided in the
    /// meantime, which outranks a retry.
    /// Only drops it while `mac` is still the latest reading, so a newer
    /// gateway seen meanwhile is still delivered.
    public func dropUndeliveredChange(for mac: String) {
        lock.lock()
        if (lastMAC ?? "") == mac { undelivered = false }
        lock.unlock()
    }

    /// Reads and normalizes the gateway MAC once. Returns the value whether or
    /// not it changed, which makes an explicit UI refresh easy to test.
    @discardableResult
    public func refresh() -> String? {
        var problem: ProfileProblem?
        var expected = false
        let raw: String?
        do {
            raw = try provider.readGatewayMAC()
        } catch {
            raw = nil
            problem = ProfileProblem(error)
            // Every join starts with the gateway missing from the ARP table
            // for a moment: worth a note, not an error.
            if case GatewayMACReadError.noMACForGateway = error { expected = true }
        }
        let current = raw.flatMap(GatewayMAC.normalized)
        if raw != nil, current == nil {
            problem = .unrecognisedGatewayMAC
        }
        let callback: ChangeHandler?
        lock.lock()
        let changed = current != lastMAC
        if changed {
            lastMAC = current
            undelivered = true
        }
        // One delivery at a time: the timer and a refresh from the app can
        // poll at once, and the same change must not be handled twice. A poll
        // that finds a delivery running leaves the change to it, or to the
        // next poll if it fails.
        let deliver = undelivered && !delivering && handler != nil
        if deliver { delivering = true }
        callback = deliver ? handler : nil
        let problemChanged = problem != readProblem
        readProblem = problem
        lock.unlock()

        if problemChanged {
            if let problem, expected {
                PSLog.info(PSLog.helper, "The default gateway has no hardware address yet: \(problem.message)")
            } else if let problem {
                PSLog.error(PSLog.helper, "The default gateway could not be read: \(problem.message)")
            } else {
                PSLog.info(PSLog.helper, "The default gateway can be read again.")
            }
        }
        guard deliver, let callback else { return current }
        let handled = callback(current)
        lock.lock()
        delivering = false
        // A newer change that arrived meanwhile stays undelivered whatever
        // this older one did.
        if lastMAC == current, handled { undelivered = false }
        lock.unlock()
        return current
    }
}
