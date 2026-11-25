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
    case noGatewayInRoute
    case noMACForGateway(String)

    public var errorDescription: String? {
        switch self {
        case .launchFailed(let tool, let reason):
            return String(localized: "\(tool) could not be started: \(reason)")
        case .exitStatus(let tool, let status):
            return String(localized: "\(tool) exited with status \(Int(status))")
        case .outputTooLarge(let tool, let maximum):
            return String(localized: "\(tool) wrote more than \(maximum) bytes")
        case .unreadableOutput(let tool):
            return String(localized: "\(tool) wrote output that is not text")
        case .noGatewayInRoute:
            return String(localized: "the default route has no IPv4 gateway")
        case .noMACForGateway(let gateway):
            return String(localized: "no hardware address is known for the gateway \(gateway)")
        }
    }
}

public struct SystemGatewayMACProvider: GatewayMACProviding, Sendable {
    public static let maximumCommandOutputBytes = 64 * 1024

    public init() {}

    public func currentGatewayMAC() -> String? {
        try? readGatewayMAC()
    }

    public func readGatewayMAC() throws -> String? {
        let route = try run(executable: "/sbin/route", arguments: ["-n", "get", "-inet", "default"])
        guard let gateway = gatewayAddress(in: route) else {
            throw GatewayMACReadError.noGatewayInRoute
        }
        let arp = try run(executable: "/usr/sbin/arp", arguments: ["-n", gateway])
        let mac = arp.split(whereSeparator: { $0.isWhitespace || $0 == "(" || $0 == ")" })
            .prefix(512)
            .compactMap { GatewayMAC.normalized(String($0)) }
            .first
        guard let mac else { throw GatewayMACReadError.noMACForGateway(gateway) }
        return mac
    }

    private func gatewayAddress(in output: String) -> String? {
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
        task.standardError = Pipe()
        do {
            try task.run()
        } catch {
            throw GatewayMACReadError.launchFailed(tool: tool, reason: error.localizedDescription)
        }
        task.waitUntilExit()
        guard task.terminationStatus == 0 else {
            throw GatewayMACReadError.exitStatus(tool: tool, status: task.terminationStatus)
        }
        let data = pipe.fileHandleForReading.readData(ofLength: Self.maximumCommandOutputBytes + 1)
        guard data.count <= Self.maximumCommandOutputBytes else {
            throw GatewayMACReadError.outputTooLarge(tool: tool, maximum: Self.maximumCommandOutputBytes)
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
    private var readProblem: String?
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
    public var lastReadProblem: String? {
        lock.lock()
        defer { lock.unlock() }
        return readProblem
    }

    /// Forgets a change the handler has not managed to act on yet, so the next
    /// poll does not deliver it again. For when the user decided in the
    /// meantime, which outranks a retry.
    public func dropUndeliveredChange() {
        lock.lock()
        undelivered = false
        lock.unlock()
    }

    /// Reads and normalizes the gateway MAC once. Returns the value whether or
    /// not it changed, which makes an explicit UI refresh easy to test.
    @discardableResult
    public func refresh() -> String? {
        var problem: String?
        let raw: String?
        do {
            raw = try provider.readGatewayMAC()
        } catch {
            raw = nil
            problem = error.localizedDescription
        }
        let current = raw.flatMap(GatewayMAC.normalized)
        if raw != nil, current == nil {
            problem = String(localized: "the gateway's hardware address is not in a recognised form")
        }
        let callback: ChangeHandler?
        lock.lock()
        let changed = current != lastMAC
        if changed {
            lastMAC = current
            undelivered = true
        }
        let deliver = undelivered
        callback = deliver ? handler : nil
        let problemChanged = problem != readProblem
        readProblem = problem
        lock.unlock()

        if problemChanged {
            if let problem {
                PSLog.error(PSLog.helper, "The default gateway could not be read: \(problem)")
            } else {
                PSLog.info(PSLog.helper, "The default gateway can be read again.")
            }
        }
        guard deliver, let callback else { return current }
        let handled = callback(current)
        lock.lock()
        // A newer change that arrived meanwhile stays undelivered whatever
        // this older one did.
        if lastMAC == current, handled { undelivered = false }
        lock.unlock()
        return current
    }
}
