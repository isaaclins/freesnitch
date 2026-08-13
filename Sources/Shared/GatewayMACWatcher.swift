import Foundation

/// A small injectable seam around the system route and ARP tools. Tests can
/// provide a fixed value without invoking a shell or any Wi-Fi API.
public protocol GatewayMACProviding: Sendable {
    func currentGatewayMAC() -> String?
}

public struct SystemGatewayMACProvider: GatewayMACProviding, Sendable {
    public static let maximumCommandOutputBytes = 64 * 1024

    public init() {}

    public func currentGatewayMAC() -> String? {
        guard let route = run(
            executable: "/sbin/route",
            arguments: ["-n", "get", "-inet", "default"]
        ), let gateway = gatewayAddress(in: route) else {
            return nil
        }
        guard let arp = run(
            executable: "/usr/sbin/arp",
            arguments: ["-n", gateway]
        ) else {
            return nil
        }
        return arp.split(whereSeparator: { $0.isWhitespace || $0 == "(" || $0 == ")" })
            .prefix(512)
            .compactMap { GatewayMAC.normalized(String($0)) }
            .first
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

    private func run(executable: String, arguments: [String]) -> String? {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: executable)
        task.arguments = arguments
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = Pipe()
        do {
            try task.run()
            task.waitUntilExit()
            guard task.terminationStatus == 0 else { return nil }
            let data = pipe.fileHandleForReading.readData(ofLength: Self.maximumCommandOutputBytes + 1)
            guard data.count <= Self.maximumCommandOutputBytes else { return nil }
            return String(data: data, encoding: .utf8)
        } catch {
            return nil
        }
    }
}

/// Polls the default gateway without ever binding a profile that the user has
/// not explicitly associated with that gateway MAC. The watcher reports only
/// a changed canonical MAC; policy selection belongs to ProfileCoordinator.
public final class GatewayMACWatcher: @unchecked Sendable {
    public typealias ChangeHandler = (String?) -> Void

    private let provider: GatewayMACProviding
    private let queue: DispatchQueue
    private let lock = NSLock()
    private var timer: DispatchSourceTimer?
    private var lastMAC: String?
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

    /// Reads and normalizes the gateway MAC once. Returns the value whether or
    /// not it changed, which makes an explicit UI refresh easy to test.
    @discardableResult
    public func refresh() -> String? {
        let current = provider.currentGatewayMAC().flatMap(GatewayMAC.normalized)
        let callback: ChangeHandler?
        lock.lock()
        let changed = current != lastMAC
        if changed { lastMAC = current }
        callback = changed ? handler : nil
        lock.unlock()
        if changed { callback?(current) }
        return current
    }
}
