import Foundation
import Darwin

final class NetMonitor: @unchecked Sendable {
    private var lsofTimer: DispatchSourceTimer?
    private var trafficTimer: DispatchSourceTimer?
    private var nettopProc: Process?
    private var nettopInput: Pipe?
    private var nettopOutput: FileHandle?
    /// Bumped on every start and stop, so output from a nettop that has
    /// already been replaced is dropped instead of landing in the new frame.
    private var nettopGeneration = 0
    private var bundleIDs: [String: String?] = [:]
    private let queue = DispatchQueue(label: "io.isaaclins.freesnitch.netmon", qos: .utility)

    var onConnections: (([Connection]) -> Void)?
    var onSample: ((TrafficSample) -> Void)?
    var onProcessUsage: (([ProcessUsage]) -> Void)?

    private var lastInterfaceTotals: [String: InterfaceTotals] = [:]
    private var lastTrafficUptime: TimeInterval = 0
    private var pending = ""
    private var frame: [String] = []
    private(set) var isRunning = false

    /// Start and stop arrive on XPC threads while nettop output is parsed on
    /// `queue`; running both there keeps the frame state single-threaded.
    func start() {
        queue.sync {
            stopLocked()   // idempotent: tear down any existing pollers before (re)starting
            startLsofPolling()
            startTrafficSampling()
            startNettop()
            isRunning = true
        }
    }

    func stop() {
        queue.sync { stopLocked() }
    }

    private func stopLocked() {
        lsofTimer?.cancel(); lsofTimer = nil
        trafficTimer?.cancel(); trafficTimer = nil
        lastInterfaceTotals = [:]
        nettopGeneration += 1
        nettopOutput?.readabilityHandler = nil; nettopOutput = nil
        nettopProc?.terminate(); nettopProc = nil
        nettopInput = nil
        pending = ""; frame = []
        isRunning = false
    }

    private func startLsofPolling() {
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + 1.0, repeating: .seconds(2))
        t.setEventHandler { [weak self] in self?.pollLsof() }
        t.resume()
        lsofTimer = t
    }

    private func pollLsof() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        p.arguments = ["-i", "-n", "-P", "-F", "pcnT"]
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = Pipe()
        do { try p.run() } catch { return }
        // Drain the pipe BEFORE waiting. `lsof -i` on a busy Mac easily exceeds
        // the 64 KB pipe buffer, and waiting first deadlocks the monitor queue
        // permanently: lsof blocks writing, we block waiting, and the
        // connection list never updates again.
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        guard let txt = String(data: data, encoding: .utf8) else { return }

        var conns: [Connection] = []
        var pid: Int32 = 0
        var pname = ""
        for line in txt.split(separator: "\n") {
            guard let first = line.first else { continue }
            let rest = String(line.dropFirst())
            switch first {
            case "p":
                pid = Int32(rest) ?? 0
            case "c":
                pname = rest
            case "n":
                if let c = parseN(line: rest, pid: pid, name: pname) { conns.append(c) }
            default: break
            }
        }
        onConnections?(conns)
    }

    private func parseN(line: String, pid: Int32, name: String) -> Connection? {
        guard line.contains("->") else { return nil }
        let parts = line.split(separator: " ").map(String.init)
        let addrPart = parts.first ?? line
        let halves = addrPart.split(separator: "-", maxSplits: 1).map(String.init)
        guard halves.count == 2 else { return nil }
        let local = halves[0]
        let remoteRaw = halves[1].hasPrefix(">") ? String(halves[1].dropFirst()) : halves[1]
        guard let (lip, lport) = splitHostPort(local) else { return nil }
        guard let (rip, rport) = splitHostPort(remoteRaw) else { return nil }
        _ = lip
        let path = pidPath(pid)
        let bundle = bundleID(forPath: path)
        return Connection(
            pid: pid,
            processName: name,
            processPath: path,
            processBundleId: bundle,
            localPort: lport,
            remoteHost: rip,
            remoteIP: rip,
            remotePort: rport,
            direction: .outgoing,
            status: .established,
            protocolName: "tcp"
        )
    }

    private func splitHostPort(_ s: String) -> (String, Int)? {
        if s.hasPrefix("[") {
            guard let close = s.firstIndex(of: "]") else { return nil }
            let host = String(s[s.index(after: s.startIndex)..<close])
            let after = s.index(after: close)
            guard after < s.endIndex, s[after] == ":" else { return nil }
            let port = Int(s[s.index(after: after)...]) ?? 0
            return (host, port)
        }
        guard let lastColon = s.lastIndex(of: ":") else { return nil }
        let host = String(s[s.startIndex..<lastColon])
        let portStr = s[s.index(after: lastColon)...]
        return (host, Int(portStr) ?? 0)
    }

    /// One syscall instead of spawning `ps` for every connection on every
    /// poll, which on a busy Mac was hundreds of processes every two seconds.
    private func pidPath(_ pid: Int32) -> String {
        guard pid > 0 else { return "" }
        var buf = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        guard proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 else { return "" }
        return String(cString: buf)
    }

    private func bundleID(forPath path: String) -> String? {
        guard !path.isEmpty else { return nil }
        if let cached = bundleIDs[path] { return cached }
        if bundleIDs.count > 1024 { bundleIDs.removeAll() }
        let found = readBundleID(forPath: path)
        bundleIDs[path] = found
        return found
    }

    private func readBundleID(forPath path: String) -> String? {
        var p = path
        if let r = p.range(of: ".app/", options: .backwards) { p = String(p[..<r.upperBound]) }
        let plist = (p as NSString).appendingPathComponent("Contents/Info.plist")
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: plist)) else { return nil }
        guard let d = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { return nil }
        return d["CFBundleIdentifier"] as? String
    }

    private func startNettop() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/nettop")
        p.arguments = ["-P", "-x", "-L", "0", "-J", "bytes_in,bytes_out", "-s", "1"]
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = Pipe()
        // nettop watches its standard input, and at end of file that watch
        // fires without pause: launchd gives the helper /dev/null, so nettop
        // spun at over 100% CPU on an idle Mac (#142, #144). A pipe that stays
        // open and never carries data keeps it asleep between samples.
        let input = Pipe(); p.standardInput = input
        do { try p.run() } catch { PSLog.error(PSLog.netmon, "nettop failed: \(error)"); return }
        nettopProc = p
        nettopInput = input
        nettopOutput = pipe.fileHandleForReading
        pending = ""; frame = []
        let generation = nettopGeneration

        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            // At end of file the handler keeps firing with empty reads,
            // millions of times a second, until it is removed. Every nettop
            // that stopped or was replaced left the helper spinning (#144).
            if data.isEmpty { handle.readabilityHandler = nil; return }
            guard let s = String(data: data, encoding: .utf8) else { return }
            self?.queue.async { [weak self] in
                guard let self, self.nettopGeneration == generation else { return }
                self.ingestNettop(s)
            }
        }
    }

    /// nettop writes one *frame* per interval: a `,bytes_in,bytes_out,` header
    /// followed by one cumulative line per process. A pipe read is not a frame -
    /// it can split mid-line or carry half a frame - so reading whatever arrived
    /// as a frame produced nonsense (multi-GB/s spikes). Buffer, cut on the
    /// header, and only report whole frames.
    private func ingestNettop(_ chunk: String) {
        pending += chunk
        while let nl = pending.firstIndex(of: "\n") {
            let line = String(pending[pending.startIndex..<nl])
            pending = String(pending[pending.index(after: nl)...])
            if line.hasPrefix(",bytes_in") {
                if !frame.isEmpty { completeFrame(frame) }
                frame = []
            } else if !line.isEmpty {
                frame.append(line)
            }
        }
    }

    private func completeFrame(_ lines: [String]) {
        var usages: [ProcessUsage] = []
        for line in lines {
            let parts = line.split(separator: ",")
            guard parts.count >= 3,
                  let bin = Int64(parts[parts.count - 2]),
                  let bout = Int64(parts[parts.count - 1]) else { continue }

            let identifier = String(parts[0])
            let separator = identifier.lastIndex(of: ".")
            let processName: String
            let pid: Int32?
            if let separator,
               let parsedPID = Int32(String(identifier[identifier.index(after: separator)...])) {
                processName = String(identifier[..<separator])
                pid = parsedPID
            } else {
                processName = identifier
                pid = nil
            }
            usages.append(ProcessUsage(processName: processName, pid: pid, bytesIn: bin, bytesOut: bout))
        }
        onProcessUsage?(usages)
    }

    /// The live speed comes from the interface counters, once a second.
    /// nettop block-buffers into a pipe, so its frames arrive in bursts of
    /// about eleven every eleven seconds; a rate taken from their arrival
    /// times updated the menu bar every ten seconds or more (#156).
    private func startTrafficSampling() {
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now(), repeating: .seconds(1), leeway: .milliseconds(100))
        t.setEventHandler { [weak self] in self?.sampleTraffic() }
        t.resume()
        trafficTimer = t
    }

    private func sampleTraffic() {
        let now = ProcessInfo.processInfo.systemUptime
        let totals = NetMonitor.interfaceTotals()
        let previous = lastInterfaceTotals
        let dt = now - lastTrafficUptime
        lastInterfaceTotals = totals
        lastTrafficUptime = now
        // The first reading is only a baseline: the counters run since boot.
        guard !previous.isEmpty, dt > 0 else { return }
        let (deltaIn, deltaOut) = NetMonitor.delta(from: previous, to: totals)
        onSample?(TrafficSample(timestamp: Date(),
                                bytesIn: Int64(Double(deltaIn) / dt),
                                bytesOut: Int64(Double(deltaOut) / dt)))
    }

    struct InterfaceTotals: Equatable {
        var bytesIn: UInt64
        var bytesOut: UInt64
    }

    /// Bytes moved since the previous reading, summed over the interfaces in
    /// both. An interface that appeared, vanished or was reset (its counter
    /// went down) contributes nothing for this second rather than a negative
    /// or since-boot jump.
    static func delta(from previous: [String: InterfaceTotals],
                      to current: [String: InterfaceTotals]) -> (UInt64, UInt64) {
        var bytesIn: UInt64 = 0
        var bytesOut: UInt64 = 0
        for (name, now) in current {
            guard let before = previous[name] else { continue }
            if now.bytesIn >= before.bytesIn { bytesIn &+= now.bytesIn - before.bytesIn }
            if now.bytesOut >= before.bytesOut { bytesOut &+= now.bytesOut - before.bytesOut }
        }
        return (bytesIn, bytesOut)
    }

    /// 64-bit byte counters of the Ethernet-like interfaces (Wi-Fi, Ethernet,
    /// USB tethering, cellular). Loopback, tunnels and bridges are left out
    /// because their traffic is also counted on the interface it really
    /// leaves by, and a VPN would otherwise count every byte twice.
    /// `getifaddrs` would be simpler, but its counters are 32-bit and wrap
    /// after 4 GB.
    static func interfaceTotals() -> [String: InterfaceTotals] {
        var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, 0]
        var length = 0
        guard sysctl(&mib, UInt32(mib.count), nil, &length, nil, 0) == 0, length > 0 else { return [:] }
        var buffer = [UInt8](repeating: 0, count: length)
        guard sysctl(&mib, UInt32(mib.count), &buffer, &length, nil, 0) == 0 else { return [:] }

        var totals: [String: InterfaceTotals] = [:]
        buffer.withUnsafeBytes { raw in
            var offset = 0
            while offset + MemoryLayout<if_msghdr>.size <= length {
                let header = raw.loadUnaligned(fromByteOffset: offset, as: if_msghdr.self)
                let messageLength = Int(header.ifm_msglen)
                guard messageLength > 0 else { break }
                defer { offset += messageLength }
                guard Int32(header.ifm_type) == RTM_IFINFO2,
                      offset + MemoryLayout<if_msghdr2>.size <= length else { continue }
                let info = raw.loadUnaligned(fromByteOffset: offset, as: if_msghdr2.self)
                guard info.ifm_flags & IFF_LOOPBACK == 0,
                      [IFT_ETHER, IFT_CELLULAR].contains(Int32(info.ifm_data.ifi_type)) else { continue }
                var nameBuffer = [CChar](repeating: 0, count: Int(IF_NAMESIZE))
                guard if_indextoname(UInt32(info.ifm_index), &nameBuffer) != nil else { continue }
                let name = String(cString: nameBuffer)
                // Virtual machines' interfaces carry traffic that leaves again
                // through the Mac's own interface.
                guard !name.hasPrefix("vmenet") else { continue }
                totals[name] = InterfaceTotals(bytesIn: info.ifm_data.ifi_ibytes,
                                               bytesOut: info.ifm_data.ifi_obytes)
            }
        }
        return totals
    }
}
