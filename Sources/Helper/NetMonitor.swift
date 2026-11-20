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
    /// Signed bundle id per process (pid and its executable path), so a
    /// binary swapped in at a path never inherits an earlier process's id.
    private var bundleIDs: [Int32: (path: String, id: CodeSigningIdentity.SignedBundle?)] = [:]
    /// Processes whose signature could not be read, and when to try again, so
    /// an app updated on disk while it runs is not checked on every poll.
    private var bundleIDRetry: [Int32: (path: String, after: Date)] = [:]
    private let queue = DispatchQueue(label: "io.isaaclins.freesnitch.netmon", qos: .utility)

    var onConnections: (([Connection]) -> Void)?
    var onSample: ((TrafficSample) -> Void)?
    var onProcessUsage: (([ProcessUsage]) -> Void)?

    private var lastInterfaceTotals: [String: InterfaceTotals] = [:]
    private var lastTrafficUptime: TimeInterval = 0
    private var pending = ""
    private var frame: [String] = []
    /// Bytes per open socket from the latest nettop frame. lsof lists the
    /// connections but carries no byte counts, so without these every
    /// destination, country and app row in the Monitor read 0 bytes (#466).
    private var socketBytes: [SocketKey: SocketBytes] = [:]
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
        socketBytes = [:]
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
        // A socket shared by two descriptors is listed once per descriptor;
        // counting it twice would double its bytes in every sum.
        var seen = Set<String>()
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
                if var c = parseN(line: rest, pid: pid, name: pname),
                   seen.insert("\(pid) \(c.localPort) \(c.remoteIP) \(c.remotePort)").inserted {
                    if let bytes = socketBytes[SocketKey(pid: pid, localPort: c.localPort, remotePort: c.remotePort)] {
                        c.bytesIn = bytes.bytesIn
                        c.bytesOut = bytes.bytesOut
                    }
                    conns.append(c)
                }
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
        let bundle = bundleID(forPath: path, pid: pid)
        return Connection(
            pid: pid,
            processName: name,
            processPath: path,
            processBundleId: bundle?.identifier,
            processTeamId: bundle?.team,
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

    /// The bundle id from the process's valid, Apple-issued code signature,
    /// never from its unsigned Info.plist (#351, see `CodeSigningIdentity`).
    /// It is checked for the running process and cached per process; a
    /// lookup that could not read any signature is not cached, so the next
    /// poll tries again.
    private func bundleID(forPath path: String, pid: Int32) -> CodeSigningIdentity.SignedBundle? {
        guard !path.isEmpty, pid > 0 else { return nil }
        if let cached = bundleIDs[pid], cached.path == path { return cached.id }
        if let retry = bundleIDRetry[pid], retry.path == path, retry.after > Date() { return nil }
        if bundleIDs.count > 1024 { bundleIDs.removeAll() }
        if bundleIDRetry.count > 1024 { bundleIDRetry.removeAll() }
        switch CodeSigningIdentity.resolve(executablePath: path, auditToken: nil, pid: pid, fileFallback: false) {
        case .unavailable:
            bundleIDRetry[pid] = (path, Date().addingTimeInterval(60))
            return nil
        case .noBundle:
            bundleIDs[pid] = (path, nil)
            return nil
        case .resolved(let signed):
            bundleIDs[pid] = (path, signed)
            return signed
        }
    }

    private func startNettop() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/nettop")
        // Per socket, not per process (`-P`): the socket lines are what give
        // each connection its bytes (#466). `-n` keeps addresses numeric, as
        // lsof writes them.
        p.arguments = ["-x", "-n", "-L", "0", "-J", "bytes_in,bytes_out", "-s", "1"]
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
        let parsed = NetMonitor.parseFrame(lines)
        socketBytes = parsed.sockets
        onProcessUsage?(parsed.usages)
    }

    /// One open socket, as both nettop and lsof can name it. The remote
    /// address is left out on purpose: the two tools write link-local IPv6
    /// addresses differently (`fe80::1%en1` against `fe80:f::1`), and a
    /// process never has two connected sockets on the same local port to the
    /// same remote port at once.
    struct SocketKey: Hashable {
        let pid: Int32
        let localPort: Int
        let remotePort: Int
    }

    struct SocketBytes: Equatable {
        var bytesIn: Int64
        var bytesOut: Int64
    }

    /// Reads one nettop frame: a cumulative `name.pid,in,out,` line per
    /// process, each followed by a `proto local<->remote,in,out,` line per
    /// socket of that process. Listening sockets and sockets without counts
    /// are skipped.
    static func parseFrame(_ lines: [String]) -> (usages: [ProcessUsage], sockets: [SocketKey: SocketBytes]) {
        var usages: [ProcessUsage] = []
        var sockets: [SocketKey: SocketBytes] = [:]
        var currentPID: Int32?
        for line in lines {
            let parts = line.split(separator: ",", omittingEmptySubsequences: false)
            guard parts.count >= 3 else { continue }
            let identifier = String(parts[0])
            let bin = Int64(parts[1])
            let bout = Int64(parts[2])

            if let arrow = identifier.range(of: "<->") {
                guard let pid = currentPID, let bin, let bout,
                      let space = identifier[..<arrow.lowerBound].firstIndex(of: " "),
                      let localPort = port(of: identifier[identifier.index(after: space)..<arrow.lowerBound]),
                      let remotePort = port(of: identifier[arrow.upperBound...]),
                      localPort > 0, remotePort > 0 else { continue }
                let key = SocketKey(pid: pid, localPort: localPort, remotePort: remotePort)
                var total = sockets[key] ?? SocketBytes(bytesIn: 0, bytesOut: 0)
                total.bytesIn &+= bin
                total.bytesOut &+= bout
                sockets[key] = total
                continue
            }

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
            currentPID = pid
            guard let bin, let bout else { continue }
            usages.append(ProcessUsage(processName: processName, pid: pid, bytesIn: bin, bytesOut: bout))
        }
        return (usages, sockets)
    }

    /// The port at the end of a nettop endpoint: `1.2.3.4:443` for IPv4,
    /// `fe80::1%en1.443` for IPv6. `*` (no port) gives nil.
    private static func port(of endpoint: Substring) -> Int? {
        let colon = endpoint.lastIndex(of: ":")
        let dot = endpoint.lastIndex(of: ".")
        guard let cut = [colon, dot].compactMap({ $0 }).max() else { return nil }
        return Int(endpoint[endpoint.index(after: cut)...])
    }

    /// The live speed comes from the interface counters, once a second.
    /// nettop block-buffers into a pipe, so its frames arrive in bursts of
    /// about eleven every eleven seconds; a rate taken from their arrival
    /// times updated the menu bar every ten seconds or more (#156).
    private func startTrafficSampling() {
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now(), repeating: NetMonitor.trafficSampleInterval, leeway: .milliseconds(100))
        t.setEventHandler { [weak self] in self?.sampleTraffic() }
        t.resume()
        trafficTimer = t
    }

    /// How often the live speed is sampled (#156).
    static let trafficSampleInterval: DispatchTimeInterval = .seconds(1)

    private func sampleTraffic() {
        recordTraffic(NetMonitor.interfaceTotals(), at: ProcessInfo.processInfo.systemUptime)
    }

    /// One tick of the live speed: the rate since the previous reading, from
    /// the uptime the reading was taken at, so a tick that fires late on a
    /// busy Mac still reports bytes per second. Runs on `queue`; the time is a
    /// parameter so a test can drive it without waiting on a real clock.
    func recordTraffic(_ totals: [String: InterfaceTotals], at now: TimeInterval) {
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

    /// Byte counters of the interfaces traffic really leaves the Mac by:
    /// Ethernet-like ones (Wi-Fi, Ethernet, USB tethering) and cellular.
    /// Loopback, tunnels and bridges are left out, because their traffic is
    /// also counted on the interface it leaves by, and a VPN would otherwise
    /// count every byte twice. So are AirDrop, Sidecar, Internet Sharing and
    /// virtual machine interfaces, which are Ethernet-like but carry traffic
    /// that is local or counted again on the real interface.
    ///
    /// The per-interface MIB is read because it is exact and 64-bit for any
    /// user. `getifaddrs` and `NET_RT_IFLIST2` return counters truncated to
    /// 32 bits and rounded, which wrap every half minute at 1 Gbit/s.
    static func interfaceTotals() -> [String: InterfaceTotals] {
        guard let list = if_nameindex() else { return [:] }
        defer { if_freenameindex(list) }
        var totals: [String: InterfaceTotals] = [:]
        var entry = list
        while entry.pointee.if_index != 0, let rawName = entry.pointee.if_name {
            defer { entry += 1 }
            let name = String(cString: rawName)
            guard !excludedInterfacePrefixes.contains(where: { name.hasPrefix($0) }) else { continue }
            var mib: [Int32] = [CTL_NET, PF_LINK, NETLINK_GENERIC, IFMIB_IFDATA,
                                Int32(entry.pointee.if_index), IFDATA_GENERAL]
            var data = ifmibdata()
            var length = MemoryLayout<ifmibdata>.size
            guard sysctl(&mib, UInt32(mib.count), &data, &length, nil, 0) == 0,
                  data.ifmd_flags & UInt32(IFF_LOOPBACK) == 0,
                  [IFT_ETHER, IFT_CELLULAR].contains(Int32(data.ifmd_data.ifi_type)) else { continue }
            totals[name] = InterfaceTotals(bytesIn: data.ifmd_data.ifi_ibytes,
                                           bytesOut: data.ifmd_data.ifi_obytes)
        }
        return totals
    }

    /// AirDrop and peer-to-peer Wi-Fi (awdl, llw, nan), Internet Sharing's
    /// access point (ap), the Mac's internal links (anpi) and virtual
    /// machines (vmenet).
    private static let excludedInterfacePrefixes = ["awdl", "llw", "nan", "ap", "anpi", "vmenet"]
}
