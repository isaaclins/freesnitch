import Foundation

final class PFManager: @unchecked Sendable {
    // Keep the established anchor name so a rename cannot strand active firewall rules.
    static let anchorName = "puresnitch"
    private let anchorPath = "/etc/pf.anchors/puresnitch"
    private let pfctl = "/sbin/pfctl"
    private let queue = DispatchQueue(label: "io.isaaclins.freesnitch.pf")
    private var loaded = false

    /// The pf table the address feeds are rendered into. It is a table rather
    /// than one rule per entry, so a feed of a hundred thousand networks stays
    /// one pf object instead of a hundred thousand rules.
    static let ipBlocklistTable = "freesnitch_ipblock"

    private let stateLock = NSLock()
    private var ipBlocklist: IPBlocklistSet = .empty
    private var resolverAddresses: [String] = []
    private var lastRules: [Rule] = []

    /// Serializes every write and load of the anchor, so the expiry timer can
    /// never load an older rule set over a newer one.
    private let applyLock = NSLock()
    /// Fires when the next temporary rule runs out. Guarded by `applyLock`.
    private var expiryTimer: DispatchSourceTimer?

    /// Invalid rules are omitted from the anchor, but their rejection is sent
    /// to the helper event stream so the GUI can show it to the user.
    var onWarning: ((String) -> Void)?

    func install() throws {
        applyLock.lock()
        defer { applyLock.unlock() }
        try ensureMainPFConfReferencesAnchor()
        try run(pfctl, ["-E"]) // enable pf
        // Use the same fail-open load path as later rule/feed updates. If a
        // feed table is rejected, the user's anchor still gets loaded without
        // the feed rather than leaving enforcement in a half-applied state.
        try writeAndLoad(rules: [])
        loaded = true
    }

    func uninstall() throws {
        applyLock.lock()
        defer { applyLock.unlock() }
        expiryTimer?.cancel()
        expiryTimer = nil
        _ = try? run(pfctl, ["-a", PFManager.anchorName, "-F", "all"])
        _ = try? run(pfctl, ["-a", PFManager.anchorName, "-f", "/dev/null"])
        loaded = false
    }

    var isLoaded: Bool { loaded }

    func applyRules(_ rules: [Rule]) throws {
        applyLock.lock()
        defer { applyLock.unlock() }
        stateLock.lock()
        lastRules = rules
        stateLock.unlock()
        try writeAndLoad(rules: rules)
    }

    /// Publishes an address feed set into the anchor.
    ///
    /// Rendering is skipped entirely while the anchor is not loaded, for the
    /// same reason rules are: enforcement is off, so the feed is blocking
    /// nothing and must not say otherwise.
    func setIPBlocklist(_ set: IPBlocklistSet, resolverAddresses: [String] = []) throws {
        applyLock.lock()
        defer { applyLock.unlock() }
        stateLock.lock()
        ipBlocklist = set
        self.resolverAddresses = resolverAddresses
        let rules = lastRules
        stateLock.unlock()
        guard loaded else { return }
        try writeAndLoad(rules: rules)
    }

    /// Writes the anchor and loads it. If the load fails with the address feed
    /// present, the anchor is rewritten without it and loaded again: a feed
    /// must never be able to leave the machine with no anchor at all, and a
    /// firewall that drops the feed is strictly safer than one that drops the
    /// user's own rules.
    private func writeAndLoad(rules: [Rule]) throws {
        scheduleExpiryRender(for: rules)
        try writeAnchorFile(rules: rules, includeIPBlocklist: true)
        do {
            try loadAnchor()
        } catch {
            stateLock.lock()
            let hadBlocklist = !ipBlocklist.isEmpty
            stateLock.unlock()
            guard hadBlocklist else { throw error }
            onWarning?(
                "PF rejected the anchor while the IP blocklist table was present; "
                    + "reloading without it so the firewall keeps its own rules: \(error.localizedDescription)"
            )
            PSLog.error(PSLog.pf, "pf anchor load failed with the IP blocklist table; retrying without it")
            try writeAnchorFile(rules: rules, includeIPBlocklist: false)
            try loadAnchor()
        }
    }

    /// The matcher and the DNS proxy stop applying a temporary rule the moment
    /// it expires, but pf only changes when the anchor is rendered again, so a
    /// "deny for 1 hour" kept blocking until the next rule change (issue #180).
    /// One timer for the earliest expiry re-renders the anchor then, and that
    /// render schedules the next one. It runs on the wall clock, so a Mac that
    /// slept through the expiry re-renders as soon as it wakes.
    private func scheduleExpiryRender(for rules: [Rule], now: Date = Date()) {
        scheduleRender(at: PFManager.nextExpiry(of: rules, after: now), now: now)
    }

    private func scheduleRender(at deadline: Date?, now: Date = Date()) {
        expiryTimer?.cancel()
        expiryTimer = nil
        guard let deadline else { return }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(wallDeadline: .now() + max(0, deadline.timeIntervalSince(now)), leeway: .seconds(1))
        timer.setEventHandler { [weak self] in self?.renderAfterExpiry() }
        timer.resume()
        expiryTimer = timer
    }

    /// The earliest moment a rule the anchor carries runs out. Rules pf never
    /// carries, such as an app's temporary deny, need no render.
    static func nextExpiry(of rules: [Rule], after now: Date) -> Date? {
        rules
            .filter { $0.enabled && !hasExpired($0, at: now) && reachesPF($0) }
            .compactMap(\.expiresAt)
            .min()
    }

    /// A failed reload is tried again after this long, so one pfctl hiccup
    /// cannot leave an expired rule in pf until some unrelated change.
    static let expiryRetryInterval: TimeInterval = 30

    private func renderAfterExpiry() {
        applyLock.lock()
        defer { applyLock.unlock() }
        guard loaded else { return }
        stateLock.lock()
        let rules = lastRules
        stateLock.unlock()
        do {
            try writeAndLoad(rules: rules)
        } catch {
            onWarning?("PF could not drop an expired temporary rule from the anchor, trying again in "
                + "\(Int(PFManager.expiryRetryInterval)) seconds: \(error.localizedDescription)")
            let now = Date()
            let retry = now.addingTimeInterval(PFManager.expiryRetryInterval)
            scheduleRender(at: min(retry, PFManager.nextExpiry(of: rules, after: now) ?? retry), now: now)
        }
    }

    private func loadAnchor() throws {
        try run(pfctl, ["-a", PFManager.anchorName, "-f", anchorPath])
    }

    private func writeAnchorFile(rules: [Rule], includeIPBlocklist: Bool) throws {
        stateLock.lock()
        let set = includeIPBlocklist ? ipBlocklist : .empty
        let resolvers = resolverAddresses
        stateLock.unlock()
        let content = renderAnchor(
            rules: rules,
            ipBlocklist: set,
            resolverAddresses: resolvers
        ) { [weak self] rule, reason in
            self?.reportRejected(rule: rule, reason: reason)
        }
        try content.write(toFile: anchorPath, atomically: true, encoding: .utf8)
    }

    /// Render a complete anchor without touching the filesystem. Keeping this
    /// separate from the privileged write makes the safety checks directly
    /// exercisable and guarantees that every emitted destination was checked.
    func renderAnchor(
        rules: [Rule],
        ipBlocklist: IPBlocklistSet = .empty,
        resolverAddresses: [String] = [],
        now: Date = Date(),
        onRejected: ((Rule, String) -> Void)? = nil
    ) -> String {
        var lines: [String] = []
        lines.append("# FreeSnitch pf anchor - auto-generated. Do not edit.")
        lines.append("# Hostname rules are intentionally not emitted to pf.")
        lines.append("# The Network Extension filter evaluates them when active, avoiding pf's one-time DNS resolution.")
        lines.append("# If that filter is inactive, hostname rules are not enforced by this anchor.")
        lines.append("# Deny rules that name an app are not emitted either: pf cannot tell processes apart,")
        lines.append("# so an app's address or port deny would block every app on the Mac.")
        lines.append("# Allow and ask rules are emitted even when they name an app, so the address feeds below,")
        lines.append("# which only this anchor enforces, never block what the user allowed.")
        lines.append("# Rules are written in priority order, the order the Network Extension consults them.")
        lines.append("set block-policy drop")
        lines.append("set skip on lo0")

        // Every line is quick, so pf stops at the first line that matches, as
        // the matcher stops at the first rule in its order. Writing every deny
        // before every allow let a lower-priority deny override a
        // higher-priority allow (issue #181), so the lines follow the
        // matcher's own order: priority first, then the snapshot's order.
        let liveRules = PreparedRuleSet(rules: rules).ordered.filter { !PFManager.hasExpired($0, at: now) }
        let renderedRules = liveRules.filter { PFManager.reachesPF($0) }

        for rule in renderedRules {
            let verb = rule.action == .deny ? "block" : "pass"
            if let line = pfLine(rule: rule, verb: verb, onRejected: onRejected) {
                lines.append(line)
            }
        }

        lines.append(contentsOf: ipBlocklistLines(ipBlocklist, resolverAddresses: resolverAddresses))

        return lines.joined(separator: "\n") + "\n"
    }

    /// pf matches packets, not processes, so a block line rendered from an
    /// app's deny rule blocked that destination for every app (issue #155).
    /// Those rules belong to the Network Extension, which sees the process.
    /// An app's allow rule is still rendered: dropping it would let an
    /// address feed block what the user allowed, and a pass line can only
    /// block less. The test is the matcher's own, so pf and the extension
    /// agree on which rules apply to every app: a bundle id or path that is
    /// not empty. A name alone identifies nothing (#157).
    static func namesAnApp(_ rule: Rule) -> Bool {
        !(rule.processBundleId ?? "").isEmpty || !(rule.processPath ?? "").isEmpty
    }

    /// Which rules the anchor renders at all: every allow, and the denies that
    /// do not name an app (issue #155). An ask rule is rendered as a pass: the
    /// matcher stops at it and the extension asks, and allows when nobody can
    /// answer, so a lower-priority deny behind it must not block in pf.
    static func reachesPF(_ rule: Rule) -> Bool {
        switch rule.action {
        case .allow, .ask: return true
        case .deny: return !namesAnApp(rule)
        }
    }

    /// The matcher's own test: a rule still applies at the instant it expires.
    static func hasExpired(_ rule: Rule, at now: Date) -> Bool {
        guard let expiresAt = rule.expiresAt else { return false }
        return expiresAt < now
    }

    /// The address feed section (issue #51).
    ///
    /// It is emitted last on purpose. Every rule in this anchor is `quick`, so
    /// the user's own rules, including their allow rules, are consulted first
    /// and a feed can never override a decision the user made. The passes that
    /// precede the block are the bypasses that no feed may cross: DNS, DHCP,
    /// and the configured resolvers. Loopback is already covered by the
    /// `set skip on lo0` at the top of the anchor.
    private func ipBlocklistLines(_ set: IPBlocklistSet, resolverAddresses: [String]) -> [String] {
        let entries = set.pfTableEntries()
        guard !entries.isEmpty else { return [] }

        var lines: [String] = []
        lines.append("# IP and CIDR blocklist feeds. Addresses only; domain blocklists are DNS-layer and are not here.")
        if entries.count < set.acceptedEntryCount {
            lines.append("# Truncated to \(entries.count) of \(set.acceptedEntryCount) entries by the anchor size bound.")
        }
        lines.append("pass out quick proto { tcp udp } to any port 53")
        lines.append("pass out quick proto { tcp udp } to any port { 67 68 }")
        lines.append("pass out quick proto { tcp udp } to any port { 546 547 }")
        for resolver in resolverAddresses {
            // A resolver address arrives from system configuration, so it is
            // validated exactly like any other destination before it can
            // become a pf token.
            guard let kind = PFHostValidator.kind(for: resolver), kind != .hostname else { continue }
            lines.append("pass out quick to \(resolver)")
        }
        lines.append("table <\(PFManager.ipBlocklistTable)> persist { \(entries.joined(separator: ", ")) }")
        lines.append("block out quick proto { tcp udp } to <\(PFManager.ipBlocklistTable)>")
        return lines
    }

    private func pfLine(
        rule r: Rule,
        verb: String,
        onRejected: ((Rule, String) -> Void)?
    ) -> String? {
        func reject(_ reason: String) -> String? {
            onRejected?(r, reason)
            return nil
        }

        var destination: String?
        if let rawIP = r.remoteIP, !rawIP.isEmpty {
            guard let kind = PFHostValidator.kind(for: rawIP) else {
                return reject("invalid remoteIP '\(rawIP)': \(PFHostValidator.rejectionReason(for: rawIP))")
            }
            guard kind != .hostname else {
                return reject("hostname destination '\(rawIP)' is enforced by the Network Extension filter layer when active and is not emitted to PF")
            }
            destination = rawIP
        } else if let rawHost = r.remoteHost, !rawHost.isEmpty {
            guard let kind = PFHostValidator.kind(for: rawHost) else {
                return reject("invalid remoteHost '\(rawHost)': \(PFHostValidator.rejectionReason(for: rawHost))")
            }
            guard kind != .hostname else {
                return reject("hostname destination '\(rawHost)' is enforced by the Network Extension filter layer when active and is not emitted to PF")
            }
            destination = rawHost
        }

        var port: Int?
        if let rawPort = r.remotePort, rawPort != 0 {
            guard (1...65535).contains(rawPort) else {
                return reject("invalid destination port \(rawPort); expected 1 through 65535")
            }
            port = rawPort
        }

        guard destination != nil || port != nil else {
            return reject("rule has no valid destination or destination port")
        }

        if verb == "block" {
            if let destination,
               let reason = PFHostValidator.protectedDestinationReason(for: destination) {
                return reject("blocking \(destination) is unsafe: \(reason)")
            }
            if let port {
                if port == 53 {
                    return reject("blocking destination port 53 could disable DNS")
                }
                if port == 67 || port == 68 {
                    return reject("blocking destination port \(port) could disable DHCP")
                }
            }
        }

        var line = verb
        if r.direction != .any {
            line += r.direction == .incoming ? " in" : " out"
        }
        line += " quick proto { tcp udp }"
        if let destination { line += " to \(destination)" }
        if let port { line += " port \(port)" }
        return line
    }

    private func reportRejected(rule: Rule, reason: String) {
        let message = "Skipped PF rule \(rule.id.uuidString) from anchor \(PFManager.anchorName): \(reason)"
        PSLog.error(PSLog.pf, message)
        onWarning?(message)
    }

    private func ensureMainPFConfReferencesAnchor() throws {
        let path = "/etc/pf.conf"
        guard let original = try? String(contentsOfFile: path, encoding: .utf8) else { return }
        if original.contains("anchor \"puresnitch\"") { return }
        var lines = original.components(separatedBy: "\n")
        if !lines.contains(where: { $0.contains("anchor \"puresnitch\"") }) {
            lines.append("anchor \"puresnitch\"")
            lines.append("load anchor \"puresnitch\" from \"/etc/pf.anchors/puresnitch\"")
        }
        let backup = path + ".puresnitch.bak"
        if !FileManager.default.fileExists(atPath: backup) {
            try? original.write(toFile: backup, atomically: true, encoding: .utf8)
        }
        try lines.joined(separator: "\n").write(toFile: path, atomically: true, encoding: .utf8)
    }

    @discardableResult
    private func run(_ exec: String, _ args: [String]) throws -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: exec)
        p.arguments = args
        let pipeOut = Pipe(); let pipeErr = Pipe()
        p.standardOutput = pipeOut
        p.standardError = pipeErr
        try p.run()
        p.waitUntilExit()
        let outData = pipeOut.fileHandleForReading.readDataToEndOfFile()
        let errData = pipeErr.fileHandleForReading.readDataToEndOfFile()
        let out = String(data: outData, encoding: .utf8) ?? ""
        let err = String(data: errData, encoding: .utf8) ?? ""
        if p.terminationStatus != 0 {
            let message = "\(exec) \(args.joined(separator: " ")) -> rc=\(p.terminationStatus) err=\(err)"
            PSLog.error(PSLog.pf, message)
            onWarning?("PF command failed: \(message)")
            throw NSError(domain: "PFManager", code: Int(p.terminationStatus), userInfo: [NSLocalizedDescriptionKey: err.isEmpty ? out : err])
        }
        return out
    }
}
