import Foundation

final class PFManager: @unchecked Sendable {
    // Keep the established anchor name so a rename cannot strand active firewall rules.
    static let anchorName = "puresnitch"
    private let anchorPath = "/etc/pf.anchors/puresnitch"
    private let pfctl = "/sbin/pfctl"
    private let queue = DispatchQueue(label: "io.isaaclins.freesnitch.pf")
    private var loaded = false

    /// Invalid rules are omitted from the anchor, but their rejection is sent
    /// to the helper event stream so the GUI can show it to the user.
    var onWarning: ((String) -> Void)?

    func install() throws {
        try ensureMainPFConfReferencesAnchor()
        try writeAnchorFile(rules: [])
        try run(pfctl, ["-E"]) // enable pf
        try loadAnchor()
        loaded = true
    }

    func uninstall() throws {
        _ = try? run(pfctl, ["-a", PFManager.anchorName, "-F", "all"])
        _ = try? run(pfctl, ["-a", PFManager.anchorName, "-f", "/dev/null"])
        loaded = false
    }

    var isLoaded: Bool { loaded }

    func applyRules(_ rules: [Rule]) throws {
        try writeAnchorFile(rules: rules)
        try loadAnchor()
    }

    private func loadAnchor() throws {
        try run(pfctl, ["-a", PFManager.anchorName, "-f", anchorPath])
    }

    private func writeAnchorFile(rules: [Rule]) throws {
        let content = renderAnchor(rules: rules) { [weak self] rule, reason in
            self?.reportRejected(rule: rule, reason: reason)
        }
        try content.write(toFile: anchorPath, atomically: true, encoding: .utf8)
    }

    /// Render a complete anchor without touching the filesystem. Keeping this
    /// separate from the privileged write makes the safety checks directly
    /// exercisable and guarantees that every emitted destination was checked.
    func renderAnchor(rules: [Rule], onRejected: ((Rule, String) -> Void)? = nil) -> String {
        var lines: [String] = []
        lines.append("# FreeSnitch pf anchor - auto-generated. Do not edit.")
        lines.append("# Hostname rules are intentionally not emitted to pf.")
        lines.append("# The Network Extension filter evaluates them when active, avoiding pf's one-time DNS resolution.")
        lines.append("# If that filter is inactive, hostname rules are not enforced by this anchor.")
        lines.append("set block-policy drop")
        lines.append("set skip on lo0")

        let denyRules = rules.filter { $0.action == .deny && $0.enabled }
        let allowRules = rules.filter { $0.action == .allow && $0.enabled }

        for rule in denyRules {
            if let line = pfLine(rule: rule, verb: "block", onRejected: onRejected) {
                lines.append(line)
            }
        }
        for rule in allowRules {
            if let line = pfLine(rule: rule, verb: "pass", onRejected: onRejected) {
                lines.append(line)
            }
        }

        return lines.joined(separator: "\n") + "\n"
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
