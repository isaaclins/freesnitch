import Foundation

final class PFManager: @unchecked Sendable {
    // Keep the established anchor name so a rename cannot strand active firewall rules.
    static let anchorName = "puresnitch"
    private let anchorPath = "/etc/pf.anchors/puresnitch"
    private let pfctl = "/sbin/pfctl"
    private let queue = DispatchQueue(label: "io.isaaclins.freesnitch.pf")
    private var loaded = false

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
        var lines: [String] = []
        lines.append("# FreeSnitch pf anchor - auto-generated. Do not edit.")
        lines.append("set block-policy drop")
        lines.append("set skip on lo0")

        let denyRules = rules.filter { $0.action == .deny && $0.enabled }
        let allowRules = rules.filter { $0.action == .allow && $0.enabled }

        for r in denyRules {
            if let line = pfLine(rule: r, verb: "block") { lines.append(line) }
        }
        for r in allowRules {
            if let line = pfLine(rule: r, verb: "pass") { lines.append(line) }
        }

        let content = lines.joined(separator: "\n") + "\n"
        try content.write(toFile: anchorPath, atomically: true, encoding: .utf8)
    }

    private func pfLine(rule r: Rule, verb: String) -> String? {
        var dir = "out"
        if r.direction == .incoming { dir = "in" }
        if r.direction == .any { dir = "" }
        var line = "\(verb) \(dir) quick".trimmingCharacters(in: .whitespaces) + " "
        line += "proto { tcp udp } "
        if let ip = r.remoteIP, !ip.isEmpty {
            line += "to \(ip) "
        } else if let host = r.remoteHost, !host.isEmpty {
            line += "to \(host) "
        }
        if let p = r.remotePort, p > 0 {
            line += "port \(p) "
        }
        if (r.remoteIP?.isEmpty ?? true) && (r.remoteHost?.isEmpty ?? true) && (r.remotePort ?? 0) == 0 {
            return nil
        }
        return line.trimmingCharacters(in: .whitespaces)
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
            PSLog.error(PSLog.pf, "\(exec) \(args.joined(separator: " ")) -> rc=\(p.terminationStatus) err=\(err)")
            throw NSError(domain: "PFManager", code: Int(p.terminationStatus), userInfo: [NSLocalizedDescriptionKey: err.isEmpty ? out : err])
        }
        return out
    }
}
