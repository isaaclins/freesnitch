import Foundation

struct ExtensionInspection {
    let report: ExtensionReport
    let approvalState: String
    let filterConfigurationState: String
    let filterEnabledState: String
    let snapshotState: String
    let runningState: String
}

struct SystemExtensionObservation: Sendable {
    let state: String
    let detail: String
}

struct FilterObservation: Sendable {
    let configuration: String
    let enabled: String
    let detail: String
}

enum ExtensionInspector {
    static func inspect() async -> ExtensionInspection {
        let system: SystemExtensionObservation
        let filter: FilterObservation
        if CLIAppBundle.hasEmbeddedNetworkExtension {
            system = await Task.detached { SystemExtensionProbe.read() }.value
            filter = await FilterPreferencesProbe.read()
        } else {
            system = SystemExtensionObservation(state: "not-in-build", detail: "This FreeSnitch app build does not embed the network extension.")
            filter = FilterObservation(configuration: "not-in-build", enabled: "no", detail: "The monitor-only build has no content filter configuration.")
        }

        let xpcMessage = "The bare CLI cannot inspect the network extension's app-group XPC service on the live shipping setup. Direct extension running and rule snapshot state are unknown; approval and filter configuration are reported separately."
        let snapshot = SnapshotReport(state: "unknown",
                                      mode: nil,
                                      ruleCount: nil,
                                      updatedAt: nil,
                                      generation: nil,
                                      message: xpcMessage)
        let message = [system.detail, filter.detail, xpcMessage]
            .filter { !$0.isEmpty }
            .joined(separator: " ")
        let report = ExtensionReport(
            identifier: AppConstants.bundleIdNetExt,
            approval: system.state,
            running: "unknown",
            filterConfiguration: filter.configuration,
            filterEnabled: filter.enabled,
            snapshot: snapshot,
            message: message.isEmpty ? nil : message
        )
        return ExtensionInspection(report: report,
                                   approvalState: system.state,
                                   filterConfigurationState: filter.configuration,
                                   filterEnabledState: filter.enabled,
                                   snapshotState: snapshot.state,
                                   runningState: "unknown")
    }
}

enum SystemExtensionProbe {
    static func read() -> SystemExtensionObservation {
        let executable = "/usr/bin/systemextensionsctl"
        guard FileManager.default.isExecutableFile(atPath: executable) else {
            return SystemExtensionObservation(state: "unknown", detail: "systemextensionsctl is unavailable on this macOS installation.")
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = ["list"]
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        do {
            try process.run()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            let text = String(data: data, encoding: .utf8) ?? ""
            return parse(text, exitStatus: process.terminationStatus)
        } catch {
            return SystemExtensionObservation(state: "unknown", detail: "Could not query system extension approval: \(error.localizedDescription).")
        }
    }

    static func parse(_ text: String, exitStatus: Int32) -> SystemExtensionObservation {
        let lines = text.components(separatedBy: .newlines)
        let matchingLines = lines.filter { $0.contains(AppConstants.bundleIdNetExt) }
        guard !matchingLines.isEmpty else {
            let detail = exitStatus == 0
                ? "The FreeSnitch network extension is not listed as installed or approved."
                : "The system extension listing did not contain FreeSnitch (exit status \(exitStatus))."
            return SystemExtensionObservation(state: "not-approved", detail: detail)
        }

        let statuses = matchingLines.map { $0.lowercased() }
        let hasActiveGeneration = statuses.contains { status in
            let negativeState = status.contains("terminated") ||
                status.contains("deactivated") ||
                status.contains("disabled") ||
                status.contains("inactive") ||
                status.contains("not running") ||
                status.contains("not approved") ||
                status.contains("waiting for user approval") ||
                status.contains("needs user approval") ||
                status.contains("waiting for approval") ||
                status.contains("needs approval")
            return !negativeState &&
                (status.contains("active") ||
                 status.contains("activated") ||
                 status.contains("enabled") ||
                 status.contains("running"))
        }
        if hasActiveGeneration {
            return SystemExtensionObservation(state: "approved", detail: "The FreeSnitch network extension is approved by macOS.")
        }

        let hasApprovalProblem = statuses.contains { status in
            status.contains("waiting for user approval") ||
                status.contains("needs user approval") ||
                status.contains("not approved") ||
                status.contains("deactivated") ||
                status.contains("disabled")
        }
        if hasApprovalProblem {
            return SystemExtensionObservation(state: "not-approved", detail: "The FreeSnitch network extension is installed but is waiting for approval or is disabled.")
        }

        let allTerminatedWaitingToUninstall = statuses.allSatisfy { status in
            status.contains("terminated") && status.contains("waiting to uninstall")
        }
        if allTerminatedWaitingToUninstall {
            return SystemExtensionObservation(state: "unknown", detail: "The FreeSnitch network extension has only terminated generations waiting to uninstall; no approved generation was found.")
        }
        return SystemExtensionObservation(state: "unknown", detail: "The FreeSnitch network extension is listed, but macOS reported no active generation.")
    }
}

enum FilterPreferencesProbe {
    static func read() async -> FilterObservation {
        guard CLIAppBundle.hasEmbeddedNetworkExtension else {
            return FilterObservation(configuration: "not-in-build",
                                     enabled: "no",
                                     detail: "The monitor-only build has no content filter configuration.")
        }
        guard let state = AppPreferences.string(forKey: AppPreferences.Key.filterConfigurationState) else {
            return FilterObservation(configuration: "unknown",
                                     enabled: "unknown",
                                     detail: "The GUI has not published a content filter configuration status. The CLI cannot call NEFilterManager without the GUI's restricted entitlement.")
        }
        let detail = AppPreferences.string(forKey: AppPreferences.Key.filterConfigurationDetail)
            ?? "The GUI published filter configuration state \(state)."
        switch state {
        case "installed-enabled": return FilterObservation(configuration: "installed", enabled: "yes", detail: detail)
        case "installed-disabled": return FilterObservation(configuration: "installed", enabled: "no", detail: detail)
        case "missing": return FilterObservation(configuration: "missing", enabled: "no", detail: detail)
        default: return FilterObservation(configuration: "unknown", enabled: "unknown", detail: detail)
        }
    }
}

enum PFProbe {
    static let anchor = PFReport(anchor: PFManagerName.anchor,
                                 path: PFManagerName.path,
                                 installed: "unknown",
                                 valid: "unknown",
                                 helperLoaded: nil,
                                 message: nil)

    static func read(helperStatus: HelperStatus?) -> PFReport {
        let path = PFManagerName.path
        let exists = FileManager.default.fileExists(atPath: path)
        let helperLoaded = helperStatus?.pfctlActive
        let helperError = helperStatus?.pfctlError

        if let helperError, !helperError.isEmpty {
            return PFReport(anchor: PFManagerName.anchor,
                            path: path,
                            installed: exists ? "yes" : "unknown",
                            valid: "invalid",
                            helperLoaded: helperLoaded,
                            message: "The helper recorded a pf failure: \(helperError). A malformed host specification can reject the entire ruleset. Remove or correct the offending rule, then retry enforcement.")
        }
        guard exists else {
            return PFReport(anchor: PFManagerName.anchor,
                            path: path,
                            installed: "no",
                            valid: helperLoaded == true ? "unknown" : "not-installed",
                            helperLoaded: helperLoaded,
                            message: helperLoaded == true
                                ? "The helper says the pf anchor is loaded, but the anchor file is missing."
                                : "The pf anchor is not installed; this is normal while enforcement is off.")
        }

        let validation = runSyntaxCheck(path: path)
        if validation.ok {
            return PFReport(anchor: PFManagerName.anchor,
                            path: path,
                            installed: "yes",
                            valid: "valid",
                            helperLoaded: helperLoaded,
                            message: validation.message)
        }
        if validation.isSyntaxFailure {
            return PFReport(anchor: PFManagerName.anchor,
                            path: path,
                            installed: "yes",
                            valid: "invalid",
                            helperLoaded: helperLoaded,
                            message: "The pf anchor failed syntax validation: \(validation.message) A single malformed host specification can reject the entire ruleset. Remove or correct the offending rule, then retry enforcement.")
        }
        return PFReport(anchor: PFManagerName.anchor,
                        path: path,
                        installed: "yes",
                        valid: "unknown",
                        helperLoaded: helperLoaded,
                        message: validation.message)
    }

    private static func runSyntaxCheck(path: String) -> (ok: Bool, isSyntaxFailure: Bool, message: String) {
        let executable = "/sbin/pfctl"
        guard FileManager.default.isExecutableFile(atPath: executable) else {
            return (false, false, "pfctl is unavailable, so the anchor could not be checked.")
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = ["-n", "-a", PFManagerName.anchor, "-f", path]
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        do {
            try process.run()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            let rawMessage = (String(data: data, encoding: .utf8) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            if process.terminationStatus == 0 {
                return (true, false, rawMessage.isEmpty ? "The pf anchor passed syntax validation." : rawMessage)
            }
            let lower = rawMessage.lowercased()
            let syntax = lower.contains("syntax") || lower.contains("parse") || lower.contains("host") || lower.contains("address") || lower.contains("invalid")
            let message = compactPFMessage(rawMessage)
            return (false, syntax, message.isEmpty ? "pfctl rejected the anchor with exit status \(process.terminationStatus)." : message)
        } catch {
            return (false, false, "Could not run pfctl for a syntax check: \(error.localizedDescription).")
        }
    }

    private static func compactPFMessage(_ raw: String) -> String {
        let lines = raw.split(whereSeparator: \.isNewline).map(String.init)
        let useful = lines.filter {
            let lower = $0.lowercased()
            return lower.contains("could not parse") || lower.contains("syntax error") || lower.contains("invalid")
        }
        let selected = Array((useful.isEmpty ? lines : useful).prefix(4))
        let omitted = max(0, (useful.isEmpty ? lines.count : useful.count) - selected.count)
        var result = selected.joined(separator: " ")
        if omitted > 0 { result += " (\(omitted) more pfctl diagnostics omitted)" }
        return result
    }
}

enum PFManagerName {
    static let anchor = "puresnitch"
    static let path = "/etc/pf.anchors/puresnitch"
}
