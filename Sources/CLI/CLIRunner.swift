import Foundation
import ServiceManagement

final class CLIRunner {
    private let invocation: CLIInvocation

    init(invocation: CLIInvocation) {
        self.invocation = invocation
    }

    func run() async throws -> CommandResult {
        switch invocation.command {
        case .status: return try await status()
        case .doctor: return await doctor()
        case .mode(let mode): return try await setMode(mode)
        case .rules(let command): return try await rules(command)
        case .monitor(let command): return try await monitor(command)
        case .connections(let limit): return try await connections(limit)
        case .traffic(let limit): return try await traffic(limit)
        case .processes(let limit): return try await processes(limit)
        case .blocked(let limit): return try await blocked(limit)
        case .denied(let limit): return try await denied(limit)
        case .blocklists: return try await listBlocklists()
        case .refreshBlocklists: return try await refreshBlocklists()
        case .blocklist(let id, let enabled): return try await setBlocklist(id: id, enabled: enabled)
        case .doh(let url): return try await setDoH(url)
        case .enforcement(let enabled): return try await setEnforcement(enabled)
        case .pf(let operation): return try await pf(operation)
        case .flush: return try await flush()
        case .settings(let command): return try await settings(command)
        case .help, .version:
            return CommandResult(data: EmptyPayload(), human: "")
        }
    }

    private func status() async throws -> CommandResult {
        let helper = CLIHelperClient()
        let helperStatus = try await helper.prepare()
        let extensionInspection = await ExtensionInspector.inspect()
        let report = statusReport(helperStatus: helperStatus, extensionReport: extensionInspection.report)
        return CommandResult(data: report, human: humanStatus(report))
    }

    private func doctor() async -> CommandResult {
        let extensionInspection = await ExtensionInspector.inspect()
        let helper = CLIHelperClient()
        var helperStatus: HelperStatus?
        var helperError: CLIError?
        do {
            helperStatus = try await helper.prepare()
        } catch let error as CLIError {
            helperError = error
        } catch {
            helperError = CLIError(.internalFailure, message: error.localizedDescription)
        }

        let pf = PFProbe.read(helperStatus: helperStatus)
        var findings: [DoctorFinding] = []
        appendHelperFindings(findings: &findings, status: helperStatus, error: helperError, observedVersion: helper.observedVersion)
        appendExtensionFindings(findings: &findings, inspection: extensionInspection)
        appendPFFinding(findings: &findings, report: pf)

        let healthy = findings.allSatisfy { $0.state != "problem" }
        let exitCode = findings.first(where: { $0.exitCode != nil })?.exitCode
            .flatMap { CLIExitCode(rawValue: $0) } ?? .success
        let report = DoctorReport(healthy: healthy,
                                  findings: findings,
                                  helper: helperStatus.map(helperReport),
                                  extensionStatus: extensionInspection.report,
                                  pf: pf)
        let doctorError = healthy
            ? nil
            : CLIError(exitCode,
                       code: "doctor_found_problems",
                       message: "Doctor found one or more unhealthy FreeSnitch components.",
                       remediation: "Read each finding's action, fix the first actionable problem, and rerun `freesnitch doctor`.")
        return CommandResult(data: report,
                             human: humanDoctor(report),
                             exitCode: exitCode,
                             error: doctorError)
    }

    private func setMode(_ mode: AppMode) async throws -> CommandResult {
        let helper = CLIHelperClient()
        _ = try await helper.prepare()
        try await helper.setMode(mode)
        AppPreferences.set(mode.rawValue, forKey: AppPreferences.Key.mode)
        let rules = try await helper.listRules()
        let sync = await syncSnapshot(mode: mode, rules: rules)
        let report = PolicyChangeReport(operation: "mode",
                                        mode: canonicalMode(mode),
                                        ruleCount: rules.count,
                                        extensionSync: sync.state,
                                        extensionMessage: sync.message)
        let warning = sync.message.map { "\nWarning: \($0)" } ?? ""
        return CommandResult(data: report,
                             human: "Mode: \(modeLabel(mode)) (\(canonicalMode(mode)))\nRules synchronized: \(sync.state)\(warning)")
    }

    private func rules(_ command: RulesCommand) async throws -> CommandResult {
        switch command {
        case .list(let options): return try await listRules(options)
        case .show(let id): return try await showRule(id)
        case .add(let rule): return try await addRule(rule)
        case .setEnabled(let ids, let enabled): return try await setRulesEnabled(ids, enabled: enabled)
        case .remove(let ids): return try await removeRules(ids)
        case .importFile(let path): return try await importRules(path)
        case .exportFile(let path): return try await exportRules(path)
        }
    }

    private func listRules(_ options: RulesListOptions) async throws -> CommandResult {
        let helper = CLIHelperClient()
        _ = try await helper.prepare()
        let rules = try await helper.listRules(profile: options.profile ?? "")
        var filtered = filterRules(rules, options: options)
        var blocklistInfo: BlocklistInfo?
        if let reference = options.blocklist {
            let lists = try await helper.blocklists()
            blocklistInfo = try resolveBlocklist(reference, from: lists)
            filtered = []
        }
        if let limit = options.limit { filtered = Array(filtered.prefix(limit)) }
        let report = RuleListReport(category: categoryName(options.category),
                                    profile: options.profile,
                                    group: options.group,
                                    blocklist: options.blocklist,
                                    search: options.search,
                                    count: filtered.count,
                                    rules: filtered,
                                    blocklistInfo: blocklistInfo)
        return CommandResult(data: report, human: humanRules(report))
    }

    private func showRule(_ id: UUID) async throws -> CommandResult {
        let helper = CLIHelperClient()
        _ = try await helper.prepare()
        let rules = try await helper.listRules()
        guard let rule = rules.first(where: { $0.id == id }) else {
            throw CLIError(.operationFailed,
                           code: "rule_not_found",
                           message: "No rule with ID \(id.uuidString) exists.",
                           remediation: "Run `freesnitch rules list` to see current rule IDs.")
        }
        return CommandResult(data: rule, human: humanRule(rule))
    }

    private func addRule(_ rule: Rule) async throws -> CommandResult {
        let helper = CLIHelperClient()
        let status = try await helper.prepare()
        try await helper.addRule(rule)
        let rules = try await helper.listRules()
        let sync = await syncSnapshot(mode: status.mode, rules: rules)
        let report = RuleAddedReport(rule: rule, extensionSync: sync.state, extensionMessage: sync.message)
        let warning = sync.message.map { "\nWarning: \($0)" } ?? ""
        return CommandResult(data: report,
                             human: "Added rule \(rule.id.uuidString).\n\(humanRule(rule))\nExtension synchronization: \(sync.state).\(warning)")
    }

    private func setRulesEnabled(_ ids: [UUID], enabled: Bool) async throws -> CommandResult {
        let helper = CLIHelperClient()
        let status = try await helper.prepare()
        var succeeded: [UUID] = []
        var failures: [RuleMutationFailure] = []
        for id in ids {
            do {
                let rules = try await helper.listRules()
                guard var rule = rules.first(where: { $0.id == id }) else {
                    failures.append(RuleMutationFailure(id: id, message: "rule not found"))
                    continue
                }
                rule.enabled = enabled
                try await helper.addRule(rule)
                succeeded.append(id)
            } catch let error as CLIError {
                if error.exitCode == .helperUnreachable || error.exitCode == .helperVersionMismatch {
                    throw error
                }
                failures.append(RuleMutationFailure(id: id, message: error.message))
            }
        }
        let currentRules = try await helper.listRules()
        let sync = succeeded.isEmpty ? (state: "not-needed", message: nil) : await syncSnapshot(mode: status.mode, rules: currentRules)
        let report = RuleMutationReport(operation: enabled ? "enable" : "disable",
                                        requested: ids,
                                        succeeded: succeeded,
                                        failed: failures,
                                        extensionSync: sync.state,
                                        extensionMessage: sync.message)
        let failureText = failures.isEmpty ? "" : "\nFailures: " + failures.map { "\($0.id): \($0.message)" }.joined(separator: "; ")
        let warning = sync.message.map { "\nWarning: \($0)" } ?? ""
        let mutationError = failures.isEmpty
            ? nil
            : CLIError(.operationFailed,
                       code: "rule_mutation_partial_failure",
                       message: "One or more rule mutations failed.",
                       remediation: "Review the failed IDs in the response and rerun the operation after fixing the helper error.")
        return CommandResult(data: report,
                             human: "\(enabled ? "Enabled" : "Disabled") \(succeeded.count) of \(ids.count) rules.\(failureText)\nExtension synchronization: \(sync.state).\(warning)",
                             exitCode: failures.isEmpty ? .success : .operationFailed,
                             error: mutationError)
    }

    private func removeRules(_ ids: [UUID]) async throws -> CommandResult {
        let helper = CLIHelperClient()
        let status = try await helper.prepare()
        var succeeded: [UUID] = []
        var failures: [RuleMutationFailure] = []
        for id in ids {
            do {
                try await helper.removeRule(id)
                succeeded.append(id)
            } catch let error as CLIError {
                if error.exitCode == .helperUnreachable || error.exitCode == .helperVersionMismatch {
                    throw error
                }
                failures.append(RuleMutationFailure(id: id, message: error.message))
            }
        }
        let currentRules = try await helper.listRules()
        let sync = succeeded.isEmpty ? (state: "not-needed", message: nil) : await syncSnapshot(mode: status.mode, rules: currentRules)
        let report = RuleMutationReport(operation: "remove",
                                        requested: ids,
                                        succeeded: succeeded,
                                        failed: failures,
                                        extensionSync: sync.state,
                                        extensionMessage: sync.message)
        let failureText = failures.isEmpty ? "" : "\nFailures: " + failures.map { "\($0.id): \($0.message)" }.joined(separator: "; ")
        let warning = sync.message.map { "\nWarning: \($0)" } ?? ""
        let mutationError = failures.isEmpty
            ? nil
            : CLIError(.operationFailed,
                       code: "rule_mutation_partial_failure",
                       message: "One or more rule removals failed.",
                       remediation: "Review the failed IDs in the response and rerun the operation after fixing the helper error.")
        return CommandResult(data: report,
                             human: "Removed \(succeeded.count) of \(ids.count) rules.\(failureText)\nExtension synchronization: \(sync.state).\(warning)",
                             exitCode: failures.isEmpty ? .success : .operationFailed,
                             error: mutationError)
    }

    private func importRules(_ path: String) async throws -> CommandResult {
        let data: Data
        if path == "-" {
            data = FileHandle.standardInput.readDataToEndOfFile()
        } else {
            do { data = try Data(contentsOf: URL(fileURLWithPath: path)) }
            catch {
                throw CLIError(.invalidArgument, message: "Could not read import file \(path): \(error.localizedDescription).", remediation: "Provide a readable JSON export or use - for standard input.")
            }
        }
        let rules: [Rule]
        if let document = try? CLIJSON.decode(RuleExportDocument.self, from: data) {
            rules = document.rules
        } else if let raw = try? CLIJSON.decode([Rule].self, from: data) {
            rules = raw
        } else {
            throw CLIError(.invalidArgument,
                           message: "The import is not a FreeSnitch rule export or Rule array.",
                           remediation: "Create a file with `freesnitch rules export` or provide a JSON array of Rule objects.")
        }
        let helper = CLIHelperClient()
        let status = try await helper.prepare()
        try await helper.importRules(rules)
        let currentRules = try await helper.listRules()
        let sync = await syncSnapshot(mode: status.mode, rules: currentRules)
        let report = RuleImportReport(imported: rules.count,
                                      ids: rules.map(\.id),
                                      source: path,
                                      extensionSync: sync.state,
                                      extensionMessage: sync.message)
        let warning = sync.message.map { "\nWarning: \($0)" } ?? ""
        return CommandResult(data: report,
                             human: "Imported \(rules.count) rules from \(path) as an upsert/merge.\nExtension synchronization: \(sync.state).\(warning)")
    }

    private func exportRules(_ path: String?) async throws -> CommandResult {
        let helper = CLIHelperClient()
        _ = try await helper.prepare()
        let rules = try await helper.listRules()
        let document = RuleExportDocument(format: "freesnitch.rules.v1",
                                          version: 1,
                                          exportedAt: Date(),
                                          rules: rules)
        if let path, path != "-" {
            do {
                try CLIJSON.encode(document).write(to: URL(fileURLWithPath: path), options: .atomic)
            } catch {
                throw CLIError(.operationFailed, message: "Could not write export file \(path): \(error.localizedDescription).", remediation: "Choose a writable output path.")
            }
            let report = RuleExportReport(count: rules.count, output: path, format: document.format)
            return CommandResult(data: report, human: "Exported \(rules.count) rules to \(path).")
        }
        let encoded = CLIOutput.encode(document)
        return CommandResult(data: document, human: String(data: encoded, encoding: .utf8) ?? "")
    }

    private func monitor(_ command: MonitorCommand) async throws -> CommandResult {
        switch command {
        case .connections(let limit): return try await connections(limit)
        case .traffic(let limit): return try await traffic(limit)
        case .processes(let limit): return try await processes(limit)
        case .summary(let limit): return try await summary(limit)
        case .blocked(let limit): return try await blocked(limit)
        case .denied(let limit): return try await denied(limit)
        }
    }

    private func connections(_ limit: Int) async throws -> CommandResult {
        let helper = CLIHelperClient()
        _ = try await helper.prepare()
        let values = Array(try await helper.connections().prefix(limit))
        let report = ConnectionsReport(requestedLimit: limit, returned: values.count, connections: values)
        return CommandResult(data: report, human: humanConnections(report))
    }

    private func traffic(_ limit: Int) async throws -> CommandResult {
        let helper = CLIHelperClient()
        _ = try await helper.prepare()
        let values = Array(try await helper.trafficSamples().prefix(limit))
        let report = TrafficReport(requestedLimit: limit,
                                   returned: values.count,
                                   samples: values,
                                   note: values.count < limit ? "The helper protocol exposes the current sample, not a history buffer; no samples were invented." : nil)
        return CommandResult(data: report, human: humanTraffic(report))
    }

    private func processes(_ limit: Int) async throws -> CommandResult {
        let helper = CLIHelperClient()
        _ = try await helper.prepare()
        let values = Array(try await helper.processUsage().sorted { ($0.bytesIn + $0.bytesOut) > ($1.bytesIn + $1.bytesOut) }.prefix(limit))
        let report = ProcessUsageReport(requestedLimit: limit, returned: values.count, usage: values)
        return CommandResult(data: report, human: humanProcesses(report))
    }

    private func summary(_ limit: Int) async throws -> CommandResult {
        let helper = CLIHelperClient()
        _ = try await helper.prepare()
        let connections = try await helper.connections()
        let usage = try await helper.processUsage()
        let report = aggregate(connections: connections, usage: usage, limit: limit)
        return CommandResult(data: report, human: humanSummary(report))
    }

    private func blocked(_ limit: Int) async throws -> CommandResult {
        let helper = CLIHelperClient()
        _ = try await helper.prepare()
        let values = Array(try await helper.recentBlocked(limit: limit).prefix(limit))
        let report = ConnectionsReport(requestedLimit: limit, returned: values.count, connections: values)
        return CommandResult(data: report, human: humanConnections(report, title: "Recently Blocked"))
    }

    private func denied(_ limit: Int) async throws -> CommandResult {
        let helper = CLIHelperClient()
        _ = try await helper.prepare()
        let values = Array(try await helper.recentDenied(limit: limit).prefix(limit))
        let report = ConnectionsReport(requestedLimit: limit, returned: values.count, connections: values)
        return CommandResult(data: report, human: humanConnections(report, title: "Recently Denied"))
    }

    private func listBlocklists() async throws -> CommandResult {
        let helper = CLIHelperClient()
        _ = try await helper.prepare()
        let values = try await helper.blocklists()
        let report = values.map { BlocklistReport(id: $0.id, name: $0.name, url: $0.url, enabled: $0.enabled, lastUpdated: $0.lastUpdated, entryCount: $0.entryCount) }
        return CommandResult(data: report, human: humanBlocklists(report))
    }

    private func refreshBlocklists() async throws -> CommandResult {
        let helper = CLIHelperClient()
        _ = try await helper.prepare()
        try await helper.refreshBlocklists()
        let values = try await helper.blocklists()
        let report = values.map { BlocklistReport(id: $0.id, name: $0.name, url: $0.url, enabled: $0.enabled, lastUpdated: $0.lastUpdated, entryCount: $0.entryCount) }
        return CommandResult(data: report, human: "Refreshed blocklists.\n" + humanBlocklists(report))
    }

    private func setBlocklist(id reference: String, enabled: Bool) async throws -> CommandResult {
        let helper = CLIHelperClient()
        _ = try await helper.prepare()
        let lists = try await helper.blocklists()
        let target = try resolveBlocklist(reference, from: lists)
        try await helper.setBlocklist(id: target.id.uuidString, enabled: enabled)
        let report = BlocklistReport(id: target.id, name: target.name, url: target.url, enabled: enabled, lastUpdated: target.lastUpdated, entryCount: target.entryCount)
        return CommandResult(data: report, human: "Blocklist \(target.name) (\(target.id.uuidString)): \(humanBool(enabled)).")
    }

    private func setDoH(_ value: String) async throws -> CommandResult {
        guard let url = URL(string: value), let scheme = url.scheme?.lowercased(), scheme == "https" || scheme == "http" else {
            throw CLIError(.invalidArgument, message: "Invalid DoH URL `\(value)`.", remediation: "Use an http or https URL such as https://cloudflare-dns.com/dns-query.")
        }
        let helper = CLIHelperClient()
        _ = try await helper.prepare()
        try await helper.setDoH(url: url.absoluteString)
        let report = SettingReport(key: "doh_url", label: "DNS over HTTPS upstream", value: url.absoluteString, changed: true, detail: nil)
        return CommandResult(data: report, human: "DNS over HTTPS upstream: \(url.absoluteString)")
    }

    private func setEnforcement(_ enabled: Bool) async throws -> CommandResult {
        if !enabled { try requireYes("enforcement off") }
        let helper = CLIHelperClient()
        _ = try await helper.prepare()
        do {
            try await helper.setEnforcement(enabled)
        } catch let error as CLIError where error.exitCode == .operationFailed {
            throw CLIError(.pfAnchorFailure,
                           message: "The helper could not turn enforcement \(enabled ? "on" : "off"): \(error.message)",
                           remediation: "Run `freesnitch doctor`; a malformed host specification can reject the whole pf ruleset.")
        }
        AppPreferences.set(enabled, forKey: AppPreferences.Key.enforcement)
        let status = try await helper.prepare()
        let report = helperReport(status)
        return CommandResult(data: report,
                             human: "Enforcement: \(humanBool(enabled)).\nPF anchor: \(humanBool(status.pfctlActive)); DNS proxy: \(humanBool(status.dnsProxyActive)).")
    }

    private func pf(_ operation: PFCommand) async throws -> CommandResult {
        if case .uninstall = operation { try requireYes("pf uninstall") }
        let helper = CLIHelperClient()
        _ = try await helper.prepare()
        do {
            switch operation {
            case .install: try await helper.installPF()
            case .uninstall: try await helper.uninstallPF()
            }
        } catch let error as CLIError where error.exitCode == .operationFailed {
            throw CLIError(.pfAnchorFailure, message: "The helper could not complete the pf operation: \(error.message)", remediation: "Run `freesnitch doctor` before retrying.")
        }
        let report = PFProbe.read(helperStatus: try? await helper.prepare())
        return CommandResult(data: report, human: "pf \(operationName(operation)) completed.\n\(humanPF(report))")
    }

    private func flush() async throws -> CommandResult {
        try requireYes("flush")
        let helper = CLIHelperClient()
        _ = try await helper.prepare()
        do { try await helper.flush() }
        catch let error as CLIError where error.exitCode == .operationFailed {
            throw CLIError(.pfAnchorFailure, message: "The helper could not flush the pf anchor: \(error.message)", remediation: "Run `freesnitch doctor` and use `pkill -x FreeSnitch` as the emergency fail-open escape hatch.")
        }
        let report = PFProbe.read(helperStatus: try? await helper.prepare())
        return CommandResult(data: report, human: "Firewall flush completed.\n\(humanPF(report))")
    }

    private func settings(_ command: SettingsCommand) async throws -> CommandResult {
        switch command {
        case .helper(let action): return try await helperSettings(action)
        case .boolean(let key, let label, let value): return try await booleanSetting(key: key, label: label, value: value)
        case .enforcement(let value):
            if let value { return try await setEnforcement(value) }
            let helper = CLIHelperClient()
            let status = try await helper.prepare()
            let report = helperReport(status)
            return CommandResult(data: report, human: "Enforcement: \(humanBool(status.pfctlActive || status.dnsProxyActive)).")
        case .mode(let mode): return try await setMode(mode)
        case .doh(let url): return try await setDoH(url)
        case .dnsStatus:
            let helper = CLIHelperClient()
            let status = try await helper.prepare()
            let report = SettingReport(key: "dns_proxy", label: "Local DNS proxy", value: status.dnsProxyActive ? "running" : "stopped", changed: false, detail: "Port \(status.dnsProxyPort)")
            return CommandResult(data: report, human: "Local DNS proxy: \(status.dnsProxyActive ? "running" : "stopped") on port \(status.dnsProxyPort).")
        case .blocklists(let refresh):
            return refresh ? try await refreshBlocklists() : try await listBlocklists()
        case .blocklist(let id, let enabled): return try await setBlocklist(id: id, enabled: enabled)
        }
    }

    private func helperSettings(_ action: HelperSettingsCommand) async throws -> CommandResult {
        if case .openLoginItems = action {
            try openLoginItems()
            let report = HelperSettingsReport(registration: helperRegistrationState(), reachable: false, version: nil, detail: "Opened System Settings > General > Login Items & Extensions.")
            return CommandResult(data: report, human: "Opened System Settings > General > Login Items & Extensions.")
        }
        let registration = helperRegistrationState()
        let helper = CLIHelperClient()
        do {
            let status = try await helper.prepare()
            let report = HelperSettingsReport(registration: registration, reachable: true, version: status.version, detail: nil)
            return CommandResult(data: report, human: "Helper registration: \(registration).\nHelper XPC: reachable (v\(status.version)).")
        } catch let error as CLIError {
            let report = HelperSettingsReport(registration: registration, reachable: false, version: helper.observedVersion, detail: error.message)
            return CommandResult(data: report,
                                 human: "Helper registration: \(registration).\nHelper XPC: unreachable.\nWhat to do: \(error.remediation ?? "Run freesnitch doctor.")",
                                 exitCode: error.exitCode,
                                 error: error)
        }
    }

    private func booleanSetting(key: String, label: String, value: Bool?) async throws -> CommandResult {
        if key == "launch-at-login" {
            let service = SMAppService.mainApp
            if let value {
                do {
                    if value { try service.register() }
                    else { try await service.unregister() }
                } catch {
                    throw CLIError(.operationFailed, message: "Could not change launch at login: \(error.localizedDescription).", remediation: "Run the command from the FreeSnitch app bundle and inspect Login Items in System Settings.")
                }
            }
            let enabled = service.status == .enabled
            let report = BooleanStateReport(key: key, label: label, value: enabled)
            return CommandResult(data: report, human: "Launch at login: \(humanBool(enabled)).")
        }
        let current = AppPreferences.bool(forKey: key)
        let selected = value ?? current
        if let value { AppPreferences.set(value, forKey: key) }
        let report = BooleanStateReport(key: key, label: label, value: selected)
        return CommandResult(data: report, human: "\(label.capitalized): \(humanBool(selected)).")
    }

    private func openLoginItems() throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        process.arguments = ["x-apple.systempreferences:com.apple.LoginItems-Settings.extension"]
        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            throw CLIError(.operationFailed, message: "Could not open Login Items in System Settings: \(error.localizedDescription).", remediation: "Open System Settings > General > Login Items & Extensions manually.")
        }
        guard process.terminationStatus == 0 else {
            throw CLIError(.operationFailed, message: "System Settings refused the Login Items URL.", remediation: "Open System Settings > General > Login Items & Extensions manually.")
        }
    }

    private func helperRegistrationState() -> String {
        let service = SMAppService.daemon(plistName: "io.isaaclins.freesnitch.helper.plist")
        switch service.status {
        case .enabled: return "enabled"
        case .requiresApproval: return "requires-approval"
        case .notRegistered: return "not-registered"
        case .notFound: return "not-found"
        @unknown default: return "unknown"
        }
    }

    private func syncSnapshot(mode: AppMode, rules: [Rule]) async -> (state: String, message: String?) {
        do {
            let snapshot = SharedRuleBridge.Snapshot(mode: mode, rules: rules)
            let data = try JSONEncoder().encode(snapshot)
            let status = try await CLIExtensionClient().updateSnapshot(data)
            if status.state == "ready" {
                return ("ready", nil)
            }
            return (status.state, status.message ?? "The extension acknowledged the connection but did not accept a ready rule snapshot.")
        } catch let error as ExtensionClientError {
            return ("not-delivered", "Rules remain saved in the helper, but the network extension did not receive the snapshot: \(error.message)")
        } catch {
            return ("not-delivered", "Rules remain saved in the helper, but the network extension snapshot could not be encoded or delivered: \(error.localizedDescription)")
        }
    }

    private func statusReport(helperStatus: HelperStatus, extensionReport: ExtensionReport) -> StatusReport {
        StatusReport(version: helperStatus.version,
                     mode: canonicalMode(helperStatus.mode),
                     modeLabel: modeLabel(helperStatus.mode),
                     enforcement: helperStatus.pfctlActive || helperStatus.dnsProxyActive,
                     helper: helperReport(helperStatus),
                     extensionStatus: extensionReport)
    }

    private func helperReport(_ status: HelperStatus) -> HelperReport {
        HelperReport(reachable: true,
                     version: status.version,
                     expectedVersion: CLIAppBundle.expectedBuildIdentity,
                     versionMatches: AppConstants.identityMatches(reported: status.version, expected: CLIAppBundle.expectedBuildIdentity),
                     running: status.running,
                     pfctlActive: status.pfctlActive,
                     pfctlError: status.pfctlError,
                     dnsProxyActive: status.dnsProxyActive,
                     dnsProxyPort: status.dnsProxyPort,
                     activeRules: status.activeRules,
                     blockedToday: status.blockedToday)
    }

    private func filterRules(_ rules: [Rule], options: RulesListOptions) -> [Rule] {
        var result = rules
        switch options.category {
        case .all: break
        case .active: result = result.filter { $0.enabled && $0.action == .allow }
        case .deny: result = result.filter { $0.action == .deny }
        case .recentChanges: result = result.filter { $0.createdAt >= Date().addingTimeInterval(-7 * 24 * 3600) }.sorted { $0.createdAt > $1.createdAt }
        case .recentlyUsed: result = result.filter { $0.lastUsedAt != nil }.sorted { ($0.lastUsedAt ?? .distantPast) > ($1.lastUsedAt ?? .distantPast) }
        case .temporary: result = result.filter { $0.temporary }
        case .unapproved: result = result.filter { $0.action == .ask }
        }
        if let group = options.group { result = result.filter { $0.groupName == group } }
        if let search = options.search, !search.isEmpty {
            result = result.filter {
                ($0.processName ?? "").localizedCaseInsensitiveContains(search) ||
                ($0.remoteHost ?? "").localizedCaseInsensitiveContains(search)
            }
        }
        return result
    }

    private func resolveBlocklist(_ reference: String, from lists: [BlocklistInfo]) throws -> BlocklistInfo {
        if let id = UUID(uuidString: reference), let match = lists.first(where: { $0.id == id }) { return match }
        if let match = lists.first(where: { $0.name.caseInsensitiveCompare(reference) == .orderedSame }) { return match }
        throw CLIError(.operationFailed,
                       code: "blocklist_not_found",
                       message: "No blocklist named or identified by `\(reference)` exists.",
                       remediation: "Run `freesnitch blocklists` to see current IDs and names.")
    }

    private func aggregate(connections: [Connection], usage: [ProcessUsage], limit: Int) -> AggregateSummary {
        struct ProcessValue {
            var name: String
            var bundle: String?
            var path: String?
            var bytesIn: Int64
            var bytesOut: Int64
        }
        var processes: [String: ProcessValue] = [:]
        var domains: [String: (Int64, Int64)] = [:]
        var countries: [String: (String, Int64, Int64)] = [:]
        func key(for connection: Connection) -> String {
            connection.processBundleId ?? connection.processPath
        }
        for connection in connections {
            let key = key(for: connection)
            var value = processes[key] ?? ProcessValue(name: connection.processName,
                                                        bundle: connection.processBundleId,
                                                        path: connection.processPath,
                                                        bytesIn: 0,
                                                        bytesOut: 0)
            value.bytesIn += connection.bytesIn
            value.bytesOut += connection.bytesOut
            processes[key] = value
            let domain = connection.remoteHost.isEmpty ? connection.remoteIP : connection.remoteHost
            var domainValue = domains[domain] ?? (0, 0)
            domainValue.0 += connection.bytesIn
            domainValue.1 += connection.bytesOut
            domains[domain] = domainValue
            if let code = connection.countryCode, !code.isEmpty {
                var countryValue = countries[code] ?? (connection.country ?? code, 0, 0)
                countryValue.1 += connection.bytesIn
                countryValue.2 += connection.bytesOut
                countries[code] = countryValue
            }
        }
        for item in usage {
            let connection = item.pid.flatMap { pid in connections.first { $0.pid == pid } }
                ?? connections.first { $0.processName == item.processName }
            guard let connection else { continue }
            let processKey = key(for: connection)
            guard var value = processes[processKey] else { continue }
            value.bytesIn += item.bytesIn
            value.bytesOut += item.bytesOut
            processes[processKey] = value
        }
        let topProcesses = processes.values
            .sorted { ($0.bytesIn + $0.bytesOut) > ($1.bytesIn + $1.bytesOut) }
            .prefix(limit)
            .map { AggregateProcess(name: $0.name, processBundleId: $0.bundle, processPath: $0.path, bytesIn: $0.bytesIn, bytesOut: $0.bytesOut, totalBytes: $0.bytesIn + $0.bytesOut) }
        let topDomains = domains
            .map { AggregateDomain(domain: $0.key, bytesIn: $0.value.0, bytesOut: $0.value.1, totalBytes: $0.value.0 + $0.value.1) }
            .sorted { $0.totalBytes > $1.totalBytes }
            .prefix(limit)
        let topCountries = countries
            .map { AggregateCountry(country: $0.value.0, countryCode: $0.key, bytesIn: $0.value.1, bytesOut: $0.value.2, totalBytes: $0.value.1 + $0.value.2) }
            .sorted { $0.totalBytes > $1.totalBytes }
            .prefix(limit)
        return AggregateSummary(requestedLimit: limit,
                                topProcesses: Array(topProcesses),
                                topDomains: Array(topDomains),
                                topCountries: Array(topCountries),
                                countryData: topCountries.isEmpty ? "No country metadata was present in helper connection records." : "Country totals use metadata present in helper connection records.")
    }

    private func requireYes(_ operation: String) throws {
        guard invocation.yes else {
            throw CLIError(.refused,
                           message: "`\(operation)` is a recovery/destructive operation and requires explicit --yes. The CLI never prompts.",
                           remediation: "Re-run `freesnitch \(operation) --yes` after checking the command and keeping `pkill -x FreeSnitch` available as the emergency fail-open escape hatch.")
        }
    }

    private func operationName(_ operation: PFCommand) -> String {
        switch operation {
        case .install: return "install"
        case .uninstall: return "uninstall"
        }
    }

    private func categoryName(_ category: RuleCategory) -> String {
        switch category {
        case .all: return "all"
        case .active: return "active"
        case .deny: return "deny"
        case .recentChanges: return "recent-changes"
        case .recentlyUsed: return "recently-used"
        case .temporary: return "temporary"
        case .unapproved: return "unapproved"
        }
    }

    private func humanStatus(_ report: StatusReport) -> String {
        """
        FreeSnitch status
          Version: \(report.version)
          Mode: \(report.modeLabel) (\(report.mode))
          Enforcement: \(humanBool(report.enforcement))
          Helper: \(report.helper.reachable ? "reachable" : "unreachable") (running \(report.helper.running ? "yes" : "no"))
          PF anchor: \(humanBool(report.helper.pfctlActive))
          DNS proxy: \(report.helper.dnsProxyActive ? "running" : "stopped") on port \(report.helper.dnsProxyPort)
          Extension approval: \(report.extensionStatus.approval)
          Extension XPC running: \(report.extensionStatus.running)
          Filter configuration: \(report.extensionStatus.filterConfiguration) (enabled \(report.extensionStatus.filterEnabled))
          Rule snapshot (direct extension XPC): \(report.extensionStatus.snapshot.state)\(report.extensionStatus.snapshot.ruleCount.map { " (\($0) rules)" } ?? "")
        \(report.extensionStatus.message.map { "  Detail: \($0)" } ?? "")
        """
    }

    private func humanDoctor(_ report: DoctorReport) -> String {
        let hasUnknown = report.findings.contains { $0.state == "unknown" }
        let header = report.healthy
            ? (hasUnknown ? "FreeSnitch doctor: no provable problems" : "FreeSnitch doctor: healthy")
            : "FreeSnitch doctor: problems found"
        let body = report.findings.map { finding in
            let label = finding.state.uppercased()
            return "[\(label)] \(finding.message)\n       What to do: \(finding.action)"
        }.joined(separator: "\n")
        return header + "\n" + body
    }

    private func humanRules(_ report: RuleListReport) -> String {
        if let blocklist = report.blocklistInfo {
            return "Blocklist: \(blocklist.name) (\(blocklist.id.uuidString))\n  Enabled: \(humanBool(blocklist.enabled))\n  Entries: \(blocklist.entryCount)\n  URL: \(blocklist.url)"
        }
        if report.rules.isEmpty { return "No rules matched (category \(report.category))." }
        return report.rules.map(humanRule).joined(separator: "\n\n")
    }

    private func humanRule(_ rule: Rule) -> String {
        let process = rule.processName ?? rule.processBundleId ?? rule.processPath ?? "Any Process"
        let destination = rule.remoteHost ?? rule.remoteIP ?? "Any destination"
        let port = rule.remotePort.map { ":\($0)" } ?? ""
        return "\(rule.id.uuidString)  \(rule.enabled ? "enabled" : "disabled")  \(rule.action.rawValue)\n  \(process) -> \(destination)\(port)\n  direction=\(rule.direction.rawValue) scope=\(rule.scope.rawValue) priority=\(rule.priority) profile=\(rule.profile)\n  group=\(rule.groupName ?? "-") temporary=\(rule.temporary ? "yes" : "no") hits=\(rule.hitCount)\n  created=\(formatDate(rule.createdAt))\(rule.expiresAt.map { " expires=\(formatDate($0))" } ?? "")\(rule.notes.map { "\n  notes=\($0)" } ?? "")"
    }

    private func humanConnections(_ report: ConnectionsReport, title: String = "Connections") -> String {
        if report.connections.isEmpty { return "\(title): none." }
        return "\(title) (\(report.returned), limit \(report.requestedLimit))\n" + report.connections.map { connection in
            let destination = connection.remoteHost.isEmpty ? connection.remoteIP : connection.remoteHost
            return "  \(connection.processName) [pid \(connection.pid)] -> \(destination):\(connection.remotePort) \(connection.status.rawValue) in=\(connection.bytesIn) out=\(connection.bytesOut)"
        }.joined(separator: "\n")
    }

    private func humanTraffic(_ report: TrafficReport) -> String {
        if report.samples.isEmpty { return "Traffic: no sample." }
        return "Traffic samples (\(report.returned), limit \(report.requestedLimit))\n" + report.samples.map { "  \(formatDate($0.timestamp)) in=\($0.bytesIn) B/s out=\($0.bytesOut) B/s" }.joined(separator: "\n") + (report.note.map { "\nNote: \($0)" } ?? "")
    }

    private func humanProcesses(_ report: ProcessUsageReport) -> String {
        if report.usage.isEmpty { return "Per-process usage: none." }
        return "Per-process usage (\(report.returned), limit \(report.requestedLimit))\n" + report.usage.map { "  \($0.processName)\($0.pid.map { " [pid \($0)]" } ?? "") in=\($0.bytesIn) out=\($0.bytesOut)" }.joined(separator: "\n")
    }

    private func humanSummary(_ report: AggregateSummary) -> String {
        let processes = report.topProcesses.map { "  \($0.name): \($0.totalBytes) bytes" }.joined(separator: "\n")
        let domains = report.topDomains.map { "  \($0.domain): \($0.totalBytes) bytes" }.joined(separator: "\n")
        let countries = report.topCountries.map { "  \($0.country) (\($0.countryCode)): \($0.totalBytes) bytes" }.joined(separator: "\n")
        return "Top processes\n\(processes.isEmpty ? "  none" : processes)\n\nTop domains\n\(domains.isEmpty ? "  none" : domains)\n\nTop countries\n\(countries.isEmpty ? "  none" : countries)\n\n\(report.countryData)"
    }

    private func humanBlocklists(_ values: [BlocklistReport]) -> String {
        if values.isEmpty { return "Blocklists: none." }
        return values.map { "  \($0.id.uuidString)  \($0.name)  \($0.enabled ? "on" : "off")  entries=\($0.entryCount)\($0.lastUpdated.map { " updated=\(formatDate($0))" } ?? "")" }.joined(separator: "\n")
    }

    private func humanPF(_ report: PFReport) -> String {
        "PF anchor \(report.anchor): installed=\(report.installed), valid=\(report.valid), helper-loaded=\(report.helperLoaded.map(humanBool) ?? "unknown")\(report.message.map { "\n  \($0)" } ?? "")"
    }

    private func appendHelperFindings(findings: inout [DoctorFinding], status: HelperStatus?, error: CLIError?, observedVersion: String?) {
        if let status {
            findings.append(DoctorFinding(id: "helper_reachable", state: "ok", message: "The privileged helper is reachable.", action: "No action needed.", exitCode: nil))
            let expectedIdentity = CLIAppBundle.expectedBuildIdentity
            let versionMatches = AppConstants.identityMatches(reported: status.version, expected: expectedIdentity)
            findings.append(DoctorFinding(id: "helper_version", state: versionMatches ? "ok" : "problem", message: versionMatches ? "The helper and app both report version \(status.version)." : "The helper reports version \(status.version), but this app is \(expectedIdentity). Helper-side fixes are not active until it is replaced.", action: versionMatches ? "No action needed." : "Open FreeSnitch and use Repair, or run: \(AppConstants.helperKickstartCommand)", exitCode: versionMatches ? nil : CLIExitCode.helperVersionMismatch.rawValue))
            return
        }
        let reachable = error?.exitCode == .helperVersionMismatch
        findings.append(DoctorFinding(id: "helper_reachable", state: reachable ? "ok" : "problem", message: reachable ? "The helper answered, but it is not the build this app expects." : "The privileged helper could not be reached.", action: reachable ? "See the helper version finding." : "Run `freesnitch settings helper recheck`; approve FreeSnitch in Login Items, then run doctor again.", exitCode: reachable ? nil : (error?.exitCode ?? CLIExitCode.helperUnreachable).rawValue))
        let staleExpected = CLIAppBundle.expectedBuildIdentity
        let staleReported = observedVersion ?? "unknown"
        let staleMessage = "A helper from an earlier install is still running. It reports \(staleReported), but this app is \(staleExpected), so helper-side fixes are not active."
        findings.append(DoctorFinding(id: "helper_version", state: reachable ? "problem" : "unknown", message: reachable ? staleMessage : "The helper version could not be checked.", action: reachable ? "Open FreeSnitch and use Repair, or run: \(AppConstants.helperKickstartCommand)" : "Fix helper reachability first, then rerun doctor.", exitCode: reachable ? CLIExitCode.helperVersionMismatch.rawValue : nil))
    }

    private func appendExtensionFindings(findings: inout [DoctorFinding], inspection: ExtensionInspection) {
        switch inspection.approvalState {
        case "not-in-build": findings.append(DoctorFinding(id: "extension_approval", state: "ok", message: "This monitor-only build intentionally does not embed the network extension.", action: "Use the firewall build generated from project-netext.yml to diagnose per-process filtering.", exitCode: nil))
        case "approved": findings.append(DoctorFinding(id: "extension_approval", state: "ok", message: "The network extension is approved.", action: "No action needed.", exitCode: nil))
        case "not-approved": findings.append(DoctorFinding(id: "extension_approval", state: "problem", message: "The network extension is not approved or is not installed.", action: "Use a signed firewall build, activate FreeSnitch, and approve the extension in System Settings > Privacy & Security when macOS asks.", exitCode: CLIExitCode.extensionNotApproved.rawValue))
        default: findings.append(DoctorFinding(id: "extension_approval", state: "unknown", message: "macOS did not provide a reliable network extension approval state.", action: "Run doctor from the signed app bundle on the firewall build and inspect System Settings > Privacy & Security.", exitCode: nil))
        }

        switch inspection.filterConfigurationState {
        case "not-in-build": findings.append(DoctorFinding(id: "filter_configuration", state: "ok", message: "This monitor-only build has no content filter configuration by design.", action: "Use the firewall build when per-process filtering is required.", exitCode: nil))
        case "installed" where inspection.filterEnabledState == "yes": findings.append(DoctorFinding(id: "filter_configuration", state: "ok", message: "The content filter configuration is installed and enabled.", action: "No action needed.", exitCode: nil))
        case "installed": findings.append(DoctorFinding(id: "filter_configuration", state: "problem", message: "The network extension is approved, but the content filter configuration is installed and disabled.", action: "Launch the FreeSnitch GUI once so it can enable the filter configuration, then rerun doctor.", exitCode: CLIExitCode.filterConfigurationMissing.rawValue))
        case "missing": findings.append(DoctorFinding(id: "filter_configuration", state: "problem", message: "The network extension is approved, but no content filter configuration is installed.", action: "Launch the FreeSnitch GUI once; after activation completes it installs the filter configuration. Then rerun doctor.", exitCode: CLIExitCode.filterConfigurationMissing.rawValue))
        default: findings.append(DoctorFinding(id: "filter_configuration", state: "unknown", message: "The content filter configuration could not be read.", action: "Run doctor from the signed firewall build and inspect Network Extension permissions.", exitCode: nil))
        }

        if inspection.approvalState == "not-in-build" {
            findings.append(DoctorFinding(id: "extension_running", state: "ok", message: "No network extension XPC listener is expected in this monitor-only build.", action: "Use the firewall build to test extension XPC.", exitCode: nil))
        } else {
            switch inspection.runningState {
            case "yes":
                findings.append(DoctorFinding(id: "extension_running", state: "ok", message: "The network extension XPC listener is running.", action: "No action needed.", exitCode: nil))
            case "no":
                findings.append(DoctorFinding(id: "extension_running", state: "problem", message: "The network extension is not answering its XPC service.", action: "Approve and activate the extension, ensure the filter configuration is enabled, and rerun doctor.", exitCode: CLIExitCode.extensionNotApproved.rawValue))
            default:
                findings.append(DoctorFinding(id: "extension_running", state: "unknown", message: "The CLI cannot inspect the network extension's direct XPC state on the live shipping setup, so running is unknown.", action: "Do not infer an extension failure from this finding. A helper-mediated extension health query is required for a direct running check.", exitCode: nil))
            }
        }

        if inspection.approvalState == "not-in-build" {
            findings.append(DoctorFinding(id: "filter_snapshot", state: "ok", message: "No network extension snapshot is expected in this monitor-only build.", action: "Use the firewall build to test rule snapshot delivery.", exitCode: nil))
        } else if inspection.snapshotState == "ready" {
            findings.append(DoctorFinding(id: "filter_snapshot", state: "ok", message: "A rule snapshot was delivered over XPC and is ready for filtering.", action: "No action needed.", exitCode: nil))
        } else if inspection.runningState == "yes" {
            findings.append(DoctorFinding(id: "filter_snapshot", state: "problem", message: "The extension is running but has no ready rule snapshot from a trusted client.", action: "Run `freesnitch mode alert` or a rules mutation to deliver a snapshot, then rerun doctor. Filtering remains fail-open until one arrives.", exitCode: CLIExitCode.snapshotMissing.rawValue))
        } else {
            findings.append(DoctorFinding(id: "filter_snapshot", state: "unknown", message: "The CLI cannot query the extension's direct XPC snapshot state on the live shipping setup, so the rule snapshot is unknown.", action: "Do not infer a missing snapshot from this finding. Use a rule mutation to test snapshot delivery; a helper-mediated health query is required for a persistent status check.", exitCode: nil))
        }
    }

    private func appendPFFinding(findings: inout [DoctorFinding], report: PFReport) {
        switch report.valid {
        case "valid", "not-installed": findings.append(DoctorFinding(id: "pf_anchor", state: "ok", message: report.message ?? "The pf anchor is healthy.", action: "No action needed.", exitCode: nil))
        case "invalid": findings.append(DoctorFinding(id: "pf_anchor", state: "problem", message: report.message ?? "The pf anchor is invalid.", action: "Remove or correct the offending rule, then retry the enforcement command. Keep `pkill -x FreeSnitch` available as the emergency fail-open escape hatch.", exitCode: CLIExitCode.pfAnchorFailure.rawValue))
        default: findings.append(DoctorFinding(id: "pf_anchor", state: "unknown", message: report.message ?? "The pf anchor could not be checked.", action: "Run doctor with the necessary local pf permissions, then retry the syntax check.", exitCode: nil))
        }
    }

    private func formatDate(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }
}
