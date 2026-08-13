import Foundation

struct SnapshotReport: Encodable {
    let state: String
    let mode: String?
    let ruleCount: Int?
    let updatedAt: Date?
    let generation: UInt64?
    let message: String?
}

struct ExtensionReport: Encodable {
    let identifier: String
    let approval: String
    let running: String
    let filterConfiguration: String
    let filterEnabled: String
    let snapshot: SnapshotReport
    let message: String?
}

struct StatusReport: Encodable {
    let version: String
    let mode: String
    let modeLabel: String
    let enforcement: Bool
    let dohUpstream: String
    let helper: HelperReport
    let extensionStatus: ExtensionReport
}

struct HelperReport: Encodable {
    let reachable: Bool
    /// The build the helper process is running.
    let version: String
    /// The build installed on disk, which is what the helper should be running.
    let expectedVersion: String
    /// The installed build as the helper itself reads it. Absent on helpers
    /// that predate the running/installed split.
    let installedVersion: String?
    let versionMatches: Bool
    let running: Bool
    let pfctlActive: Bool
    let pfctlError: String?
    let dnsProxyActive: Bool
    let dnsProxyPort: Int
    let activeRules: Int
    let blockedToday: Int
    let policyGeneration: UInt64?
}

struct BlocklistReport: Encodable {
    let id: UUID
    let name: String
    let url: String
    let enabled: Bool
    let lastUpdated: Date?
    let entryCount: Int
}

struct RuleListReport: Encodable {
    let category: String
    let profile: String?
    let group: String?
    let blocklist: String?
    let search: String?
    let count: Int
    let rules: [Rule]
    let blocklistInfo: BlocklistInfo?
}

struct RuleMutationReport: Encodable {
    let operation: String
    let requested: [UUID]
    let succeeded: [UUID]
    let failed: [RuleMutationFailure]
    let generation: UInt64?
    let extensionSync: String
    let extensionMessage: String?
}

struct RuleMutationFailure: Encodable {
    let id: UUID
    let message: String
}

struct RuleAddedReport: Encodable {
    let rule: Rule
    let generation: UInt64?
    let extensionSync: String
    let extensionMessage: String?
}

struct RuleImportReport: Encodable {
    let imported: Int
    let ids: [UUID]
    let source: String
    let generation: UInt64?
    let extensionSync: String
    let extensionMessage: String?
}

struct PolicyChangeReport: Encodable {
    let operation: String
    let mode: String
    let ruleCount: Int
    let generation: UInt64?
    let extensionSync: String
    let extensionMessage: String?
}

// The export document itself lives in Sources/Shared/RuleExportFormat.swift so
// the GUI and the CLI read and write the same file contract.

struct RuleExportReport: Encodable {
    let count: Int
    let output: String
    let format: String
}

struct ConnectionsReport: Encodable {
    let requestedLimit: Int
    let returned: Int
    let connections: [Connection]
}

struct TrafficReport: Encodable {
    let requestedLimit: Int
    let returned: Int
    let samples: [TrafficSample]
    let note: String?
}

struct ProcessUsageReport: Encodable {
    let requestedLimit: Int
    let returned: Int
    let usage: [ProcessUsage]
}

struct AggregateSummary: Encodable {
    let requestedLimit: Int
    let topProcesses: [AggregateProcess]
    let topDomains: [AggregateDomain]
    let topCountries: [AggregateCountry]
    let countryData: String
}

struct AggregateProcess: Encodable {
    let name: String
    let processBundleId: String?
    let processPath: String?
    let bytesIn: Int64
    let bytesOut: Int64
    let totalBytes: Int64
}

struct AggregateDomain: Encodable {
    let domain: String
    let bytesIn: Int64
    let bytesOut: Int64
    let totalBytes: Int64
}

struct AggregateCountry: Encodable {
    let country: String
    let countryCode: String
    let bytesIn: Int64
    let bytesOut: Int64
    let totalBytes: Int64
}

struct SettingReport: Encodable {
    let key: String
    let label: String
    let value: String
    let changed: Bool
    let detail: String?
}

struct HelperSettingsReport: Encodable {
    let registration: String
    let reachable: Bool
    /// The build the helper process is running, when it answered.
    let version: String?
    /// The build installed on disk right now.
    let installedVersion: String?
    /// The running helper predates the installed bundle, so helper-side fixes
    /// are not active until it is restarted.
    let stale: Bool
    let detail: String?
}

struct PFReport: Encodable {
    let anchor: String
    let path: String
    let installed: String
    let valid: String
    let helperLoaded: Bool?
    let message: String?
}

struct DoctorFinding: Encodable {
    let id: String
    let state: String
    let message: String
    let action: String
    let exitCode: Int?
}

struct DoctorReport: Encodable {
    let healthy: Bool
    let findings: [DoctorFinding]
    let helper: HelperReport?
    let extensionStatus: ExtensionReport
    let pf: PFReport
}

struct VersionReport: Encodable {
    let version: String
    let cliBundleIdentifier: String
}

struct BooleanStateReport: Encodable {
    let key: String
    let label: String
    let value: Bool
}

// MARK: - Pending connection alerts

struct PendingAlertRow: Encodable {
    let id: UUID
    let process: String
    let processPath: String
    let processBundleId: String?
    let destination: String
    let address: String
    let port: Int
    let direction: String
    let protocolName: String
    let askedAt: Date
    let expiresAt: Date
    let secondsRemaining: Int

    init(_ descriptor: PendingAlertDescriptor, now: Date = Date()) {
        self.id = descriptor.id
        self.process = descriptor.processName
        self.processPath = descriptor.processPath
        self.processBundleId = descriptor.processBundleId
        self.destination = descriptor.destination
        self.address = descriptor.remoteIP
        self.port = descriptor.remotePort
        self.direction = descriptor.direction.rawValue
        self.protocolName = descriptor.protocolName
        self.askedAt = descriptor.askedAt
        self.expiresAt = descriptor.expiresAt
        self.secondsRemaining = descriptor.secondsRemaining(now: now)
    }
}

struct PendingAlertsReport: Encodable {
    let count: Int
    let appAttached: Bool
    let capacity: Int
    let alerts: [PendingAlertRow]
    /// Why the list is empty, when it is. Never omitted for an empty list.
    let reason: String?
}

struct AlertAnswerReport: Encodable {
    let id: UUID
    let state: String
    let allow: Bool?
    let decision: String?
    let answeredBy: String?
    let resolvedAt: Date?
    let scope: String?
    let remember: String
    let ruleStored: Bool
    let ruleId: UUID?
    let ruleMessage: String?
    let message: String
}

/// `freesnitch alerts ...`. Parsing lives here rather than in the shared token
/// parser so the answer shape stays next to the model it produces.
enum AlertsCommand {
    case list
    case answer(PendingAlertAnswerRequest)
}

enum AlertsCommandParser {
    static func name(for command: AlertsCommand) -> String {
        switch command {
        case .list: return "alerts list"
        case .answer: return "alerts answer"
        }
    }

    static func parse(_ tokens: [String]) throws -> AlertsCommand {
        guard let subcommand = tokens.first else {
            throw CLIError(.invalidArgument,
                           message: "alerts requires a subcommand.",
                           remediation: "Use `freesnitch alerts list` or `freesnitch alerts answer ID --allow|--deny`.")
        }
        let rest = Array(tokens.dropFirst())
        switch subcommand {
        case "list", "ls":
            guard rest.isEmpty else {
                throw CLIError(.invalidArgument,
                               message: "unexpected argument `\(rest[0])` for alerts list.",
                               remediation: "Run `freesnitch alerts list --help` for usage.")
            }
            return .list
        case "answer":
            return .answer(try parseAnswer(rest))
        default:
            throw CLIError(.invalidArgument,
                           message: "unknown alerts subcommand `\(subcommand)`.",
                           remediation: "Use list or answer.")
        }
    }

    private static func parseAnswer(_ tokens: [String]) throws -> PendingAlertAnswerRequest {
        guard let idToken = tokens.first, !idToken.hasPrefix("-") else {
            throw CLIError(.invalidArgument,
                           message: "alerts answer requires an alert ID.",
                           remediation: "Run `freesnitch alerts list` to see the pending alert IDs.")
        }
        guard let id = UUID(uuidString: idToken) else {
            throw CLIError(.invalidArgument,
                           message: "`\(idToken)` is not a valid alert ID.",
                           remediation: "Use the ID printed by `freesnitch alerts list`.")
        }

        var allow: Bool?
        var scope: PendingAlertScope?
        var remember: PendingAlertRemember?
        var index = 1
        func value(for flag: String) throws -> String {
            index += 1
            guard index < tokens.count, !tokens[index].isEmpty else {
                throw CLIError(.invalidArgument,
                               message: "\(flag) requires a value.",
                               remediation: "Run `freesnitch alerts answer --help` for usage.")
            }
            return tokens[index]
        }

        while index < tokens.count {
            let token = tokens[index]
            switch token {
            case "--allow":
                guard allow == nil else { throw conflictingDecision() }
                allow = true
            case "--deny", "--block":
                guard allow == nil else { throw conflictingDecision() }
                allow = false
            case "--scope":
                let raw = try value(for: token)
                guard let parsed = PendingAlertScope.parse(raw) else {
                    throw CLIError(.invalidArgument,
                                   message: "invalid alert scope `\(raw)`.",
                                   remediation: "Use process, domain, ip, or port.")
                }
                scope = parsed
            case "--remember":
                guard remember == nil else { throw conflictingRemember() }
                let raw = try value(for: token)
                do { remember = try PendingAlertDuration.parse(raw) }
                catch let error as PendingAlertError {
                    throw CLIError(.invalidArgument,
                                   message: error.errorDescription ?? "invalid duration `\(raw)`.",
                                   remediation: "Use forever, or a number followed by s, m, h, or d, for example `--remember 30m`.")
                }
            case "--temporary":
                guard remember == nil else { throw conflictingRemember() }
                remember = .duration(PendingAlertLimits.temporaryRememberDuration)
            default:
                throw CLIError(.invalidArgument,
                               message: "unexpected argument `\(token)` for alerts answer.",
                               remediation: "Run `freesnitch alerts answer --help` for usage.")
            }
            index += 1
        }

        guard let allow else {
            throw CLIError(.invalidArgument,
                           message: "alerts answer requires --allow or --deny.",
                           remediation: "An alert is a question about one paused flow; say which verdict to give it.")
        }
        let effectiveRemember = remember ?? .no
        if scope != nil, !effectiveRemember.storesRule {
            throw CLIError(.invalidArgument,
                           message: "--scope only applies to a remembered decision.",
                           remediation: "Add `--remember <duration>` or `--temporary`, or drop --scope to answer this flow only.")
        }
        let answer = PendingAlertAnswer(allow: allow, scope: scope, remember: effectiveRemember)
        do { try answer.validate() }
        catch let error as PendingAlertError {
            throw CLIError(.invalidArgument,
                           message: error.errorDescription ?? "the answer was rejected.",
                           remediation: "Run `freesnitch alerts answer --help` for usage.")
        }
        return PendingAlertAnswerRequest(id: id, answer: answer)
    }

    private static func conflictingDecision() -> CLIError {
        CLIError(.invalidArgument,
                 message: "use exactly one of --allow or --deny.",
                 remediation: "An alert is answered once, with one verdict.")
    }

    private static func conflictingRemember() -> CLIError {
        CLIError(.invalidArgument,
                 message: "use exactly one of --remember or --temporary.",
                 remediation: "`--temporary` is `--remember \(PendingAlertDuration.describe(PendingAlertLimits.temporaryRememberDuration))`.")
    }
}
