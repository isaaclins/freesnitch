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
