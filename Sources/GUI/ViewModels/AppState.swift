import Foundation
import SwiftUI
import AppKit
import Combine

@MainActor
final class AppState: ObservableObject {
    @Published var mode: AppMode = .alert
    @Published var connections: [Connection] = []
    @Published var rules: [Rule] = []
    @Published var blocklists: [BlocklistInfo] = []
    @Published var profiles: [Profile] = []
    @Published var activeProfile: String = "default"
    @Published var trafficHistory: [TrafficSample] = []
    @Published var currentIn: Int64 = 0
    @Published var currentOut: Int64 = 0
    @Published var totalIn: Int64 = 0
    @Published var totalOut: Int64 = 0
    @Published var deniedCount: Int = 0
    @Published var unconfirmedCount: Int = 0
    @Published var incomingCount: Int = 0
    @Published var pendingAlerts: [PendingAlert] = []
    @Published var helperConnected: Bool = false
    @Published var pfctlEnabled: Bool = false
    @Published var dnsProxyEnabled: Bool = false
    @Published var logs: [LogEntry] = []
    @Published var topProcesses: [ProcessStats] = []
    @Published var topDomains: [DomainStats] = []
    @Published var topCountries: [CountryStats] = []
    @Published var searchQuery: String = ""

    let helper = HelperClient()
    private let store: RuleStore? = {
        try? RuleStore(path: AppConstants.supportDir.appendingPathComponent("ui-cache.sqlite").path)
    }()

    struct PendingAlert: Identifiable {
        let id = UUID()
        let connection: Connection
        let reply: (Bool, Bool) -> Void
    }

    struct LogEntry: Identifiable {
        let id = UUID()
        let timestamp: Date
        let level: String
        let message: String
    }

    struct ProcessStats: Identifiable {
        let id: String
        let name: String
        let bytesIn: Int64
        let bytesOut: Int64
        let icon: NSImage?
        var total: Int64 { bytesIn + bytesOut }
    }

    struct DomainStats: Identifiable {
        let id: String
        let domain: String
        let bytesIn: Int64
        let bytesOut: Int64
        var total: Int64 { bytesIn + bytesOut }
    }

    struct CountryStats: Identifiable {
        let id: String
        let country: String
        let countryCode: String
        let bytesIn: Int64
        let bytesOut: Int64
        var total: Int64 { bytesIn + bytesOut }
    }

    init() {
        helper.state = self
    }

    func bootstrap() {
        helper.startMonitoring()
        helper.installPF()
        refreshRules()
    }

    func refreshRules() {
        helper.listRules { [weak self] rules in
            self?.rules = rules
        }
    }

    func setMode(_ m: AppMode) {
        mode = m
        helper.setMode(m)
    }

    func updateConnections(_ conns: [Connection]) {
        connections = conns
        deniedCount = conns.filter { $0.status == .denied }.count
        incomingCount = conns.filter { $0.direction == .incoming }.count
        unconfirmedCount = conns.filter { $0.status == .pending }.count
        Task { await self.recomputeAggregates() }
    }

    func appendSample(_ s: TrafficSample) {
        trafficHistory.append(s)
        if trafficHistory.count > 600 { trafficHistory.removeFirst(trafficHistory.count - 600) }
        currentIn = s.bytesIn
        currentOut = s.bytesOut
        totalIn &+= s.bytesIn
        totalOut &+= s.bytesOut
    }

    func presentAlert(for c: Connection, reply: @escaping (Bool, Bool) -> Void) {
        pendingAlerts.append(PendingAlert(connection: c, reply: reply))
    }

    func resolveAlert(_ alert: PendingAlert, allow: Bool, remember: Bool) {
        alert.reply(allow, remember)
        pendingAlerts.removeAll { $0.id == alert.id }
        if remember {
            let rule = Rule(
                processBundleId: alert.connection.processBundleId,
                processPath: alert.connection.processPath,
                processName: alert.connection.processName,
                remoteHost: alert.connection.remoteHost,
                remotePort: alert.connection.remotePort,
                direction: alert.connection.direction,
                action: allow ? .allow : .deny,
                scope: alert.connection.remoteHost.isEmpty ? .ip : .domain,
                priority: 100,
                profile: activeProfile,
                groupName: nil,
                notes: "Created from alert"
            )
            helper.addRule(rule)
            refreshRules()
        }
    }

    func appendLog(level: String, message: String) {
        let entry = LogEntry(timestamp: Date(), level: level, message: message)
        logs.append(entry)
        if logs.count > 1000 { logs.removeFirst(logs.count - 1000) }
    }

    func recomputeAggregates() async {
        let conns = self.connections
        var byProc: [String: (Int64, Int64, NSImage?)] = [:]
        var byDom: [String: (Int64, Int64)] = [:]
        var byCountry: [String: (String, Int64, Int64)] = [:]
        for c in conns {
            let pkey = c.processBundleId ?? c.processPath
            let cur = byProc[pkey] ?? (0, 0, nil)
            byProc[pkey] = (cur.0 + c.bytesIn, cur.1 + c.bytesOut, cur.2 ?? AppIcon.resolve(bundleId: c.processBundleId, path: c.processPath, name: c.processName))
            let dom = c.remoteHost.isEmpty ? c.remoteIP : c.remoteHost
            let cd = byDom[dom] ?? (0, 0)
            byDom[dom] = (cd.0 + c.bytesIn, cd.1 + c.bytesOut)
            if let cc = c.countryCode, !cc.isEmpty {
                let cur = byCountry[cc] ?? (c.country ?? cc, 0, 0)
                byCountry[cc] = (cur.0, cur.1 + c.bytesIn, cur.2 + c.bytesOut)
            }
        }
        topProcesses = byProc.map { (k, v) in
            ProcessStats(id: k, name: (k as NSString).lastPathComponent, bytesIn: v.0, bytesOut: v.1, icon: v.2)
        }.sorted { $0.total > $1.total }.prefix(20).map { $0 }
        topDomains = byDom.map { (k, v) in
            DomainStats(id: k, domain: k, bytesIn: v.0, bytesOut: v.1)
        }.sorted { $0.total > $1.total }.prefix(20).map { $0 }
        topCountries = byCountry.map { (cc, v) in
            CountryStats(id: cc, country: v.0, countryCode: cc, bytesIn: v.1, bytesOut: v.2)
        }.sorted { $0.total > $1.total }.prefix(20).map { $0 }
    }

}
