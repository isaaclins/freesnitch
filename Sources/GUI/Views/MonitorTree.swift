import Foundation

/// The live monitor's app/destination tree, as data.
///
/// This file deliberately imports nothing but Foundation and the shared
/// models. It knows nothing about SwiftUI, AppState or HelperClient, for two
/// reasons:
///
/// 1. Grouping runs OFF the render path, on a background task, so it has to be
///    a plain value transformation that can be handed to another executor.
/// 2. `Scripts/test_monitor_tree.sh` compiles exactly this file against
///    `Sources/Shared` and proves the ordering, rollup and bounding properties
///    on the shipping code rather than on a copy of it.
///
/// Nothing here decides anything. A `MonitorRuleTarget` only describes a rule
/// the user could ask the helper to store; the helper validates and owns it.

// MARK: - Bounds

/// Every number here bounds work or output. The live monitor can hand us
/// thousands of connections several times a second, so grouping is linear in
/// the connection count and everything downstream of it is capped.
enum MonitorTreeLimits {
    /// App rows a snapshot may contain.
    static let maxApps = 200
    /// Destination rows one app may show when expanded.
    static let maxDestinationsPerApp = 120
    /// Distinct destinations tracked per app while grouping. Traffic from
    /// destinations past this cap still rolls up into the app row, it just
    /// gets no row of its own. This is what stops a port scan or a chatty
    /// resolver from turning one app into an unbounded dictionary.
    static let trackedDestinationsPerApp = 512
    /// Rows remembered by the ordering ledger. Pruned only for keys that are
    /// absent from the current snapshot, so a visible row never moves.
    static let orderLedgerCapacity = 8192
}

// MARK: - Values

struct MonitorTrafficTotals: Hashable, Sendable {
    var bytesIn: Int64 = 0
    var bytesOut: Int64 = 0

    var total: Int64 { bytesIn &+ bytesOut }

    mutating func add(bytesIn incoming: Int64, bytesOut outgoing: Int64) {
        bytesIn &+= max(0, incoming)
        bytesOut &+= max(0, outgoing)
    }
}

struct MonitorDestinationNode: Identifiable, Hashable, Sendable {
    /// Stable for the life of the destination under this app.
    let id: String
    let appID: String
    /// What the row shows: the resolved name when there is one, else the IP.
    let label: String
    /// The domain to write into a rule, when this destination has one.
    let remoteHost: String?
    /// The literal address to write into a rule, when there is no name.
    let remoteIP: String?
    let countryCode: String?
    let connectionCount: Int
    /// How many of those connections the filter denied. The Monitor never
    /// showed a connection's verdict anywhere, so the menu bar's "Recently
    /// denied" badge pointed at a list that did not exist (#138).
    let deniedCount: Int
    let traffic: MonitorTrafficTotals
    /// Arrival rank. Ordering only; never derived from traffic.
    let order: UInt64
}

struct MonitorAppNode: Identifiable, Hashable, Sendable {
    let id: String
    let name: String
    let bundleID: String?
    let path: String?
    let connectionCount: Int
    /// Denied connections, rolled up over every destination of this app.
    let deniedCount: Int
    /// Distinct destinations this app contacted, including the ones with no
    /// row of their own.
    let destinationCount: Int
    /// Rolled up over every connection of this app, including destinations
    /// that were not given a row.
    let traffic: MonitorTrafficTotals
    let destinations: [MonitorDestinationNode]
    /// Tracked destinations that did not fit `maxDestinationsPerApp`.
    let hiddenDestinationCount: Int
    /// Connections past `trackedDestinationsPerApp`: counted and rolled up,
    /// never given a row.
    let ungroupedConnectionCount: Int
    /// Largest destination total under this app, for bar scaling.
    let peakDestinationTraffic: Int64
    let order: UInt64
}

struct MonitorTreeSnapshot: Sendable {
    var apps: [MonitorAppNode] = []
    /// Apps that did not fit `maxApps`.
    var hiddenAppCount: Int = 0
    var connectionCount: Int = 0
    var peakAppTraffic: Int64 = 0
    /// Incremented once per rebuild, so a view can tell two snapshots apart.
    var revision: UInt64 = 0

    var isEmpty: Bool { apps.isEmpty }
    var destinationCount: Int { apps.reduce(0) { $0 + $1.destinationCount } }
}

// MARK: - Ordering

/// The ordering rule for the whole monitor, in one place.
///
/// **Rows are ordered by arrival and never by traffic.** The first time a key
/// (an app, or a destination under an app) is seen it is given the next rank,
/// and it keeps that rank for as long as it stays visible. Traffic counters
/// change several times a second; if they influenced order, a row would move
/// out from under the pointer between press and release and a click meant for
/// one app would land on another. That is a correctness bug, not a cosmetic
/// one, which is why ordering has no access to byte counts at all.
///
/// Keys that arrive in the same rebuild are ranked in sorted key order, so the
/// result does not depend on the order the helper happened to deliver
/// connections in.
struct MonitorRowOrder: Sendable {
    private var ranks: [String: UInt64] = [:]
    private var lastSeen: [String: UInt64] = [:]
    private var nextRank: UInt64 = 0
    private var generation: UInt64 = 0

    var trackedKeyCount: Int { ranks.count }

    func rank(of key: String) -> UInt64? { ranks[key] }

    func hasRank(_ key: String) -> Bool { ranks[key] != nil }

    mutating func beginGeneration() {
        generation &+= 1
    }

    /// Ranks a key the first time it is seen and marks it present in this
    /// generation. Re-ranking an existing key is impossible by construction.
    mutating func admit(_ key: String) {
        if ranks[key] == nil {
            ranks[key] = nextRank
            nextRank &+= 1
        }
        lastSeen[key] = generation
    }

    /// Drops keys that are absent from the current generation, and only once
    /// the ledger is over capacity. A row on screen is never forgotten.
    mutating func prune(capacity: Int = MonitorTreeLimits.orderLedgerCapacity) {
        guard ranks.count > capacity else { return }
        let current = generation
        for (key, seen) in lastSeen where seen != current {
            ranks.removeValue(forKey: key)
            lastSeen.removeValue(forKey: key)
        }
    }
}

// MARK: - Keys

enum MonitorTreeKey {
    /// Identity of an app row. A bundle id is the most stable thing we get; a
    /// path is next; a bare name is the last resort so a process with neither
    /// still groups instead of scattering one row per connection.
    static func app(_ connection: Connection) -> String {
        if let bundle = normalized(connection.processBundleId) { return "bundle\u{1}" + bundle }
        if let path = normalized(connection.processPath) { return "path\u{1}" + path }
        return "name\u{1}" + connection.processName
    }

    /// Identity of a destination row, scoped to its app so the same domain
    /// under two apps is two independent rows with independent decisions.
    static func destination(appKey: String, connection: Connection) -> String {
        appKey + "\u{2}" + host(connection)
    }

    /// The resolved name when the flow has one, else the literal address.
    static func host(_ connection: Connection) -> String {
        let name = connection.remoteHost.trimmingCharacters(in: .whitespacesAndNewlines)
        if !name.isEmpty { return name.lowercased() }
        return connection.remoteIP.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    static func normalized(_ value: String?) -> String? {
        guard let value else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}

// MARK: - Builder

struct MonitorTreeBuild: Sendable {
    let snapshot: MonitorTreeSnapshot
    let order: MonitorRowOrder
}

/// Groups a flat connection list into the two-level tree.
///
/// Pure and bounded: one linear pass over the connections, then a sort of the
/// group keys that are new in this rebuild. Never call this on the main
/// thread; `MonitorTreeController` runs it on a background task.
enum MonitorTreeBuilder {
    private struct DestinationAccumulator {
        var label: String
        var remoteHost: String?
        var remoteIP: String?
        var countryCode: String?
        var connectionCount: Int = 0
        var deniedCount: Int = 0
        var traffic = MonitorTrafficTotals()
    }

    private struct AppAccumulator {
        var name: String
        var bundleID: String?
        var path: String?
        var connectionCount: Int = 0
        var deniedCount: Int = 0
        var traffic = MonitorTrafficTotals()
        var destinations: [String: DestinationAccumulator] = [:]
        var ungroupedConnectionCount: Int = 0
    }

    static func build(connections: [Connection],
                      order incomingOrder: MonitorRowOrder,
                      revision: UInt64 = 0) -> MonitorTreeBuild {
        var apps: [String: AppAccumulator] = [:]
        apps.reserveCapacity(min(connections.count, MonitorTreeLimits.maxApps * 2))

        for connection in connections {
            let appKey = MonitorTreeKey.app(connection)
            let hostKey = MonitorTreeKey.host(connection)
            let destinationKey = appKey + "\u{2}" + hostKey

            var app = apps.removeValue(forKey: appKey) ?? AppAccumulator(
                name: displayName(for: connection),
                bundleID: MonitorTreeKey.normalized(connection.processBundleId),
                path: MonitorTreeKey.normalized(connection.processPath)
            )
            app.connectionCount += 1
            if connection.status == .denied { app.deniedCount += 1 }
            app.traffic.add(bytesIn: connection.bytesIn, bytesOut: connection.bytesOut)
            if app.bundleID == nil { app.bundleID = MonitorTreeKey.normalized(connection.processBundleId) }
            if app.path == nil { app.path = MonitorTreeKey.normalized(connection.processPath) }

            if var destination = app.destinations[destinationKey] {
                destination.connectionCount += 1
                if connection.status == .denied { destination.deniedCount += 1 }
                destination.traffic.add(bytesIn: connection.bytesIn, bytesOut: connection.bytesOut)
                if destination.countryCode == nil {
                    destination.countryCode = MonitorTreeKey.normalized(connection.countryCode)
                }
                app.destinations[destinationKey] = destination
            } else if app.destinations.count < MonitorTreeLimits.trackedDestinationsPerApp {
                var destination = newDestination(for: connection, hostKey: hostKey)
                destination.connectionCount = 1
                destination.deniedCount = connection.status == .denied ? 1 : 0
                destination.traffic.add(bytesIn: connection.bytesIn, bytesOut: connection.bytesOut)
                app.destinations[destinationKey] = destination
            } else {
                // Past the tracking cap. The bytes stay in the app rollup,
                // which is the number the user acts on; only the row is
                // dropped, and the count of what was dropped is shown.
                app.ungroupedConnectionCount += 1
            }
            apps[appKey] = app
        }

        var order = incomingOrder
        order.beginGeneration()

        // Rank whatever is new, in sorted key order, so a shuffled input
        // produces the identical tree.
        var newKeys: [String] = []
        for (appKey, app) in apps {
            if !order.hasRank(appKey) { newKeys.append(appKey) }
            for destinationKey in app.destinations.keys where !order.hasRank(destinationKey) {
                newKeys.append(destinationKey)
            }
        }
        newKeys.sort()
        for key in newKeys { order.admit(key) }
        for (appKey, app) in apps {
            order.admit(appKey)
            for destinationKey in app.destinations.keys { order.admit(destinationKey) }
        }

        var appNodes: [MonitorAppNode] = []
        appNodes.reserveCapacity(apps.count)
        for (appKey, app) in apps {
            let ranked = app.destinations
                .map { (key: $0.key, value: $0.value, rank: order.rank(of: $0.key) ?? .max) }
                .sorted { $0.rank < $1.rank }
            let shown = ranked.prefix(MonitorTreeLimits.maxDestinationsPerApp)
            let destinations = shown.map { entry in
                MonitorDestinationNode(id: entry.key,
                                       appID: appKey,
                                       label: entry.value.label,
                                       remoteHost: entry.value.remoteHost,
                                       remoteIP: entry.value.remoteIP,
                                       countryCode: entry.value.countryCode,
                                       connectionCount: entry.value.connectionCount,
                                       deniedCount: entry.value.deniedCount,
                                       traffic: entry.value.traffic,
                                       order: entry.rank)
            }
            appNodes.append(MonitorAppNode(id: appKey,
                                           name: app.name,
                                           bundleID: app.bundleID,
                                           path: app.path,
                                           connectionCount: app.connectionCount,
                                           deniedCount: app.deniedCount,
                                           destinationCount: app.destinations.count,
                                           traffic: app.traffic,
                                           destinations: destinations,
                                           hiddenDestinationCount: ranked.count - destinations.count,
                                           ungroupedConnectionCount: app.ungroupedConnectionCount,
                                           peakDestinationTraffic: destinations.map(\.traffic.total).max() ?? 0,
                                           order: order.rank(of: appKey) ?? .max))
        }
        appNodes.sort { $0.order < $1.order }
        let hiddenAppCount = max(0, appNodes.count - MonitorTreeLimits.maxApps)
        if hiddenAppCount > 0 { appNodes.removeLast(hiddenAppCount) }

        order.prune()

        let snapshot = MonitorTreeSnapshot(apps: appNodes,
                                           hiddenAppCount: hiddenAppCount,
                                           connectionCount: connections.count,
                                           peakAppTraffic: appNodes.map(\.traffic.total).max() ?? 0,
                                           revision: revision)
        return MonitorTreeBuild(snapshot: snapshot, order: order)
    }

    private static func newDestination(for connection: Connection, hostKey: String) -> DestinationAccumulator {
        let name = connection.remoteHost.trimmingCharacters(in: .whitespacesAndNewlines)
        let ip = connection.remoteIP.trimmingCharacters(in: .whitespacesAndNewlines)
        if name.isEmpty {
            return DestinationAccumulator(label: ip.isEmpty ? "Unknown destination" : ip,
                                          remoteHost: nil,
                                          remoteIP: ip.isEmpty ? nil : ip,
                                          countryCode: MonitorTreeKey.normalized(connection.countryCode))
        }
        return DestinationAccumulator(label: name,
                                      remoteHost: name,
                                      remoteIP: ip.isEmpty ? nil : ip,
                                      countryCode: MonitorTreeKey.normalized(connection.countryCode))
    }

    private static func displayName(for connection: Connection) -> String {
        if !connection.processName.isEmpty { return connection.processName }
        if !connection.processPath.isEmpty { return (connection.processPath as NSString).lastPathComponent }
        return connection.processBundleId ?? "Unknown process"
    }
}

// MARK: - Rule targets

/// What a row can ask the helper to write a rule about.
///
/// Identity is the process plus the remote endpoint, and nothing else. It
/// deliberately excludes direction, priority and the process display name, so
/// a rule stored earlier for the same app and destination is recognised as
/// this row's decision instead of producing a second, competing rule.
struct MonitorRuleTarget: Hashable, Sendable {
    enum Kind: String, Sendable {
        case app
        case destination
    }

    let kind: Kind
    let processBundleID: String?
    let processPath: String?
    let remoteHost: String?
    let remoteIP: String?

    private init(kind: Kind, processBundleID: String?, processPath: String?, remoteHost: String?, remoteIP: String?) {
        self.kind = kind
        self.processBundleID = processBundleID
        self.processPath = processPath
        self.remoteHost = remoteHost
        self.remoteIP = remoteIP
    }

    /// Every app connection, wherever it goes.
    static func app(_ node: MonitorAppNode) -> MonitorRuleTarget? {
        guard node.bundleID != nil || node.path != nil else { return nil }
        return MonitorRuleTarget(kind: .app,
                                 processBundleID: node.bundleID,
                                 processPath: node.path,
                                 remoteHost: nil,
                                 remoteIP: nil)
    }

    /// One destination of one app.
    ///
    /// A row always gets an identity, even when the endpoint is something the
    /// helper would refuse, such as a reverse-DNS name. `isAddressable` then
    /// reports false and the row shows its controls as unavailable, which is
    /// more honest than silently deciding about a different endpoint than the
    /// one the row displays.
    static func destination(_ node: MonitorDestinationNode, in app: MonitorAppNode) -> MonitorRuleTarget? {
        guard app.bundleID != nil || app.path != nil else { return nil }
        if let host = MonitorTreeKey.normalized(node.remoteHost)?.lowercased() {
            let isAddress = PFHostValidator.kind(for: host) == .ip
            return MonitorRuleTarget(kind: .destination,
                                     processBundleID: app.bundleID,
                                     processPath: app.path,
                                     remoteHost: isAddress ? nil : host,
                                     remoteIP: isAddress ? host : nil)
        }
        guard let ip = MonitorTreeKey.normalized(node.remoteIP)?.lowercased() else { return nil }
        return MonitorRuleTarget(kind: .destination,
                                 processBundleID: app.bundleID,
                                 processPath: app.path,
                                 remoteHost: nil,
                                 remoteIP: ip)
    }

    /// The target an existing rule speaks about, when it speaks about a row of
    /// this tree at all. Port-specific rules, wildcard patterns and rules with
    /// no process identity address something else and are left alone.
    static func of(_ rule: Rule) -> MonitorRuleTarget? {
        if let port = rule.remotePort, port != 0 { return nil }
        let bundle = MonitorTreeKey.normalized(rule.processBundleId)
        let path = MonitorTreeKey.normalized(rule.processPath)
        guard bundle != nil || path != nil else { return nil }
        switch remoteEndpoint(host: rule.remoteHost, ip: rule.remoteIP) {
        case .none?:
            return MonitorRuleTarget(kind: .app,
                                     processBundleID: bundle,
                                     processPath: path,
                                     remoteHost: nil,
                                     remoteIP: nil)
        case .host(let host)?:
            return MonitorRuleTarget(kind: .destination,
                                     processBundleID: bundle,
                                     processPath: path,
                                     remoteHost: host,
                                     remoteIP: nil)
        case .address(let ip)?:
            return MonitorRuleTarget(kind: .destination,
                                     processBundleID: bundle,
                                     processPath: path,
                                     remoteHost: nil,
                                     remoteIP: ip)
        case nil:
            // A wildcard, a CIDR or an endpoint we cannot read is broader, or
            // simply other, than any single row. It stays unclaimed.
            return nil
        }
    }

    private enum RemoteEndpoint {
        case none
        case host(String)
        case address(String)
    }

    /// A remote endpoint always lands in exactly one slot, so a row and a rule
    /// that mean the same destination hash the same way. An address written
    /// into `remoteHost` by an older path is recognised as an address. `nil`
    /// means the endpoint is not one row's business.
    private static func remoteEndpoint(host: String?, ip: String?) -> RemoteEndpoint? {
        let rawHost = MonitorTreeKey.normalized(host)?.lowercased()
        let rawIP = MonitorTreeKey.normalized(ip)?.lowercased()
        if let rawHost {
            if rawHost.hasPrefix("*") || rawHost.hasPrefix(".") { return nil }
            switch PFHostValidator.kind(for: rawHost) {
            case .hostname?: return .host(rawHost)
            case .ip?: return .address(rawHost)
            case .cidr?, .none: return nil
            }
        }
        guard let rawIP else { return RemoteEndpoint.none }
        return PFHostValidator.kind(for: rawIP) == nil ? nil : .address(rawIP)
    }

    /// Can the helper be asked about this endpoint at all. Validation itself
    /// still happens in the helper; this only avoids offering a control that
    /// could not possibly succeed.
    var isAddressable: Bool {
        switch kind {
        case .app:
            return processBundleID != nil || processPath != nil
        case .destination:
            if let remoteHost { return PFHostValidator.kind(for: remoteHost) != nil }
            if let remoteIP { return PFHostValidator.kind(for: remoteIP) != nil }
            return false
        }
    }
}

/// Builds the rule a row would ask for. Nothing here is enforced: the value is
/// handed to `HelperClient.addRule`, and the helper validates and stores it.
enum MonitorRuleDraft {
    static let noteApp = "Created from the monitor, app row"
    static let noteDestination = "Created from the monitor, destination row"

    static func rule(for target: MonitorRuleTarget,
                     processName: String?,
                     action: RuleAction,
                     profile: String,
                     existing: Rule?) -> Rule? {
        guard target.isAddressable else { return nil }
        if var rule = existing {
            // Same row, different answer: change the rule the user already
            // made here instead of stacking a second one beside it.
            rule.action = action
            rule.enabled = true
            return rule
        }
        return Rule(processBundleId: target.processBundleID,
                    processPath: target.processPath,
                    processName: MonitorTreeKey.normalized(processName),
                    remoteHost: target.remoteHost,
                    remoteIP: target.remoteIP,
                    remotePort: nil,
                    direction: .any,
                    action: action,
                    scope: scope(for: target),
                    priority: target.kind == .destination ? 110 : 100,
                    profile: profile,
                    groupName: nil,
                    notes: target.kind == .destination ? noteDestination : noteApp)
    }

    private static func scope(for target: MonitorRuleTarget) -> RuleScope {
        switch target.kind {
        case .app: return .process
        case .destination: return target.remoteHost != nil ? .domain : .ip
        }
    }
}

/// The rules that already exist for rows of this tree, keyed by row.
///
/// Built once per helper snapshot rather than searched per row, so a few
/// hundred rows and a few thousand rules do not multiply on the render path.
/// This is a display of stored policy, never a substitute for it: what is
/// enforced is whatever the helper and the extension hold.
struct MonitorDecisionIndex: Sendable {
    private var byTarget: [MonitorRuleTarget: Rule] = [:]

    init() {}

    init(rules: [Rule], profile: String) {
        for rule in rules {
            // Two layers can be in force at once: the always layer and the
            // selected profile. Rules of another profile are not in force and
            // must not be shown as this row's decision.
            guard rule.profile == profile || rule.profile == Profile.alwaysName else { continue }
            guard let target = MonitorRuleTarget.of(rule) else { continue }
            guard let current = byTarget[target] else {
                byTarget[target] = rule
                continue
            }
            if wins(rule, over: current) { byTarget[target] = rule }
        }
    }

    var count: Int { byTarget.count }

    func rule(for target: MonitorRuleTarget?) -> Rule? {
        guard let target else { return nil }
        return byTarget[target]
    }

    /// Same order the matcher uses: priority first, then the newer rule, with
    /// the id as a last tiebreak so the display never flickers between two
    /// equally ranked rules.
    private func wins(_ candidate: Rule, over current: Rule) -> Bool {
        if candidate.enabled != current.enabled { return candidate.enabled }
        if candidate.priority != current.priority { return candidate.priority > current.priority }
        if candidate.createdAt != current.createdAt { return candidate.createdAt > current.createdAt }
        return candidate.id.uuidString > current.id.uuidString
    }
}
