import Foundation

public enum RuleAction: String, Codable, CaseIterable, Sendable {
    case allow
    case deny
    case ask
}

public enum RuleDirection: String, Codable, CaseIterable, Sendable {
    case outgoing
    case incoming
    case any
}

public enum RuleScope: String, Codable, CaseIterable, Sendable {
    case process
    case domain
    case ip
    case port
    case any
}

public enum AppMode: String, Codable, CaseIterable, Sendable {
    case alert
    case silentAllow
    case silentDeny
}

public struct Rule: Identifiable, Codable, Hashable, Sendable {
    public var id: UUID
    public var processBundleId: String?
    /// Who signed the app this rule's bundle id was made for (#364): its team
    /// id, or `CodeSigningIdentity.appleTeam` for Apple's own code. An allow
    /// or ask rule only matches a process signed by this team, so another
    /// developer cannot sign a binary with the app's identifier and inherit
    /// its rules. Nil until known: a rule from before #364, or one written
    /// by hand, learns it the first time its app is seen.
    public var processTeamId: String?
    public var processPath: String?
    public var processName: String?
    public var remoteHost: String?
    public var remoteIP: String?
    public var remotePort: Int?
    public var direction: RuleDirection
    public var action: RuleAction
    public var scope: RuleScope
    public var priority: Int
    public var profile: String
    public var groupName: String?
    public var notes: String?
    public var enabled: Bool
    public var temporary: Bool
    public var createdAt: Date
    public var expiresAt: Date?
    public var lastUsedAt: Date?
    public var hitCount: Int

    public init(
        id: UUID = UUID(),
        processBundleId: String? = nil,
        processTeamId: String? = nil,
        processPath: String? = nil,
        processName: String? = nil,
        remoteHost: String? = nil,
        remoteIP: String? = nil,
        remotePort: Int? = nil,
        direction: RuleDirection = .outgoing,
        action: RuleAction = .ask,
        scope: RuleScope = .domain,
        priority: Int = 100,
        profile: String = Profile.alwaysName,
        groupName: String? = nil,
        notes: String? = nil,
        enabled: Bool = true,
        temporary: Bool = false,
        createdAt: Date = Date(),
        expiresAt: Date? = nil,
        lastUsedAt: Date? = nil,
        hitCount: Int = 0
    ) {
        self.id = id
        self.processBundleId = processBundleId
        self.processTeamId = processTeamId
        self.processPath = processPath
        self.processName = processName
        self.remoteHost = remoteHost
        self.remoteIP = remoteIP
        self.remotePort = remotePort
        self.direction = direction
        self.action = action
        self.scope = scope
        self.priority = priority
        self.profile = profile
        self.groupName = groupName
        self.notes = notes
        self.enabled = enabled
        self.temporary = temporary
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.lastUsedAt = lastUsedAt
        self.hitCount = hitCount
    }
}

public struct Connection: Identifiable, Codable, Hashable, Sendable {
    /// The process name on the DNS proxy's alerts. The proxy cannot tell
    /// which app sent a lookup, so a rule remembered from such an alert
    /// carries this name and no app, and covers every app's lookups.
    public static let dnsLookupProcessName = "dns"

    public enum Status: String, Codable, Sendable {
        case allowed
        case denied
        case pending
        case established
        case closed
    }

    public var id: UUID
    public var pid: Int32
    public var processName: String
    public var processPath: String
    /// The bundle id from the process's valid, Apple-issued code signature
    /// (#351). The only bundle id an allow or ask rule matches, and the one
    /// new rules are written with.
    public var processBundleId: String?
    /// The team that signed `processBundleId` (#364), or
    /// `CodeSigningIdentity.appleTeam` for Apple's own code. Nil exactly when
    /// there is no signed bundle id.
    public var processTeamId: String?
    /// The bundle id the app's unsigned Info.plist claims, when it differs
    /// from `processBundleId` or there is no signed one. Anyone can write it,
    /// so it can only ever make a deny rule match: claiming another app's id
    /// can get a binary blocked, never let through.
    public var claimedBundleId: String?
    public var localPort: Int
    public var remoteHost: String
    public var remoteIP: String
    public var remotePort: Int
    public var direction: RuleDirection
    public var status: Status
    public var protocolName: String
    public var bytesIn: Int64
    public var bytesOut: Int64
    public var country: String?
    public var countryCode: String?
    /// The city the coordinates belong to. Nil means the geolocation database
    /// knew only the country, and `latitude`/`longitude` are then the country
    /// centroid rather than a place anyone connected to.
    public var city: String?
    public var latitude: Double?
    public var longitude: Double?
    public var firstSeen: Date
    public var lastSeen: Date
    /// A name this address was recently seen under, for display when the
    /// connection itself carries only the address (#168). Never a rule target:
    /// rules are written from `remoteHost` and `remoteIP`.
    public var resolvedName: String?

    public init(
        id: UUID = UUID(),
        pid: Int32,
        processName: String,
        processPath: String,
        processBundleId: String? = nil,
        processTeamId: String? = nil,
        claimedBundleId: String? = nil,
        localPort: Int = 0,
        remoteHost: String = "",
        remoteIP: String = "",
        remotePort: Int = 0,
        direction: RuleDirection = .outgoing,
        status: Status = .pending,
        protocolName: String = "tcp",
        bytesIn: Int64 = 0,
        bytesOut: Int64 = 0,
        country: String? = nil,
        countryCode: String? = nil,
        city: String? = nil,
        latitude: Double? = nil,
        longitude: Double? = nil,
        firstSeen: Date = Date(),
        lastSeen: Date = Date()
    ) {
        self.id = id
        self.pid = pid
        self.processName = processName
        self.processPath = processPath
        self.processBundleId = processBundleId
        self.processTeamId = processTeamId
        self.claimedBundleId = claimedBundleId
        self.localPort = localPort
        self.remoteHost = remoteHost
        self.remoteIP = remoteIP
        self.remotePort = remotePort
        self.direction = direction
        self.status = status
        self.protocolName = protocolName
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
        self.country = country
        self.countryCode = countryCode
        self.city = city
        self.latitude = latitude
        self.longitude = longitude
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
    }
}

extension Connection {
    /// One row per socket: the latest. The helper saves every open connection
    /// again on each poll, under a new id and with the bytes that socket had
    /// moved by then, so summing saved rows counted one socket once per poll
    /// (#466). Order follows the first row seen for each socket.
    public static func latestPerSocket(_ connections: [Connection]) -> [Connection] {
        struct Key: Hashable {
            let pid: Int32
            let localPort: Int
            let remoteIP: String
            let remotePort: Int
            let protocolName: String
            let direction: RuleDirection
        }
        var order: [Key] = []
        var latest: [Key: Connection] = [:]
        for connection in connections {
            let key = Key(pid: connection.pid, localPort: connection.localPort, remoteIP: connection.remoteIP,
                          remotePort: connection.remotePort, protocolName: connection.protocolName,
                          direction: connection.direction)
            guard let kept = latest[key] else {
                order.append(key)
                latest[key] = connection
                continue
            }
            let newer = connection.lastSeen != kept.lastSeen
                ? connection.lastSeen > kept.lastSeen
                : connection.bytesIn + connection.bytesOut > kept.bytesIn + kept.bytesOut
            if newer { latest[key] = connection }
        }
        return order.compactMap { latest[$0] }
    }
}

public struct Profile: Identifiable, Codable, Hashable, Sendable {
    public static let alwaysName = "always"
    public static let defaultName = "default"

    public var id: UUID
    public var name: String
    public var mode: AppMode
    public var icon: String
    public var isActive: Bool
    /// Blocklists selected for this profile. The set is intentionally separate
    /// from the global BlocklistInfo.enabled field, which is retained for
    /// compatibility with older helpers and exports.
    public var blocklistIDs: Set<UUID>

    public init(
        id: UUID = UUID(),
        name: String,
        mode: AppMode = .alert,
        icon: String = "shield",
        isActive: Bool = false,
        blocklistIDs: Set<UUID> = []
    ) {
        self.id = id
        self.name = name
        self.mode = mode
        self.icon = icon
        self.isActive = isActive
        self.blocklistIDs = blocklistIDs
    }
}

/// A network fingerprint explicitly associated with one profile by the user.
/// The gateway MAC is stored in canonical lower-case colon notation.
public struct ProfileNetworkBinding: Identifiable, Codable, Hashable, Sendable {
    public var id: UUID
    public var profileName: String
    public var gatewayMAC: String
    public var createdAt: Date

    public init(
        id: UUID = UUID(),
        profileName: String,
        gatewayMAC: String,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.profileName = profileName
        self.gatewayMAC = gatewayMAC
        self.createdAt = createdAt
    }
}

/// The result shown to the user after a profile switch. A switch is reversible
/// once, until another switch replaces this undo point.
public struct ProfileSwitchNotice: Codable, Hashable, Sendable {
    public var activeProfile: String
    public var activeRuleCount: Int
    public var pausedProfile: String?
    public var pausedRuleCount: Int
    public var canUndo: Bool

    public init(
        activeProfile: String,
        activeRuleCount: Int,
        pausedProfile: String? = nil,
        pausedRuleCount: Int = 0,
        canUndo: Bool = true
    ) {
        self.activeProfile = activeProfile
        self.activeRuleCount = activeRuleCount
        self.pausedProfile = pausedProfile
        self.pausedRuleCount = pausedRuleCount
        self.canUndo = canUndo
    }

    public var message: String {
        guard let pausedProfile, pausedRuleCount > 0 else { return String(localized: "\(activeRuleCount) rules active") }
        return String(localized: "\(activeRuleCount) rules active, \(pausedRuleCount) \(pausedProfile) rules paused")
    }
}

/// One authoritative policy assembled from exactly two rule layers: Always and
/// the selected profile. Blocklists are deny-only sets and may be accumulated
/// independently without adding another allow layer.
public struct ProfilePolicy: Hashable, Sendable {
    public let profile: Profile
    public let alwaysRules: [Rule]
    public let profileRules: [Rule]
    public let rules: [Rule]
    public let selectedBlocklistIDs: Set<UUID>

    public init(
        profile: Profile,
        alwaysRules: [Rule],
        profileRules: [Rule],
        selectedBlocklistIDs: Set<UUID> = []
    ) {
        self.profile = profile
        self.alwaysRules = alwaysRules
        self.profileRules = profile.name == Profile.alwaysName ? [] : profileRules
        self.rules = self.alwaysRules + self.profileRules
        self.selectedBlocklistIDs = selectedBlocklistIDs
    }

    /// The rule layer count is deliberately fixed. There is no profile parent
    /// or inherited allow layer that could make precedence ambiguous.
    public var allowLayerCount: Int {
        profileRules.isEmpty ? 1 : 2
    }

    public var activeRuleCount: Int {
        rules.filter(\.enabled).count
    }

    public var activeProfileRuleCount: Int {
        profileRules.filter(\.enabled).count
    }

    public var denyRuleCount: Int {
        rules.filter { $0.enabled && $0.action == .deny }.count
    }
}

public struct TrafficSample: Codable, Sendable {
    public let timestamp: Date
    public let bytesIn: Int64
    public let bytesOut: Int64
    public init(timestamp: Date, bytesIn: Int64, bytesOut: Int64) {
        self.timestamp = timestamp
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
    }
}

public struct ProcessUsage: Codable, Sendable {
    public let processName: String
    public let pid: Int32?
    public let bytesIn: Int64
    public let bytesOut: Int64
    public init(processName: String, pid: Int32?, bytesIn: Int64, bytesOut: Int64) {
        self.processName = processName
        self.pid = pid
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
    }
}

/// One DNS proxy listener that stopped serving: which transport, on which
/// loopback address, and why (#265).
public struct DNSListenerFailure: Codable, Sendable, Hashable {
    /// "udp" or "tcp".
    public let transport: String
    /// The loopback address the listener was bound to, "127.0.0.1" or "::1".
    public let address: String
    public let reason: String
    public init(transport: String, address: String, reason: String) {
        self.transport = transport
        self.address = address
        self.reason = reason
    }
}

public struct HelperStatus: Codable, Sendable {
    /// The build the helper process is actually running. Captured when the
    /// process started, so an in-place update cannot change it under a daemon
    /// that was never restarted.
    public let version: String
    public let running: Bool
    public let pfctlActive: Bool
    public let pfctlError: String?
    public let dnsProxyActive: Bool
    /// Whether anything FreeSnitch runs can still block: the pf anchor is
    /// loaded or the DNS proxy is listening. A turn-off that could not empty
    /// the anchor leaves pf on with the proxy stopped, and that is not off
    /// (issue #211).
    public var enforcementActive: Bool { pfctlActive || dnsProxyActive }
    public let dnsProxyPort: Int
    public let activeRules: Int
    public let blockedToday: Int
    /// The mode the helper restored from its store. The GUI defaults to
    /// `.alert` before it connects, so without this the two disagree after a
    /// restart and the GUI's default overwrites the user's real choice.
    public var mode: AppMode = .alert
    /// Optional for decoding status payloads from older helpers.
    public var policyGeneration: UInt64?
    /// The build currently installed on disk, read when the status was built.
    /// Different from `version` exactly when the helper is stale. Optional so
    /// status payloads from helpers that predate #36 still decode.
    public var installedVersion: String?
    /// The app copy the helper process was started from, frozen at process
    /// start. launchd keeps running the helper from the copy that registered
    /// it, which is not the copy the user opens once FreeSnitch has been moved
    /// or copied to another Applications folder (#418). Optional so status
    /// payloads from older helpers still decode.
    public var appPath: String?
    /// The proxy listeners that failed since the proxy last started, so the
    /// status can say which DNS transports are still serving instead of one
    /// running flag for all four (#265). Optional so status payloads from
    /// older helpers still decode.
    public var dnsProxyFailedListeners: [DNSListenerFailure]?
    public init(version: String, running: Bool, pfctlActive: Bool, pfctlError: String? = nil, dnsProxyActive: Bool, dnsProxyPort: Int, activeRules: Int, blockedToday: Int, mode: AppMode = .alert, policyGeneration: UInt64? = nil, installedVersion: String? = nil, appPath: String? = nil, dnsProxyFailedListeners: [DNSListenerFailure]? = nil) {
        self.appPath = appPath
        self.dnsProxyFailedListeners = dnsProxyFailedListeners
        self.mode = mode
        self.policyGeneration = policyGeneration
        self.installedVersion = installedVersion
        self.version = version
        self.running = running
        self.pfctlActive = pfctlActive
        self.pfctlError = pfctlError
        self.dnsProxyActive = dnsProxyActive
        self.dnsProxyPort = dnsProxyPort
        self.activeRules = activeRules
        self.blockedToday = blockedToday
    }

    /// The DNS proxy's state in one phrase: "running", "stopped", or which
    /// listeners failed, so a partial failure reads as partial (#265).
    public var dnsProxySummary: String {
        let failed = dnsProxyFailedListeners ?? []
        guard !failed.isEmpty else { return dnsProxyActive ? "running" : "stopped" }
        let detail = failed
            .map { "\($0.transport.uppercased()) on \($0.address) failed (\($0.reason))" }
            .joined(separator: ", ")
        // The proxy's two loopback addresses (DNSProxyAddress). Spelled out
        // here because harnesses compile this file without that one.
        let all = Set(["127.0.0.1", "::1"].flatMap { address in
            ["udp", "tcp"].map { "\($0) \(address)" }
        })
        let down = Set(failed.map { "\($0.transport) \($0.address)" })
        if all.isSubset(of: down) { return "not serving, " + detail }
        return (dnsProxyActive ? "running, but " : "only partly running, ") + detail
    }
}

public struct BlocklistInfo: Codable, Sendable, Identifiable, Hashable {
    public var id: UUID
    public var name: String
    public var url: String
    public var enabled: Bool
    public var lastUpdated: Date?
    public var entryCount: Int
    public init(id: UUID = UUID(), name: String, url: String, enabled: Bool = true, lastUpdated: Date? = nil, entryCount: Int = 0) {
        self.id = id
        self.name = name
        self.url = url
        self.enabled = enabled
        self.lastUpdated = lastUpdated
        self.entryCount = entryCount
    }
}

public struct AppConstants {
    public static let bundleIdGUI = "io.isaaclins.freesnitch"
    public static let bundleIdCLI = "io.isaaclins.freesnitch.cli"
    public static let bundleIdHelper = "io.isaaclins.freesnitch.helper"
    public static let bundleIdNetExt = "io.isaaclins.freesnitch.netext"
    public static let xpcMachServiceName = "io.isaaclins.freesnitch.helper"
    /// App<->extension XPC. Must be prefixed by an app group the process owns,
    /// so a regular (non-daemon) app can vend it via NSXPCListener.
    public static let ipcMachServiceName = "BHAF4L4726.io.isaaclins.freesnitch.ipc"
    public static let appGroup = "BHAF4L4726.io.isaaclins.freesnitch"
    public static let teamID = "BHAF4L4726"
    public static let version: String =
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.2.0"

    /// The build number, when the running code has an Info.plist to read it
    /// from. A bare command line tool has none, so this is optional rather
    /// than defaulted: a wrong build number is worse than an absent one.
    public static let buildNumber: String? =
        Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String

    /// Marketing version plus build, for example "0.2.0 (12)".
    ///
    /// The marketing version alone cannot identify a build. Every build of
    /// this release reports "0.2.0", so a helper left over from an earlier
    /// build answers with a version identical to the running app and a stale
    /// helper stays invisible. That is exactly the incident behind #24, where
    /// a build 10 helper served a build 11 app and the pf fix silently never
    /// took effect.
    public static var buildIdentity: String {
        guard let buildNumber else { return version }
        return "\(version) (\(buildNumber))"
    }

    /// Does a peer's reported identity describe the build we expect.
    ///
    /// The comparison is deliberately asymmetric.
    ///
    /// `expected` comes from a real bundle and normally knows its build
    /// number. When it does, a peer that reports no build number is a helper
    /// built before this check existed, and being unable to answer the
    /// question is itself proof that it is stale. Treating that as a match was
    /// the first version of this fix, and it meant the very first upgrade
    /// carrying the fix could not detect the stale helper it was written for.
    ///
    /// When `expected` has no build number, typically a CLI running outside an
    /// app bundle, nothing can be proven, so fall back to the marketing
    /// version. A mismatch we cannot demonstrate must not be reported: a
    /// firewall that cries wolf gets ignored.
    public static func identityMatches(reported: String, expected: String) -> Bool {
        if reported == expected { return true }
        guard expected.contains("(") else {
            return marketingVersion(of: reported) == marketingVersion(of: expected)
        }
        return false
    }

    private static func marketingVersion(of identity: String) -> String {
        identity.split(separator: " ").first.map(String.init) ?? identity
    }
    /// The privileged recovery command for replacing a stale helper. Shared so
    /// the GUI banner and the CLI doctor cannot drift into telling the user two
    /// different things.
    /// Emitted by the helper when the active profile changes, so a connected
    /// GUI resynchronizes from the helper-owned snapshot instead of guessing.
    public static let profilePolicyChangedLogMessage = "Active profile policy changed; resynchronizing."
    /// Sent when rules learned the team that signs their app (#364), so the
    /// GUI hands the extension the policy that carries it.
    public static let ruleSigningTeamsLearnedLogMessage = "Rules learned the signing team of their app; resynchronizing."
    /// Sent when an automatic profile switch fails or stops failing (#269), so
    /// the GUI shows the current state of it without waiting for a refresh.
    public static let profileNetworkSwitchStateChangedLogMessage = "Automatic profile switch state changed; resynchronizing."

    public static let helperKickstartCommand =
        "sudo launchctl kickstart -k system/io.isaaclins.freesnitch.helper"

    /// The same restart, without `sudo`, for the already-root helper to run on
    /// itself when the signed GUI asks it to finish an update. Never a bootout,
    /// never an unregister: #24 showed that path can delete the service.
    public static let helperKickstartArguments =
        ["kickstart", "-k", "system/io.isaaclins.freesnitch.helper"]

    public static let dnsProxyPort: UInt16 = 53
    public static let defaultDoHUpstream = "https://cloudflare-dns.com/dns-query"

    public static var supportDir: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        let dir = base.appendingPathComponent("FreeSnitch", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }
}
