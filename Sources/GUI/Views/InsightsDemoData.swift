import Foundation

/// Synthetic Insights rows for the demo harness.
///
/// Insights reads through the privileged helper, so a demo build shows four
/// empty panes and a UI change to this screen cannot be reviewed before it
/// ships. That is exactly how a blank panel reached a release once. Everything
/// here is fixed, local, and gated on `FREESNITCH_DEMO`, so an installed copy
/// never reaches it.
enum InsightsDemoData {
    static var isEnabled: Bool {
        ProcessInfo.processInfo.environment["FREESNITCH_DEMO"] == "1"
    }

    private static let now = Date()

    static let apps: [InsightsAppSummary] = [
        app("company.thebrowser.Browser", "Arc", "/Applications/Arc.app", 24, 18_400, 2_968_000_000, 50_800_000),
        app("com.apple.dt.Xcode", "Xcode", "/Applications/Xcode.app", 6, 1_340, 2_272_000_000, 12_900_000),
        app("com.apple.Music", "Music", "/System/Applications/Music.app", 4, 4_820, 1_240_000_000, 6_200_000),
        app("com.hnc.Discord", "Discord", "/Applications/Discord.app", 4, 9_120, 864_000_000, 102_300_000),
        app("com.apple.Safari", "Safari", "/Applications/Safari.app", 31, 12_600, 762_000_000, 51_800_000),
        app("com.anthropic.claudefordesktop", "Claude", "/Applications/Claude.app", 3, 2_210, 322_000_000, 58_000_000),
        app("com.apple.mail", "Mail", "/System/Applications/Mail.app", 5, 3_480, 278_000_000, 36_000_000),
        app("net.whatsapp.WhatsApp", "WhatsApp", "/Applications/WhatsApp.app", 3, 6_100, 80_000_000, 30_000_000),
        app("dev.zed.Zed", "Zed", "/Applications/Zed.app", 2, 412, 51_500_000, 6_700_000)
    ]

    static func destinations(for appIdentity: String) -> [InsightsDestinationSummary] {
        switch appIdentity {
        case "company.thebrowser.Browser":
            return [
                destination(appIdentity, domain: "www.youtube.com", ip: "142.250.203.110", count: 9_400, bytesIn: 2_940_000_000, bytesOut: 48_000_000, otherApps: 1),
                destination(appIdentity, domain: "fonts.gstatic.com", ip: "2a00:1450:4001:82f::2003", count: 2_100, bytesIn: 22_800_000, bytesOut: 1_900_000, otherApps: 2),
                destination(appIdentity, domain: "stats.g.doubleclick.net", ip: "142.250.27.154", count: 610, bytesIn: 0, bytesOut: 1_200, otherApps: 3),
                destination(appIdentity, domain: nil, ip: "203.0.113.42", count: 340, bytesIn: 5_400_000, bytesOut: 900_000, otherApps: 0)
            ]
        case "com.apple.Music":
            return [
                destination(appIdentity, domain: "aod.itunes.apple.com", ip: "17.253.53.207", count: 3_910, bytesIn: 1_210_000_000, bytesOut: 4_000_000, otherApps: 0),
                destination(appIdentity, domain: "play.itunes.apple.com", ip: "17.253.53.208", count: 640, bytesIn: 21_400_000, bytesOut: 1_400_000, otherApps: 0),
                destination(appIdentity, domain: "is1-ssl.mzstatic.com", ip: "17.253.53.210", count: 210, bytesIn: 8_600_000, bytesOut: 800_000, otherApps: 2)
            ]
        case "com.hnc.Discord":
            return [
                destination(appIdentity, domain: "gateway.discord.gg", ip: "162.159.128.233", count: 7_800, bytesIn: 768_000_000, bytesOut: 95_000_000, otherApps: 0),
                destination(appIdentity, domain: "cdn.discordapp.com", ip: "162.159.130.234", count: 1_320, bytesIn: 96_000_000, bytesOut: 7_300_000, otherApps: 0)
            ]
        default:
            return [
                destination(appIdentity, domain: "github.com", ip: "140.82.121.4", count: 980, bytesIn: 286_000_000, bytesOut: 31_000_000, otherApps: 4),
                destination(appIdentity, domain: "developer.apple.com", ip: "17.253.27.204", count: 360, bytesIn: 74_000_000, bytesOut: 5_200_000, otherApps: 2)
            ]
        }
    }

    static let unresolved: [InsightsUnresolvedDestination] = [
        InsightsUnresolvedDestination(remoteIP: "203.0.113.42", connectionCount: 340, appCount: 1,
                                      appNames: ["Arc"], bytesIn: 5_400_000, bytesOut: 900_000, lastSeen: now),
        InsightsUnresolvedDestination(remoteIP: "198.51.100.77", connectionCount: 96, appCount: 1,
                                      appNames: ["Zed"], bytesIn: 8_300_000, bytesOut: 920_000, lastSeen: now),
        InsightsUnresolvedDestination(remoteIP: "192.0.2.51", connectionCount: 60, appCount: 3,
                                      appNames: [], bytesIn: 1_200_000, bytesOut: 240_000, lastSeen: now)
    ]

    static let proposals: [InsightsProposedRule] = [
        InsightsProposedRule(appIdentity: "com.hnc.Discord", appDisplayName: "Discord",
                             processBundleId: "com.hnc.Discord",
                             processPath: "/Applications/Discord.app",
                             domain: "science.discord.com", remoteIP: nil,
                             connectionCount: 412, otherAppCount: 0, lastSeen: now),
        InsightsProposedRule(appIdentity: "company.thebrowser.Browser", appDisplayName: "Arc",
                             processBundleId: "company.thebrowser.Browser", processPath: "/Applications/Arc.app",
                             domain: "stats.g.doubleclick.net", remoteIP: nil,
                             connectionCount: 610, otherAppCount: 3, lastSeen: now),
        InsightsProposedRule(appIdentity: "dev.zed.Zed", appDisplayName: "Zed",
                             processBundleId: "dev.zed.Zed", processPath: "/Applications/Zed.app",
                             domain: nil, remoteIP: "198.51.100.77",
                             connectionCount: 96, otherAppCount: 0, lastSeen: now)
    ]

    static let findings: [InsightsBehaviourFinding] = [
        InsightsBehaviourFinding(appIdentity: "com.hnc.Discord", displayName: "Discord",
                                 oldVersion: "0.0.312", newVersion: "0.0.318",
                                 destination: "science.discord.com", firstSeen: now,
                                 connectionCount: 128, versionKnown: true),
        InsightsBehaviourFinding(appIdentity: "net.whatsapp.WhatsApp", displayName: "WhatsApp",
                                 oldVersion: nil, newVersion: nil,
                                 destination: "crashlogs.whatsapp.net", firstSeen: now,
                                 connectionCount: 44, versionKnown: false)
    ]

    private static func app(_ identity: String, _ name: String, _ path: String,
                            _ destinations: Int, _ connections: Int,
                            _ bytesIn: Int64, _ bytesOut: Int64) -> InsightsAppSummary {
        InsightsAppSummary(appIdentity: identity, displayName: name,
                           processBundleId: identity.contains(".") ? identity : nil,
                           processPath: path,
                           destinationCount: destinations, connectionCount: connections,
                           bytesIn: bytesIn, bytesOut: bytesOut, lastSeen: now)
    }

    private static func destination(_ identity: String, domain: String?, ip: String?,
                                    count: Int, bytesIn: Int64, bytesOut: Int64,
                                    otherApps: Int) -> InsightsDestinationSummary {
        InsightsDestinationSummary(appIdentity: identity,
                                   destinationKey: domain ?? ip ?? "",
                                   resolvedDomain: domain,
                                   remoteIP: ip,
                                   connectionCount: count,
                                   bytesIn: bytesIn,
                                   bytesOut: bytesOut,
                                   otherAppCount: otherApps,
                                   lastSeen: now)
    }
}
