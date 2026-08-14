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
        app("com.spotify.client", "Spotify", "/Applications/Spotify.app", 6, 4_820, 3_580_000_000, 42_000_000),
        app("com.google.Chrome", "Google Chrome", "/Applications/Google Chrome.app", 24, 18_400, 1_240_000_000, 96_000_000),
        app("com.hnc.Discord", "Discord", "/Applications/Discord.app", 4, 9_120, 768_000_000, 95_000_000),
        app("com.googlecode.iterm2", "iTerm", "/Applications/iTerm.app", 9, 1_340, 482_000_000, 41_000_000),
        app("com.microsoft.VSCode", "Visual Studio Code", "/Applications/Visual Studio Code.app", 7, 880, 51_500_000, 6_700_000),
        app("com.tinyspeck.slackmacgap", "Slack", "/Applications/Slack.app", 3, 6_210, 285_000_000, 26_000_000),
        app("claude", "claude", "/usr/local/bin/claude", 1, 412, 322_000_000, 18_000_000),
        app("co.corecode.MacUpdater", "MacUpdater", "/Applications/MacUpdater.app", 2, 96, 8_300_000, 920_000)
    ]

    static func destinations(for appIdentity: String) -> [InsightsDestinationSummary] {
        switch appIdentity {
        case "com.spotify.client":
            return [
                destination(appIdentity, domain: "audio-fa.scdn.co", ip: "104.199.65.9", count: 3_910, bytesIn: 3_370_000_000, bytesOut: 28_000_000, otherApps: 0),
                destination(appIdentity, domain: "apresolve.spotify.com", ip: "35.186.224.25", count: 640, bytesIn: 12_400_000, bytesOut: 2_100_000, otherApps: 0),
                destination(appIdentity, domain: "spclient.wg.spotify.com", ip: "35.186.224.47", count: 210, bytesIn: 9_800_000, bytesOut: 4_300_000, otherApps: 0),
                destination(appIdentity, domain: nil, ip: "192.0.2.51", count: 60, bytesIn: 1_200_000, bytesOut: 240_000, otherApps: 2)
            ]
        case "com.google.Chrome":
            return [
                destination(appIdentity, domain: "www.googleapis.com", ip: "142.250.74.234", count: 8_400, bytesIn: 148_000_000, bytesOut: 18_600_000, otherApps: 3),
                destination(appIdentity, domain: "fonts.gstatic.com", ip: "2a00:1450:4001:82f::2003", count: 2_100, bytesIn: 22_800_000, bytesOut: 1_900_000, otherApps: 1),
                destination(appIdentity, domain: nil, ip: "203.0.113.42", count: 340, bytesIn: 5_400_000, bytesOut: 900_000, otherApps: 0)
            ]
        case "com.hnc.Discord":
            return [
                destination(appIdentity, domain: "gateway.discord.gg", ip: "162.159.128.233", count: 7_800, bytesIn: 768_000_000, bytesOut: 95_000_000, otherApps: 0),
                destination(appIdentity, domain: "cdn.discordapp.com", ip: "162.159.130.234", count: 1_320, bytesIn: 96_000_000, bytesOut: 7_300_000, otherApps: 0)
            ]
        default:
            return [
                destination(appIdentity, domain: "github.com", ip: "140.82.121.4", count: 980, bytesIn: 482_000_000, bytesOut: 41_000_000, otherApps: 4),
                destination(appIdentity, domain: "registry.npmjs.org", ip: "2606:4700::6810:1b23", count: 360, bytesIn: 74_000_000, bytesOut: 5_200_000, otherApps: 2)
            ]
        }
    }

    static let unresolved: [InsightsUnresolvedDestination] = [
        InsightsUnresolvedDestination(remoteIP: "198.51.100.77", connectionCount: 96, appCount: 1,
                                      appNames: ["MacUpdater"], bytesIn: 8_300_000, bytesOut: 920_000, lastSeen: now),
        InsightsUnresolvedDestination(remoteIP: "149.154.167.51", connectionCount: 64, appCount: 1,
                                      appNames: ["Telegram"], bytesIn: 78_000_000, bytesOut: 14_000_000, lastSeen: now),
        InsightsUnresolvedDestination(remoteIP: "203.0.113.42", connectionCount: 340, appCount: 2,
                                      appNames: ["Google Chrome", "Setapp"], bytesIn: 5_400_000, bytesOut: 900_000, lastSeen: now),
        InsightsUnresolvedDestination(remoteIP: "192.0.2.51", connectionCount: 60, appCount: 3,
                                      appNames: [], bytesIn: 1_200_000, bytesOut: 240_000, lastSeen: now)
    ]

    static let proposals: [InsightsProposedRule] = [
        InsightsProposedRule(appIdentity: "com.adobe.acc.AdobeCreativeCloud", appDisplayName: "Adobe CC",
                             processBundleId: "com.adobe.acc.AdobeCreativeCloud",
                             processPath: "/Applications/Adobe Creative Cloud.app",
                             domain: "cc-api-data.adobe.io", remoteIP: nil,
                             connectionCount: 412, otherAppCount: 2, lastSeen: now),
        InsightsProposedRule(appIdentity: "com.google.Chrome", appDisplayName: "Google Chrome",
                             processBundleId: "com.google.Chrome", processPath: "/Applications/Google Chrome.app",
                             domain: "update.googleapis.com", remoteIP: nil,
                             connectionCount: 88, otherAppCount: 0, lastSeen: now),
        InsightsProposedRule(appIdentity: "co.corecode.MacUpdater", appDisplayName: "MacUpdater",
                             processBundleId: "co.corecode.MacUpdater", processPath: "/Applications/MacUpdater.app",
                             domain: nil, remoteIP: "198.51.100.77",
                             connectionCount: 96, otherAppCount: 0, lastSeen: now)
    ]

    static let findings: [InsightsBehaviourFinding] = [
        InsightsBehaviourFinding(appIdentity: "com.hnc.Discord", displayName: "Discord",
                                 oldVersion: "0.0.312", newVersion: "0.0.318",
                                 destination: "science.discord.com", firstSeen: now,
                                 connectionCount: 128, versionKnown: true),
        InsightsBehaviourFinding(appIdentity: "com.tinyspeck.slackmacgap", displayName: "Slack",
                                 oldVersion: nil, newVersion: nil,
                                 destination: "telemetry.slack.com", firstSeen: now,
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
