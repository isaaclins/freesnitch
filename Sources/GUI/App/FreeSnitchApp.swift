import SwiftUI
import AppKit

@main
struct FreeSnitchApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    private let sparkleUpdater = SparkleUpdaterController()

    /// Command-1 for the first sidebar row, and so on. Beyond nine there is no
    /// digit left to press, so those pages keep the menu item without a
    /// shortcut rather than being given an arbitrary one.
    private func pageShortcut(_ index: Int) -> KeyEquivalent {
        KeyEquivalent(Character(String(index + 1)))
    }

    var body: some Scene {
        // An App needs a scene, and the app menu's Settings item plus ⌘, come
        // from this one existing. Its content is a redirector rather than the
        // settings UI: Settings is a page of the main window now (#63), so
        // this scene hands the request over and closes itself before it is
        // ever seen.
        Settings {
            SettingsSceneRedirect { delegate.windowManager?.showSettings() }
        }
        .commands {
            CommandGroup(after: .appInfo) {
                CheckForUpdatesView(updater: sparkleUpdater.updater)
                Divider()
                // Positional, not mnemonic: these switch between sidebar
                // pages, and every Mac app with a sidebar or tabs binds that to
                // Command-1 through Command-n. Letter mnemonics belong to
                // commands, and Command-Option-N in particular read as "new".
                // Numbering here follows MainPage.allCases, which is the same
                // order the sidebar draws, so the number you press is the row
                // you see and reordering the sidebar cannot make a shortcut lie.
                ForEach(Array(MainPage.allCases.enumerated()), id: \.element.id) { index, page in
                    Button(page.title) {
                        delegate.windowManager.showPage(page)
                    }
                    .keyboardShortcut(pageShortcut(index), modifiers: .command)
                }
            }
            // Command-F, where every Mac app keeps it. It focuses the search
            // field the current page shows rather than opening a find bar of
            // its own (#96).
            CommandGroup(after: .textEditing) {
                Button("Find") { delegate.windowManager.focusSearch() }
                    .keyboardShortcut("f", modifiers: .command)
            }
        }
    }
}

/// Sends the standard Settings action to the Settings page of the main window.
///
/// SwiftUI opens the settings scene's window before any SwiftUI lifecycle
/// callback runs, so the window is hidden the moment this view is installed in
/// it and closed on the next turn of the run loop. The user sees the main
/// window switch to Settings, never a second window.
struct SettingsSceneRedirect: NSViewRepresentable {
    let openSettingsPage: () -> Void

    func makeNSView(context: Context) -> NSView { RedirectingView(open: openSettingsPage) }

    func updateNSView(_ nsView: NSView, context: Context) {}

    final class RedirectingView: NSView {
        private let open: () -> Void

        init(open: @escaping () -> Void) {
            self.open = open
            super.init(frame: .zero)
        }

        @available(*, unavailable)
        required init?(coder: NSCoder) { fatalError("not used") }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            guard let window = window else { return }
            window.alphaValue = 0
            window.setIsVisible(false)
            DispatchQueue.main.async { [weak window, open] in
                window?.close()
                open()
            }
        }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let state: AppState
    let systemExtension: SystemExtensionManager
    var menubar: MenubarController!
    var windowManager: WindowManager!

    override init() {
        // Freeze the identity of the bundle this process launched from, so a
        // later in-place update cannot change what this app claims to be.
        AppBundleIdentity.captureRunningIdentity()
        let state = AppState()
        self.state = state
        self.systemExtension = SystemExtensionManager(state: state)
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        windowManager = WindowManager(state: state, systemExtension: systemExtension)
        menubar = MenubarController(state: state, systemExtension: systemExtension, windows: windowManager)
        menubar.install()
        state.helper.registerDaemon()
        // bootstrap() (rule load + monitoring) is driven by HelperClient once
        // the helper is actually reachable. See HelperClient.setConnected.
        state.helper.connect()
        // Seed the initial rule snapshot so the network extension receives the
        // current mode and rules as soon as its XPC listener is available.
        state.syncSharedRules()

        // Per-process firewall (Network System Extension). `activate()` is a
        // no-op unless this build embeds one. The monitor-only build does
        // not, so no extension approval prompt appears.
        if ProcessInfo.processInfo.environment["FREESNITCH_DEMO"] != "1" {
            systemExtension.activate()
        }

        // A menu-bar-only app that shows nothing on first launch reads as
        // broken. Open the monitor once so the helper-approval banner is
        // actually seen.
        if ProcessInfo.processInfo.environment["FREESNITCH_DEMO"] != "1",
           !UserDefaults.standard.bool(forKey: "PSDidFirstRun") {
            UserDefaults.standard.set(true, forKey: "PSDidFirstRun")
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
                self?.windowManager.showNetworkMonitor()
            }
        }

        if ProcessInfo.processInfo.environment["FREESNITCH_DEMO"] == "1" {
            seedDemoState()
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.7) {
                switch ProcessInfo.processInfo.environment["FREESNITCH_DEMO_WINDOW"] {
                case "monitor": self.windowManager.showNetworkMonitor()
                case "rules": self.windowManager.showRulesManager()
                case "insights": self.windowManager.showInsights()
                case "profiles": self.windowManager.showProfiles()
                case "settings": self.windowManager.showSettings()
                // The connection alert is the app's most consequential screen
                // and the only one that cannot be reached from the sidebar, so
                // without this it is the one screen nobody can review before it
                // ships. The reply is a no-op here; nothing is enforced.
                case "alert": self.seedDemoAlert()
                default: break
                }
            }
        }
    }

    private func seedDemoAlert() {
        // Built here rather than picked out of `state.connections`: a running
        // helper replaces that list with live data, so the demo alert appeared
        // or did not depending on what the Mac happened to be doing.
        let now = Date()
        let connection = Connection(pid: 4242,
                                    processName: "Discord",
                                    processPath: "/Applications/Discord.app",
                                    processBundleId: "com.hnc.Discord",
                                    remoteHost: "gateway.discord.gg",
                                    remoteIP: "162.159.128.233",
                                    remotePort: 443,
                                    direction: .outgoing,
                                    status: .pending,
                                    bytesIn: 0,
                                    bytesOut: 0,
                                    countryCode: "NL",
                                    city: "Amsterdam",
                                    latitude: 52.37,
                                    longitude: 4.90,
                                    firstSeen: now,
                                    lastSeen: now)
        state.pendingAlerts = [AppState.PendingAlert(connection: connection) { _, _ in }]
    }

    private func seedDemoState() {
        // Synthetic samples for the menubar + popover traffic graph
        var samples: [TrafficSample] = []
        let now = Date()
        for i in 0..<60 {
            let t = now.addingTimeInterval(TimeInterval(i - 60))
            let inB = Int64.random(in: 50_000...450_000)
            let outB = Int64.random(in: 20_000...250_000)
            samples.append(TrafficSample(timestamp: t, bytesIn: inB, bytesOut: outB))
        }
        state.trafficHistory = samples
        state.currentIn = 332_000
        state.currentOut = 2_180_000
        state.totalIn = 952_000_000
        state.totalOut = 288_000_000
        state.deniedCount = 3
        state.incomingCount = 19
        state.unconfirmedCount = 283

        // Synthetic process list
        let procs: [(String, Int64, Int64, String)] = [
            ("Dia", 3_580_000_000, 480_000_000, "compass"),
            ("iTerm", 5_200_000_000, 410_000_000, "terminal"),
            ("Discord", 768_000_000, 95_000_000, "message"),
            ("claude", 322_000_000, 18_000_000, "sparkles"),
            ("Slack", 285_000_000, 26_000_000, "bubble.left.and.bubble.right"),
            ("WhatsApp", 80_000_000, 30_000_000, "bubble.left"),
            ("Telegram", 78_000_000, 14_000_000, "paperplane"),
            ("Spotify", 58_000_000, 4_500_000, "music.note"),
            ("Visual Studio Code", 51_500_000, 6_700_000, "chevron.left.forwardslash.chevron.right"),
            ("Cursor", 28_300_000, 1_500_000, "command"),
            ("Arc", 22_400_000, 5_800_000, "globe"),
            ("Microsoft Edge", 17_200_000, 3_400_000, "globe.americas"),
            ("Google Chrome", 14_900_000, 2_800_000, "globe.europe.africa"),
            ("MacUpdater", 8_300_000, 920_000, "arrow.clockwise"),
            ("Setapp", 6_500_000, 870_000, "rectangle.grid.2x2"),
            ("bun", 5_200_000, 1_400_000, "hare.fill"),
            ("Microsoft Teams", 4_100_000, 1_200_000, "person.3"),
            ("ChatGPT", 2_100_000, 400_000, "brain")
        ]
        state.topProcesses = procs.map { (n, i, o, _) in
            AppState.ProcessStats(id: n, name: n, bytesIn: i, bytesOut: o, icon: AppIcon.resolve(name: n))
        }

        let domains: [(String, Int64)] = [
            ("fbcdn.net", 12_300_000_000),
            ("googlevideo.com", 7_080_000_000),
            ("scdn.co", 7_080_000_000),
            ("apple.com", 1_240_000_000),
            ("github.com", 482_000_000)
        ]
        state.topDomains = domains.map { (d, t) in
            AppState.DomainStats(id: d, domain: d, bytesIn: t * 7 / 10, bytesOut: t * 3 / 10)
        }

        let countries: [(String, String, Int64)] = [
            ("Canada", "CA", 28_300_000_000),
            ("United States", "US", 23_200_000_000),
            ("Germany", "DE", 14_200_000_000),
            ("United Kingdom", "GB", 4_100_000_000),
            ("Japan", "JP", 1_900_000_000)
        ]
        state.topCountries = countries.map { (n, c, t) in
            AppState.CountryStats(id: c, country: n, countryCode: c, bytesIn: t * 6 / 10, bytesOut: t * 4 / 10)
        }

        // Synthetic live connections. The map and the monitor tree are both
        // built from `connections`, so without these the demo shows an empty
        // world and an empty tree, which is exactly what needs reviewing.
        // Cities are spread across continents, and two are IPv6, so clustering
        // and the antimeridian arc both have something to do.
        let endpoints: [(String, String, String?, String, String, String, String, Double, Double, Int, Int64, Int64)] = [
            ("Spotify", "/Applications/Spotify.app", "com.spotify.client", "audio-fa.scdn.co", "104.199.65.9", "Stockholm", "SE", 59.33, 18.06, 443, 3_580_000_000, 42_000_000),
            ("Spotify", "/Applications/Spotify.app", "com.spotify.client", "apresolve.spotify.com", "35.186.224.25", "Ashburn", "US", 39.04, -77.49, 443, 12_400_000, 2_100_000),
            ("Google Chrome", "/Applications/Google Chrome.app", "com.google.Chrome", "www.googleapis.com", "142.250.74.234", "Zurich", "CH", 47.37, 8.54, 443, 148_000_000, 18_600_000),
            ("Google Chrome", "/Applications/Google Chrome.app", "com.google.Chrome", "fonts.gstatic.com", "2a00:1450:4001:82f::2003", "Frankfurt", "DE", 50.11, 8.68, 443, 22_800_000, 1_900_000),
            ("Google Chrome", "/Applications/Google Chrome.app", "com.google.Chrome", "", "203.0.113.42", "Singapore", "SG", 1.35, 103.82, 443, 5_400_000, 900_000),
            ("Discord", "/Applications/Discord.app", "com.hnc.Discord", "gateway.discord.gg", "162.159.128.233", "Amsterdam", "NL", 52.37, 4.90, 443, 768_000_000, 95_000_000),
            ("Discord", "/Applications/Discord.app", "com.hnc.Discord", "cdn.discordapp.com", "162.159.130.234", "Paris", "FR", 48.86, 2.35, 443, 96_000_000, 7_300_000),
            ("Telegram", "/Applications/Telegram.app", "ru.keepcoder.Telegram", "", "149.154.167.51", "Amsterdam", "NL", 52.37, 4.90, 443, 78_000_000, 14_000_000),
            ("Visual Studio Code", "/Applications/Visual Studio Code.app", "com.microsoft.VSCode", "update.code.visualstudio.com", "13.107.42.16", "Dublin", "IE", 53.35, -6.26, 443, 51_500_000, 6_700_000),
            ("Visual Studio Code", "/Applications/Visual Studio Code.app", "com.microsoft.VSCode", "marketplace.visualstudio.com", "13.107.6.175", "Sydney", "AU", -33.87, 151.21, 443, 9_200_000, 3_100_000),
            ("claude", "/usr/local/bin/claude", nil, "api.anthropic.com", "160.79.104.10", "San Francisco", "US", 37.77, -122.42, 443, 322_000_000, 18_000_000),
            ("iTerm", "/Applications/iTerm.app", "com.googlecode.iterm2", "github.com", "140.82.121.4", "Seattle", "US", 47.61, -122.33, 443, 482_000_000, 41_000_000),
            ("iTerm", "/Applications/iTerm.app", "com.googlecode.iterm2", "registry.npmjs.org", "2606:4700::6810:1b23", "Tokyo", "JP", 35.68, 139.69, 443, 74_000_000, 5_200_000),
            ("Slack", "/Applications/Slack.app", "com.tinyspeck.slackmacgap", "wss-primary.slack.com", "99.86.90.51", "São Paulo", "BR", -23.55, -46.63, 443, 285_000_000, 26_000_000),
            ("MacUpdater", "/Applications/MacUpdater.app", "co.corecode.MacUpdater", "", "198.51.100.77", "Toronto", "CA", 43.65, -79.38, 443, 8_300_000, 920_000)
        ]
        state.connections = endpoints.enumerated().map { index, e in
            let (name, path, bundle, host, ip, city, code, lat, lon, port, inB, outB) = e
            return Connection(pid: Int32(600 + index),
                              processName: name,
                              processPath: path,
                              processBundleId: bundle,
                              remoteHost: host,
                              remoteIP: ip,
                              remotePort: port,
                              direction: .outgoing,
                              status: .allowed,
                              bytesIn: inB,
                              bytesOut: outB,
                              countryCode: code,
                              city: city,
                              latitude: lat,
                              longitude: lon,
                              firstSeen: now.addingTimeInterval(-Double(index) * 90),
                              lastSeen: now.addingTimeInterval(-Double(index) * 3))
        }

        // Synthetic rules so the demo showcases the populated Rules manager
        state.rules = [
            Rule(processBundleId: "com.spotify.client", processPath: "/Applications/Spotify.app", processName: "Spotify", remoteHost: "*.scdn.co", direction: .outgoing, action: .allow, scope: .domain, priority: 100, profile: "default", notes: "Allow audio streaming", lastUsedAt: now.addingTimeInterval(-120), hitCount: 482),
            Rule(processBundleId: "com.microsoft.VSCode", processPath: "/Applications/Visual Studio Code.app", processName: "Visual Studio Code", remoteHost: "update.code.visualstudio.com", direction: .outgoing, action: .allow, scope: .domain, priority: 90, profile: "default", lastUsedAt: now.addingTimeInterval(-3600), hitCount: 31),
            Rule(processBundleId: "com.google.Chrome", processPath: "/Applications/Google Chrome.app", processName: "Google Chrome", remoteHost: "*.googleapis.com", direction: .outgoing, action: .allow, scope: .domain, priority: 80, profile: "default", hitCount: 1290),
            Rule(processBundleId: "com.hnc.Discord", processPath: "/Applications/Discord.app", processName: "Discord", remoteHost: "*.discord.gg", direction: .outgoing, action: .allow, scope: .domain, priority: 70, profile: "default", hitCount: 96),
            Rule(processBundleId: "com.adobe.acc", processPath: "/Applications/Adobe Creative Cloud.app", processName: "Adobe CC", remoteHost: "*.adobe.io", direction: .outgoing, action: .deny, scope: .domain, priority: 95, profile: "default", notes: "Block telemetry", hitCount: 211),
            Rule(processName: "Any Process", remoteHost: "*.doubleclick.net", direction: .outgoing, action: .deny, scope: .domain, priority: 60, profile: "default", notes: "Ad/tracker", hitCount: 3771),
            Rule(processName: "Any Process", remoteHost: "*.facebook.com", direction: .outgoing, action: .deny, scope: .domain, priority: 60, profile: "default", notes: "Tracker", hitCount: 845),
            Rule(processBundleId: "us.zoom.xos", processPath: "/Applications/Zoom.app", processName: "zoom.us", remoteHost: "*.zoom.us", direction: .outgoing, action: .allow, scope: .domain, priority: 50, profile: "default", temporary: true, expiresAt: now.addingTimeInterval(3600), hitCount: 12),
            Rule(processBundleId: "ru.keepcoder.Telegram", processPath: "/Applications/Telegram.app", processName: "Telegram", remoteHost: "149.154.167.0/24", remoteIP: "149.154.167.0/24", direction: .outgoing, action: .ask, scope: .ip, priority: 40, profile: "default", hitCount: 0)
        ]

        // Synthetic blocklists
        state.blocklists = [
            BlocklistInfo(name: "FireHOL", url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", enabled: true, entryCount: 3768),
            BlocklistInfo(name: "NoCoin", url: "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt", enabled: true, entryCount: 313),
            BlocklistInfo(name: "URLhaus", url: "https://urlhaus.abuse.ch/downloads/hostfile/", enabled: true, entryCount: 513),
            BlocklistInfo(name: "Anti PopAds", url: "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts", enabled: true, entryCount: 755),
            BlocklistInfo(name: "Peter Lowe", url: "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts", enabled: true, entryCount: 3509),
            BlocklistInfo(name: "Ad Way", url: "https://adaway.org/hosts.txt", enabled: true, entryCount: 6540),
            BlocklistInfo(name: "Anudeep", url: "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt", enabled: true, entryCount: 42258),
            BlocklistInfo(name: "KADhosts", url: "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt", enabled: true, entryCount: 48346),
            BlocklistInfo(name: "OISD", url: "https://big.oisd.nl/hosts", enabled: true, entryCount: 57167),
            BlocklistInfo(name: "HaGeZi Multi Light", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/light.txt", enabled: true, entryCount: 60913),
            BlocklistInfo(name: "1Host Lite", url: "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/hosts.txt", enabled: true, entryCount: 94647),
            BlocklistInfo(name: "HaGeZi Threat", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/tif.txt", enabled: true, entryCount: 301675)
        ]

        seedDemoProfiles()
    }

    /// Profiles live in the helper, so without this the Profiles screen is
    /// empty in demo mode and cannot be reviewed before it ships.
    private func seedDemoProfiles() {
        let lists = Array(state.blocklists.prefix(6))
        let home = Profile(name: "default",
                           mode: .alert,
                           icon: "house",
                           isActive: true,
                           blocklistIDs: Set(lists.prefix(3).map(\.id)))
        let cafe = Profile(name: "Cafe",
                           mode: .silentDeny,
                           icon: "cup.and.saucer",
                           blocklistIDs: Set(lists.map(\.id)))
        let work = Profile(name: "Work",
                           mode: .silentAllow,
                           icon: "building.2",
                           blocklistIDs: [])
        let snapshot = ProfileSnapshot(
            profiles: [home, cafe, work],
            activeProfile: home.name,
            alwaysRuleCount: 9,
            activeProfileRuleCount: 3,
            blocklists: state.blocklists,
            selectedBlocklistIDs: home.blocklistIDs,
            bindings: [
                ProfileNetworkBinding(profileName: "default", gatewayMAC: "a4:2b:8c:11:04:9f"),
                ProfileNetworkBinding(profileName: "Cafe", gatewayMAC: "de:ad:be:ef:00:11")
            ],
            currentGatewayMAC: "a4:2b:8c:11:04:9f",
            notice: nil,
            canUndo: false)
        ProfileClient.shared.demoBlocklistSink = { [weak state] lists in
            state?.blocklists = lists
        }
        ProfileClient.shared.adoptDemoSnapshot(snapshot)
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        windowManager.showMainWindow()
        return true
    }
}
