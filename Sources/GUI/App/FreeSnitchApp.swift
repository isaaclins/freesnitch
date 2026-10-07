import SwiftUI
import AppKit

@main
struct FreeSnitchApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    private let sparkleUpdater = SparkleUpdaterController.shared

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
        if ProcessInfo.processInfo.environment["FREESNITCH_DEMO"] == "1" {
            // The demo shows sample data only. It never registers the helper
            // and never talks to one, so on a Mac where FreeSnitch is installed
            // the owner's real traffic cannot end up in a screenshot, and the
            // "approve the helper" banner does not cover the screen under review.
            state.helperInstallState = .enabled
            state.helperConnected = true
        } else {
            state.helper.registerDaemon()
            // bootstrap() (rule load + monitoring) is driven by HelperClient once
            // the helper is actually reachable. See HelperClient.setConnected.
            state.helper.connect()
        }
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
                case "popover": self.menubar.showPopover()
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
        // What a running firewall looks like: asking about new connections,
        // with rules and blocklists in force.
        state.mode = .alert
        state.showDemoEnforcement()
        state.currentIn = 332_000
        state.currentOut = 2_180_000
        state.deniedCount = 3
        state.incomingCount = 19
        state.unconfirmedCount = 283

        // Synthetic live connections. The map, the monitor tree and the
        // summary are all built from this one list, so they agree with each
        // other. Apps are ones whose icons are on most Macs (Apple's own) or on
        // a typical developer's, and cities are spread across continents so
        // clustering and the antimeridian arc both have something to do.
        typealias Endpoint = (name: String, path: String, bundle: String?, host: String, ip: String,
                              city: String, code: String, lat: Double, lon: Double,
                              bytesIn: Int64, bytesOut: Int64, denied: Bool)
        let endpoints: [Endpoint] = [
            ("Safari", "/Applications/Safari.app", "com.apple.Safari", "www.apple.com", "17.253.144.10", "Cupertino", "US", 37.32, -122.03, 412_000_000, 18_400_000, false),
            ("Safari", "/Applications/Safari.app", "com.apple.Safari", "github.com", "140.82.121.4", "Frankfurt", "DE", 50.11, 8.68, 286_000_000, 31_000_000, false),
            ("Safari", "/Applications/Safari.app", "com.apple.Safari", "www.theverge.com", "151.101.1.52", "London", "GB", 51.51, -0.13, 64_000_000, 2_400_000, false),
            ("Arc", "/Applications/Arc.app", "company.thebrowser.Browser", "www.youtube.com", "142.250.203.110", "Warsaw", "PL", 52.23, 21.01, 2_940_000_000, 48_000_000, false),
            ("Arc", "/Applications/Arc.app", "company.thebrowser.Browser", "fonts.gstatic.com", "2a00:1450:4001:82f::2003", "Frankfurt", "DE", 50.11, 8.68, 22_800_000, 1_900_000, false),
            ("Arc", "/Applications/Arc.app", "company.thebrowser.Browser", "stats.g.doubleclick.net", "142.250.27.154", "Brussels", "BE", 50.85, 4.35, 0, 1_200, true),
            ("Arc", "/Applications/Arc.app", "company.thebrowser.Browser", "", "203.0.113.42", "Singapore", "SG", 1.35, 103.82, 5_400_000, 900_000, false),
            ("Xcode", "/Applications/Xcode.app", "com.apple.dt.Xcode", "developer.apple.com", "17.253.27.204", "San Jose", "US", 37.34, -121.89, 1_860_000_000, 9_800_000, false),
            ("Xcode", "/Applications/Xcode.app", "com.apple.dt.Xcode", "devimages-cdn.apple.com", "17.253.85.201", "Tokyo", "JP", 35.68, 139.69, 412_000_000, 3_100_000, false),
            ("Discord", "/Applications/Discord.app", "com.hnc.Discord", "gateway.discord.gg", "162.159.128.233", "Amsterdam", "NL", 52.37, 4.90, 768_000_000, 95_000_000, false),
            ("Discord", "/Applications/Discord.app", "com.hnc.Discord", "cdn.discordapp.com", "162.159.130.234", "Paris", "FR", 48.86, 2.35, 96_000_000, 7_300_000, false),
            ("Music", "/System/Applications/Music.app", "com.apple.Music", "aod.itunes.apple.com", "17.253.53.207", "Stockholm", "SE", 59.33, 18.06, 1_240_000_000, 6_200_000, false),
            ("Mail", "/System/Applications/Mail.app", "com.apple.mail", "imap.mail.me.com", "17.42.251.41", "Ashburn", "US", 39.04, -77.49, 182_000_000, 24_000_000, false),
            ("Mail", "/System/Applications/Mail.app", "com.apple.mail", "outlook.office365.com", "52.97.146.162", "Dublin", "IE", 53.35, -6.26, 96_000_000, 12_000_000, false),
            ("Claude", "/Applications/Claude.app", "com.anthropic.claudefordesktop", "api.anthropic.com", "160.79.104.10", "San Francisco", "US", 37.77, -122.42, 322_000_000, 58_000_000, false),
            ("WhatsApp", "/Applications/WhatsApp.app", "net.whatsapp.WhatsApp", "g.whatsapp.net", "157.240.17.52", "São Paulo", "BR", -23.55, -46.63, 80_000_000, 30_000_000, false),
            ("Zed", "/Applications/Zed.app", "dev.zed.Zed", "api.zed.dev", "104.18.22.183", "Sydney", "AU", -33.87, 151.21, 51_500_000, 6_700_000, false)
        ]
        state.connections = endpoints.enumerated().map { index, e in
            Connection(pid: Int32(600 + index),
                       processName: e.name,
                       processPath: e.path,
                       processBundleId: e.bundle,
                       remoteHost: e.host,
                       remoteIP: e.ip,
                       remotePort: 443,
                       direction: .outgoing,
                       status: e.denied ? .denied : .allowed,
                       bytesIn: e.bytesIn,
                       bytesOut: e.bytesOut,
                       countryCode: e.code,
                       city: e.city,
                       latitude: e.lat,
                       longitude: e.lon,
                       firstSeen: now.addingTimeInterval(-Double(index) * 90),
                       lastSeen: now.addingTimeInterval(-Double(index) * 3))
        }
        state.totalIn = endpoints.reduce(0) { $0 + $1.bytesIn }
        state.totalOut = endpoints.reduce(0) { $0 + $1.bytesOut }

        // The summary column is the same list, totalled three ways.
        func top<Key: Hashable>(_ key: (Endpoint) -> Key?) -> [(Key, Int64, Int64)] {
            var sums: [Key: (Int64, Int64)] = [:]
            for e in endpoints {
                guard let k = key(e) else { continue }
                let s = sums[k] ?? (0, 0)
                sums[k] = (s.0 + e.bytesIn, s.1 + e.bytesOut)
            }
            return sums.map { ($0.key, $0.value.0, $0.value.1) }
                .sorted { $0.1 + $0.2 > $1.1 + $1.2 }
                .prefix(5).map { $0 }
        }
        let paths = Dictionary(endpoints.map { ($0.name, ($0.bundle, $0.path)) }, uniquingKeysWith: { a, _ in a })
        state.topProcesses = top { $0.name }.map { name, inB, outB in
            AppState.ProcessStats(id: name, name: name, bytesIn: inB, bytesOut: outB,
                                  icon: AppIcon.resolve(bundleId: paths[name]?.0, path: paths[name]?.1, name: name))
        }
        state.topDomains = top { e -> String? in
            let labels = e.host.split(separator: ".")
            return labels.count >= 2 ? labels.suffix(2).joined(separator: ".") : nil
        }.map { domain, inB, outB in
            AppState.DomainStats(id: domain, domain: domain, bytesIn: inB, bytesOut: outB)
        }
        let english = Locale(identifier: "en_US")
        state.topCountries = top { $0.code }.map { code, inB, outB in
            AppState.CountryStats(id: code, country: english.localizedString(forRegionCode: code) ?? code,
                                  countryCode: code, bytesIn: inB, bytesOut: outB)
        }

        // Synthetic rules so the demo showcases the populated Rules manager
        state.rules = [
            Rule(processBundleId: "com.apple.Music", processPath: "/System/Applications/Music.app", processName: "Music", remoteHost: "*.itunes.apple.com", direction: .outgoing, action: .allow, scope: .domain, priority: 100, profile: "default", notes: "Allow audio streaming", lastUsedAt: now.addingTimeInterval(-120), hitCount: 482),
            Rule(processBundleId: "com.apple.dt.Xcode", processPath: "/Applications/Xcode.app", processName: "Xcode", remoteHost: "*.apple.com", direction: .outgoing, action: .allow, scope: .domain, priority: 90, profile: "default", lastUsedAt: now.addingTimeInterval(-3600), hitCount: 31),
            Rule(processBundleId: "company.thebrowser.Browser", processPath: "/Applications/Arc.app", processName: "Arc", remoteHost: "*.youtube.com", direction: .outgoing, action: .allow, scope: .domain, priority: 80, profile: "default", hitCount: 1290),
            Rule(processBundleId: "com.hnc.Discord", processPath: "/Applications/Discord.app", processName: "Discord", remoteHost: "*.discord.gg", direction: .outgoing, action: .allow, scope: .domain, priority: 70, profile: "default", hitCount: 96),
            Rule(processBundleId: "com.hnc.Discord", processPath: "/Applications/Discord.app", processName: "Discord", remoteHost: "science.discord.com", direction: .outgoing, action: .deny, scope: .domain, priority: 95, profile: "default", notes: "Block telemetry", hitCount: 211),
            Rule(processName: "Any Process", remoteHost: "*.doubleclick.net", direction: .outgoing, action: .deny, scope: .domain, priority: 60, profile: "default", notes: "Ad/tracker", hitCount: 3771),
            Rule(processName: "Any Process", remoteHost: "*.facebook.com", direction: .outgoing, action: .deny, scope: .domain, priority: 60, profile: "default", notes: "Tracker", hitCount: 845),
            Rule(processBundleId: "com.anthropic.claudefordesktop", processPath: "/Applications/Claude.app", processName: "Claude", remoteHost: "api.anthropic.com", direction: .outgoing, action: .allow, scope: .domain, priority: 50, profile: "default", lastUsedAt: now.addingTimeInterval(-40), hitCount: 1204),
            Rule(processBundleId: "dev.zed.Zed", processPath: "/Applications/Zed.app", processName: "Zed", remoteHost: "*.zed.dev", direction: .outgoing, action: .allow, scope: .domain, priority: 50, profile: "default", temporary: true, expiresAt: now.addingTimeInterval(3600), hitCount: 12),
            Rule(processBundleId: "com.apple.Safari", processPath: "/Applications/Safari.app", processName: "Safari", remoteHost: "github.com", direction: .outgoing, action: .allow, scope: .domain, priority: 50, profile: "default", lastUsedAt: now.addingTimeInterval(-300), hitCount: 640),
            Rule(processBundleId: "com.apple.mail", processPath: "/System/Applications/Mail.app", processName: "Mail", remoteHost: "*.mail.me.com", direction: .outgoing, action: .allow, scope: .domain, priority: 50, profile: "default", hitCount: 2210),
            Rule(processBundleId: "com.apple.mail", processPath: "/System/Applications/Mail.app", processName: "Mail", remoteHost: "outlook.office365.com", direction: .outgoing, action: .allow, scope: .domain, priority: 50, profile: "default", hitCount: 388),
            Rule(processBundleId: "company.thebrowser.Browser", processPath: "/Applications/Arc.app", processName: "Arc", remoteHost: "*.google-analytics.com", direction: .outgoing, action: .deny, scope: .domain, priority: 60, profile: "default", notes: "Tracker", hitCount: 1532),
            Rule(processName: "Any Process", remoteHost: "*.scorecardresearch.com", direction: .outgoing, action: .deny, scope: .domain, priority: 60, profile: "default", notes: "Tracker", hitCount: 97),
            Rule(processBundleId: "net.whatsapp.WhatsApp", processPath: "/Applications/WhatsApp.app", processName: "WhatsApp", remoteHost: "*.whatsapp.net", direction: .outgoing, action: .allow, scope: .domain, priority: 50, profile: "default", hitCount: 902),
            Rule(processBundleId: "net.whatsapp.WhatsApp", processPath: "/Applications/WhatsApp.app", processName: "WhatsApp", remoteHost: "157.240.0.0/16", remoteIP: "157.240.0.0/16", direction: .outgoing, action: .ask, scope: .ip, priority: 40, profile: "default", hitCount: 0)
        ]

        // Synthetic blocklists. They are seeded straight into the profile
        // snapshot, which is where every screen reads them from (#135).
        let blocklists = [
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

        seedDemoProfiles(blocklists: blocklists)
    }

    /// Profiles live in the helper, so without this the Profiles screen is
    /// empty in demo mode and cannot be reviewed before it ships.
    private func seedDemoProfiles(blocklists: [BlocklistInfo]) {
        let lists = Array(blocklists.prefix(6))
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
            blocklists: blocklists,
            selectedBlocklistIDs: home.blocklistIDs,
            bindings: [
                ProfileNetworkBinding(profileName: "default", gatewayMAC: "a4:2b:8c:11:04:9f"),
                ProfileNetworkBinding(profileName: "Cafe", gatewayMAC: "de:ad:be:ef:00:11")
            ],
            currentGatewayMAC: "a4:2b:8c:11:04:9f",
            notice: nil,
            canUndo: false)
        ProfileClient.shared.adoptDemoSnapshot(snapshot)
    }

    /// The status item is the last visible trace of the app, so it goes before
    /// the process does rather than at whatever moment AppKit gets around to it.
    func applicationWillTerminate(_ notification: Notification) {
        menubar?.removeStatusItem()
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        windowManager.showMainWindow()
        return true
    }
}
