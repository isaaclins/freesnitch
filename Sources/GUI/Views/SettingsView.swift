import SwiftUI
import ServiceManagement

struct SettingsView: View {
    @EnvironmentObject var state: AppState
    let systemExtension: SystemExtensionManager
    @ObservedObject private var mapHome = MapHomeAnchor.shared
    @ObservedObject var uninstall: UninstallFlowModel
    @State private var doh = ""
    /// What the helper last confirmed, so Apply knows whether there is
    /// anything to apply.
    @State private var savedDoH = ""
    @State private var dohError: String?
    /// The resolvers macOS uses and the VPNs connected, kept current (#424).
    @ObservedObject private var network = VPNMonitor.shared
    private var systemResolvers: [String] { network.systemResolvers }
    @State private var launchAtLogin = SMAppService.mainApp.status == .enabled
    /// Owned by the window model, so Help > Command-Line Tool can open
    /// Settings on that pane (#423).
    @Binding var pane: Pane
    /// The app icon in the look macOS currently uses for it (#471).
    @State private var appIcon = SettingsView.currentAppIcon()
    @Environment(\.colorScheme) private var colorScheme

    /// The parts of Settings. A page, not a window, so these are chosen in the
    /// content rather than by a `TabView` (#100).
    enum Pane: String, CaseIterable, Identifiable {
        case general, dns, commandLine, uninstall, about
        var id: String { rawValue }
        var title: String {
            switch self {
            case .general: return String(localized: "General")
            case .dns: return String(localized: "DNS")
            case .commandLine: return String(localized: "Command Line")
            case .uninstall: return String(localized: "Uninstall")
            case .about: return String(localized: "About")
            }
        }
    }

    /// Deliberately not a `TabView`.
    ///
    /// A `TabView` on macOS installs its own `NSToolbar` on the window to draw
    /// its tab bar, and never gives the window's own toolbar back: one visit to
    /// Settings left every other page without a title, a sidebar control or a
    /// search field until the app was relaunched (#100). A window also gets one
    /// navigation system, and this window's is the sidebar.
    var body: some View {
        VStack(spacing: 0) {
            Picker("Section", selection: $pane) {
                ForEach(Pane.allCases) { pane in
                    Text(pane.title).tag(pane)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(maxWidth: 520)
            .padding(.horizontal, 16)
            .padding(.top, 12)
            .padding(.bottom, 10)
            Divider()
            content
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(minWidth: 520, maxWidth: .infinity, minHeight: 420, maxHeight: .infinity)
        .onAppear { loadDoHUpstream(); network.refresh() }
        .onChange(of: state.helperConnected) { connected in
            if connected { loadDoHUpstream() }
        }
        .onChange(of: state.dnsProxyEnabled) { _ in network.refresh() }
        .onChange(of: pane) { _ in network.refresh() }
        // Coming back from System Settings, where the tab sends you to change
        // the DNS server, has to show the new answer.
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didBecomeKeyNotification)) { _ in
            network.refresh()
        }
    }

    @ViewBuilder
    private var content: some View {
        switch pane {
        case .general: generalTab
        case .dns: dnsTab
        case .commandLine: CommandLineSettingsView()
        case .uninstall: uninstallTab
        case .about: aboutTab
        }
    }

    private var generalTab: some View {
        VStack(alignment: .leading, spacing: 0) {
            HelperBanner(systemExtension: systemExtension)
            Form {
                // The banner above already states any helper problem in full,
                // so this row reports status rather than repeating the
                // complaint, and its buttons sit in a labelled row instead of
                // standing alone (#104).
                Section("Privileged helper") {
                    // A stale helper is restarted with one privileged command.
                    // Printed inside the status line it could not be copied or
                    // run; here it is a value the user can click to copy (#117).
                    if case .mismatch = state.helperVersionState {
                        HStack(alignment: .firstTextBaseline, spacing: 12) {
                            Text("Restart command")
                            Spacer(minLength: 8)
                            CopyableValue(value: AppConstants.helperKickstartCommand)
                        }
                    }
                    LabeledContent("Status") {
                        Text(helperSummary)
                            .multilineTextAlignment(.trailing)
                    }
                    LabeledContent("Actions") {
                        HStack(spacing: 8) {
                            if state.helperInstallState != .enabled {
                                Button("Open Login Items…") { state.helper.openLoginItemsSettings() }
                            }
                            Button("Check Again") { state.helper.refreshInstallState(); state.helper.ping() }
                        }
                    }
                }
                // What a connected VPN means for the rules, said next to the
                // helper's status (#424). Only shown while one is connected.
                if let summary = VPNStatus.rulesSummary(network.vpns) {
                    Section("VPN") {
                        LabeledContent("Connected") {
                            Text(vpnList)
                                .multilineTextAlignment(.trailing)
                        }
                        Text(summary)
                            .font(.caption).foregroundColor(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                Section("Menu bar") {
                    Toggle("Show download and upload speeds in the menu bar",
                           isOn: $state.showSpeedsInMenuBar)
                    Toggle("Show FreeSnitch in the Dock", isOn: $state.showDockIcon)
                    if !state.showDockIcon {
                        Text("FreeSnitch keeps running in the menu bar. Open its windows from the menu bar icon.")
                            .font(.caption).foregroundColor(.secondary)
                    }
                }
                // Every failure path in the app writes here: a rejected mode
                // change, a remembered rule the helper refused, a connection
                // allowed without asking. Nothing rendered it, so all of that
                // was invisible (#131).
                Section("Recent activity") {
                    if state.logs.isEmpty {
                        Text("Nothing to report. Rejected changes and connections allowed without asking appear here.")
                            .font(.caption).foregroundColor(.secondary)
                    } else {
                        ForEach(state.logs.suffix(20).reversed()) { entry in
                            HStack(alignment: .firstTextBaseline, spacing: 8) {
                                Image(systemName: entry.level == "error"
                                      ? "xmark.octagon.fill"
                                      : (entry.level == "warning" ? "exclamationmark.triangle.fill" : "info.circle"))
                                    .foregroundStyle(entry.level == "error" ? Color.red : (entry.level == "warning" ? Color.orange : Color.secondary))
                                    .accessibilityHidden(true)
                                Text(entry.message)
                                    .font(.callout)
                                    .fixedSize(horizontal: false, vertical: true)
                                Spacer(minLength: 8)
                                Text(entry.timestamp, format: .dateTime.hour().minute())
                                    .font(.caption).foregroundStyle(.secondary).monospacedDigit()
                            }
                        }
                    }
                }
                Section("General") {
                    Toggle("Launch FreeSnitch at login", isOn: $launchAtLogin)
                        .onChange(of: launchAtLogin) { newValue in setLaunchAtLogin(newValue) }
                    Toggle("Show alerts on all Spaces", isOn: $state.showAlertsOnAllSpaces)
                }
                // A privacy choice belongs in Settings with its explanation,
                // not inside an unlabelled glyph menu floating on the map
                // (#138).
                Section("Map") {
                    Toggle("Use Location Services to place this Mac", isOn: Binding(
                        get: { mapHome.usesLocationServices },
                        set: { mapHome.setUsesLocationServices($0) }))
                    Text("Off by default. FreeSnitch estimates where this Mac is from its time zone, which needs no permission and never leaves the Mac. Turning this on asks macOS for your location once, only to place the marker the connection arcs start from.")
                        .font(.caption).foregroundColor(.secondary)
                    Text(mapHome.source.summary)
                        .font(.caption).foregroundColor(.secondary)
                }
                Section("Enforcement") {
                    // The same switch, the same name and the same states as the
                    // one in the Rules sidebar. It used to be called "Block
                    // traffic" here and "Blocklists" there, and this copy
                    // ignored both the pending and the failed state (#139).
                    Toggle(EnforcementControl.title, isOn: $state.enforcementEnabled)
                        .disabled(!state.helperConnected || state.enforcementChangePending)
                        .help(state.helperConnected
                              ? EnforcementControl.help
                              : String(localized: "Approve the FreeSnitch helper to change this."))
                    if state.enforcementChangePending {
                        Label("Applying…", systemImage: "clock")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    if let failure = state.enforcementFailure {
                        Label(failure, systemImage: "exclamationmark.triangle.fill")
                            .font(.caption).foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Text(EnforcementControl.explanation)
                        .font(.caption).foregroundColor(.secondary)
                }
                IPFeedsSection()
                Section("Mode") {
                    Picker("Default mode", selection: Binding(get: { state.mode }, set: { state.setMode($0) })) {
                        ForEach(AppMode.allCases, id: \.self) { mode in
                            Label(mode.title, systemImage: mode.symbol).tag(mode)
                        }
                    }
                    if let scope = state.modeOwnerDescription {
                        Text(scope).font(.caption).foregroundColor(.secondary)
                    }
                    if let failure = state.modeChangeFailure {
                        Label(failure, systemImage: "exclamationmark.triangle.fill")
                            .font(.caption).foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Toggle("Ask about destinations an app already uses", isOn: $state.askAboutKnownContacts)
                        .disabled(state.mode != .alert)
                    Text(state.askAboutKnownContacts
                         ? "Alert mode asks about every new connection, including destinations this app has reached before."
                         : "Alert mode allows a destination without asking when this app has reached it before. Each one is recorded in Recent activity.")
                        .font(.caption).foregroundColor(.secondary)
                }
            }
            .formStyle(.grouped)
            Spacer(minLength: 0)
        }
    }

    /// "Not running" was printed whether the helper was unreachable, the
    /// switch was off, or the proxy had genuinely failed (#131).
    private var dnsProxyStatus: String {
        guard state.helperConnected else { return String(localized: "Unavailable while the helper is not connected") }
        if state.dnsProxyEnabled { return String(localized: "Running on port \(String(state.dnsProxyPort))") }
        return state.enforcementEnabled ? String(localized: "Not running") : String(localized: "Off, because enforcement is off")
    }

    /// A running proxy is not the same as a proxy in use. FreeSnitch does not
    /// change the Mac's DNS servers, so lookups only reach the proxy, and the
    /// upstream above, when the network's DNS server is this Mac. Without
    /// saying so, a saved upstream read as broken: the Mac kept asking the
    /// resolver it already had (#142).
    /// The proxy answers on 127.0.0.1 and ::1 only (#205), so only a DNS
    /// server set to one of those reaches it.
    private var routesThroughProxy: Bool {
        systemResolvers.contains(where: DNSProxyAddress.reachesProxy)
    }

    /// A DNS server set to one of this Mac's own network addresses. Before
    /// #205 that reached the proxy; it no longer does, so it is named here
    /// rather than reported as working.
    private var ownNetworkResolvers: [String] {
        DNSProxyAddress.ownNetworkResolvers(systemResolvers, own: Self.ownAddresses())
    }

    private static func ownAddresses() -> Set<String> {
        var result: Set<String> = []
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return result }
        defer { freeifaddrs(list) }
        for entry in sequence(first: first, next: { $0.pointee.ifa_next }) {
            guard let addr = entry.pointee.ifa_addr else { continue }
            let family = Int32(addr.pointee.sa_family)
            guard family == AF_INET || family == AF_INET6 else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let length = socklen_t(family == AF_INET ? MemoryLayout<sockaddr_in>.size : MemoryLayout<sockaddr_in6>.size)
            guard getnameinfo(addr, length, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
            result.insert(String(cString: host).split(separator: "%").first.map(String.init) ?? "")
        }
        return result
    }

    private var dnsUsage: (status: String, detail: String) {
        guard state.helperConnected else {
            return (String(localized: "Unknown", comment: "Whether this Mac uses the DNS proxy"), String(localized: "The helper is not connected."))
        }
        // Pointed at this Mac with nothing listening, every lookup fails. That
        // is the one state here that breaks the network, so it comes first.
        if !state.dnsProxyEnabled, routesThroughProxy {
            return (String(localized: "No", comment: "Whether this Mac uses the DNS proxy"),
                    String(localized: "This Mac's DNS server is set to this Mac, but the FreeSnitch DNS proxy is not running. Unless another DNS app answers there, names cannot be looked up. Turn enforcement on, or set the DNS server back in System Settings > Network."))
        }
        if !routesThroughProxy, !ownNetworkResolvers.isEmpty {
            let servers = ownNetworkResolvers.joined(separator: ", ")
            return (String(localized: "No", comment: "Whether this Mac uses the DNS proxy"),
                    String(localized: "This Mac's DNS servers include \(servers), an address of this Mac itself. The FreeSnitch DNS proxy only answers on 127.0.0.1, so lookups sent there get no answer unless another DNS app answers. To use FreeSnitch, turn enforcement on and set the DNS server to 127.0.0.1 in System Settings > Network > your network > Details > DNS."))
        }
        guard state.enforcementEnabled else {
            return (String(localized: "No", comment: "Whether this Mac uses the DNS proxy"),
                    String(localized: "The upstream applies only while enforcement is on. Turn it on in General."))
        }
        guard state.dnsProxyEnabled else {
            return (String(localized: "No", comment: "Whether this Mac uses the DNS proxy"), String(localized: "Enforcement is on, but the DNS proxy is not running."))
        }
        // A VPN that brings its own DNS outranks the network's DNS server,
        // so the general advice below would send the user to a setting that
        // changes nothing while it is connected (#424).
        let vpnDNS = VPNStatus.dnsSummary(network.vpns, routesThroughProxy: routesThroughProxy)
        if routesThroughProxy {
            return (String(localized: "Yes", comment: "Whether this Mac uses the DNS proxy"),
                    String(localized: "This Mac's DNS server is FreeSnitch, which filters lookups and forwards the rest over HTTPS. \(vpnDNS ?? String(localized: "A DNS profile, VPN or DNS app can still take some or all lookups elsewhere."))"))
        }
        // Only a VPN that takes every lookup replaces the advice below. A
        // split-DNS one takes just its domains, so the rest still bypass
        // FreeSnitch the ordinary way and the advice stands.
        if let vpnDNS, VPNStatus.dnsOwner(network.vpns) != nil {
            return (String(localized: "No", comment: "Whether this Mac uses the DNS proxy"), vpnDNS)
        }
        let servers = systemResolvers.isEmpty
            ? String(localized: "the resolver your network or a DNS app provides")
            : systemResolvers.joined(separator: ", ")
        return (String(localized: "No", comment: "Whether this Mac uses the DNS proxy"),
                String(localized: "This Mac sends its lookups to \(servers) directly. FreeSnitch does not change your network settings. To send them through FreeSnitch, set the DNS server to 127.0.0.1 in System Settings > Network > your network > Details > DNS. A DNS profile, VPN or DNS app takes priority over that. Set it back before you turn enforcement off or remove FreeSnitch, or this Mac cannot look up names.")
                + (vpnDNS.map { " " + $0 } ?? ""))
    }

    /// "Tailscale", one name per connected VPN. The tunnel interface is
    /// left out: it means nothing to most people.
    private var vpnList: String {
        network.vpns.map(\.displayName).joined(separator: ", ")
    }

    private var helperSummary: String {
        if case .mismatch(let helperVersion, let appVersion) = state.helperVersionState {
            return String(localized: "Running version \(helperVersion), while this app is version \(appVersion)")
        }
        switch state.helperInstallState {
        case .enabled: return state.helperConnected ? String(localized: "Connected") : String(localized: "Approved, connecting…")
        case .requiresApproval: return String(localized: "Waiting for your approval")
        case .notRegistered, .unknown: return String(localized: "Not installed")
        case .wrongLocation:
            if InstallLocation.stuckInstalledCopy != nil { return String(localized: "macOS runs a temporary copy, so reinstall FreeSnitch") }
            return InstallLocation.isInUserApplications(InstallLocation.runningOriginal)
                ? String(localized: "Copy FreeSnitch to /Applications") : String(localized: "Move FreeSnitch to /Applications")
        case .notFound: return String(localized: "Registration record missing")
        case .failed(let m): return String(localized: "Failed: \(m)")
        }
    }

    private func setLaunchAtLogin(_ enabled: Bool) {
        // The demo shares the installed app's bundle id: its login item is the
        // real one (#389).
        guard !DemoMode.isOn else { return }
        do {
            if enabled { try SMAppService.mainApp.register() }
            else { try SMAppService.mainApp.unregister() }
        } catch {
            state.appendLog(level: "error", message: String(localized: "Login item change failed: \(error.localizedDescription)"))
            launchAtLogin = SMAppService.mainApp.status == .enabled
        }
    }

    private func loadDoHUpstream() {
        state.helper.getDoHUpstream { value, error in
            Task { @MainActor in
                if let value {
                    doh = value
                    savedDoH = value
                    dohError = nil
                } else {
                    // Keep the field empty rather than putting a sentinel such
                    // as "Unknown" into editable state, where pressing Return
                    // would try to save the sentinel as a resolver URL.
                    doh = ""
                    dohError = error ?? String(localized: "The effective DoH upstream is unavailable.")
                }
            }
        }
    }

    private func saveDoHUpstream() {
        let value = doh
        // Checked here first with the helper's own rule, so a refusal reads
        // in the app's language; the helper still checks and logs in English.
        if let rejection = DoHUpstreamValidator.rejection(for: value) {
            dohError = Self.message(for: rejection)
            return
        }
        state.helper.remote?.setDoHUpstream(url: value) { ok, message in
            Task { @MainActor in
                if ok {
                    savedDoH = value
                    dohError = nil
                } else {
                    dohError = message ?? String(localized: "The helper refused the DoH upstream.")
                }
            }
        }
    }

    /// One whole sentence per refusal (#464): splicing the helper's English
    /// reason into a translated sentence left English inside it.
    static func message(for rejection: DoHUpstreamValidator.Rejection) -> String {
        let reason: String
        switch rejection {
        case .empty:
            reason = String(localized: "The upstream URL is empty.")
        case .surroundingWhitespace:
            reason = String(localized: "The upstream URL starts or ends with a space.")
        case .notAURL:
            reason = String(localized: "The upstream is not a URL.")
        case .notHTTPS:
            reason = String(localized: "The upstream URL must start with https://.")
        case .missingHost:
            reason = String(localized: "The upstream URL has no host.")
        }
        return reason + " " + String(localized: "Use an HTTPS URL with a host, such as https://cloudflare-dns.com/dns-query.")
    }

    /// Grouped, like General: a plain form put the label outside the content
    /// column and pinned the status to the far edge of the pane (#112).
    private var dnsTab: some View {
        Form {
            Section("DNS over HTTPS upstream") {
                // The prompt is deliberately not a URL: macOS styles a URL in
                // a field as a blue link, and an empty field then reads as if
                // it already held that value.
                // Return was the only way to save, and nothing said so: an
                // edited field looked saved and was not (#142).
                HStack {
                    TextField("Upstream", text: $doh,
                              prompt: Text("Leave empty to use the system resolver"))
                        .onSubmit { saveDoHUpstream() }
                    Button("Apply") { saveDoHUpstream() }
                        .disabled(doh == savedDoH)
                }
                .disabled(!state.helperConnected)
                if let dohError, state.helperConnected {
                    Text(dohError).font(.caption).foregroundColor(.red)
                }
                Text(state.helperConnected
                     ? "Cloudflare, Quad9 and Google answer at /dns-query on cloudflare-dns.com, dns.quad9.net and dns.google."
                     : "The upstream lives in the privileged helper, so it can be changed once the helper is connected.")
                    .font(.caption).foregroundColor(.secondary)
            }
            Section("Local DNS proxy") {
                LabeledContent("Status") {
                    Text(dnsProxyStatus)
                }
                LabeledContent("Used by this Mac") {
                    Text(dnsUsage.status)
                }
                if !network.vpns.isEmpty {
                    LabeledContent("VPN") {
                        Text(vpnList)
                            .multilineTextAlignment(.trailing)
                    }
                }
                Text(dnsUsage.detail)
                    .font(.caption).foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                // Network Settings can't take DNS back from a VPN that
                // brings its own, so the button would lead nowhere (#424).
                if state.dnsProxyEnabled != routesThroughProxy || (!routesThroughProxy && !ownNetworkResolvers.isEmpty),
                   routesThroughProxy || VPNStatus.dnsOwner(network.vpns) == nil {
                    Button("Open Network Settings…") {
                        if let url = URL(string: "x-apple.systempreferences:com.apple.Network-Settings.extension") {
                            NSWorkspace.shared.open(url)
                        }
                    }
                }
                Text("The DNS proxy runs inside the privileged helper and filters domain lookups against the enabled blocklists. It reports as running only once the helper confirms it.")
                    .font(.caption).foregroundColor(.secondary)
            }
        }
        .formStyle(.grouped)
    }

    /// Deliberate removal, deliberately its own tab. It must not sit next to
    /// the helper's Repair action in General: repair and uninstall are
    /// different actions and #24 is what happens when they blur.
    private var uninstallTab: some View {
        UninstallView(flow: uninstall)
    }

    private var aboutTab: some View {
        VStack(spacing: 12) {
            // The real application icon, the way Apple's About panel shows it,
            // not a stand-in symbol (#114). On macOS 26 and later the system
            // picks its light, dark, clear or tinted look from the icon style
            // in System Settings. NSApp.applicationIconImage keeps the look
            // the app started with, so ask the workspace again whenever the
            // settings or the appearance change (#471).
            Image(nsImage: appIcon)
                .resizable()
                .frame(width: 96, height: 96)
                .accessibilityHidden(true)
            Text("FreeSnitch").font(.title.bold())
            Text("Version \(AppConstants.version)").font(.subheadline).foregroundColor(.secondary)
            UpdaterSettingsView()
            Text("Open-source application firewall for macOS.").font(.caption).foregroundColor(.secondary)
            Link("github.com/isaaclins/freesnitch", destination: URL(string: "https://github.com/isaaclins/freesnitch")!)
                .font(.caption)
            Text("MIT License · © 2026 FreeSnitch contributors")
                .font(.caption2).foregroundColor(.secondary)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear { appIcon = Self.currentAppIcon() }
        .onChange(of: colorScheme) { _ in appIcon = Self.currentAppIcon() }
        // macOS sends no notice when only the icon style changes. Changing it
        // means going to System Settings, so look again when FreeSnitch comes
        // back to the front.
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            appIcon = Self.currentAppIcon()
        }
    }

    /// A fresh bitmap of the icon as macOS draws it right now. The workspace
    /// hands back the same image object every time, which SwiftUI would take
    /// as unchanged and never redraw.
    private static func currentAppIcon() -> NSImage {
        let icon = NSWorkspace.shared.icon(forFile: Bundle.main.bundlePath)
        let side = 96 * (NSScreen.main?.backingScaleFactor ?? 2)
        guard let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(side), pixelsHigh: Int(side),
                                         bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                         colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0),
              let context = NSGraphicsContext(bitmapImageRep: rep) else { return NSApp.applicationIconImage }
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = context
        icon.draw(in: NSRect(x: 0, y: 0, width: side, height: side))
        NSGraphicsContext.restoreGraphicsState()
        let image = NSImage(size: NSSize(width: 96, height: 96))
        image.addRepresentation(rep)
        return image
    }
}
