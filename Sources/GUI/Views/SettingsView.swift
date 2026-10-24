import SwiftUI
import ServiceManagement
import SystemConfiguration

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
    @State private var systemResolvers: [String] = []
    @State private var launchAtLogin = SMAppService.mainApp.status == .enabled
    @State private var pane: Pane = .general

    /// The parts of Settings. A page, not a window, so these are chosen in the
    /// content rather than by a `TabView` (#100).
    enum Pane: String, CaseIterable, Identifiable {
        case general, dns, uninstall, about
        var id: String { rawValue }
        var title: String {
            switch self {
            case .general: return "General"
            case .dns: return "DNS"
            case .uninstall: return "Uninstall"
            case .about: return "About"
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
            .frame(maxWidth: 440)
            .padding(.horizontal, 16)
            .padding(.top, 12)
            .padding(.bottom, 10)
            Divider()
            content
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(minWidth: 520, maxWidth: .infinity, minHeight: 420, maxHeight: .infinity)
        .onAppear { loadDoHUpstream(); systemResolvers = Self.currentSystemResolvers() }
        .onChange(of: state.helperConnected) { connected in
            if connected { loadDoHUpstream() }
        }
        .onChange(of: state.dnsProxyEnabled) { _ in systemResolvers = Self.currentSystemResolvers() }
        .onChange(of: pane) { _ in systemResolvers = Self.currentSystemResolvers() }
        // Coming back from System Settings, where the tab sends you to change
        // the DNS server, has to show the new answer.
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didBecomeKeyNotification)) { _ in
            systemResolvers = Self.currentSystemResolvers()
        }
    }

    @ViewBuilder
    private var content: some View {
        switch pane {
        case .general: generalTab
        case .dns: dnsTab
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
                              : "Approve the FreeSnitch helper to change this.")
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
        guard state.helperConnected else { return "Unavailable while the helper is not connected" }
        if state.dnsProxyEnabled { return "Running on port \(state.dnsProxyPort)" }
        return state.enforcementEnabled ? "Not running" : "Off, because enforcement is off"
    }

    /// A running proxy is not the same as a proxy in use. FreeSnitch does not
    /// change the Mac's DNS servers, so lookups only reach the proxy, and the
    /// upstream above, when the network's DNS server is this Mac. Without
    /// saying so, a saved upstream read as broken: the Mac kept asking the
    /// resolver it already had (#142).
    /// The proxy listens on every interface, so a DNS server set to one of
    /// this Mac's own addresses reaches it as well as loopback does.
    private var routesThroughProxy: Bool {
        let own = Self.ownAddresses()
        return systemResolvers.contains { server in
            server == "::1" || server.hasPrefix("127.") || own.contains(server)
        }
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
            return ("Unknown", "The helper is not connected.")
        }
        // Pointed at this Mac with nothing listening, every lookup fails. That
        // is the one state here that breaks the network, so it comes first.
        if !state.dnsProxyEnabled, routesThroughProxy {
            return ("No",
                    "This Mac's DNS server is set to this Mac, but the FreeSnitch DNS proxy is not running. Unless another DNS app answers there, names cannot be looked up. Turn enforcement on, or set the DNS server back in System Settings > Network.")
        }
        guard state.enforcementEnabled else {
            return ("No",
                    "The upstream applies only while enforcement is on. Turn it on in General.")
        }
        guard state.dnsProxyEnabled else {
            return ("No", "Enforcement is on, but the DNS proxy is not running.")
        }
        if routesThroughProxy {
            return ("Yes", "This Mac's DNS server is FreeSnitch, which filters lookups and forwards the rest over HTTPS. A DNS profile, VPN or DNS app can still take some or all lookups elsewhere.")
        }
        let servers = systemResolvers.isEmpty
            ? "the resolver your network or a DNS app provides"
            : systemResolvers.joined(separator: ", ")
        return ("No",
                "This Mac sends its lookups to \(servers) directly. FreeSnitch does not change your network settings. To send them through FreeSnitch, set the DNS server to 127.0.0.1 in System Settings > Network > your network > Details > DNS. A DNS profile, VPN or DNS app takes priority over that. Set it back before you turn enforcement off or remove FreeSnitch, or this Mac cannot look up names.")
    }

    /// The resolvers macOS is using right now, as the system reports them.
    private static func currentSystemResolvers() -> [String] {
        guard let store = SCDynamicStoreCreate(nil, "FreeSnitchSettings" as CFString, nil, nil),
              let dns = SCDynamicStoreCopyValue(store, "State:/Network/Global/DNS" as CFString) as? [String: Any],
              let servers = dns["ServerAddresses"] as? [String] else { return [] }
        return servers
    }

    private var helperSummary: String {
        if case .mismatch(let helperVersion, let appVersion) = state.helperVersionState {
            return "Running version \(helperVersion), while this app is version \(appVersion)"
        }
        switch state.helperInstallState {
        case .enabled: return state.helperConnected ? "Connected" : "Approved, connecting…"
        case .requiresApproval: return "Waiting for your approval"
        case .notRegistered, .unknown: return "Not installed"
        case .wrongLocation: return "Move FreeSnitch to /Applications"
        case .notFound: return "Registration record missing"
        case .failed(let m): return "Failed: \(m)"
        }
    }

    private func setLaunchAtLogin(_ enabled: Bool) {
        do {
            if enabled { try SMAppService.mainApp.register() }
            else { try SMAppService.mainApp.unregister() }
        } catch {
            state.appendLog(level: "error", message: "Login item change failed: \(error.localizedDescription)")
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
                    dohError = error ?? "The effective DoH upstream is unavailable."
                }
            }
        }
    }

    private func saveDoHUpstream() {
        let value = doh
        state.helper.remote?.setDoHUpstream(url: value) { ok, message in
            Task { @MainActor in
                if ok {
                    savedDoH = value
                    dohError = nil
                } else {
                    dohError = message ?? "The helper refused the DoH upstream."
                }
            }
        }
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
                Text(dnsUsage.detail)
                    .font(.caption).foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if state.dnsProxyEnabled != routesThroughProxy {
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
            // not a stand-in symbol (#114).
            Image(nsImage: NSApp.applicationIconImage)
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
    }
}
