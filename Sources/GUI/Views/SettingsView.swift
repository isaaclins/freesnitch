import SwiftUI
import ServiceManagement

struct SettingsView: View {
    @EnvironmentObject var state: AppState
    let systemExtension: SystemExtensionManager
    @State private var doh = ""
    @State private var dohError: String?
    @State private var launchAtLogin = SMAppService.mainApp.status == .enabled
    @State private var pane: Pane = .general

    /// The parts of Settings. A page, not a window, so these are chosen in the
    /// content rather than by a `TabView` (#100).
    enum Pane: String, CaseIterable, Identifiable {
        case general, dns, blocklists, uninstall, about
        var id: String { rawValue }
        var title: String {
            switch self {
            case .general: return "General"
            case .dns: return "DNS"
            case .blocklists: return "Blocklists"
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
        .onAppear { loadDoHUpstream() }
        .onChange(of: state.helperConnected) { connected in
            if connected { loadDoHUpstream() }
        }
    }

    @ViewBuilder
    private var content: some View {
        switch pane {
        case .general: generalTab
        case .dns: dnsTab
        case .blocklists: blocklistsTab
        case .uninstall: uninstallTab
        case .about: aboutTab
        }
    }

    private var generalTab: some View {
        VStack(alignment: .leading, spacing: 0) {
            HelperBanner(systemExtension: systemExtension)
            Form {
                Section("Privileged helper") {
                    HStack {
                        Text(helperSummary)
                        Spacer()
                        Button("Check Again") { state.helper.refreshInstallState(); state.helper.ping() }
                    }
                    if state.helperInstallState != .enabled {
                        Button("Open Login Items…") { state.helper.openLoginItemsSettings() }
                    }
                }
                Section("Menu bar") {
                    Toggle("Show download and upload speeds in the menu bar",
                           isOn: $state.showSpeedsInMenuBar)
                }
                Section("General") {
                    Toggle("Launch FreeSnitch at login", isOn: $launchAtLogin)
                        .onChange(of: launchAtLogin) { newValue in setLaunchAtLogin(newValue) }
                    Toggle("Show alerts on all Spaces", isOn: $state.showAlertsOnAllSpaces)
                }
                Section("Enforcement") {
                    Toggle("Block traffic, don't just watch it", isOn: $state.enforcementEnabled)
                        .disabled(!state.helperConnected)
                    Text("Off by default. Turning this on lets FreeSnitch load a pf firewall anchor and run a DNS proxy on port \(AppConstants.dnsProxyPort), which changes how this Mac resolves names and filters packets. Leave it off to use FreeSnitch purely as a traffic monitor.")
                        .font(.caption).foregroundColor(.secondary)
                }
                Section("Mode") {
                    Picker("Default mode", selection: Binding(get: { state.mode }, set: { state.setMode($0) })) {
                        ForEach(AppMode.allCases, id: \.self) { mode in
                            Label(mode.title, systemImage: mode.symbol).tag(mode)
                        }
                    }
                }
            }
            .formStyle(.grouped)
            Spacer(minLength: 0)
        }
    }

    private var helperSummary: String {
        if case .mismatch(let helperVersion, let appVersion) = state.helperVersionState {
            return "Stale helper: running v\(helperVersion), installed v\(appVersion). Restart it with `\(AppConstants.helperKickstartCommand)`"
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
        state.helper.remote?.setDoHUpstream(url: doh) { ok, message in
            Task { @MainActor in
                if ok {
                    dohError = nil
                } else {
                    dohError = message ?? "The helper refused the DoH upstream."
                }
            }
        }
    }

    private var dnsTab: some View {
        Form {
            Section("DNS over HTTPS upstream") {
                TextField("DoH URL", text: $doh)
                    .onSubmit { saveDoHUpstream() }
                if let dohError {
                    Text(dohError).font(.caption).foregroundColor(.red)
                }
                Text("Examples:").font(.caption).foregroundColor(.secondary)
                Text("https://cloudflare-dns.com/dns-query").font(.caption.monospaced())
                Text("https://dns.quad9.net/dns-query").font(.caption.monospaced())
                Text("https://dns.google/dns-query").font(.caption.monospaced())
            }
            Section("Local DNS proxy") {
                HStack {
                    Text("Status")
                    Spacer()
                    Text(state.dnsProxyEnabled ? "Running on port \(AppConstants.dnsProxyPort)" : "Not running")
                        .foregroundColor(.secondary)
                }
                Text("The DNS proxy runs inside the privileged helper and filters domain lookups against the enabled blocklists. It reports as running only once the helper confirms it.")
                    .font(.caption).foregroundColor(.secondary)
            }
        }
    }

    private var blocklistsTab: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Blocklists").font(.headline)
                Spacer()
                Button("Refresh All") { state.helper.refreshBlocklists() }
            }
            Text("Blocklists filter DNS names only. They do not stop connections made to hardcoded IP addresses or names resolved by an app's own encrypted DNS, such as Chrome and Firefox DoH.")
                .font(.caption)
                .foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if !state.enforcementEnabled && state.blocklists.contains(where: { $0.enabled }) {
                Text("Enforcement is off, so enabled blocklists are currently blocking nothing.")
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if state.blocklists.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("No blocklists loaded")
                        .font(.body).foregroundColor(.secondary)
                    Text(state.helperConnected
                         ? "Press Refresh All to download the default blocklists."
                         : "Blocklists live in the privileged helper. Approve the helper first. See the General tab.")
                        .font(.caption).foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                .padding(.top, 8)
            }
            List(state.blocklists) { b in
                HStack {
                    Toggle("", isOn: Binding(
                        get: { b.enabled },
                        set: { newValue in
                            state.helper.remote?.enableBlocklist(idString: b.id.uuidString, enabled: newValue) { _, _ in }
                        }
                    ))
                    .labelsHidden()
                    VStack(alignment: .leading) {
                        Text(b.name).font(.body)
                        Text(b.url).font(.caption2).foregroundColor(.secondary).lineLimit(1)
                    }
                    Spacer()
                    Text("\(b.entryCount)").font(.caption.monospacedDigit())
                        .foregroundColor(.secondary)
                }
            }
        }
    }

    /// Deliberate removal, deliberately its own tab. It must not sit next to
    /// the helper's Repair action in General: repair and uninstall are
    /// different actions and #24 is what happens when they blur.
    private var uninstallTab: some View {
        UninstallView(systemExtension: systemExtension)
    }

    private var aboutTab: some View {
        VStack(spacing: 12) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 64)).foregroundColor(PSTheme.accent)
            Text("FreeSnitch").font(.title.bold())
            Text("v\(AppConstants.version)").font(.subheadline).foregroundColor(.secondary)
            Text("Open-source application firewall for macOS.").font(.caption).foregroundColor(.secondary)
            Link("github.com/isaaclins/freesnitch", destination: URL(string: "https://github.com/isaaclins/freesnitch")!)
                .font(.caption)
            Text("MIT License · © 2026 FreeSnitch contributors")
                .font(.caption2).foregroundColor(.secondary)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
