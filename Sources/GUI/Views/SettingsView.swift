import SwiftUI
import ServiceManagement

struct SettingsView: View {
    @EnvironmentObject var state: AppState
    let systemExtension: SystemExtensionManager
    @ObservedObject private var mapHome = MapHomeAnchor.shared
    @ObservedObject var uninstall: UninstallFlowModel
    @State private var doh = ""
    @State private var dohError: String?
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

    /// Grouped, like General: a plain form put the label outside the content
    /// column and pinned the status to the far edge of the pane (#112).
    private var dnsTab: some View {
        Form {
            Section("DNS over HTTPS upstream") {
                // The prompt is deliberately not a URL: macOS styles a URL in
                // a field as a blue link, and an empty field then reads as if
                // it already held that value.
                TextField("Upstream", text: $doh,
                          prompt: Text("Leave empty to use the system resolver"))
                    .onSubmit { saveDoHUpstream() }
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
