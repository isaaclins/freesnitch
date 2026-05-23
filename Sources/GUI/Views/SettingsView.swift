import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var state: AppState
    @State private var doh = AppConstants.defaultDoHUpstream
    @State private var startAtLogin = true
    @State private var showAlertsOnAllSpaces = true

    var body: some View {
        TabView {
            generalTab.tabItem { Label("General", systemImage: "gear") }
            dnsTab.tabItem { Label("DNS", systemImage: "globe") }
            blocklistsTab.tabItem { Label("Blocklists", systemImage: "shield.lefthalf.filled") }
            profilesTab.tabItem { Label("Profiles", systemImage: "person.crop.circle") }
            aboutTab.tabItem { Label("About", systemImage: "info.circle") }
        }
        .padding(16)
        .frame(width: 520, height: 420)
    }

    private var generalTab: some View {
        Form {
            Toggle("Launch PureSnitch at login", isOn: $startAtLogin)
            Toggle("Show alerts on all Spaces", isOn: $showAlertsOnAllSpaces)
            Section("Mode") {
                Picker("Default mode", selection: Binding(get: { state.mode }, set: { state.setMode($0) })) {
                    Text("Alert").tag(AppMode.alert)
                    Text("Silent Allow").tag(AppMode.silentAllow)
                    Text("Silent Deny").tag(AppMode.silentDeny)
                }
            }
        }
    }

    private var dnsTab: some View {
        Form {
            Section("DNS over HTTPS upstream") {
                TextField("DoH URL", text: $doh)
                    .onSubmit { state.helper.remote?.setDoHUpstream(url: doh) { _, _ in } }
                Text("Examples:").font(.caption).foregroundColor(.secondary)
                Text("https://cloudflare-dns.com/dns-query").font(.caption.monospaced())
                Text("https://dns.quad9.net/dns-query").font(.caption.monospaced())
                Text("https://dns.google/dns-query").font(.caption.monospaced())
            }
            Section("Local DNS proxy") {
                Toggle("Use system DNS via PureSnitch (port 53)", isOn: .constant(true))
                Text("PureSnitch installs itself as the system DNS resolver to intercept and filter domain lookups.")
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

    private var profilesTab: some View {
        VStack(alignment: .leading) {
            Text("Profiles").font(.headline)
            ForEach(state.profiles) { p in
                HStack {
                    Image(systemName: p.icon)
                    Text(p.name)
                    Spacer()
                    if p.isActive {
                        PSChip("Active", color: PSTheme.accentGreen)
                    } else {
                        Button("Activate") {
                            state.activeProfile = p.name
                        }
                    }
                }.padding(.vertical, 4)
            }
        }
    }

    private var aboutTab: some View {
        VStack(spacing: 12) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 64)).foregroundColor(PSTheme.accent)
            Text("PureSnitch").font(.title.bold())
            Text("v\(AppConstants.version)").font(.subheadline).foregroundColor(.secondary)
            Text("Open-source application firewall for macOS.").font(.caption).foregroundColor(.secondary)
            Link("github.com/moamenbasel/puresnitch", destination: URL(string: "https://github.com/moamenbasel/puresnitch")!)
                .font(.caption)
            Text("MIT License · © 2026 Moamen Basel")
                .font(.caption2).foregroundColor(.secondary)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
