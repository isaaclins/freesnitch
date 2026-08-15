import SwiftUI
import AppKit

struct NetworkMonitorView: View {
    @EnvironmentObject var state: AppState
    let systemExtension: SystemExtensionManager
    @State private var selectedProcess: String? = nil
    /// Supplied by the window's toolbar search field.
    @Binding var searchText: String
    /// Owns the grouped tree, its expansion state and its decisions. A
    /// StateObject, so expansion survives every refresh of the live data.
    @StateObject private var tree = MonitorTreeController()
    /// What the map says about itself, shown in its header (#103).
    @State private var mapSummary = "Locations are estimates"

    var body: some View {
        VStack(spacing: 0) {
            HelperBanner(systemExtension: systemExtension)
            HStack(spacing: 0) {
                sidebar
                    .frame(width: 330)
                Divider()
                mapPane
                    .frame(minWidth: 320, maxWidth: .infinity, maxHeight: .infinity)
                Divider()
                summaryPane
                    .frame(width: 280)
            }
        }
        // Grouping happens on a background task inside the controller. The
        // view hands it data and never groups anything itself.
        .onAppear {
            tree.ingest(connections: state.connections)
            tree.updateDecisions(rules: state.rules, profile: state.activeProfile)
        }
        .onReceive(state.$connections) { tree.ingest(connections: $0) }
        .onReceive(state.$rules) { tree.updateDecisions(rules: $0, profile: state.activeProfile) }
        .onReceive(state.$activeProfile) { tree.updateDecisions(rules: state.rules, profile: $0) }
        // The title says what failed, not that something was rejected, and
        // the body is never empty (#117).
        .alert("Could not save that decision",
               isPresented: Binding(get: { tree.errorMessage != nil },
                                    set: { if !$0 { tree.errorMessage = nil } })) {
            Button("OK", role: .cancel) { tree.errorMessage = nil }
        } message: {
            Text(tree.errorMessage ?? "The helper did not say why. Try again in a moment.")
        }
    }

    /// Every pane on every other page has a header band. This one started
    /// with content, so the divider under the toolbar met nothing (#103).
    private var sidebar: some View {
        HeaderedPane {
            PaneHeader("Apps", count: tree.snapshot.apps.count) {
                Button("Collapse all") { tree.collapseAll() }
                    .buttonStyle(.borderless)
                    .font(.callout)
                    .help("Collapse every app in the list.")
            }
        } content: {
            sidebarContent
        }
    }

    private var sidebarContent: some View {
        VStack(alignment: .leading, spacing: 0) {
            MonitorTreeList(controller: tree,
                            searchText: searchText,
                            selectedAppID: $selectedProcess)

            // The count and the collapse control belong in a status bar under
            // the list, where Finder keeps "9 items", not crowding the search
            // field out of its own row.
            Divider()
            HStack(spacing: 8) {
                // The two bars on every row encode sent and received, and
                // nothing said so anywhere (#76). The status bar is where
                // Finder keeps this kind of standing information.
                trafficLegend
                Spacer()
            }
            .padding(.horizontal, 10).padding(.vertical, 6)
            .background(.bar)
        }
    }

    private var trafficLegend: some View {
        HStack(spacing: 10) {
            legendItem("Sent", color: MonitorTrafficBars.sentColor)
            legendItem("Received", color: MonitorTrafficBars.receivedColor)
        }
        .padding(.leading, 4)
    }

    private func legendItem(_ label: String, color: Color) -> some View {
        HStack(spacing: 4) {
            Capsule().fill(color).frame(width: 12, height: 3)
            Text(label).font(.caption).foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)
    }

    private var mapPane: some View {
        HeaderedPane {
            PaneHeader("Map") {
                Text(mapSummary)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                // CC BY asks that the credit be visible where the data is
                // shown. Directly above the map is, and it stops the credit
                // covering the very thing it describes (#103).
                Link(IPGeoCache.attribution.text,
                     destination: URL(string: IPGeoCache.attribution.linkURL) ?? URL(string: "https://db-ip.com/")!)
                    .font(.caption)
                    .help("\(IPGeoCache.attribution.text), licensed \(IPGeoCache.attribution.licenseName)")
            }
        } content: {
            mapContent
        }
    }

    private var mapContent: some View {
        Group {
            if #available(macOS 14.0, *) {
                ConnectionMapPane(connections: connectionsForMap(),
                                  onSummaryChange: { mapSummary = $0 })
                    .overlay(alignment: .top) {
                        if connectionsForMap().isEmpty {
                            Text(state.helperConnected
                                 ? "No located connections yet"
                                 : "Waiting for the FreeSnitch helper")
                                .font(.callout)
                                .padding(.horizontal, 10).padding(.vertical, 5)
                                .background(.regularMaterial, in: Capsule())
                                .padding(.top, 10)
                        }
                    }
            } else {
                legacyConnectionList
            }
        }
    }

    // Fallback for macOS 13 (Ventura), where the SwiftUI `Map` API is unavailable.
    private var legacyConnectionList: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                Label("Map view requires macOS 14 or later", systemImage: "map")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .padding(12)
                Divider()
                ForEach(connectionsForMap()) { c in
                    HStack(spacing: 8) {
                        Image(systemName: "globe.americas")
                            .foregroundStyle(Color.accentColor)
                            .frame(width: 16)
                        Text(legacyLabel(c)).font(.body).lineLimit(1)
                        Spacer()
                        if let cc = c.countryCode, !cc.isEmpty {
                            Text(cc).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .padding(.horizontal, 12).padding(.vertical, 6)
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func legacyLabel(_ c: Connection) -> String {
        if let country = c.country, !country.isEmpty { return country }
        if !c.remoteHost.isEmpty { return c.remoteHost }
        return c.remoteIP
    }

    /// The right-hand summary, as a grouped list of labelled values.
    ///
    /// It used to open with a 22pt title and two saturated gradient cards, then
    /// list bare rows under grey captions. Sections and `LabeledContent` say
    /// the same thing in the shape System Settings uses.
    private var summaryPane: some View {
        VStack(spacing: 0) {
            PaneHeader("Summary") {
                Text("\(InsightsView.plural(state.topProcesses.count, "process")), \(InsightsView.plural(state.topDomains.count, "domain"))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Divider()

            List {
                Section("Throughput") {
                    LabeledContent("Down", value: PSFormat.bytesPerSec(state.currentIn))
                    LabeledContent("Up", value: PSFormat.bytesPerSec(state.currentOut))
                }
                Section("Top Processes") {
                    ForEach(state.topProcesses.prefix(5)) { p in
                        LabeledContent(p.name, value: PSFormat.bytes(p.total))
                    }
                }
                Section("Top Domains") {
                    ForEach(state.topDomains.prefix(5)) { d in
                        LabeledContent(d.domain, value: PSFormat.bytes(d.total))
                    }
                }
                Section("Top Countries") {
                    ForEach(state.topCountries.prefix(5)) { c in
                        LabeledContent(c.country, value: PSFormat.bytes(c.total))
                    }
                }
            }
            .listStyle(.inset)
            .monospacedDigit()
        }
    }

    /// Only connections we actually have coordinates for. The previous version
    /// scattered pins at made-up latitudes when geolocation was missing, which
    /// meant the map confidently showed traffic that never happened.
    private func connectionsForMap() -> [Connection] {
        state.connections.filter { $0.latitude != nil && $0.longitude != nil }
    }
}

struct SmallStatRow: View {
    let label: String
    let value: String
    var body: some View {
        LabeledContent(label, value: value)
            .lineLimit(1)
    }
}
