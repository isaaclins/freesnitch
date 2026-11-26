import SwiftUI
import AppKit

struct NetworkMonitorView: View {
    @EnvironmentObject var state: AppState
    let systemExtension: SystemExtensionManager
    /// Owns the denied filter, so the menu bar can set it before this view
    /// exists (#138).
    @ObservedObject var model: MainWindowModel
    @State private var selectedProcess: String? = nil
    /// Supplied by the window's toolbar search field.
    @Binding var searchText: String
    /// Owns the grouped tree, its expansion state and its decisions. A
    /// StateObject, so expansion survives every refresh of the live data.
    @StateObject private var tree = MonitorTreeController()
    /// What the map says about itself, shown in its header (#103).
    @State private var mapSummary = String(localized: "Locations are estimates")

    var body: some View {
        VStack(spacing: 0) {
            HelperBanner(systemExtension: systemExtension)
            HStack(spacing: 0) {
                // One list in both layouts, so hiding the map keeps its scroll
                // position and focus. Without the map it takes its room (#473).
                sidebar
                    .frame(minWidth: MainWindowMetrics.listPaneWidth,
                           maxWidth: model.isMonitorMapVisible ? MainWindowMetrics.listPaneWidth : .infinity,
                           maxHeight: .infinity)
                if model.isMonitorMapVisible {
                    Divider()
                    mapPane
                        .frame(minWidth: MainWindowMetrics.paneMinWidth, maxWidth: .infinity, maxHeight: .infinity)
                }
                Divider()
                summaryPane
                    .frame(width: MainWindowMetrics.detailPaneWidth)
            }
        }
        // Grouping happens on a background task inside the controller. The
        // view hands it data and never groups anything itself.
        .onAppear {
            tree.ingest(connections: state.connections)
            tree.updateDecisions(rules: state.rules, profile: state.activeProfile)
        }
        .onReceive(state.$connections) { tree.ingest(connections: $0) }
        .onReceive(tree.$snapshot) { revealRequestedRow(in: $0) }
        .onReceive(state.$rules) { tree.updateDecisions(rules: $0, profile: state.activeProfile) }
        .onReceive(state.$activeProfile) { tree.updateDecisions(rules: state.rules, profile: $0) }
        // The title says what failed, not that something was rejected, and
        // the body is never empty (#117).
        .alert("Could not save that decision",
               isPresented: Binding(get: { tree.errorMessage != nil },
                                    set: { if !$0 { tree.errorMessage = nil } })) {
            Button("OK", role: .cancel) { tree.errorMessage = nil }
        } message: {
            Text(tree.errorMessage ?? String(localized: "The helper did not say why. Try again in a moment."))
        }
    }

    /// Every pane on every other page has a header band. This one started
    /// with content, so the divider under the toolbar met nothing (#103).
    private var sidebar: some View {
        HeaderedPane {
            PaneHeader("Apps", count: tree.snapshot.apps.count) {
                // The menu bar counts denied connections and offers to show
                // them, so there has to be a list of them to show (#138).
                Picker("Show", selection: $model.monitorDeniedOnly) {
                    Text("All").tag(false)
                    // Its own key: the header is narrow, and a language may
                    // need a shorter word here than for a denied connection.
                    Text("monitor-filter.denied", comment: "Monitor list filter: only apps with denied connections").tag(true)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
                .help("Show every app, or only the ones with denied connections.")
                // Longer languages don't fit the words next to the title and
                // the filter in this fixed-width pane, so the button falls
                // back to its icon there rather than cutting the title short.
                ViewThatFits(in: .horizontal) {
                    Button("Collapse all") { tree.collapseAll() }
                        .lineLimit(1)
                        .fixedSize()
                    Button { tree.collapseAll() } label: {
                        Image(systemName: "arrow.up.and.line.horizontal.and.arrow.down")
                    }
                    .accessibilityLabel("Collapse all")
                }
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
                            deniedOnly: model.monitorDeniedOnly,
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

    private func legendItem(_ label: LocalizedStringKey, color: Color) -> some View {
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
                                 ? String(localized: "No located connections yet")
                                 : String(localized: "Waiting for the FreeSnitch helper"))
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
                Text(String(localized: "\(state.topProcesses.count) processes, \(state.topDomains.count) domains"))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Divider()

            List {
                if let destination = selectedDestination {
                    EndpointDetailsSection(destination: destination)
                }
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

    /// The destination row that is selected, if the selection is one.
    private var selectedDestination: MonitorDestinationNode? {
        guard let id = selectedProcess else { return nil }
        for app in tree.snapshot.apps {
            if let destination = app.destinations.first(where: { $0.id == id }) { return destination }
        }
        return nil
    }

    /// Selects and reveals the row a demo asked for, once it exists.
    private func revealRequestedRow(in snapshot: MonitorTreeSnapshot) {
        guard let ip = model.monitorRevealIP else { return }
        for app in snapshot.apps {
            guard let destination = app.destinations.first(where: { $0.remoteIP == ip }) else { continue }
            if !tree.isExpanded(app) { tree.toggleExpansion(app) }
            selectedProcess = destination.id
            model.monitorRevealIP = nil
            return
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
