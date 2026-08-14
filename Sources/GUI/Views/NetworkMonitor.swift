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
        .alert("The helper did not accept that",
               isPresented: Binding(get: { tree.errorMessage != nil },
                                    set: { if !$0 { tree.errorMessage = nil } })) {
            Button("OK", role: .cancel) { tree.errorMessage = nil }
        } message: {
            Text(tree.errorMessage ?? "")
        }
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            MonitorTreeList(controller: tree,
                            searchText: searchText,
                            selectedAppID: $selectedProcess)

            // The count and the collapse control belong in a status bar under
            // the list, where Finder keeps "9 items", not crowding the search
            // field out of its own row.
            Divider()
            HStack(spacing: 8) {
                Text("\(tree.snapshot.apps.count) apps")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
                Spacer()
                Button("Collapse all") { tree.collapseAll() }
                    .buttonStyle(.link)
                    .font(.caption)
            }
            .padding(.horizontal, 10).padding(.vertical, 6)
            .background(.bar)
        }
    }

    private var mapPane: some View {
        Group {
            if #available(macOS 14.0, *) {
                ConnectionMapPane(connections: connectionsForMap())
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
            HStack(spacing: 6) {
                Text("Summary").font(.headline)
                Text("\(state.topProcesses.count) processes, \(state.topDomains.count) domains")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                Spacer()
            }
            .padding(.horizontal, 12).padding(.vertical, 8)
            .background(.bar)
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
