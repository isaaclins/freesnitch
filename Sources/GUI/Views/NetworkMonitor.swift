import SwiftUI
import MapKit
import AppKit

struct NetworkMonitorView: View {
    @EnvironmentObject var state: AppState
    @State private var selectedProcess: String? = nil
    @State private var searchText: String = ""

    var body: some View {
        HStack(spacing: 0) {
            sidebar
                .frame(width: 240)
                .background(PSTheme.bgSidebar)
            Divider().background(PSTheme.stroke)
            mapPane
            Divider().background(PSTheme.stroke)
            summaryPane
                .frame(width: 280)
                .background(PSTheme.bgSecondary)
        }
        .background(PSTheme.bgPrimary)
        .preferredColorScheme(.dark)
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").foregroundColor(PSTheme.textMuted)
                TextField("Search", text: $searchText)
                    .textFieldStyle(.plain)
                    .foregroundColor(PSTheme.textPrimary)
            }
            .padding(.horizontal, 10).padding(.vertical, 6)
            .background(PSTheme.bgTertiary)
            .clipShape(RoundedRectangle(cornerRadius: 6))
            .padding(8)

            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(filteredProcesses) { p in
                        ProcessRow(stats: p, selected: selectedProcess == p.id)
                            .onTapGesture { selectedProcess = (selectedProcess == p.id ? nil : p.id) }
                    }
                }
            }
        }
    }

    private var filteredProcesses: [AppState.ProcessStats] {
        if searchText.isEmpty { return state.topProcesses }
        return state.topProcesses.filter { $0.name.localizedCaseInsensitiveContains(searchText) }
    }

    private var mapPane: some View {
        Group {
            if #available(macOS 14.0, *) {
                ConnectionMapPane(connections: connectionsForMap())
            } else {
                legacyConnectionList
            }
        }
    }

    // Fallback for macOS 13 (Ventura), where the SwiftUI `Map` API is unavailable.
    private var legacyConnectionList: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 6) {
                    Image(systemName: "map").foregroundColor(PSTheme.textMuted)
                    Text("Map view requires macOS 14 or later")
                        .font(.system(size: 12)).foregroundColor(PSTheme.textMuted)
                    Spacer()
                }
                .padding(12)
                Divider().background(PSTheme.stroke)
                ForEach(connectionsForMap()) { c in
                    HStack(spacing: 8) {
                        Image(systemName: "globe.americas").foregroundColor(PSTheme.accentBlue)
                            .frame(width: 16)
                        Text(legacyLabel(c))
                            .font(.system(size: 12)).foregroundColor(PSTheme.textPrimary).lineLimit(1)
                        Spacer()
                        if let cc = c.countryCode, !cc.isEmpty {
                            Text(cc).font(.system(size: 10, weight: .semibold)).foregroundColor(PSTheme.textSecondary)
                        }
                    }
                    .padding(.horizontal, 12).padding(.vertical, 6)
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(PSTheme.bgPrimary)
    }

    private func legacyLabel(_ c: Connection) -> String {
        if let country = c.country, !country.isEmpty { return country }
        if !c.remoteHost.isEmpty { return c.remoteHost }
        return c.remoteIP
    }

    private var summaryPane: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                summaryHeader
                statsRow
                Group {
                    sectionHeader("Top Processes")
                    ForEach(state.topProcesses.prefix(5)) { p in
                        SmallStatRow(label: p.name, value: PSFormat.bytes(p.total))
                    }
                }
                Group {
                    sectionHeader("Top Domains")
                    ForEach(state.topDomains.prefix(5)) { d in
                        SmallStatRow(label: d.domain, value: PSFormat.bytes(d.total))
                    }
                }
                Group {
                    sectionHeader("Top Countries")
                    ForEach(state.topCountries.prefix(5)) { c in
                        SmallStatRow(label: c.country, value: PSFormat.bytes(c.total))
                    }
                }
            }
            .padding(14)
        }
    }

    private var summaryHeader: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Summary").font(.system(size: 22, weight: .bold)).foregroundColor(PSTheme.textPrimary)
            Text("\(state.topProcesses.count) processes, \(state.topDomains.count) domains")
                .font(.system(size: 11)).foregroundColor(PSTheme.textMuted)
        }
    }

    private var statsRow: some View {
        HStack(spacing: 8) {
            statPill(value: PSFormat.bytesPerSec(state.currentIn), label: "down", color: Color.blue.opacity(0.35))
            statPill(value: PSFormat.bytesPerSec(state.currentOut), label: "up", color: Color.purple.opacity(0.35))
        }
    }

    private func statPill(value: String, label: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(value).font(.system(size: 18, weight: .bold)).foregroundColor(.white)
            Text(label).font(.system(size: 10)).foregroundColor(PSTheme.textSecondary)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(color)
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private func sectionHeader(_ s: String) -> some View {
        Text(s).font(.system(size: 11, weight: .semibold)).foregroundColor(PSTheme.textMuted)
    }

    private func connectionsForMap() -> [Connection] {
        let valid = state.connections.filter { $0.latitude != nil && $0.longitude != nil }
        if valid.isEmpty {
            return state.connections.prefix(40).enumerated().map { i, c in
                var copy = c
                copy.latitude = 20 + Double((i * 17) % 60 - 30)
                copy.longitude = Double((i * 41) % 360 - 180)
                return copy
            }
        }
        return valid
    }
}

struct ProcessRow: View {
    let stats: AppState.ProcessStats
    let selected: Bool
    var body: some View {
        HStack(spacing: 8) {
            if let i = stats.icon {
                Image(nsImage: i).resizable().frame(width: 18, height: 18)
            } else {
                Image(systemName: "app.dashed").foregroundColor(PSTheme.textSecondary)
                    .frame(width: 18, height: 18)
            }
            Text(stats.name).lineLimit(1).font(.system(size: 12)).foregroundColor(PSTheme.textPrimary)
            Spacer()
            Text(PSFormat.bytes(stats.total))
                .font(.system(size: 10, weight: .semibold))
                .foregroundColor(PSTheme.textSecondary)
            statusDot
            statusBadge
        }
        .padding(.horizontal, 8).padding(.vertical, 5)
        .background(selected ? PSTheme.accent.opacity(0.18) : Color.clear)
        .contentShape(Rectangle())
    }
    private var statusDot: some View {
        Circle().fill(PSTheme.accentBlue).frame(width: 6, height: 6)
    }
    private var statusBadge: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 3).fill(PSTheme.accentGreen)
            Image(systemName: "checkmark").font(.system(size: 7, weight: .bold)).foregroundColor(.white)
        }
        .frame(width: 12, height: 12)
    }
}

struct NodePin: View {
    let label: String
    var body: some View {
        VStack(spacing: 4) {
            Text(label).font(.system(size: 10, weight: .semibold))
                .padding(.horizontal, 6).padding(.vertical, 2)
                .foregroundColor(.white)
                .background(Color.black.opacity(0.55))
                .clipShape(Capsule())
            Circle().fill(Color.white.opacity(0.9))
                .frame(width: 10, height: 10)
                .overlay(Circle().stroke(Color.white, lineWidth: 1.5))
        }
    }
}

@available(macOS 14.0, *)
private struct ConnectionMapPane: View {
    let connections: [Connection]
    @State private var cameraPosition: MapCameraPosition = .region(
        MKCoordinateRegion(center: .init(latitude: 20, longitude: 0),
                           span: .init(latitudeDelta: 130, longitudeDelta: 360)))

    var body: some View {
        Map(position: $cameraPosition) {
            ForEach(connections) { c in
                Annotation(c.country ?? "?", coordinate: .init(latitude: c.latitude ?? 0, longitude: c.longitude ?? 0)) {
                    NodePin(label: c.country ?? c.remoteHost)
                }
            }
        }
        .mapStyle(.standard(elevation: .flat, emphasis: .muted, pointsOfInterest: .excludingAll))
        .colorScheme(.dark)
    }
}

struct SmallStatRow: View {
    let label: String
    let value: String
    var body: some View {
        HStack {
            Text(label).font(.system(size: 11)).foregroundColor(PSTheme.textPrimary).lineLimit(1)
            Spacer()
            Text(value).font(.system(size: 10, weight: .semibold))
                .foregroundColor(PSTheme.textSecondary)
        }
        .padding(.vertical, 2)
    }
}
