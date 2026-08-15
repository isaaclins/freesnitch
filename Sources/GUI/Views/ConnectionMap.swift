import SwiftUI
import MapKit
import CoreLocation
import AppKit

/// The connection map: one arc from this Mac to every endpoint cluster, with
/// the clustering following the camera the way Apple Maps reveals detail.
///
/// Two rules shape the code here. Clustering never runs on the render path, so
/// a monitor holding thousands of live connections cannot stutter a pan. And
/// node identity is stable across passes, so a node never jumps out from under
/// the pointer between the press and the release.
@available(macOS 14.0, *)
struct ConnectionMapPane: View {
    let connections: [Connection]
    /// Reports the caveat and credit line so the pane header can show it above
    /// the map rather than on top of it (#103).
    var onSummaryChange: ((String) -> Void)? = nil

    @StateObject private var model = ConnectionMapModel()
    @ObservedObject private var home = MapHomeAnchor.shared
    @State private var cameraPosition: MapCameraPosition = .region(Self.worldRegion)
    @State private var tier: MapDetailTier = .widest
    @State private var viewWidth: Double = 640
    @State private var isPlacingHome = false
    @State private var cameraCenter = CameraCenterBox()
    /// The pin whose callout is open. Pins were decoration before: nothing on
    /// the map answered a click (#138).
    @State private var selectedNode: MapNode?

    private static let worldRegion = MKCoordinateRegion(
        center: CLLocationCoordinate2D(latitude: 20, longitude: 0),
        span: MKCoordinateSpan(latitudeDelta: 130, longitudeDelta: 360))

    var body: some View {
        GeometryReader { geometry in
            MapReader { proxy in
                map
                    .gesture(placementGesture(proxy: proxy),
                             including: isPlacingHome ? .gesture : .subviews)
            }
            .overlay(alignment: .topTrailing) { controls }
            .overlay(alignment: .top) { placementBanner }
            .overlay(alignment: .bottomLeading) { calloutOverlay }
            .onAppear {
                viewWidth = geometry.size.width
                refresh()
            }
            .onChange(of: geometry.size.width) { _, width in viewWidth = width }
            .onChange(of: inputFingerprint) { _, _ in refresh() }
            .onChange(of: tier) { _, _ in refresh() }
            .onChange(of: home.point) { _, _ in refresh() }
        }
    }

    private var map: some View {
        Map(position: $cameraPosition) {
            ForEach(model.result.arcs) { arc in
                MapPolyline(coordinates: arc.points.map(\.coordinate))
                    .stroke(PSTheme.accentBlue.opacity(0.16 + 0.52 * arc.intensity),
                            style: StrokeStyle(lineWidth: 0.7 + 2.0 * arc.intensity,
                                               lineCap: .round,
                                               lineJoin: .round))
            }

            Annotation("Your Mac", coordinate: home.point.coordinate) {
                HomePin(isEstimate: home.isEstimate)
            }

            ForEach(model.result.nodes) { node in
                // A named annotation: an empty title left the map with no
                // content at all to VoiceOver (#120). The pin is a button
                // because a place on the map is worth asking about, and it used
                // to answer nothing at all (#138).
                Annotation(node.title, coordinate: node.point.coordinate) {
                    NodePin(node: node, isSelected: selectedNode?.id == node.id)
                        .help("\(node.title): \(node.connectionCount) connection\(node.connectionCount == 1 ? "" : "s")")
                }
            }
        }
        .mapStyle(.standard(elevation: .flat, emphasis: .muted, pointsOfInterest: .excludingAll))
        // No compass and no scale: this is a small inspector view, not a map
        // you navigate, and Apple leaves that furniture off at this size.
        .mapControls { }
        .onMapCameraChange(frequency: .continuous) { context in
            cameraCenter.center = context.region.center
            let next = MapDetailTier.tier(longitudeDelta: context.region.span.longitudeDelta,
                                          viewWidth: viewWidth,
                                          previous: tier)
            // Assigning only on a real tier change keeps a drag from
            // invalidating the view on every frame.
            if next != tier { tier = next }
        }
    }

    /// What a pin knows, in the shape Maps uses: the place, then who went
    /// there, then how much.
    private func nodeCallout(_ node: MapNode) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(node.title).font(.headline)
                Spacer(minLength: 8)
                Button {
                    selectedNode = nil
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Close")
            }
            if let detail = node.detail {
                Text(detail).font(.subheadline).foregroundStyle(.secondary)
            }
            Divider()
            if node.appNames.isEmpty {
                Text("No app could be identified for this location.")
                    .font(.callout).foregroundStyle(.secondary)
            } else {
                Text("Reached by").font(.caption).foregroundStyle(.secondary)
                ForEach(node.appNames, id: \.self) { name in
                    Text(name).font(.callout)
                }
                if node.appCount > node.appNames.count {
                    Text("and \(node.appCount - node.appNames.count) more")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Divider()
            Text("\(node.connectionCount) connection\(node.connectionCount == 1 ? "" : "s") · \(PSFormat.bytes(node.bytes))")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(14)
        .frame(width: 240, alignment: .leading)
    }

    private var controls: some View {
        Menu {
            // A place on the map has to be askable about. MapKit consumes the
            // click before SwiftUI sees it, so a pin cannot open its own
            // callout here; the same answer is one menu away instead, and
            // choosing a place rings its pin and opens its card (#138).
            if !model.result.nodes.isEmpty {
                Menu("Locations") {
                    ForEach(model.result.nodes.prefix(15)) { node in
                        Button {
                            selectedNode = node
                        } label: {
                            Text("\(node.title) · \(node.connectionCount) connection\(node.connectionCount == 1 ? "" : "s")")
                        }
                    }
                }
                Divider()
            }
            Button(isPlacingHome ? "Stop placing your Mac" : "Place your Mac on the map…") {
                isPlacingHome.toggle()
            }
            Button("Move your Mac to the map center") {
                let center = cameraCenter.center
                home.setManualPoint(MapPoint(latitude: center.latitude, longitude: center.longitude))
                isPlacingHome = false
            }
            Button("Use the time zone estimate") {
                home.resetToEstimate()
                isPlacingHome = false
            }
            Divider()
            // The privacy decision itself lives in Settings, where a Mac user
            // looks for one, rather than inside a glyph floating on the map
            // (#138). This says where it is and what it currently says.
            Text(home.source.summary)
            Text(home.usesLocationServices
                 ? "Location Services is on, in Settings under Map."
                 : "Location Services is off. Turn it on in Settings under Map.")
        } label: {
            Image(systemName: "house.circle.fill")
                .font(.body.weight(.semibold))
                .foregroundStyle(.primary)
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .padding(6)
        .background(.regularMaterial, in: Circle())
        .padding(10)
        .help("Where this Mac sits on the map: \(home.source.summary.lowercased())")
    }

    @ViewBuilder
    private var placementBanner: some View {
        if isPlacingHome {
            HStack(spacing: 8) {
                Text("Click the map to place your Mac")
                    .font(.callout)
                    .foregroundStyle(.primary)
                Button("Cancel") { isPlacingHome = false }
                    .buttonStyle(.plain)
                    .font(.callout.weight(.semibold))
                    .foregroundStyle(Color.accentColor)
            }
            .padding(.horizontal, 10).padding(.vertical, 5)
            .background(.regularMaterial, in: Capsule())
            .padding(.top, 10)
        }
    }

    /// The caveat and the data credit, for the pane header above the map.
    /// They used to be a capsule lying on the tiles, which covered the very
    /// thing they describe (#103). CC BY only asks that the credit be visible
    /// where the data is shown, and a header directly above the map is.
    static func attributionText(hiddenCount: Int, aggregated: Bool) -> String {
        var parts = ["Locations are estimates"]
        if aggregated { parts.append("grouped to keep the map readable") }
        if hiddenCount > 0 { parts.append("\(hiddenCount) quieter locations not shown") }
        return parts.joined(separator: " \u{00b7} ")
    }

    private func placementGesture(proxy: MapProxy) -> some Gesture {
        SpatialTapGesture(coordinateSpace: .local).onEnded { value in
            guard isPlacingHome, let coordinate = proxy.convert(value.location, from: .local) else { return }
            home.setManualPoint(MapPoint(latitude: coordinate.latitude,
                                         longitude: MapGeometry.wrapLongitude(coordinate.longitude)))
            isPlacingHome = false
        }
    }

    /// The callout is a card in the pane rather than a popover on the pin:
    /// a popover attached to an annotation is never presented.
    @ViewBuilder
    private var calloutOverlay: some View {
        if let node = selectedNode {
            nodeCallout(node)
                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(.separator))
                .padding(10)
                .transition(.opacity)
        }
    }

    /// Cheap stand-in for comparing the whole connection array. Traffic totals
    /// move even when the count does not, and both change the picture.
    private var inputFingerprint: Int {
        var total: Int64 = 0
        for connection in connections { total &+= connection.bytesIn &+ connection.bytesOut }
        var hasher = Hasher()
        hasher.combine(connections.count)
        hasher.combine(total)
        return hasher.finalize()
    }

    private func refresh() {
        model.submit(connections: connections,
                     request: MapClusterRequest(tier: tier, home: home.point))
        onSummaryChange?(Self.attributionText(hiddenCount: model.result.hiddenNodeCount,
                                              aggregated: model.result.isAggregated))
    }
}

/// Holds the camera center without publishing it. The camera reports every
/// frame of a drag and nothing on screen depends on the center, so storing it
/// in `@State` directly would redraw the map for no reason.
@available(macOS 14.0, *)
private final class CameraCenterBox {
    var center = CLLocationCoordinate2D(latitude: 20, longitude: 0)
}

/// Owns cluster recomputation. Work runs on a background task, only one pass is
/// in flight at a time, the newest request wins, and passes are spaced out so a
/// chatty monitor cannot queue up a backlog of clustering.
@available(macOS 14.0, *)
@MainActor
final class ConnectionMapModel: ObservableObject {
    @Published private(set) var result = MapClusterResult()

    private struct Job: Sendable {
        let connections: [Connection]
        let request: MapClusterRequest
    }

    private var pending: Job?
    private var isComputing = false
    private var lastCompleted = Date.distantPast
    private var drainTask: Task<Void, Never>?
    private let minimumInterval: TimeInterval = 0.2

    func submit(connections: [Connection], request: MapClusterRequest) {
        pending = Job(connections: connections, request: request)
        drain()
    }

    private func drain() {
        guard !isComputing, drainTask == nil, let job = pending else { return }
        let wait = minimumInterval - Date().timeIntervalSince(lastCompleted)
        if wait > 0 {
            drainTask = Task { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(wait * 1_000_000_000))
                guard let self else { return }
                self.drainTask = nil
                self.drain()
            }
            return
        }

        pending = nil
        isComputing = true
        Task.detached(priority: .utility) { [weak self] in
            let computed = MapClusterEngine.build(connections: job.connections, request: job.request)
            await self?.finish(computed)
        }
    }

    private func finish(_ computed: MapClusterResult) {
        isComputing = false
        lastCompleted = Date()
        result = computed
        drain()
    }
}

struct NodePin: View {
    let node: MapNode
    /// The selected pin is drawn larger and ringed, so the callout below and
    /// the place on the map are visibly the same thing.
    var isSelected: Bool = false

    var body: some View {
        VStack(spacing: 3) {
            if node.showsLabel {
                VStack(spacing: 0) {
                    Text(labelText)
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(.primary)
                    if let detail = node.detail {
                        Text(detail)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.horizontal, 6).padding(.vertical, 2)
                .background(.regularMaterial,
                            in: RoundedRectangle(cornerRadius: 5, style: .continuous))
                .fixedSize()
            }
            Circle()
                .fill(Color.white.opacity(0.55 + 0.45 * node.intensity))
                .frame(width: dotSize, height: dotSize)
                .overlay(Circle().stroke(isSelected
                                         ? Color.accentColor
                                         : PSTheme.accentBlue.opacity(0.35 + 0.5 * node.intensity),
                                         lineWidth: isSelected ? 3 : 1.5))
        }
    }

    private var labelText: String {
        node.connectionCount > 1 ? "\(node.title) (\(node.connectionCount))" : node.title
    }

    private var dotSize: Double { (7 + 5 * node.intensity) * (isSelected ? 1.6 : 1) }
}

private struct HomePin: View {
    let isEstimate: Bool

    var body: some View {
        Circle()
            .fill(PSTheme.accent)
            .frame(width: 24, height: 24)
            // The glyph inside the marker keeps its white on the accent fill:
            // that pair is the marker's own colour scheme, the way Maps draws
            // its pins, and it is legible in both appearances.
            .overlay(Image(systemName: "house.fill")
                .font(.caption.weight(.bold))
                .foregroundStyle(.white))
            .overlay(Circle().stroke(Color.white.opacity(0.9), lineWidth: 1.5))
            .overlay(alignment: .bottom) {
                if isEstimate {
                    Text("Approximate")
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 4).padding(.vertical, 1)
                        .background(.regularMaterial, in: Capsule())
                        .fixedSize()
                        .offset(y: 13)
                }
            }
    }
}
