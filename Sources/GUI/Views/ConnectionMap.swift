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
    @StateObject private var home = MapHomeAnchor()
    @State private var cameraPosition: MapCameraPosition = .region(Self.worldRegion)
    @State private var tier: MapDetailTier = .widest
    @State private var viewWidth: Double = 640
    @State private var isPlacingHome = false
    @State private var cameraCenter = CameraCenterBox()

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
                Annotation("", coordinate: node.point.coordinate) {
                    NodePin(node: node)
                }
            }
        }
        .mapStyle(.standard(elevation: .flat, emphasis: .muted, pointsOfInterest: .excludingAll))
        .colorScheme(.dark)
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

    private var controls: some View {
        Menu {
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
            Toggle("Use Location Services (optional)", isOn: Binding(
                get: { home.usesLocationServices },
                set: { home.setUsesLocationServices($0) }))
            Text(home.source.summary)
        } label: {
            Image(systemName: "house.circle.fill")
                .font(.system(size: 14, weight: .semibold))
                .foregroundColor(PSTheme.textPrimary)
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .padding(6)
        .background(.black.opacity(0.45), in: Circle())
        .padding(10)
        .help("Where this Mac sits on the map: \(home.source.summary.lowercased())")
    }

    @ViewBuilder
    private var placementBanner: some View {
        if isPlacingHome {
            HStack(spacing: 8) {
                Text("Click the map to place your Mac")
                    .font(.system(size: 11))
                    .foregroundColor(PSTheme.textPrimary)
                Button("Cancel") { isPlacingHome = false }
                    .buttonStyle(.plain)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(PSTheme.accentBlue)
            }
            .padding(.horizontal, 10).padding(.vertical, 5)
            .background(.black.opacity(0.65), in: Capsule())
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

    var body: some View {
        VStack(spacing: 3) {
            if node.showsLabel {
                VStack(spacing: 0) {
                    Text(labelText)
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundColor(.white)
                    if let detail = node.detail {
                        Text(detail)
                            .font(.system(size: 8))
                            .foregroundColor(PSTheme.textSecondary)
                    }
                }
                .padding(.horizontal, 6).padding(.vertical, 2)
                .background(Color.black.opacity(0.55))
                .clipShape(RoundedRectangle(cornerRadius: 5, style: .continuous))
                .fixedSize()
            }
            Circle()
                .fill(Color.white.opacity(0.55 + 0.45 * node.intensity))
                .frame(width: dotSize, height: dotSize)
                .overlay(Circle().stroke(PSTheme.accentBlue.opacity(0.35 + 0.5 * node.intensity),
                                         lineWidth: 1.5))
        }
    }

    private var labelText: String {
        node.connectionCount > 1 ? "\(node.title) (\(node.connectionCount))" : node.title
    }

    private var dotSize: Double { 7 + 5 * node.intensity }
}

private struct HomePin: View {
    let isEstimate: Bool

    var body: some View {
        Circle()
            .fill(PSTheme.accent)
            .frame(width: 24, height: 24)
            .overlay(Image(systemName: "house.fill")
                .font(.system(size: 11, weight: .bold))
                .foregroundColor(.white))
            .overlay(Circle().stroke(Color.white.opacity(0.9), lineWidth: 1.5))
            .overlay(alignment: .bottom) {
                if isEstimate {
                    Text("approx.")
                        .font(.system(size: 8, weight: .semibold))
                        .foregroundColor(PSTheme.textSecondary)
                        .padding(.horizontal, 4).padding(.vertical, 1)
                        .background(Color.black.opacity(0.55), in: Capsule())
                        .fixedSize()
                        .offset(y: 13)
                }
            }
    }
}
