import Foundation

/// Forward compatibility seam for the city-level geolocation work in #60.
/// `Connection` does not carry a city yet. When it gains one, the stored
/// property satisfies this requirement and the default below stops being used,
/// so the map starts labelling cities without another change here. Declaring
/// the default on the protocol rather than on `Connection` is deliberate: an
/// `extension Connection { var city: String? }` would collide with the real
/// stored property the moment it lands.
protocol MapCityNaming {
    var city: String? { get }
}

extension MapCityNaming {
    var city: String? { nil }
}

extension Connection: MapCityNaming {}

/// How much detail the current camera earns. Everything the clusterer needs is
/// derived from one integer, so panning never changes the tier and a zoom only
/// changes it in discrete steps. That is what keeps nodes from sliding out from
/// under the pointer while the user is reaching for one.
struct MapDetailTier: Equatable, Sendable {
    /// 0 is the whole world. Each level halves the cluster cell.
    let level: Int

    static let widest = MapDetailTier(level: 1)

    /// Cluster cell edge in degrees.
    var cellDegrees: Double { 90 / pow(2, Double(level)) }

    /// Roughly how many degrees one point on screen covers at this tier. The
    /// clusterer sizes labels with it.
    var degreesPerPoint: Double { cellDegrees / Double(pointsPerCell) }

    /// Far out, a grid cell is bigger than most countries, so grouping by
    /// country reads better than grouping by an arbitrary square.
    var groupsByCountry: Bool { level <= 2 }

    private var pointsPerCell: Int { 64 }

    /// Picks the tier for a camera, with hysteresis: a tier only changes once
    /// the camera is clearly past the boundary, so a slow pinch cannot make the
    /// map flicker between two clusterings.
    static func tier(longitudeDelta: Double, viewWidth: Double, previous: MapDetailTier) -> MapDetailTier {
        let width = max(120, viewWidth)
        let delta = max(1e-6, min(360, longitudeDelta))
        let target = max(1e-6, delta / width * 64)
        let raw = log2(90 / target)
        guard raw.isFinite else { return previous }
        let clamped = min(14, max(0, raw))
        if abs(clamped - Double(previous.level)) <= 0.6 { return previous }
        return MapDetailTier(level: min(14, max(0, Int(clamped.rounded()))))
    }
}

struct MapClusterRequest: Sendable {
    var tier: MapDetailTier
    var home: MapPoint
    var maxNodes: Int = 64
    var maxLabels: Int = 22
}

struct MapNode: Identifiable, Hashable, Sendable {
    let id: String
    let point: MapPoint
    let title: String
    /// Secondary line, present when the node folds several estimated locations
    /// together or when the title is a city inside a named country.
    let detail: String?
    let connectionCount: Int
    let locationCount: Int
    let bytes: Int64
    /// 0...1 activity weight, used for pin and arc emphasis.
    let intensity: Double
    let showsLabel: Bool
    /// A bounded sample of the apps that reached this place, so a pin can say
    /// who went there. A dot in Singapore with no way to learn which app made
    /// it is a picture, not an interface (#138).
    let appNames: [String]
    let appCount: Int
}

struct MapArc: Identifiable, Sendable {
    let id: String
    let points: [MapPoint]
    let intensity: Double
}

struct MapClusterResult: Sendable {
    var nodes: [MapNode] = []
    var arcs: [MapArc] = []
    /// Endpoints that exist but did not earn a node even after aggregation.
    /// Surfaced in the UI so traffic never disappears silently.
    var hiddenNodeCount: Int = 0
    var connectionCount: Int = 0
    /// True when the endpoints were folded coarser than the camera asked for,
    /// because drawing one arc each would have meant thousands of them.
    var isAggregated: Bool = false
}

/// Pure, synchronous, and deliberately free of SwiftUI and CoreLocation so it
/// can run off the render path on a background task.
enum MapClusterEngine {
    /// A hard ceiling on the work one pass can do. The live monitor can hold
    /// thousands of connections; beyond this the busiest ones are the ones
    /// worth drawing.
    static let maxInputConnections = 6000

    static func build(connections: [Connection], request: MapClusterRequest) -> MapClusterResult {
        let input = boundedInput(connections)
        var tier = request.tier
        var buckets = bucketize(input, tier: tier)

        // Too many nodes for the arc budget is a reason to aggregate, not a
        // reason to drop the quiet ones. Step the clustering coarser until the
        // node count fits; only a world already grouped by country can still
        // overflow, and that overflow is reported rather than hidden.
        var attempts = 0
        while buckets.count > request.maxNodes, tier.level > 0, attempts < 8 {
            tier = MapDetailTier(level: max(0, tier.level - 2))
            buckets = bucketize(input, tier: tier)
            attempts += 1
        }

        // Stable order: traffic first, key second. Equal-traffic nodes therefore
        // never swap places between two passes.
        let ranked = buckets.values.sorted { left, right in
            if left.bytes != right.bytes { return left.bytes > right.bytes }
            if left.connectionCount != right.connectionCount { return left.connectionCount > right.connectionCount }
            return left.key < right.key
        }

        let retained = Array(ranked.prefix(request.maxNodes))
        let maxBytes = retained.first(where: { $0.bytes > 0 })?.bytes ?? 0
        let maxCount = retained.map(\.connectionCount).max() ?? 0

        var nodes: [MapNode] = []
        var labelled: [MapPoint] = []
        nodes.reserveCapacity(retained.count)

        for accumulator in retained {
            let point = accumulator.representativePoint
            // Label spacing follows the camera, not the (possibly coarsened)
            // cluster tier: it is a question of pixels on screen.
            let showsLabel = labelled.count < request.maxLabels
                && !collides(point, with: labelled, tier: request.tier)
            if showsLabel { labelled.append(point) }
            nodes.append(accumulator.node(
                intensity: intensity(for: accumulator, maxBytes: maxBytes, maxCount: maxCount),
                showsLabel: showsLabel))
        }

        var arcs: [MapArc] = []
        arcs.reserveCapacity(nodes.count)
        for node in nodes {
            let segments = MapGeometry.arcSegments(from: request.home, to: node.point)
            for (index, segment) in segments.enumerated() {
                arcs.append(MapArc(id: "\(node.id)#\(index)", points: segment, intensity: node.intensity))
            }
        }

        return MapClusterResult(nodes: nodes,
                                arcs: arcs,
                                hiddenNodeCount: max(0, ranked.count - retained.count),
                                connectionCount: input.count,
                                isAggregated: tier != request.tier)
    }

    private static func bucketize(_ connections: [Connection], tier: MapDetailTier) -> [String: Accumulator] {
        var buckets: [String: Accumulator] = [:]
        buckets.reserveCapacity(min(connections.count, 512))
        for connection in connections {
            guard let latitude = connection.latitude, let longitude = connection.longitude,
                  latitude.isFinite, longitude.isFinite,
                  abs(latitude) <= 90, abs(longitude) <= 180 else { continue }
            let key = clusterKey(latitude: latitude, longitude: longitude,
                                 countryCode: connection.countryCode, tier: tier)
            buckets[key, default: Accumulator(key: key)].add(connection, latitude: latitude, longitude: longitude)
        }
        return buckets
    }

    private static func boundedInput(_ connections: [Connection]) -> [Connection] {
        guard connections.count > maxInputConnections else { return connections }
        return Array(connections
            .sorted { ($0.bytesIn &+ $0.bytesOut) > ($1.bytesIn &+ $1.bytesOut) }
            .prefix(maxInputConnections))
    }

    static func clusterKey(latitude: Double, longitude: Double, countryCode: String?, tier: MapDetailTier) -> String {
        if tier.groupsByCountry, let code = countryCode, !code.isEmpty {
            return "cc:\(code)"
        }
        let cell = tier.cellDegrees
        let latitudeIndex = Int((latitude / cell).rounded(.down))
        let longitudeIndex = Int((longitude / cell).rounded(.down))
        return "g\(tier.level):\(latitudeIndex):\(longitudeIndex)"
    }

    private static func collides(_ point: MapPoint, with labelled: [MapPoint], tier: MapDetailTier) -> Bool {
        // A label capsule is roughly 110 by 30 points. In the Mercator
        // projection longitude maps linearly to x, so degrees per point is a
        // fair horizontal measure; vertically it only over-estimates, which
        // errs toward fewer labels rather than a pile.
        let longitudeGap = tier.degreesPerPoint * 110
        let latitudeGap = tier.degreesPerPoint * 30
        return labelled.contains { other in
            abs(other.latitude - point.latitude) < latitudeGap
                && abs(MapGeometry.wrapLongitude(other.longitude - point.longitude)) < longitudeGap
        }
    }

    private static func intensity(for accumulator: Accumulator, maxBytes: Int64, maxCount: Int) -> Double {
        var value: Double
        if maxBytes > 0 {
            value = log1p(Double(accumulator.bytes)) / log1p(Double(maxBytes))
        } else if maxCount > 0 {
            value = Double(accumulator.connectionCount) / Double(maxCount)
        } else {
            value = 0
        }
        // Something talking right now should not read as idle just because it
        // has moved few bytes so far.
        if accumulator.lastSeen.timeIntervalSinceNow > -15 { value = max(value, 0.35) }
        return min(1, max(0, value))
    }

    private struct Accumulator {
        let key: String
        var bytes: Int64 = 0
        var connectionCount = 0
        var lastSeen = Date.distantPast
        var locations: Set<Int> = []
        private var apps: [String: Int64] = [:]
        private var representative: Connection?
        private var representativeBytes: Int64 = -1
        var representativePoint = MapPoint(latitude: 0, longitude: 0)

        init(key: String) { self.key = key }

        mutating func add(_ connection: Connection, latitude: Double, longitude: Double) {
            let traffic = connection.bytesIn &+ connection.bytesOut
            bytes &+= traffic
            connectionCount += 1
            lastSeen = max(lastSeen, connection.lastSeen)
            var hasher = Hasher()
            hasher.combine(Int((latitude * 1000).rounded()))
            hasher.combine(Int((longitude * 1000).rounded()))
            locations.insert(hasher.finalize())
            let app = connection.processName.isEmpty ? "Unknown app" : connection.processName
            apps[app, default: 0] &+= traffic

            // The node sits on a real endpoint estimate, not on a moving
            // centroid, so adding a connection cannot shift a pin the user is
            // about to click. Ties break on the address for determinism.
            let isBetter: Bool
            if traffic != representativeBytes {
                isBetter = traffic > representativeBytes
            } else {
                isBetter = connection.remoteIP < (representative?.remoteIP ?? "\u{10FFFF}")
            }
            if isBetter {
                representative = connection
                representativeBytes = traffic
                representativePoint = MapPoint(latitude: latitude, longitude: longitude)
            }
        }

        func node(intensity: Double, showsLabel: Bool) -> MapNode {
            MapNode(id: key,
                    point: representativePoint,
                    title: title,
                    detail: detail,
                    connectionCount: connectionCount,
                    locationCount: locations.count,
                    bytes: bytes,
                    intensity: intensity,
                    showsLabel: showsLabel,
                    appNames: apps.sorted { $0.value == $1.value ? $0.key < $1.key : $0.value > $1.value }
                        .prefix(5).map(\.key),
                    appCount: apps.count)
        }

        private var title: String {
            guard let representative else { return "Unknown" }
            if let city = representative.city, !city.isEmpty { return city }
            if let country = representative.country, !country.isEmpty { return country }
            if !representative.remoteHost.isEmpty { return representative.remoteHost }
            if !representative.remoteIP.isEmpty { return representative.remoteIP }
            return "Unknown"
        }

        private var detail: String? {
            if locations.count > 1 { return "\(locations.count) locations" }
            guard let representative,
                  let city = representative.city, !city.isEmpty,
                  let country = representative.country, !country.isEmpty else { return nil }
            return country
        }
    }
}
