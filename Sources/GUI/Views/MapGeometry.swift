import Foundation
import CoreLocation

/// A coordinate that carries no CoreLocation types, so cluster results can be
/// built on a background task and handed to the main actor without fighting
/// Sendable checking. Converted to `CLLocationCoordinate2D` only at render.
struct MapPoint: Hashable, Sendable {
    var latitude: Double
    var longitude: Double

    var coordinate: CLLocationCoordinate2D {
        CLLocationCoordinate2D(latitude: latitude, longitude: longitude)
    }
}

enum MapGeometry {
    /// Great-circle path between two points, already split where it crosses the
    /// antimeridian. A straight `MapPolyline` lies about the route: on a world
    /// view the short way from Zurich to Seattle bows over the pole, and a
    /// diagonal drawn across the projection reads as a different journey.
    ///
    /// Returns one array of points per drawable segment; a path that crosses
    /// 180 degrees yields two, so MapKit never wraps the line the long way
    /// around the world.
    static func arcSegments(from start: MapPoint, to end: MapPoint) -> [[MapPoint]] {
        splitAtAntimeridian(greatCircleSamples(from: start, to: end))
    }

    static func greatCircleSamples(from start: MapPoint, to end: MapPoint) -> [MapPoint] {
        let a = unitVector(start)
        let b = unitVector(end)
        let dot = min(1, max(-1, a.x * b.x + a.y * b.y + a.z * b.z))
        let angle = acos(dot)
        guard angle > 1e-7, sin(angle) != 0 else { return [start, end] }

        let arcDegrees = angle * 180 / .pi
        let steps = max(12, min(96, Int(arcDegrees / 1.5)))
        // A pure geodesic between two nearby cities is visually straight. The
        // reference monitor bows every connection so overlapping routes stay
        // tellable apart, so lift the middle of the path slightly.
        let bow = min(6.0, arcDegrees * 0.1)
        let normal = chordNormal(from: start, to: end)

        var samples: [MapPoint] = []
        samples.reserveCapacity(steps + 1)
        for step in 0...steps {
            let t = Double(step) / Double(steps)
            let weightA = sin((1 - t) * angle) / sin(angle)
            let weightB = sin(t * angle) / sin(angle)
            let x = weightA * a.x + weightB * b.x
            let y = weightA * a.y + weightB * b.y
            let z = weightA * a.z + weightB * b.z
            let length = max(1e-12, (x * x + y * y + z * z).squareRoot())

            let lift = bow * sin(.pi * t)
            let latitude = asin(min(1, max(-1, z / length))) * 180 / .pi + normal.latitude * lift
            let longitude = atan2(y / length, x / length) * 180 / .pi + normal.longitude * lift
            samples.append(MapPoint(latitude: min(85, max(-85, latitude)),
                                    longitude: wrapLongitude(longitude)))
        }
        return samples
    }

    /// MapKit draws a segment between +179 and -179 across the whole world
    /// instead of over the seam, so cut the path there and pin both halves to
    /// the same latitude on the meridian.
    static func splitAtAntimeridian(_ samples: [MapPoint]) -> [[MapPoint]] {
        guard samples.count > 1 else { return samples.isEmpty ? [] : [samples] }
        var segments: [[MapPoint]] = []
        var current: [MapPoint] = [samples[0]]

        for index in 1..<samples.count {
            let previous = samples[index - 1]
            let point = samples[index]
            if abs(point.longitude - previous.longitude) > 180 {
                let goingEast = previous.longitude < point.longitude
                let seamLongitude = goingEast ? -180.0 : 180.0
                let unwrapped = point.longitude + (goingEast ? -360.0 : 360.0)
                let span = unwrapped - previous.longitude
                let t = span == 0 ? 0 : (seamLongitude - previous.longitude) / span
                let seamLatitude = previous.latitude + t * (point.latitude - previous.latitude)
                current.append(MapPoint(latitude: seamLatitude, longitude: seamLongitude))
                segments.append(current)
                current = [MapPoint(latitude: seamLatitude, longitude: -seamLongitude)]
            }
            current.append(point)
        }
        segments.append(current)
        return segments.filter { $0.count > 1 }
    }

    private static func unitVector(_ point: MapPoint) -> (x: Double, y: Double, z: Double) {
        let latitude = point.latitude * .pi / 180
        let longitude = point.longitude * .pi / 180
        return (cos(latitude) * cos(longitude), cos(latitude) * sin(longitude), sin(latitude))
    }

    /// Unit normal of the chord, in degrees, corrected for the longitude
    /// squeeze at the mean latitude so the bow looks symmetric on screen.
    private static func chordNormal(from start: MapPoint, to end: MapPoint) -> (latitude: Double, longitude: Double) {
        let meanLatitude = (start.latitude + end.latitude) / 2 * .pi / 180
        let scale = max(0.2, cos(meanLatitude))
        var deltaLongitude = end.longitude - start.longitude
        if deltaLongitude > 180 { deltaLongitude -= 360 }
        if deltaLongitude < -180 { deltaLongitude += 360 }
        let x = deltaLongitude * scale
        let y = end.latitude - start.latitude
        let length = (x * x + y * y).squareRoot()
        guard length > 1e-9 else { return (0, 0) }
        return (latitude: x / length, longitude: -y / length / scale)
    }

    static func wrapLongitude(_ longitude: Double) -> Double {
        var value = longitude
        while value > 180 { value -= 360 }
        while value < -180 { value += 360 }
        return value
    }
}
