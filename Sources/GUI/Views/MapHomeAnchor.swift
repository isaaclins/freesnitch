import Foundation
import CoreLocation

/// Where "your Mac" sits on the connection map.
///
/// The map used to have no anchor at all unless CoreLocation answered, which
/// meant that with Location Services off there were no connection lines and no
/// home pin (#59). A firewall should not have to ask for your location to draw
/// a line, so the anchor is now always available: a persisted pin the user can
/// place themselves, with an offline estimate from the system time zone until
/// they do. CoreLocation is one optional source among three and is never
/// touched unless the user turns it on.
@MainActor
final class MapHomeAnchor: ObservableObject {
    /// One anchor for the app. The map pane and the Settings toggle have to be
    /// looking at the same object, or turning Location Services on in Settings
    /// would not move the marker until the next launch (#138).
    static let shared = MapHomeAnchor()

    enum Source: String {
        case timeZone
        case manual
        case locationServices

        var summary: String {
            switch self {
            case .timeZone: return "Estimated from your time zone"
            case .manual: return "Set by you"
            case .locationServices: return "From Location Services"
            }
        }
    }

    @Published private(set) var point: MapPoint
    @Published private(set) var source: Source
    @Published private(set) var usesLocationServices: Bool

    private let defaults: UserDefaults
    private var locationProvider: HomeLocationProvider?

    private enum Key {
        static let latitude = "PSMapHomeLatitude"
        static let longitude = "PSMapHomeLongitude"
        static let source = "PSMapHomeSource"
        static let locationServices = "PSMapHomeUsesLocationServices"
    }

    init(defaults: UserDefaults = AppPreferences.defaults) {
        self.defaults = defaults
        let stored = Self.storedPoint(in: defaults)
        let storedSource = Source(rawValue: defaults.string(forKey: Key.source) ?? "") ?? .timeZone
        point = stored ?? Self.timeZoneEstimate()
        source = stored == nil ? .timeZone : storedSource
        usesLocationServices = defaults.bool(forKey: Key.locationServices)
        if usesLocationServices { startLocationUpdates() }
    }

    var isEstimate: Bool { source == .timeZone }

    func setManualPoint(_ point: MapPoint) {
        apply(point, source: .manual)
    }

    /// Drops the manual pin and goes back to the offline time zone estimate.
    func resetToEstimate() {
        defaults.removeObject(forKey: Key.latitude)
        defaults.removeObject(forKey: Key.longitude)
        defaults.removeObject(forKey: Key.source)
        point = Self.timeZoneEstimate()
        source = .timeZone
    }

    /// The only path that can ever touch CoreLocation, and only after the user
    /// asks for it. Nothing here runs on first launch.
    func setUsesLocationServices(_ enabled: Bool) {
        guard usesLocationServices != enabled else { return }
        usesLocationServices = enabled
        defaults.set(enabled, forKey: Key.locationServices)
        if enabled {
            startLocationUpdates()
        } else {
            locationProvider = nil
            if source == .locationServices { resetToEstimate() }
        }
    }

    private func startLocationUpdates() {
        guard locationProvider == nil else { return }
        locationProvider = HomeLocationProvider { [weak self] coordinate in
            guard let self, self.usesLocationServices else { return }
            self.apply(MapPoint(latitude: coordinate.latitude, longitude: coordinate.longitude),
                       source: .locationServices)
        }
    }

    private func apply(_ point: MapPoint, source: Source) {
        self.point = point
        self.source = source
        defaults.set(point.latitude, forKey: Key.latitude)
        defaults.set(point.longitude, forKey: Key.longitude)
        defaults.set(source.rawValue, forKey: Key.source)
    }

    private static func storedPoint(in defaults: UserDefaults) -> MapPoint? {
        guard defaults.object(forKey: Key.latitude) != nil,
              defaults.object(forKey: Key.longitude) != nil else { return nil }
        let latitude = defaults.double(forKey: Key.latitude)
        let longitude = defaults.double(forKey: Key.longitude)
        guard latitude.isFinite, longitude.isFinite,
              abs(latitude) <= 90, abs(longitude) <= 180 else { return nil }
        return MapPoint(latitude: latitude, longitude: longitude)
    }

    /// An offline, permission-free first guess. The standard UTC offset fixes a
    /// longitude within one hour of true, and the zone's region gives a
    /// plausible latitude band. It is a placeholder, labelled as one, not a
    /// claim about where the user is.
    nonisolated static func timeZoneEstimate(_ zone: TimeZone = .current) -> MapPoint {
        let standardOffset = zone.secondsFromGMT() - Int(zone.daylightSavingTimeOffset())
        let longitude = MapGeometry.wrapLongitude(Double(standardOffset) / 240)
        let region = zone.identifier.split(separator: "/").first.map(String.init) ?? ""
        let latitude: Double
        switch region {
        case "Europe": latitude = 50
        case "America": latitude = 39
        case "Asia": latitude = 34
        case "Africa": latitude = 6
        case "Australia": latitude = -27
        case "Pacific": latitude = -17
        case "Atlantic": latitude = 38
        case "Indian": latitude = -12
        case "Antarctica": latitude = -70
        case "Arctic": latitude = 78
        default: latitude = 20
        }
        return MapPoint(latitude: latitude, longitude: longitude)
    }
}

/// Optional convenience only. Constructed exclusively by `MapHomeAnchor` after
/// the user opts in, so the app never asks for Location Services on its own.
private final class HomeLocationProvider: NSObject, CLLocationManagerDelegate {
    private let locationManager = CLLocationManager()
    private let onCoordinate: (CLLocationCoordinate2D) -> Void
    private var hasRequestedAuthorization = false

    init(onCoordinate: @escaping (CLLocationCoordinate2D) -> Void) {
        self.onCoordinate = onCoordinate
        super.init()
        locationManager.delegate = self
        updateAuthorizationStatus(locationManager.authorizationStatus)
    }

    deinit {
        locationManager.stopUpdatingLocation()
    }

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        updateAuthorizationStatus(manager.authorizationStatus)
    }

    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        guard let location = locations.last, location.horizontalAccuracy >= 0 else { return }
        manager.stopUpdatingLocation()
        let coordinate = location.coordinate
        DispatchQueue.main.async { [onCoordinate] in onCoordinate(coordinate) }
    }

    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        manager.stopUpdatingLocation()
    }

    private func updateAuthorizationStatus(_ status: CLAuthorizationStatus) {
        guard CLLocationManager.locationServicesEnabled() else {
            locationManager.stopUpdatingLocation()
            return
        }
        switch status {
        case .notDetermined:
            guard !hasRequestedAuthorization else { return }
            hasRequestedAuthorization = true
            // Avoid a platform failure if an older bundle has not yet added the usage string.
            guard let usageDescription = Bundle.main.object(forInfoDictionaryKey: "NSLocationWhenInUseUsageDescription") as? String,
                  !usageDescription.isEmpty else { return }
            locationManager.requestWhenInUseAuthorization()
        case .authorizedAlways, .authorizedWhenInUse:
            locationManager.startUpdatingLocation()
        case .denied, .restricted:
            locationManager.stopUpdatingLocation()
        @unknown default:
            locationManager.stopUpdatingLocation()
        }
    }
}
