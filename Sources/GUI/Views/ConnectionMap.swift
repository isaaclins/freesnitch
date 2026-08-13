import SwiftUI
import MapKit
import CoreLocation
import AppKit

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

private struct HomePin: View {
    var body: some View {
        Circle()
            .fill(PSTheme.accent)
            .frame(width: 24, height: 24)
            .overlay(Image(systemName: "house.fill")
                .font(.system(size: 11, weight: .bold))
                .foregroundColor(.white))
            .overlay(Circle().stroke(Color.white.opacity(0.9), lineWidth: 1.5))
    }
}

private final class HomeLocationProvider: NSObject, ObservableObject, CLLocationManagerDelegate {
    @Published var coordinate: CLLocationCoordinate2D?

    private let locationManager = CLLocationManager()
    private var hasRequestedAuthorization = false

    override init() {
        super.init()
        locationManager.delegate = self
        updateAuthorizationStatus(locationManager.authorizationStatus)
    }

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        updateAuthorizationStatus(manager.authorizationStatus)
    }

    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        guard let location = locations.last, location.horizontalAccuracy >= 0 else { return }
        coordinate = location.coordinate
        manager.stopUpdatingLocation()
    }

    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        manager.stopUpdatingLocation()
    }

    private func updateAuthorizationStatus(_ status: CLAuthorizationStatus) {
        guard CLLocationManager.locationServicesEnabled() else {
            locationManager.stopUpdatingLocation()
            coordinate = nil
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
            coordinate = nil
        @unknown default:
            locationManager.stopUpdatingLocation()
            coordinate = nil
        }
    }
}

@available(macOS 14.0, *)
struct ConnectionMapPane: View {
    let connections: [Connection]
    @State private var cameraPosition: MapCameraPosition = .region(
        MKCoordinateRegion(center: .init(latitude: 20, longitude: 0),
                           span: .init(latitudeDelta: 130, longitudeDelta: 360)))
    @StateObject private var homeLocation = HomeLocationProvider()

    private var endpointGroups: [EndpointGroup] {
        var grouped: [String: [Connection]] = [:]
        for connection in connections {
            guard let latitude = connection.latitude, let longitude = connection.longitude else { continue }
            let latitudeKey = Int((latitude * 100).rounded())
            let longitudeKey = Int((longitude * 100).rounded())
            grouped["\(latitudeKey):\(longitudeKey)", default: []].append(connection)
        }

        return grouped.compactMap { key, connections in
            guard let first = connections.first,
                  let latitude = first.latitude,
                  let longitude = first.longitude else { return nil }
            return EndpointGroup(id: key,
                                 coordinate: .init(latitude: latitude, longitude: longitude),
                                 connections: connections)
        }
        .sorted { $0.id < $1.id }
    }

    var body: some View {
        Map(position: $cameraPosition) {
            if let homeCoordinate = homeLocation.coordinate {
                ForEach(endpointGroups) { group in
                    MapPolyline(coordinates: [homeCoordinate, group.coordinate])
                        .stroke(PSTheme.accentBlue.opacity(0.42), lineWidth: 1)
                }
                Annotation("Your Mac", coordinate: homeCoordinate) {
                    HomePin()
                }
            }

            ForEach(endpointGroups) { group in
                Annotation("", coordinate: group.coordinate) {
                    NodePin(label: group.label)
                }
            }
        }
        .mapStyle(.standard(elevation: .flat, emphasis: .muted, pointsOfInterest: .excludingAll))
        .colorScheme(.dark)
    }

    private struct EndpointGroup: Identifiable {
        let id: String
        let coordinate: CLLocationCoordinate2D
        let label: String

        init(id: String, coordinate: CLLocationCoordinate2D, connections: [Connection]) {
            let first = connections[0]
            let baseLabel: String
            if let country = first.country, !country.isEmpty {
                baseLabel = country
            } else if !first.remoteHost.isEmpty {
                baseLabel = first.remoteHost
            } else if !first.remoteIP.isEmpty {
                baseLabel = first.remoteIP
            } else {
                baseLabel = "Unknown"
            }
            self.id = id
            self.coordinate = coordinate
            self.label = "\(baseLabel) (\(connections.count))"
        }
    }
}

