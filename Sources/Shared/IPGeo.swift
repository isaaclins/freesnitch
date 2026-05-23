import Foundation

public actor IPGeoCache {
    public struct Entry: Codable, Sendable {
        public let ip: String
        public let country: String?
        public let countryCode: String?
        public let lat: Double?
        public let lon: Double?
    }

    public static let shared = IPGeoCache()
    private var cache: [String: Entry] = [:]
    private var inflight: [String: Task<Entry?, Never>] = [:]
    private let endpoint = "https://ip-api.com/json"

    public func lookup(_ ip: String) async -> Entry? {
        if let e = cache[ip] { return e }
        if let t = inflight[ip] { return await t.value }
        let task = Task { () -> Entry? in
            defer { self.inflight.removeValue(forKey: ip) }
            guard let url = URL(string: "\(self.endpoint)/\(ip)?fields=status,country,countryCode,lat,lon") else { return nil }
            var req = URLRequest(url: url, timeoutInterval: 4)
            req.httpMethod = "GET"
            do {
                let (data, _) = try await URLSession.shared.data(for: req)
                let j = try JSONSerialization.jsonObject(with: data) as? [String: Any]
                let e = Entry(
                    ip: ip,
                    country: j?["country"] as? String,
                    countryCode: j?["countryCode"] as? String,
                    lat: j?["lat"] as? Double,
                    lon: j?["lon"] as? Double
                )
                self.cache[ip] = e
                return e
            } catch { return nil }
        }
        inflight[ip] = task
        return await task.value
    }
}
