import Foundation

public final class IPGeoCache: @unchecked Sendable {
    public struct Entry: Codable, Sendable {
        public let ip: String
        public let country: String?
        public let countryCode: String?
        public let lat: Double?
        public let lon: Double?
    }

    public static let shared = IPGeoCache()

    private struct Source {
        let fileName: String
        let url: String
    }

    private struct Country: Sendable {
        let code: String
        let name: String?
        let latitude: Double?
        let longitude: Double?
    }

    private struct ParsedDatabase {
        let starts: [UInt32]
        let ends: [UInt32]
        let countryIndexes: [UInt16]
        let countries: [Country]
    }

    private struct GeoParseError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    private static let sources = [
        Source(
            fileName: "dbip-country-ipv4.csv",
            url: "https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-ipv4.csv"
        ),
        Source(
            fileName: "countries.csv",
            url: "https://raw.githubusercontent.com/google/dspl/master/samples/google/canonical/countries.csv"
        )
    ]
    private static let cacheLifetime: TimeInterval = 30 * 24 * 60 * 60

    private let cacheDirectory: URL
    private let loadQueue = DispatchQueue(label: "io.moamenbasel.puresnitch.geo.load", qos: .utility)
    private let stateQueue = DispatchQueue(label: "io.moamenbasel.puresnitch.geo.state")
    private var rangeStarts: [UInt32] = []
    private var rangeEnds: [UInt32] = []
    private var countryIndexes: [UInt16] = []
    private var countries: [Country] = []
    private var isLoaded = false
    private var readyCallbacks: [() -> Void] = []

    public init() {
        cacheDirectory = Self.defaultCacheDirectory()
        loadQueue.async { [weak self] in self?.loadDatabase() }
    }

    public func lookup(_ ip: String) -> Entry? {
        guard let address = Self.ipv4Value(ip), !Self.isUngeolocatable(address) else { return nil }
        return stateQueue.sync {
            guard isLoaded, let index = Self.rangeIndex(for: address, starts: rangeStarts),
                  address <= rangeEnds[index] else { return nil }
            let countryIndex = Int(countryIndexes[index])
            guard countryIndex < countries.count else { return nil }
            let country = countries[countryIndex]
            return Entry(ip: ip, country: country.name, countryCode: country.code,
                         lat: country.latitude, lon: country.longitude)
        }
    }

    public func onReady(_ callback: @escaping () -> Void) {
        var callNow = false
        stateQueue.sync {
            if isLoaded {
                callNow = true
            } else {
                readyCallbacks.append(callback)
            }
        }
        if callNow { callback() }
    }

    private static func defaultCacheDirectory() -> URL {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support", isDirectory: true)
        return appSupport.appendingPathComponent("PureSnitch", isDirectory: true)
            .appendingPathComponent("geo", isDirectory: true)
    }

    private func loadDatabase() {
        let fileManager = FileManager.default
        do {
            try fileManager.createDirectory(at: cacheDirectory, withIntermediateDirectories: true)
        } catch {
            finishLoading()
            PSLog.error(PSLog.app, "offline geolocation cache unavailable: cannot create directory - \(error)")
            return
        }

        let cached = Self.sources.map { source in
            (source: source, url: cacheDirectory.appendingPathComponent(source.fileName))
        }
        let stale = cached.filter { Self.needsRefresh(at: $0.url) }
        if !stale.isEmpty {
            let group = DispatchGroup()
            let resultLock = NSLock()
            var failures: [String] = []
            for item in stale {
                group.enter()
                download(item.source, to: item.url) { failure in
                    if let failure {
                        resultLock.lock()
                        failures.append("\(item.source.fileName): \(failure)")
                        resultLock.unlock()
                    }
                    group.leave()
                }
            }
            group.wait()
            if !failures.isEmpty {
                finishLoading()
                PSLog.error(PSLog.app, "offline geolocation download failed: \(failures.joined(separator: "; "))")
                return
            }
        }

        guard cached.allSatisfy({ fileManager.fileExists(atPath: $0.url.path) }) else {
            finishLoading()
            PSLog.error(PSLog.app, "offline geolocation cache unavailable: downloaded files are missing")
            return
        }

        do {
            var countryData = try Self.parseCountries(at: cached[1].url)
            let database = try Self.parseRanges(at: cached[0].url,
                                                countries: &countryData.countries,
                                                indexByCode: &countryData.indexByCode)
            finishLoading(database)
        } catch {
            finishLoading()
            PSLog.error(PSLog.app, "offline geolocation database could not be parsed: \(error)")
        }
    }

    private func download(_ source: Source, to destination: URL, completion: @escaping (String?) -> Void) {
        guard let url = URL(string: source.url) else {
            completion("invalid source URL")
            return
        }
        var request = URLRequest(url: url, timeoutInterval: 60)
        request.setValue("PureSnitch/0.2", forHTTPHeaderField: "User-Agent")
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error {
                completion(error.localizedDescription)
                return
            }
            guard let response = response as? HTTPURLResponse,
                  (200..<300).contains(response.statusCode) else {
                let status = (response as? HTTPURLResponse)?.statusCode ?? 0
                completion("HTTP status \(status)")
                return
            }
            guard let data, !data.isEmpty else {
                completion("empty response")
                return
            }
            do {
                try data.write(to: destination, options: .atomic)
                completion(nil)
            } catch {
                completion(error.localizedDescription)
            }
        }.resume()
    }

    private static func needsRefresh(at url: URL) -> Bool {
        guard FileManager.default.fileExists(atPath: url.path),
              let values = try? url.resourceValues(forKeys: [.contentModificationDateKey]),
              let date = values.contentModificationDate else { return true }
        return Date().timeIntervalSince(date) > cacheLifetime
    }

    private static func parseCountries(at url: URL) throws -> (countries: [Country], indexByCode: [String: UInt16]) {
        let text = try String(contentsOf: url, encoding: .utf8)
        let lines = text.split(whereSeparator: \.isNewline)
        guard let header = lines.first,
              csvFields(header).prefix(4).map({ $0.lowercased() }) == ["country", "latitude", "longitude", "name"] else {
            throw GeoParseError(message: "country file has an unexpected header")
        }

        var countries: [Country] = []
        var indexByCode: [String: UInt16] = [:]
        countries.reserveCapacity(lines.count - 1)
        indexByCode.reserveCapacity(lines.count - 1)
        for (offset, line) in lines.dropFirst().enumerated() {
            if String(line).trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { continue }
            let fields = csvFields(line)
            guard fields.count >= 4 else {
                throw GeoParseError(message: "country file line \(offset + 2) is malformed")
            }
            let code = fields[0].uppercased()
            let name = fields[3].isEmpty ? nil : fields[3]
            guard !code.isEmpty, name != nil else {
                throw GeoParseError(message: "country file line \(offset + 2) is missing a code or name")
            }
            guard countries.count < Int(UInt16.max) else {
                throw GeoParseError(message: "country metadata table is too large")
            }
            let index = UInt16(countries.count)
            countries.append(Country(code: code, name: name,
                                     latitude: Double(fields[1]), longitude: Double(fields[2])))
            indexByCode[code] = index
        }
        guard !countries.isEmpty else {
            throw GeoParseError(message: "country file is empty")
        }
        return (countries, indexByCode)
    }

    private static func parseRanges(at url: URL, countries: inout [Country], indexByCode: inout [String: UInt16]) throws -> ParsedDatabase {
        let text = try String(contentsOf: url, encoding: .utf8)
        var starts: [UInt32] = []
        var ends: [UInt32] = []
        var countryIndexes: [UInt16] = []
        starts.reserveCapacity(360_000)
        ends.reserveCapacity(360_000)
        countryIndexes.reserveCapacity(360_000)

        for (offset, line) in text.split(whereSeparator: \.isNewline).enumerated() {
            let fields = line.split(separator: ",", maxSplits: 2, omittingEmptySubsequences: false)
            guard fields.count == 3,
                  let start = ipv4Value(String(fields[0])),
                  let end = ipv4Value(String(fields[1])),
                  start <= end else {
                throw GeoParseError(message: "range file line \(offset + 1) is malformed")
            }
            if let previous = starts.last, start < previous {
                throw GeoParseError(message: "range file is not sorted at line \(offset + 1)")
            }
            let code = String(fields[2]).trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
            guard !code.isEmpty else {
                throw GeoParseError(message: "range file line \(offset + 1) has no country code")
            }
            let countryIndex: UInt16
            if let knownIndex = indexByCode[code] {
                countryIndex = knownIndex
            } else {
                guard countries.count < Int(UInt16.max) else {
                    throw GeoParseError(message: "country metadata table is too large")
                }
                countryIndex = UInt16(countries.count)
                countries.append(Country(code: code, name: nil, latitude: nil, longitude: nil))
                indexByCode[code] = countryIndex
            }
            starts.append(start)
            ends.append(end)
            countryIndexes.append(countryIndex)
        }
        guard !starts.isEmpty else {
            throw GeoParseError(message: "range file is empty")
        }
        return ParsedDatabase(starts: starts, ends: ends, countryIndexes: countryIndexes, countries: countries)
    }

    private static func csvFields(_ line: Substring) -> [String] {
        var fields: [String] = []
        var field = ""
        var quoted = false
        let characters = Array(line)
        var index = 0
        while index < characters.count {
            let character = characters[index]
            if character == "\"" {
                if quoted, index + 1 < characters.count, characters[index + 1] == "\"" {
                    field.append("\"")
                    index += 2
                    continue
                }
                quoted.toggle()
            } else if character == "," && !quoted {
                fields.append(field.trimmingCharacters(in: .whitespacesAndNewlines))
                field = ""
            } else {
                field.append(character)
            }
            index += 1
        }
        fields.append(field.trimmingCharacters(in: .whitespacesAndNewlines))
        return fields
    }

    private func finishLoading(_ database: ParsedDatabase? = nil) {
        var callbacks: [() -> Void] = []
        stateQueue.sync {
            if let database {
                rangeStarts = database.starts
                rangeEnds = database.ends
                countryIndexes = database.countryIndexes
                countries = database.countries
            }
            isLoaded = true
            callbacks = readyCallbacks
            readyCallbacks.removeAll()
        }
        callbacks.forEach { $0() }
    }

    private static func ipv4Value(_ ip: String) -> UInt32? {
        let parts = ip.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var value: UInt32 = 0
        for part in parts {
            guard let octet = UInt32(part), octet <= 255 else { return nil }
            value = (value << 8) | octet
        }
        return value
    }

    private static func isUngeolocatable(_ address: UInt32) -> Bool {
        address == 0
            || address & 0xff000000 == 0x0a000000
            || address & 0xfff00000 == 0xac100000
            || address & 0xffff0000 == 0xc0a80000
            || address & 0xff000000 == 0x7f000000
            || address & 0xffff0000 == 0xa9fe0000
            || address & 0xffc00000 == 0x64400000
            || address & 0xf0000000 == 0xe0000000
    }

    private static func rangeIndex(for address: UInt32, starts: [UInt32]) -> Int? {
        var lower = 0
        var upper = starts.count
        while lower < upper {
            let middle = (lower + upper) / 2
            if starts[middle] <= address {
                lower = middle + 1
            } else {
                upper = middle
            }
        }
        let index = lower - 1
        return index >= 0 ? index : nil
    }
}
