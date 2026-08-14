import Foundation
import Compression

/// Offline IP geolocation.
///
/// The lookup answer is city level where the database knows a city, and it
/// degrades to the country centroid, labelled as country level, where it does
/// not. Both IPv4 and IPv6 are answered from the same code path.
///
/// The shipped data is DB-IP City Lite, downloaded in bulk once and cached, and
/// never queried per address. There is no per-connection network call anywhere
/// in this file.
///
/// Storage is a compact binary index built once from the downloaded CSVs and
/// then memory mapped. The parsed tables therefore live in the page cache
/// rather than on the heap, which is what makes a database of this size
/// affordable in a menu bar app. See `Scripts/test_ipgeo.sh` for the measured
/// numbers.
public final class IPGeoCache: @unchecked Sendable {
    /// How precise a returned coordinate is. A country answer is the country
    /// centroid, not a place anyone connected to.
    public enum Precision: String, Codable, Sendable {
        case city
        case country
    }

    public struct Entry: Codable, Sendable {
        public let ip: String
        public let country: String?
        public let countryCode: String?
        public let city: String?
        public let lat: Double?
        public let lon: Double?
        public let precision: Precision

        public init(ip: String, country: String?, countryCode: String?, city: String?,
                    lat: Double?, lon: Double?, precision: Precision) {
            self.ip = ip
            self.country = country
            self.countryCode = countryCode
            self.city = city
            self.lat = lat
            self.lon = lon
            self.precision = precision
        }

        /// True when the coordinate is the city's own coordinate. False means
        /// the coordinate is the country centroid and must be presented as
        /// country level.
        public var isCityLevel: Bool { precision == .city }
    }

    /// DB-IP City Lite is CC BY 4.0 and requires a visible credit with a link
    /// back to db-ip.com wherever its results are displayed.
    public struct Attribution: Sendable {
        public let text: String
        public let linkTitle: String
        public let linkURL: String
        public let licenseName: String
        public let licenseURL: String
    }

    public static let attribution = Attribution(
        text: "IP Geolocation by DB-IP",
        linkTitle: "DB-IP",
        linkURL: "https://db-ip.com/",
        licenseName: "CC BY 4.0",
        licenseURL: "https://creativecommons.org/licenses/by/4.0/"
    )

    /// What the cache currently knows. Reported rather than guessed, so a
    /// degraded state can be shown as degraded instead of as an empty map.
    public struct Status: Sendable {
        public let isLoaded: Bool
        public let hasDatabase: Bool
        public let ipv4RangeCount: Int
        public let ipv6RangeCount: Int
        public let placeCount: Int
        public let indexBytes: Int
        public let builtAt: Date?
        public let lastError: String?
    }

    /// Writes the bytes at `url` to `destination`, or returns why it could not.
    /// The default implementation is a bounded HTTPS download. Tests supply a
    /// local one so that nothing in the test path can reach the network.
    public typealias SourceFetcher = @Sendable (_ url: String, _ destination: URL) -> String?

    public static let shared = IPGeoCache()

    // MARK: - Sources and ceilings

    struct Source: Sendable {
        let fileName: String
        let url: String
        /// Refuse anything larger. A source that grows past this is treated as
        /// a failure, not as something to load into memory and find out.
        let maxBytes: Int
    }

    /// The city databases are published only as gzip, so both are fetched
    /// compressed and decompressed while streaming.
    static let ipv4Source = Source(
        fileName: "dbip-city-ipv4.csv.gz",
        url: "https://github.com/sapics/ip-location-db/releases/download/latest/dbip-city-ipv4.csv.gz",
        maxBytes: 128 * 1024 * 1024
    )
    static let ipv6Source = Source(
        fileName: "dbip-city-ipv6.csv.gz",
        url: "https://github.com/sapics/ip-location-db/releases/download/latest/dbip-city-ipv6.csv.gz",
        maxBytes: 128 * 1024 * 1024
    )
    static let countrySource = Source(
        fileName: "countries.csv",
        url: "https://raw.githubusercontent.com/google/dspl/master/samples/google/canonical/countries.csv",
        maxBytes: 4 * 1024 * 1024
    )

    static var sources: [Source] { [ipv4Source, ipv6Source, countrySource] }

    /// DB-IP Lite is republished monthly, so a monthly refresh is as fresh as
    /// the data ever gets.
    static let cacheLifetime: TimeInterval = 30 * 24 * 60 * 60
    /// A decompressed city CSV is around 700 MB for both families together.
    /// Anything past this per file is refused rather than streamed.
    static let maxDecompressedBytes = 1_536 * 1024 * 1024
    static let maxRangeRows = 24_000_000
    static let maxPlaceCount = 4_000_000
    static let maxNameBytes = 128 * 1024 * 1024

    static let indexFileName = "dbip-city.index"
    /// Files an older FreeSnitch cached that this version no longer reads.
    static let obsoleteCacheFileNames = ["dbip-country-ipv4.csv"]

    // MARK: - Instance state

    private let cacheDirectory: URL
    private let fetcher: SourceFetcher
    private let loadQueue = DispatchQueue(label: "io.isaaclins.freesnitch.geo.load", qos: .utility)
    private let stateQueue = DispatchQueue(label: "io.isaaclins.freesnitch.geo.state")
    private var index: GeoIndex?
    private var isLoaded = false
    private var lastError: String?
    private var readyCallbacks: [() -> Void] = []

    public convenience init() {
        self.init(cacheDirectory: Self.defaultCacheDirectory(), fetcher: Self.httpFetcher, startLoading: true)
    }

    /// Designated initializer. Loading always happens on `loadQueue`, so this
    /// returns immediately and app startup never waits on a download.
    public init(cacheDirectory: URL, fetcher: @escaping SourceFetcher, startLoading: Bool = true) {
        self.cacheDirectory = cacheDirectory
        self.fetcher = fetcher
        if startLoading {
            loadQueue.async { [weak self] in self?.loadDatabase() }
        }
    }

    // MARK: - Lookup

    public func lookup(_ ip: String) -> Entry? {
        var text = ip
        let located: (place: UInt32, index: GeoIndex)? = text.withUTF8 { bytes -> (UInt32, GeoIndex)? in
            guard let target = Self.parseTarget(bytes) else { return nil }
            return stateQueue.sync { () -> (UInt32, GeoIndex)? in
                guard let index else { return nil }
                let place: UInt32?
                switch target {
                case .ipv4(let address): place = index.place(ipv4: address)
                case .ipv6(let value): place = index.place(ipv6: value)
                }
                guard let place else { return nil }
                return (place, index)
            }
        }
        guard let located else { return nil }
        return located.index.entry(ip: ip, placeIndex: located.place)
    }

    /// Range search only, with no `Entry` and therefore no string building.
    /// This is the shape the per-flow path uses when it only needs to know
    /// whether an address is locatable, and it is what the harness measures for
    /// allocation behaviour.
    public func placeIndex(ipv4 address: UInt32) -> UInt32? {
        stateQueue.sync { index?.place(ipv4: address) }
    }

    public func placeIndex(ipv6 value: IPv6Value) -> UInt32? {
        stateQueue.sync { index?.place(ipv6: value) }
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

    public var status: Status {
        stateQueue.sync {
            Status(isLoaded: isLoaded,
                   hasDatabase: index != nil,
                   ipv4RangeCount: index?.v4Count ?? 0,
                   ipv6RangeCount: index?.v6Count ?? 0,
                   placeCount: index?.placeCount ?? 0,
                   indexBytes: index?.byteCount ?? 0,
                   builtAt: index?.builtAt,
                   lastError: lastError)
        }
    }

    /// Re-runs the load path. A failure here leaves whatever is already loaded
    /// in place; it never clears a working database.
    public func reload(force: Bool = false, completion: (() -> Void)? = nil) {
        loadQueue.async { [weak self] in
            self?.loadDatabase(force: force)
            completion?()
        }
    }

    // MARK: - Loading

    private func loadDatabase(force: Bool = false) {
        let fileManager = FileManager.default
        do {
            try fileManager.createDirectory(at: cacheDirectory, withIntermediateDirectories: true)
        } catch {
            finishLoading(error: "offline geolocation cache unavailable: cannot create directory - \(error)")
            return
        }

        let indexURL = cacheDirectory.appendingPathComponent(Self.indexFileName)

        // Serve whatever is already on disk first. After the first run the map
        // has coordinates immediately, and a refresh is a background upgrade
        // rather than something the UI waits for.
        var haveIndex = currentIndex != nil
        if !haveIndex, fileManager.fileExists(atPath: indexURL.path) {
            do {
                publish(try GeoIndex(contentsOf: indexURL))
                haveIndex = true
            } catch {
                PSLog.error(PSLog.app, "offline geolocation index unusable, rebuilding: \(error)")
            }
        }

        let stale = force || Self.needsRefresh(at: indexURL)
        if !stale && haveIndex {
            finishLoading(error: nil)
            return
        }
        if haveIndex { finishLoading(error: nil) }

        do {
            try refresh(indexURL: indexURL)
            finishLoading(error: nil)
        } catch {
            let message = "offline geolocation database unavailable: \(error.localizedDescription)"
            if haveIndex {
                // The previous database is still mapped and still answering.
                setLastError(message)
                PSLog.error(PSLog.app, message)
            } else {
                finishLoading(error: message)
            }
        }
    }

    private func refresh(indexURL: URL) throws {
        let fileManager = FileManager.default
        var downloaded: [URL] = []
        defer { downloaded.forEach { try? fileManager.removeItem(at: $0) } }

        for source in Self.sources {
            let destination = cacheDirectory.appendingPathComponent(source.fileName + ".download")
            try? fileManager.removeItem(at: destination)
            if let failure = fetcher(source.url, destination) {
                throw GeoError("\(source.fileName): \(failure)")
            }
            guard let size = try? fileManager.attributesOfItem(atPath: destination.path)[.size] as? Int, size > 0 else {
                throw GeoError("\(source.fileName): the download produced no readable file")
            }
            guard size <= source.maxBytes else {
                throw GeoError("\(source.fileName): \(size) bytes exceeds the \(source.maxBytes) byte ceiling")
            }
            downloaded.append(destination)
        }

        let staging = indexURL.appendingPathExtension("building")
        try? fileManager.removeItem(at: staging)
        do {
            _ = try Self.buildIndex(ipv4CSV: downloaded[0],
                                    ipv6CSV: downloaded[1],
                                    countriesCSV: downloaded[2],
                                    to: staging)
            // Prove the file we are about to install actually opens before the
            // working one is replaced.
            let candidate = try GeoIndex(contentsOf: staging)
            // The mapping above survives the rename, so installing the file and
            // publishing it cannot disagree.
            if fileManager.fileExists(atPath: indexURL.path) {
                _ = try fileManager.replaceItemAt(indexURL, withItemAt: staging)
            } else {
                try fileManager.moveItem(at: staging, to: indexURL)
            }
            publish(candidate)
            setLastError(nil)
        } catch {
            try? fileManager.removeItem(at: staging)
            throw error
        }

        for name in Self.obsoleteCacheFileNames {
            try? fileManager.removeItem(at: cacheDirectory.appendingPathComponent(name))
        }
    }

    private func publish(_ newIndex: GeoIndex) {
        stateQueue.sync { index = newIndex }
    }

    private var currentIndex: GeoIndex? {
        stateQueue.sync { index }
    }

    private func setLastError(_ message: String?) {
        stateQueue.sync { lastError = message }
    }

    private func finishLoading(error: String?) {
        var callbacks: [() -> Void] = []
        stateQueue.sync {
            if let error { lastError = error }
            isLoaded = true
            callbacks = readyCallbacks
            readyCallbacks.removeAll()
        }
        if let error { PSLog.error(PSLog.app, error) }
        callbacks.forEach { $0() }
    }

    static func defaultCacheDirectory() -> URL {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support", isDirectory: true)
        return appSupport.appendingPathComponent("FreeSnitch", isDirectory: true)
            .appendingPathComponent("geo", isDirectory: true)
    }

    static func needsRefresh(at url: URL) -> Bool {
        guard FileManager.default.fileExists(atPath: url.path),
              let values = try? url.resourceValues(forKeys: [.contentModificationDateKey]),
              let date = values.contentModificationDate else { return true }
        return Date().timeIntervalSince(date) > cacheLifetime
    }

    /// Bounded HTTPS download straight to a file, so a large database never
    /// sits in memory as a `Data`.
    static let httpFetcher: SourceFetcher = { urlString, destination in
        guard let url = URL(string: urlString) else { return "invalid source URL" }
        var request = URLRequest(url: url, timeoutInterval: 120)
        request.setValue("FreeSnitch/0.2", forHTTPHeaderField: "User-Agent")
        let semaphore = DispatchSemaphore(value: 0)
        var failure: String?
        let task = URLSession.shared.downloadTask(with: request) { temporary, response, error in
            defer { semaphore.signal() }
            if let error {
                failure = error.localizedDescription
                return
            }
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                failure = "HTTP status \((response as? HTTPURLResponse)?.statusCode ?? 0)"
                return
            }
            guard let temporary else {
                failure = "no downloaded file"
                return
            }
            do {
                try? FileManager.default.removeItem(at: destination)
                try FileManager.default.moveItem(at: temporary, to: destination)
            } catch {
                failure = error.localizedDescription
            }
        }
        task.resume()
        // The transfer is on a utility queue and the request itself is capped,
        // so a stalled server cannot hold the queue forever.
        if semaphore.wait(timeout: .now() + 600) == .timedOut {
            task.cancel()
            return "timed out"
        }
        return failure
    }

    // MARK: - Address parsing

    enum Target {
        case ipv4(UInt32)
        case ipv6(IPv6Value)
    }

    /// Parses an address and rejects everything that cannot meaningfully be on
    /// a map: unspecified, loopback, private, link-local, shared address space
    /// and multicast, in both families.
    static func parseTarget(_ bytes: UnsafeBufferPointer<UInt8>) -> Target? {
        guard !bytes.isEmpty else { return nil }
        var hasColon = false
        for byte in bytes where byte == UInt8(ascii: ":") {
            hasColon = true
            break
        }
        if hasColon {
            guard let value = ipv6Value(bytes) else { return nil }
            // An IPv4-mapped address is an IPv4 address wearing IPv6 syntax and
            // must resolve through the IPv4 tables.
            if value.upper == 0, value.lower >> 32 == 0x0000_ffff {
                let address = UInt32(truncatingIfNeeded: value.lower)
                return isUngeolocatable(ipv4: address) ? nil : .ipv4(address)
            }
            return isUngeolocatable(ipv6: value) ? nil : .ipv6(value)
        }
        guard let address = ipv4Value(bytes), !isUngeolocatable(ipv4: address) else { return nil }
        return .ipv4(address)
    }

    public static func parseIPv4(_ ip: String) -> UInt32? {
        var text = ip
        return text.withUTF8 { ipv4Value($0) }
    }

    public static func parseIPv6(_ ip: String) -> IPv6Value? {
        var text = ip
        return text.withUTF8 { ipv6Value($0) }
    }

    static func ipv4Value(_ bytes: UnsafeBufferPointer<UInt8>) -> UInt32? {
        var value: UInt32 = 0
        var octet: UInt32 = 0
        var digits = 0
        var parts = 0
        for byte in bytes {
            if byte == UInt8(ascii: ".") {
                guard digits > 0, parts < 3 else { return nil }
                value = (value << 8) | octet
                parts += 1
                octet = 0
                digits = 0
                continue
            }
            guard byte >= UInt8(ascii: "0"), byte <= UInt8(ascii: "9"), digits < 3 else { return nil }
            octet = octet * 10 + UInt32(byte - UInt8(ascii: "0"))
            guard octet <= 255 else { return nil }
            digits += 1
        }
        guard parts == 3, digits > 0 else { return nil }
        return (value << 8) | octet
    }

    /// RFC 4291 text form, including `::` compression and a trailing dotted
    /// quad. A zone identifier is rejected: a scoped address is link-local and
    /// is not locatable anyway.
    static func ipv6Value(_ bytes: UnsafeBufferPointer<UInt8>) -> IPv6Value? {
        var groups = (UInt16(0), UInt16(0), UInt16(0), UInt16(0), UInt16(0), UInt16(0), UInt16(0), UInt16(0))
        return withUnsafeMutableBytes(of: &groups) { raw -> IPv6Value? in
            let slots = raw.bindMemory(to: UInt16.self)
            var count = 0
            var compressAt = -1
            var index = 0
            let end = bytes.count

            if end >= 2, bytes[0] == UInt8(ascii: ":") {
                guard bytes[1] == UInt8(ascii: ":") else { return nil }
                compressAt = 0
                index = 2
            }

            while index < end {
                if bytes[index] == UInt8(ascii: ":") {
                    guard compressAt < 0, count > 0 else { return nil }
                    compressAt = count
                    index += 1
                    if index == end { break }
                    continue
                }

                // A dotted quad may only appear last, and fills two groups.
                var scan = index
                var isDotted = false
                while scan < end, bytes[scan] != UInt8(ascii: ":") {
                    if bytes[scan] == UInt8(ascii: ".") { isDotted = true }
                    scan += 1
                }
                guard scan > index else { return nil }
                if isDotted {
                    guard scan == end, count + 2 <= 8,
                          let address = ipv4Value(UnsafeBufferPointer(rebasing: bytes[index..<scan])) else { return nil }
                    slots[count] = UInt16(truncatingIfNeeded: address >> 16)
                    slots[count + 1] = UInt16(truncatingIfNeeded: address)
                    count += 2
                    index = scan
                    break
                }
                guard scan - index <= 4, count < 8 else { return nil }
                var group: UInt32 = 0
                for position in index..<scan {
                    guard let digit = Self.hexDigit(bytes[position]) else { return nil }
                    group = (group << 4) | UInt32(digit)
                }
                slots[count] = UInt16(truncatingIfNeeded: group)
                count += 1
                index = scan
                if index < end {
                    guard bytes[index] == UInt8(ascii: ":") else { return nil }
                    index += 1
                    if index == end {
                        // A trailing single colon is only legal as part of "::".
                        guard compressAt == count else { return nil }
                    }
                }
            }

            if compressAt >= 0 {
                guard count < 8 else { return nil }
                let shift = 8 - count
                var slot = 7
                while slot >= compressAt + shift {
                    slots[slot] = slots[slot - shift]
                    slot -= 1
                }
                while slot >= compressAt {
                    slots[slot] = 0
                    slot -= 1
                }
            } else {
                guard count == 8 else { return nil }
            }

            var upper: UInt64 = 0
            var lower: UInt64 = 0
            for slot in 0..<4 { upper = (upper << 16) | UInt64(slots[slot]) }
            for slot in 4..<8 { lower = (lower << 16) | UInt64(slots[slot]) }
            return IPv6Value(upper: upper, lower: lower)
        }
    }

    private static func hexDigit(_ byte: UInt8) -> UInt8? {
        switch byte {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return byte - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): return byte - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"): return byte - UInt8(ascii: "A") + 10
        default: return nil
        }
    }

    static func isUngeolocatable(ipv4 address: UInt32) -> Bool {
        address & 0xff000000 == 0x00000000        // 0.0.0.0/8, this network
            || address & 0xff000000 == 0x0a000000 // 10/8
            || address & 0xfff00000 == 0xac100000 // 172.16/12
            || address & 0xffff0000 == 0xc0a80000 // 192.168/16
            || address & 0xff000000 == 0x7f000000 // 127/8
            || address & 0xffff0000 == 0xa9fe0000 // 169.254/16
            || address & 0xffc00000 == 0x64400000 // 100.64/10
            || address & 0xf0000000 == 0xe0000000 // 224/4 multicast and above
    }

    static func isUngeolocatable(ipv6 value: IPv6Value) -> Bool {
        if value.upper == 0 && (value.lower == 0 || value.lower == 1) { return true } // :: and ::1
        let top = value.upper >> 56
        if top == 0xff { return true }                                          // ff00::/8 multicast
        if value.upper >> 54 == 0x3fa { return true }                            // fe80::/10 link-local
        if value.upper >> 57 == 0x7e { return true }                             // fc00::/7 unique local
        return false
    }

    // MARK: - Errors

    struct GeoError: LocalizedError {
        let message: String
        init(_ message: String) { self.message = message }
        var errorDescription: String? { message }
    }
}

// MARK: - Compact index format
//
// The downloaded CSVs are ~700 MB of text for both families. Holding the parsed
// tables on the heap would cost hundreds of megabytes in a menu bar app, so the
// CSVs are converted once into a fixed-width binary index and then memory
// mapped read-only. Search touches a handful of pages per lookup, the pages are
// clean and evictable, and the heap holds nothing that scales with the database.
//
// Layout, little endian, every section 8-byte aligned:
//
//   0   header        (56 bytes of fields, 128 bytes reserved)
//   128 v4 rows       V4Row[v4Count]        sorted by start
//       v6 rows       V6Row[v6Count]        sorted by start
//       places        PlaceRecord[placeCount]
//       countries     CountryRecord[countryCount]
//       names         UInt8[nameBytes]      UTF-8, referenced by offset
//
// Ranges are stored as starts only. The source data is contiguous, so an
// explicit sentinel row with an invalid place index marks each hole and the
// tail; that halves the range sections and keeps the search a single array.

struct GeoIndexHeader {
    var magic: UInt64 = 0
    var formatVersion: UInt32 = 0
    var flags: UInt32 = 0
    var v4Count: UInt32 = 0
    var v6Count: UInt32 = 0
    var placeCount: UInt32 = 0
    var countryCount: UInt32 = 0
    var nameBytes: UInt64 = 0
    var totalBytes: UInt64 = 0
    var builtAt: Double = 0
}

struct GeoV4Row {
    var start: UInt32 = 0
    var place: UInt32 = 0
}

struct GeoV6Row {
    var upper: UInt64 = 0
    var lower: UInt64 = 0
    var place: UInt32 = 0
    var padding: UInt32 = 0
}

struct GeoPlaceRecord {
    var latitude: Float = 0
    var longitude: Float = 0
    var nameOffset: UInt32 = 0
    var nameLength: UInt8 = 0
    var flags: UInt8 = 0
    var countryIndex: UInt16 = 0
}

struct GeoCountryRecord {
    var latitude: Float = 0
    var longitude: Float = 0
    var nameOffset: UInt32 = 0
    var nameLength: UInt8 = 0
    var flags: UInt8 = 0
    var code0: UInt8 = 0
    var code1: UInt8 = 0
}

enum GeoIndexFormat {
    static let magic: UInt64 = {
        var value: UInt64 = 0
        for (offset, byte) in "FSGEOIX1".utf8.enumerated() { value |= UInt64(byte) << (8 * UInt64(offset)) }
        return value
    }()
    static let version: UInt32 = 1
    static let headerBytes = 128
    static let invalidPlace = UInt32.max
    static let hasCoordinates: UInt8 = 1 << 0
    static let hasName: UInt8 = 1 << 1

    struct Layout {
        let v4Count: Int
        let v6Count: Int
        let placeCount: Int
        let countryCount: Int
        let nameBytes: Int
        let v4Offset: Int
        let v6Offset: Int
        let placeOffset: Int
        let countryOffset: Int
        let nameOffset: Int
        let totalBytes: Int

        init(v4Count: Int, v6Count: Int, placeCount: Int, countryCount: Int, nameBytes: Int) {
            func align(_ value: Int) -> Int { (value + 7) & ~7 }
            self.v4Count = v4Count
            self.v6Count = v6Count
            self.placeCount = placeCount
            self.countryCount = countryCount
            self.nameBytes = nameBytes
            v4Offset = headerBytes
            v6Offset = align(v4Offset + v4Count * MemoryLayout<GeoV4Row>.stride)
            placeOffset = align(v6Offset + v6Count * MemoryLayout<GeoV6Row>.stride)
            countryOffset = align(placeOffset + placeCount * MemoryLayout<GeoPlaceRecord>.stride)
            nameOffset = align(countryOffset + countryCount * MemoryLayout<GeoCountryRecord>.stride)
            totalBytes = nameOffset + nameBytes
        }
    }
}

/// A memory-mapped index. Every accessor validates against the header counts,
/// so a corrupt file produces a wrong-but-bounded answer or nil, never a read
/// outside the mapping.
final class GeoIndex: @unchecked Sendable {
    private let base: UnsafeRawPointer
    let byteCount: Int
    let v4Count: Int
    let v6Count: Int
    let placeCount: Int
    let countryCount: Int
    let nameBytes: Int
    let builtAt: Date
    private let v4Rows: UnsafePointer<GeoV4Row>
    private let v6Rows: UnsafePointer<GeoV6Row>
    private let places: UnsafePointer<GeoPlaceRecord>
    private let countries: UnsafePointer<GeoCountryRecord>
    private let names: UnsafePointer<UInt8>

    init(contentsOf url: URL) throws {
        guard MemoryLayout<GeoV4Row>.stride == 8,
              MemoryLayout<GeoV6Row>.stride == 24,
              MemoryLayout<GeoPlaceRecord>.stride == 16,
              MemoryLayout<GeoCountryRecord>.stride == 16 else {
            throw IPGeoCache.GeoError("the index record layout does not match the on-disk format")
        }

        let descriptor = open(url.path, O_RDONLY)
        guard descriptor >= 0 else {
            throw IPGeoCache.GeoError("cannot open the index: \(String(cString: strerror(errno)))")
        }
        var info = stat()
        guard fstat(descriptor, &info) == 0 else {
            close(descriptor)
            throw IPGeoCache.GeoError("cannot stat the index")
        }
        let size = Int(info.st_size)
        guard size > GeoIndexFormat.headerBytes else {
            close(descriptor)
            throw IPGeoCache.GeoError("the index is too small to be valid (\(size) bytes)")
        }
        guard let mapped = mmap(nil, size, PROT_READ, MAP_PRIVATE, descriptor, 0), mapped != MAP_FAILED else {
            close(descriptor)
            throw IPGeoCache.GeoError("cannot map the index")
        }
        close(descriptor)

        let pointer = UnsafeRawPointer(mapped)
        let header = pointer.loadUnaligned(as: GeoIndexHeader.self)
        func reject(_ message: String) -> Error {
            munmap(mapped, size)
            return IPGeoCache.GeoError(message)
        }
        guard header.magic == GeoIndexFormat.magic else { throw reject("the index has the wrong magic") }
        guard header.formatVersion == GeoIndexFormat.version else {
            throw reject("the index format version is \(header.formatVersion), expected \(GeoIndexFormat.version)")
        }
        guard header.v4Count <= IPGeoCache.maxRangeRows, header.v6Count <= IPGeoCache.maxRangeRows,
              header.placeCount <= IPGeoCache.maxPlaceCount, header.nameBytes <= IPGeoCache.maxNameBytes,
              header.countryCount <= UInt16.max else {
            throw reject("the index header declares counts beyond the accepted ceilings")
        }
        let layout = GeoIndexFormat.Layout(v4Count: Int(header.v4Count),
                                           v6Count: Int(header.v6Count),
                                           placeCount: Int(header.placeCount),
                                           countryCount: Int(header.countryCount),
                                           nameBytes: Int(header.nameBytes))
        guard Int(header.totalBytes) == size, layout.totalBytes == size else {
            throw reject("the index is truncated or padded: header says \(header.totalBytes), layout says \(layout.totalBytes), file is \(size)")
        }

        base = pointer
        byteCount = size
        v4Count = layout.v4Count
        v6Count = layout.v6Count
        placeCount = layout.placeCount
        countryCount = layout.countryCount
        nameBytes = layout.nameBytes
        builtAt = Date(timeIntervalSince1970: header.builtAt)
        v4Rows = pointer.advanced(by: layout.v4Offset).assumingMemoryBound(to: GeoV4Row.self)
        v6Rows = pointer.advanced(by: layout.v6Offset).assumingMemoryBound(to: GeoV6Row.self)
        places = pointer.advanced(by: layout.placeOffset).assumingMemoryBound(to: GeoPlaceRecord.self)
        countries = pointer.advanced(by: layout.countryOffset).assumingMemoryBound(to: GeoCountryRecord.self)
        names = pointer.advanced(by: layout.nameOffset).assumingMemoryBound(to: UInt8.self)
        madvise(UnsafeMutableRawPointer(mutating: pointer), size, MADV_RANDOM)
    }

    deinit {
        munmap(UnsafeMutableRawPointer(mutating: base), byteCount)
    }

    /// Binary search, no allocation, cost logarithmic in the row count.
    func place(ipv4 address: UInt32) -> UInt32? {
        var lower = 0
        var upper = v4Count
        while lower < upper {
            let middle = (lower + upper) / 2
            if v4Rows[middle].start <= address { lower = middle + 1 } else { upper = middle }
        }
        let index = lower - 1
        guard index >= 0 else { return nil }
        let place = v4Rows[index].place
        guard place != GeoIndexFormat.invalidPlace, Int(place) < placeCount else { return nil }
        return place
    }

    func place(ipv6 value: IPv6Value) -> UInt32? {
        var lower = 0
        var upper = v6Count
        while lower < upper {
            let middle = (lower + upper) / 2
            let row = v6Rows[middle]
            let notAfter = row.upper < value.upper || (row.upper == value.upper && row.lower <= value.lower)
            if notAfter { lower = middle + 1 } else { upper = middle }
        }
        let index = lower - 1
        guard index >= 0 else { return nil }
        let place = v6Rows[index].place
        guard place != GeoIndexFormat.invalidPlace, Int(place) < placeCount else { return nil }
        return place
    }

    func entry(ip: String, placeIndex: UInt32) -> IPGeoCache.Entry? {
        guard Int(placeIndex) < placeCount else { return nil }
        let place = places[Int(placeIndex)]
        let city = string(offset: place.nameOffset, length: UInt32(place.nameLength),
                          when: place.flags & GeoIndexFormat.hasName != 0)
        var countryName: String?
        var countryCode: String?
        var countryLatitude: Double?
        var countryLongitude: Double?
        if Int(place.countryIndex) < countryCount {
            let country = countries[Int(place.countryIndex)]
            countryName = string(offset: country.nameOffset, length: UInt32(country.nameLength),
                                 when: country.flags & GeoIndexFormat.hasName != 0)
            if country.code0 != 0, country.code1 != 0 {
                countryCode = String(decoding: [country.code0, country.code1], as: UTF8.self)
            }
            if country.flags & GeoIndexFormat.hasCoordinates != 0 {
                countryLatitude = Double(country.latitude)
                countryLongitude = Double(country.longitude)
            }
        }

        // A city coordinate is only honest when there is a city. Everything
        // else falls back to the country centroid and says so.
        if city != nil, place.flags & GeoIndexFormat.hasCoordinates != 0 {
            return IPGeoCache.Entry(ip: ip, country: countryName, countryCode: countryCode, city: city,
                                    lat: Double(place.latitude), lon: Double(place.longitude), precision: .city)
        }
        return IPGeoCache.Entry(ip: ip, country: countryName, countryCode: countryCode, city: nil,
                                lat: countryLatitude, lon: countryLongitude, precision: .country)
    }

    private func string(offset: UInt32, length: UInt32, when condition: Bool) -> String? {
        guard condition, length > 0, Int(offset) + Int(length) <= nameBytes else { return nil }
        return String(decoding: UnsafeBufferPointer(start: names.advanced(by: Int(offset)), count: Int(length)), as: UTF8.self)
    }
}

// MARK: - Streaming input

/// Reads a file line by line, transparently decompressing gzip. Input and
/// output buffers are allocated once and reused, so streaming a 700 MB
/// decompressed CSV costs two 256 KB buffers rather than 700 MB of memory.
final class GeoLineReader {
    private let descriptor: Int32
    private let maxOutputBytes: Int
    private let isCompressed: Bool
    private var stream = compression_stream(dst_ptr: UnsafeMutablePointer<UInt8>(bitPattern: -1)!, dst_size: 0,
                                            src_ptr: UnsafePointer<UInt8>(bitPattern: -1)!, src_size: 0, state: nil)
    private var streamInitialized = false
    private let input: UnsafeMutablePointer<UInt8>
    private let output: UnsafeMutablePointer<UInt8>
    private var inputCount = 0
    private var inputOffset = 0
    private var pending: [UInt8] = []
    private(set) var outputBytes = 0

    private static let inputChunk = 256 * 1024
    private static let outputChunk = 256 * 1024

    init(url: URL, maxOutputBytes: Int) throws {
        self.maxOutputBytes = maxOutputBytes
        descriptor = open(url.path, O_RDONLY)
        guard descriptor >= 0 else {
            throw IPGeoCache.GeoError("cannot open \(url.lastPathComponent): \(String(cString: strerror(errno)))")
        }
        input = .allocate(capacity: Self.inputChunk)
        output = .allocate(capacity: Self.outputChunk)

        let read = Darwin.read(descriptor, input, Self.inputChunk)
        guard read >= 2 else {
            input.deallocate()
            output.deallocate()
            close(descriptor)
            throw IPGeoCache.GeoError("the database file is empty")
        }
        inputCount = read

        guard input[0] == 0x1f, input[1] == 0x8b else {
            isCompressed = false
            return
        }
        // Apple's COMPRESSION_ZLIB is raw DEFLATE, so the gzip wrapper is
        // stripped here and the deflate payload is streamed straight in.
        var failure: String?
        var offset = 0
        switch Self.gzipHeaderLength(input, inputCount) {
        case .success(let length): offset = length
        case .failure(let error): failure = error.message
        }
        if failure == nil, compression_stream_init(&stream, COMPRESSION_STREAM_DECODE, COMPRESSION_ZLIB) != COMPRESSION_STATUS_OK {
            failure = "cannot start the gzip decoder"
        }
        if let failure {
            input.deallocate()
            output.deallocate()
            close(descriptor)
            throw IPGeoCache.GeoError(failure)
        }
        streamInitialized = true
        isCompressed = true
        inputOffset = offset
    }

    /// Length of the gzip member header, so the raw DEFLATE payload can be fed
    /// to Apple's decoder directly.
    private static func gzipHeaderLength(_ bytes: UnsafeMutablePointer<UInt8>, _ count: Int) -> Result<Int, IPGeoCache.GeoError> {
        guard count > 10, bytes[2] == 8 else {
            return .failure(IPGeoCache.GeoError("the database is gzip with an unsupported compression method"))
        }
        let flags = bytes[3]
        var offset = 10
        if flags & 0x04 != 0 {
            guard offset + 2 <= count else { return .failure(IPGeoCache.GeoError("the gzip header is truncated")) }
            offset += 2 + (Int(bytes[offset]) | Int(bytes[offset + 1]) << 8)
        }
        for mask in [UInt8(0x08), UInt8(0x10)] where flags & mask != 0 {
            while offset < count, bytes[offset] != 0 { offset += 1 }
            offset += 1
        }
        if flags & 0x02 != 0 { offset += 2 }
        guard offset <= count else { return .failure(IPGeoCache.GeoError("the gzip header is truncated")) }
        return .success(offset)
    }

    deinit {
        if streamInitialized { compression_stream_destroy(&stream) }
        input.deallocate()
        output.deallocate()
        close(descriptor)
    }

    func forEachLine(_ body: (UnsafeBufferPointer<UInt8>) throws -> Void) throws {
        if isCompressed {
            try decompressAll(body)
        } else {
            while inputOffset < inputCount {
                let count = inputCount - inputOffset
                outputBytes += count
                guard outputBytes <= maxOutputBytes else {
                    throw IPGeoCache.GeoError("the database exceeds the \(maxOutputBytes) byte ceiling")
                }
                try emit(UnsafeBufferPointer(start: input + inputOffset, count: count), body)
                guard fill() else { break }
            }
        }
        if !pending.isEmpty {
            try pending.withUnsafeBufferPointer { try body(trimmed($0)) }
            pending.removeAll(keepingCapacity: true)
        }
    }

    /// Refills the input buffer. False means end of file.
    private func fill() -> Bool {
        inputOffset = 0
        let read = Darwin.read(descriptor, input, Self.inputChunk)
        inputCount = read > 0 ? read : 0
        return inputCount > 0
    }

    private func decompressAll(_ body: (UnsafeBufferPointer<UInt8>) throws -> Void) throws {
        var reachedInputEnd = false
        var finished = false

        while !finished {
            if inputOffset >= inputCount, !reachedInputEnd, !fill() {
                reachedInputEnd = true
                inputCount = 0
                inputOffset = 0
            }
            stream.src_ptr = UnsafePointer(input + inputOffset)
            stream.src_size = inputCount - inputOffset
            var status = COMPRESSION_STATUS_OK
            var producedInPass = 0
            repeat {
                stream.dst_ptr = output
                stream.dst_size = Self.outputChunk
                status = compression_stream_process(&stream, reachedInputEnd ? Int32(COMPRESSION_STREAM_FINALIZE.rawValue) : 0)
                let produced = Self.outputChunk - stream.dst_size
                if produced > 0 {
                    producedInPass += produced
                    outputBytes += produced
                    guard outputBytes <= maxOutputBytes else {
                        throw IPGeoCache.GeoError("the database exceeds the \(maxOutputBytes) byte decompressed ceiling")
                    }
                    try emit(UnsafeBufferPointer(start: output, count: produced), body)
                }
                if status != COMPRESSION_STATUS_OK { break }
                // After the last input byte the decoder still has to be drained:
                // it keeps answering OK until the final flush completes.
            } while stream.src_size > 0 || stream.dst_size == 0 || reachedInputEnd
            inputOffset = inputCount - stream.src_size

            switch status {
            case COMPRESSION_STATUS_ERROR:
                throw IPGeoCache.GeoError("the compressed database is corrupt")
            case COMPRESSION_STATUS_END:
                finished = true
            default:
                if reachedInputEnd, producedInPass == 0 {
                    throw IPGeoCache.GeoError("the compressed database ends before the stream does")
                }
            }
        }
    }

    private func emit(_ chunk: UnsafeBufferPointer<UInt8>, _ body: (UnsafeBufferPointer<UInt8>) throws -> Void) throws {
        guard let start = chunk.baseAddress else { return }
        var lineStart = 0
        var cursor = 0
        while cursor < chunk.count {
            guard chunk[cursor] == 0x0a else {
                cursor += 1
                continue
            }
            if pending.isEmpty {
                try body(trimmed(UnsafeBufferPointer(start: start + lineStart, count: cursor - lineStart)))
            } else {
                pending.append(contentsOf: UnsafeBufferPointer(start: start + lineStart, count: cursor - lineStart))
                try pending.withUnsafeBufferPointer { try body(trimmed($0)) }
                pending.removeAll(keepingCapacity: true)
            }
            cursor += 1
            lineStart = cursor
        }
        if lineStart < chunk.count {
            pending.append(contentsOf: UnsafeBufferPointer(start: start + lineStart, count: chunk.count - lineStart))
        }
    }

    private func trimmed(_ line: UnsafeBufferPointer<UInt8>) -> UnsafeBufferPointer<UInt8> {
        guard let start = line.baseAddress, line.count > 0, line[line.count - 1] == 0x0d else { return line }
        return UnsafeBufferPointer(start: start, count: line.count - 1)
    }
}

/// RFC 4180 field splitter over raw bytes. The row is unquoted into a reusable
/// scratch buffer, so parsing eight million rows allocates nothing per row.
final class GeoCSVRow {
    static let maxFields = 24
    private let capacity = 8192
    private let scratch: UnsafeMutablePointer<UInt8>
    private var starts = [Int](repeating: 0, count: GeoCSVRow.maxFields)
    private var lengths = [Int](repeating: 0, count: GeoCSVRow.maxFields)
    private(set) var count = 0

    init() {
        scratch = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
    }

    deinit { scratch.deallocate() }

    @discardableResult
    func parse(_ line: UnsafeBufferPointer<UInt8>) -> Bool {
        count = 0
        guard line.count <= capacity else { return false }
        var written = 0
        var fieldStart = 0
        var quoted = false
        var index = 0

        func closeField() -> Bool {
            guard count < Self.maxFields else { return false }
            starts[count] = fieldStart
            lengths[count] = written - fieldStart
            count += 1
            fieldStart = written
            return true
        }

        while index < line.count {
            let byte = line[index]
            if byte == UInt8(ascii: "\"") {
                if quoted, index + 1 < line.count, line[index + 1] == UInt8(ascii: "\"") {
                    scratch[written] = byte
                    written += 1
                    index += 2
                    continue
                }
                quoted.toggle()
                index += 1
                continue
            }
            if byte == UInt8(ascii: ",") && !quoted {
                guard closeField() else { return false }
                index += 1
                continue
            }
            scratch[written] = byte
            written += 1
            index += 1
        }
        return closeField()
    }

    func field(_ index: Int) -> UnsafeBufferPointer<UInt8> {
        guard index < count else { return UnsafeBufferPointer(start: nil, count: 0) }
        return UnsafeBufferPointer(start: scratch.advanced(by: starts[index]), count: lengths[index])
    }

    /// Parses a coordinate from raw bytes on the stack. Called twice per row
    /// across eight million rows, so it must not allocate.
    static func double(_ bytes: UnsafeBufferPointer<UInt8>) -> Double? {
        guard bytes.count > 0, bytes.count < 64, let start = bytes.baseAddress else { return nil }
        return withUnsafeTemporaryAllocation(of: CChar.self, capacity: 64) { scratch -> Double? in
            guard let head = scratch.baseAddress else { return nil }
            for offset in 0..<bytes.count { head[offset] = CChar(bitPattern: start[offset]) }
            head[bytes.count] = 0
            var end: UnsafeMutablePointer<CChar>?
            let parsed = strtod(head, &end)
            guard let end, end != head, end.pointee == 0, parsed.isFinite else { return nil }
            return parsed
        }
    }
}

/// Buffered append-only writer for the index file. One reused 1 MB buffer and
/// plain write(2), so building the index does not allocate per row.
final class GeoIndexWriter {
    private let descriptor: Int32
    private let capacity = 1 << 20
    private let buffer: UnsafeMutablePointer<UInt8>
    private var used = 0
    private(set) var offset = 0
    private var closed = false

    init(url: URL) throws {
        descriptor = open(url.path, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
        guard descriptor >= 0 else {
            throw IPGeoCache.GeoError("cannot create the index file at \(url.path): \(String(cString: strerror(errno)))")
        }
        buffer = .allocate(capacity: capacity)
    }

    deinit {
        buffer.deallocate()
        if !closed { close(descriptor) }
    }

    func append<T>(_ value: T) throws {
        var value = value
        try withUnsafeBytes(of: &value) { try append($0) }
    }

    func append(_ bytes: UnsafeRawBufferPointer) throws {
        guard var source = bytes.baseAddress else { return }
        var remaining = bytes.count
        while remaining > 0 {
            if used == capacity { try drain() }
            let count = min(capacity - used, remaining)
            memcpy(buffer + used, source, count)
            used += count
            offset += count
            source += count
            remaining -= count
        }
    }

    func appendPadding(to target: Int) throws {
        while offset < target { try append(UInt8(0)) }
    }

    func drain() throws {
        var written = 0
        while written < used {
            let count = write(descriptor, buffer + written, used - written)
            guard count > 0 else {
                throw IPGeoCache.GeoError("writing the index failed: \(String(cString: strerror(errno)))")
            }
            written += count
        }
        used = 0
    }

    /// Rewrites the header in place once the counts are known, then closes.
    func finish(header: GeoIndexHeader) throws {
        try drain()
        var header = header
        let ok: Bool = withUnsafeBytes(of: &header) { bytes in
            guard let base = bytes.baseAddress else { return false }
            return pwrite(descriptor, base, bytes.count, 0) == bytes.count
        }
        guard ok else {
            throw IPGeoCache.GeoError("writing the index header failed")
        }
        closed = true
        close(descriptor)
    }
}

/// Deduplicates (country, city, latitude, longitude) tuples while streaming.
/// Keyed by a 64-bit hash and then verified byte for byte, so a hash collision
/// costs one duplicate record rather than a wrong city.
final class GeoPlaceTable {
    private(set) var records: [GeoPlaceRecord] = []
    private var byHash: [UInt64: UInt32] = [:]
    var names: [UInt8]

    init(names: [UInt8]) {
        self.names = names
        records.reserveCapacity(1 << 19)
        byHash.reserveCapacity(1 << 20)
    }

    func index(countryIndex: UInt16, city: UnsafeBufferPointer<UInt8>,
               latitude: Double?, longitude: Double?) throws -> UInt32 {
        var flags: UInt8 = 0
        if city.count > 0, city.count <= Int(UInt8.max) { flags |= GeoIndexFormat.hasName }
        let latitudeValue = Float(latitude ?? 0)
        let longitudeValue = Float(longitude ?? 0)
        if latitude != nil, longitude != nil { flags |= GeoIndexFormat.hasCoordinates }

        var hash: UInt64 = 0xcbf29ce484222325
        func mix(_ byte: UInt8) {
            hash = (hash ^ UInt64(byte)) &* 0x100000001b3
        }
        mix(UInt8(truncatingIfNeeded: countryIndex))
        mix(UInt8(truncatingIfNeeded: countryIndex >> 8))
        mix(flags)
        for byte in city { mix(byte) }
        withUnsafeBytes(of: latitudeValue.bitPattern) { $0.forEach(mix) }
        withUnsafeBytes(of: longitudeValue.bitPattern) { $0.forEach(mix) }

        if let candidate = byHash[hash], matches(candidate, countryIndex: countryIndex, flags: flags,
                                                 latitude: latitudeValue, longitude: longitudeValue, city: city) {
            return candidate
        }

        guard records.count < IPGeoCache.maxPlaceCount else {
            throw IPGeoCache.GeoError("the city table exceeds \(IPGeoCache.maxPlaceCount) entries")
        }
        var record = GeoPlaceRecord()
        record.countryIndex = countryIndex
        record.flags = flags
        record.latitude = latitudeValue
        record.longitude = longitudeValue
        if flags & GeoIndexFormat.hasName != 0 {
            guard names.count + city.count <= IPGeoCache.maxNameBytes else {
                throw IPGeoCache.GeoError("the city name table exceeds \(IPGeoCache.maxNameBytes) bytes")
            }
            record.nameOffset = UInt32(names.count)
            record.nameLength = UInt8(city.count)
            names.append(contentsOf: city)
        }
        let index = UInt32(records.count)
        records.append(record)
        if byHash[hash] == nil { byHash[hash] = index }
        return index
    }

    private func matches(_ index: UInt32, countryIndex: UInt16, flags: UInt8,
                         latitude: Float, longitude: Float, city: UnsafeBufferPointer<UInt8>) -> Bool {
        let record = records[Int(index)]
        guard record.countryIndex == countryIndex, record.flags == flags,
              record.latitude.bitPattern == latitude.bitPattern,
              record.longitude.bitPattern == longitude.bitPattern,
              Int(record.nameLength) == (flags & GeoIndexFormat.hasName != 0 ? city.count : 0) else { return false }
        let start = Int(record.nameOffset)
        for offset in 0..<Int(record.nameLength) where names[start + offset] != city[offset] { return false }
        return true
    }
}

// MARK: - Index building

extension IPGeoCache {
    public struct BuildStats: Sendable {
        public let ipv4RangeCount: Int
        public let ipv6RangeCount: Int
        public let placeCount: Int
        public let countryCount: Int
        public let nameBytes: Int
        public let indexBytes: Int
        public let decompressedBytes: Int
        public let seconds: TimeInterval
    }

    static func countryKey(_ bytes: UnsafeBufferPointer<UInt8>) -> UInt16? {
        guard bytes.count == 2 else { return nil }
        func upper(_ byte: UInt8) -> UInt8 {
            (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "z")) ? byte - 32 : byte
        }
        return UInt16(upper(bytes[0])) << 8 | UInt16(upper(bytes[1]))
    }

    /// The country table gives names and the centroid used when a city is
    /// unknown. It is small, so it is parsed in full before any range work.
    static func parseCountryTable(at url: URL) throws -> (records: [GeoCountryRecord], names: [UInt8], indexByCode: [UInt16: UInt16]) {
        let reader = try GeoLineReader(url: url, maxOutputBytes: countrySource.maxBytes)
        let row = GeoCSVRow()
        var records: [GeoCountryRecord] = []
        var names: [UInt8] = []
        var indexByCode: [UInt16: UInt16] = [:]
        var isFirstLine = true
        var headerSeen = false

        try reader.forEachLine { line in
            guard line.count > 0 else { return }
            guard row.parse(line), row.count >= 4 else {
                throw GeoError("the country table has a malformed line")
            }
            if isFirstLine {
                isFirstLine = false
                let first = String(decoding: row.field(0), as: UTF8.self).lowercased()
                let fourth = String(decoding: row.field(3), as: UTF8.self).lowercased()
                if first == "country" && fourth == "name" {
                    headerSeen = true
                    return
                }
                throw GeoError("the country table has an unexpected header")
            }
            guard let key = countryKey(row.field(0)) else { return }
            guard indexByCode[key] == nil, records.count < Int(UInt16.max) else { return }
            var record = GeoCountryRecord()
            record.code0 = UInt8(truncatingIfNeeded: key >> 8)
            record.code1 = UInt8(truncatingIfNeeded: key)
            if let latitude = GeoCSVRow.double(row.field(1)), let longitude = GeoCSVRow.double(row.field(2)) {
                record.latitude = Float(latitude)
                record.longitude = Float(longitude)
                record.flags |= GeoIndexFormat.hasCoordinates
            }
            let name = row.field(3)
            if name.count > 0, name.count <= Int(UInt8.max) {
                record.nameOffset = UInt32(names.count)
                record.nameLength = UInt8(name.count)
                record.flags |= GeoIndexFormat.hasName
                names.append(contentsOf: name)
            }
            indexByCode[key] = UInt16(records.count)
            records.append(record)
        }

        guard headerSeen, !records.isEmpty else {
            throw GeoError("the country table is empty")
        }
        return (records, names, indexByCode)
    }

    /// Converts the two city CSVs into the binary index. Streams both files, so
    /// peak memory is the place table rather than the database.
    static func buildIndex(ipv4CSV: URL, ipv6CSV: URL, countriesCSV: URL, to output: URL) throws -> BuildStats {
        let started = Date()
        var (countryRecords, names, indexByCode) = try parseCountryTable(at: countriesCSV)
        let places = GeoPlaceTable(names: names)
        let writer = try GeoIndexWriter(url: output)
        try writer.appendPadding(to: GeoIndexFormat.headerBytes)

        let row = GeoCSVRow()
        var decompressedBytes = 0

        /// Resolves the country column, adding a code-only record when the
        /// canonical country table does not know the code. The country code is
        /// then still reported honestly, just without a name or centroid.
        func countryIndex(_ field: UnsafeBufferPointer<UInt8>) throws -> UInt16 {
            guard let key = countryKey(field) else {
                throw GeoError("a range row has an unusable country code")
            }
            if let known = indexByCode[key] { return known }
            guard countryRecords.count < Int(UInt16.max) else {
                throw GeoError("the country table is too large")
            }
            var record = GeoCountryRecord()
            record.code0 = UInt8(truncatingIfNeeded: key >> 8)
            record.code1 = UInt8(truncatingIfNeeded: key)
            let index = UInt16(countryRecords.count)
            countryRecords.append(record)
            indexByCode[key] = index
            return index
        }

        func place(_ row: GeoCSVRow) throws -> UInt32 {
            try places.index(countryIndex: try countryIndex(row.field(2)),
                             city: row.field(5),
                             latitude: GeoCSVRow.double(row.field(7)),
                             longitude: GeoCSVRow.double(row.field(8)))
        }

        // IPv4 ranges.
        var v4Count = 0
        var previousV4End: UInt32?
        let v4Reader = try GeoLineReader(url: ipv4CSV, maxOutputBytes: maxDecompressedBytes)
        try v4Reader.forEachLine { line in
            guard line.count > 0 else { return }
            guard row.parse(line), row.count >= 9,
                  let start = ipv4Value(row.field(0)), let end = ipv4Value(row.field(1)), start <= end else {
                throw GeoError("the IPv4 city database has a malformed row")
            }
            if let previous = previousV4End {
                guard start > previous else {
                    throw GeoError("the IPv4 city database is not sorted or overlaps")
                }
                if start > previous + 1 {
                    try writer.append(GeoV4Row(start: previous + 1, place: GeoIndexFormat.invalidPlace))
                    v4Count += 1
                }
            }
            guard v4Count < maxRangeRows else {
                throw GeoError("the IPv4 city database exceeds \(maxRangeRows) rows")
            }
            try writer.append(GeoV4Row(start: start, place: try place(row)))
            v4Count += 1
            previousV4End = end
        }
        if let previous = previousV4End, previous < UInt32.max {
            try writer.append(GeoV4Row(start: previous + 1, place: GeoIndexFormat.invalidPlace))
            v4Count += 1
        }
        guard v4Count > 0 else { throw GeoError("the IPv4 city database is empty") }
        decompressedBytes += v4Reader.outputBytes

        // IPv6 ranges, same shape, 128-bit keys.
        var v6Count = 0
        var previousV6End: IPv6Value?
        let v6Reader = try GeoLineReader(url: ipv6CSV, maxOutputBytes: maxDecompressedBytes)
        try v6Reader.forEachLine { line in
            guard line.count > 0 else { return }
            guard row.parse(line), row.count >= 9,
                  let start = ipv6Value(row.field(0)), let end = ipv6Value(row.field(1)), start <= end else {
                throw GeoError("the IPv6 city database has a malformed row")
            }
            if let previous = previousV6End {
                guard start > previous else {
                    throw GeoError("the IPv6 city database is not sorted or overlaps")
                }
                if let successor = previous.successor, successor < start {
                    try writer.append(GeoV6Row(upper: successor.upper, lower: successor.lower, place: GeoIndexFormat.invalidPlace))
                    v6Count += 1
                }
            }
            guard v6Count < maxRangeRows else {
                throw GeoError("the IPv6 city database exceeds \(maxRangeRows) rows")
            }
            try writer.append(GeoV6Row(upper: start.upper, lower: start.lower, place: try place(row)))
            v6Count += 1
            previousV6End = end
        }
        if let previous = previousV6End, let successor = previous.successor {
            try writer.append(GeoV6Row(upper: successor.upper, lower: successor.lower, place: GeoIndexFormat.invalidPlace))
            v6Count += 1
        }
        guard v6Count > 0 else { throw GeoError("the IPv6 city database is empty") }
        decompressedBytes += v6Reader.outputBytes

        let layout = GeoIndexFormat.Layout(v4Count: v4Count, v6Count: v6Count,
                                           placeCount: places.records.count,
                                           countryCount: countryRecords.count,
                                           nameBytes: places.names.count)
        try writer.appendPadding(to: layout.placeOffset)
        for record in places.records { try writer.append(record) }
        try writer.appendPadding(to: layout.countryOffset)
        for record in countryRecords { try writer.append(record) }
        try writer.appendPadding(to: layout.nameOffset)
        try places.names.withUnsafeBytes { try writer.append($0) }

        var header = GeoIndexHeader()
        header.magic = GeoIndexFormat.magic
        header.formatVersion = GeoIndexFormat.version
        header.v4Count = UInt32(v4Count)
        header.v6Count = UInt32(v6Count)
        header.placeCount = UInt32(places.records.count)
        header.countryCount = UInt32(countryRecords.count)
        header.nameBytes = UInt64(places.names.count)
        header.totalBytes = UInt64(layout.totalBytes)
        header.builtAt = Date().timeIntervalSince1970
        try writer.finish(header: header)

        return BuildStats(ipv4RangeCount: v4Count,
                          ipv6RangeCount: v6Count,
                          placeCount: places.records.count,
                          countryCount: countryRecords.count,
                          nameBytes: places.names.count,
                          indexBytes: layout.totalBytes,
                          decompressedBytes: decompressedBytes,
                          seconds: Date().timeIntervalSince(started))
    }
}

extension IPv6Value {
    /// The next address, or nil at the top of the space.
    var successor: IPv6Value? {
        if lower != UInt64.max { return IPv6Value(upper: upper, lower: lower + 1) }
        guard upper != UInt64.max else { return nil }
        return IPv6Value(upper: upper + 1, lower: 0)
    }
}
