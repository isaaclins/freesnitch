import Foundation

/// Offline network ownership: which autonomous system announces an address,
/// who runs it, and the address range it covers (#194).
///
/// The data is DB-IP ASN Lite, downloaded in bulk once a month next to the
/// city database and never queried per address. Like `IPGeoCache`, the CSVs
/// are converted once into a fixed-width binary index that is memory mapped,
/// so nothing on the heap scales with the database and a lookup is a binary
/// search with no network call.
public final class IPASNCache: @unchecked Sendable {
    public struct Entry: Sendable, Equatable {
        public let asn: UInt32
        /// The AS organisation as DB-IP names it. Nil when the row has none.
        public let organization: String?
        /// First and last address of the range the row covers, in text form.
        public let rangeStart: String
        public let rangeEnd: String
        /// The range as one CIDR prefix when it is exactly one, else nil.
        public let prefix: String?

        /// The prefix when there is one, else "start – end".
        public var rangeText: String { prefix ?? "\(rangeStart) – \(rangeEnd)" }
        public var asnText: String { "AS\(asn)" }
    }

    /// DB-IP ASN Lite is CC BY 4.0, the same licence and credit as the city
    /// data, so the existing "IP Geolocation by DB-IP" credit covers it.
    public static let attribution = IPGeoCache.attribution

    public struct Status: Sendable {
        public let isLoaded: Bool
        public let hasDatabase: Bool
        public let ipv4RangeCount: Int
        public let ipv6RangeCount: Int
        public let builtAt: Date?
        public let lastError: String?
    }

    public static let shared = IPASNCache()

    // MARK: - Sources and ceilings

    /// The ASN files are only published uncompressed, about 24 MB and 7 MB.
    static let ipv4Source = IPGeoCache.Source(
        fileName: "dbip-asn-ipv4.csv",
        url: "https://github.com/sapics/ip-location-db/releases/download/latest/dbip-asn-ipv4.csv",
        maxBytes: 96 * 1024 * 1024
    )
    static let ipv6Source = IPGeoCache.Source(
        fileName: "dbip-asn-ipv6.csv",
        url: "https://github.com/sapics/ip-location-db/releases/download/latest/dbip-asn-ipv6.csv",
        maxBytes: 64 * 1024 * 1024
    )
    static var sources: [IPGeoCache.Source] { [ipv4Source, ipv6Source] }

    static let cacheLifetime = IPGeoCache.cacheLifetime
    static let maxRangeRows = 8_000_000
    static let maxOrganizationCount = 2_000_000
    static let maxNameBytes = 64 * 1024 * 1024
    static let indexFileName = "dbip-asn.index"

    // MARK: - Instance state

    private let cacheDirectory: URL
    private let fetcher: IPGeoCache.SourceFetcher
    private let loadQueue = DispatchQueue(label: "io.isaaclins.freesnitch.asn.load", qos: .utility)
    private let stateQueue = DispatchQueue(label: "io.isaaclins.freesnitch.asn.state")
    private var index: ASNIndex?
    private var isLoaded = false
    private var lastError: String?
    private var readyCallbacks: [() -> Void] = []

    public convenience init() {
        self.init(cacheDirectory: IPGeoCache.defaultCacheDirectory(), fetcher: IPGeoCache.httpFetcher, startLoading: true)
    }

    /// Loading always happens on `loadQueue`, so this returns immediately.
    public init(cacheDirectory: URL, fetcher: @escaping IPGeoCache.SourceFetcher, startLoading: Bool = true) {
        self.cacheDirectory = cacheDirectory
        self.fetcher = fetcher
        if startLoading {
            loadQueue.async { [weak self] in self?.loadDatabase() }
        }
    }

    // MARK: - Lookup

    /// Private, loopback, link-local and multicast addresses have no owner on
    /// the internet and answer nil, as they do for location.
    public func lookup(_ ip: String) -> Entry? {
        var text = ip.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let target = text.withUTF8({ IPGeoCache.parseTarget($0) }) else { return nil }
        return stateQueue.sync { () -> Entry? in
            guard let index else { return nil }
            switch target {
            case .ipv4(let address): return index.entry(ipv4: address)
            case .ipv6(let value): return index.entry(ipv6: value)
            }
        }
    }

    public func onReady(_ callback: @escaping () -> Void) {
        var callNow = false
        stateQueue.sync {
            if isLoaded { callNow = true } else { readyCallbacks.append(callback) }
        }
        if callNow { callback() }
    }

    public var status: Status {
        stateQueue.sync {
            Status(isLoaded: isLoaded,
                   hasDatabase: index != nil,
                   ipv4RangeCount: index?.v4Count ?? 0,
                   ipv6RangeCount: index?.v6Count ?? 0,
                   builtAt: index?.builtAt,
                   lastError: lastError)
        }
    }

    /// A failure leaves whatever is already loaded in place.
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
            finishLoading(error: "offline network owner cache unavailable: cannot create directory - \(error)")
            return
        }

        let indexURL = cacheDirectory.appendingPathComponent(Self.indexFileName)
        var haveIndex = stateQueue.sync { index != nil }
        if !haveIndex, fileManager.fileExists(atPath: indexURL.path) {
            do {
                let opened = try ASNIndex(contentsOf: indexURL)
                stateQueue.sync { index = opened }
                haveIndex = true
            } catch {
                PSLog.error(PSLog.app, "offline network owner index unusable, rebuilding: \(error)")
            }
        }

        let stale = force || IPGeoCache.needsRefresh(at: indexURL)
        if !stale && haveIndex {
            finishLoading(error: nil)
            return
        }
        if haveIndex { finishLoading(error: nil) }

        do {
            try refresh(indexURL: indexURL)
            finishLoading(error: nil)
        } catch {
            let message = "offline network owner database unavailable: \(error.localizedDescription)"
            if haveIndex {
                stateQueue.sync { lastError = message }
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
                try? fileManager.removeItem(at: destination)
                throw IPGeoCache.GeoError("\(source.fileName): \(failure)")
            }
            downloaded.append(destination)
            guard let size = try? fileManager.attributesOfItem(atPath: destination.path)[.size] as? Int, size > 0 else {
                throw IPGeoCache.GeoError("\(source.fileName): the download produced no readable file")
            }
            guard size <= source.maxBytes else {
                throw IPGeoCache.GeoError("\(source.fileName): \(size) bytes exceeds the \(source.maxBytes) byte ceiling")
            }
        }

        let staging = indexURL.appendingPathExtension("building")
        try? fileManager.removeItem(at: staging)
        do {
            _ = try Self.buildIndex(ipv4CSV: downloaded[0], ipv6CSV: downloaded[1], to: staging)
            // Prove the new file opens before it replaces the working one.
            let candidate = try ASNIndex(contentsOf: staging)
            if fileManager.fileExists(atPath: indexURL.path) {
                _ = try fileManager.replaceItemAt(indexURL, withItemAt: staging)
            } else {
                try fileManager.moveItem(at: staging, to: indexURL)
            }
            stateQueue.sync {
                index = candidate
                lastError = nil
            }
        } catch {
            try? fileManager.removeItem(at: staging)
            throw error
        }
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

    // MARK: - Range text

    /// The prefix length when `start...end` is exactly one CIDR block.
    static func prefixLength(ipv4 start: UInt32, end: UInt32) -> Int? {
        guard start <= end else { return nil }
        let span = UInt64(end - start) + 1
        guard span & (span - 1) == 0 else { return nil }
        let hostBits = span.trailingZeroBitCount
        if hostBits < 32, start & ((UInt32(1) << UInt32(hostBits)) - 1) != 0 { return nil }
        return 32 - hostBits
    }

    static func prefixLength(ipv6 start: IPv6Value, end: IPv6Value) -> Int? {
        guard start <= end else { return nil }
        // Host bits: the trailing run of differing bits, where start has zeros
        // and end has ones. Every bit above it must match.
        let xorUpper = start.upper ^ end.upper
        let xorLower = start.lower ^ end.lower
        let hostBits: Int
        if xorUpper == 0 {
            // A run of n ones has n + 1 a power of two, so n is its bit count.
            guard (xorLower &+ 1) & xorLower == 0 else { return nil }
            hostBits = xorLower.nonzeroBitCount
        } else {
            guard xorLower == UInt64.max, (xorUpper &+ 1) & xorUpper == 0 else { return nil }
            hostBits = 64 + xorUpper.nonzeroBitCount
        }
        guard start.lower & xorLower == 0, start.upper & xorUpper == 0 else { return nil }
        return 128 - hostBits
    }

    static func ipv4Text(_ address: UInt32) -> String {
        "\(address >> 24).\((address >> 16) & 0xff).\((address >> 8) & 0xff).\(address & 0xff)"
    }

    static func ipv6Text(_ value: IPv6Value) -> String {
        var raw = in6_addr()
        withUnsafeMutableBytes(of: &raw) { bytes in
            for offset in 0..<8 {
                bytes[offset] = UInt8(truncatingIfNeeded: value.upper >> UInt64(56 - 8 * offset))
                bytes[8 + offset] = UInt8(truncatingIfNeeded: value.lower >> UInt64(56 - 8 * offset))
            }
        }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &raw, &buffer, socklen_t(buffer.count)) != nil else { return "::" }
        return String(cString: buffer)
    }
}

// MARK: - Compact index format
//
// Little endian, every section 8-byte aligned:
//
//   0   header         (ASNIndexHeader, 128 bytes reserved)
//   128 v4 rows        ASNV4Row[v4Count]   sorted by start, no overlaps
//       v6 rows        ASNV6Row[v6Count]   sorted by start, no overlaps
//       organizations  ASNOrgRecord[orgCount]
//       names          UInt8[nameBytes]    UTF-8, referenced by offset
//
// Unlike the city index every row keeps its end, because the ASN data has
// real holes and the range itself is shown to the user.

struct ASNIndexHeader {
    var magic: UInt64 = 0
    var formatVersion: UInt32 = 0
    var flags: UInt32 = 0
    var v4Count: UInt32 = 0
    var v6Count: UInt32 = 0
    var orgCount: UInt32 = 0
    var reserved: UInt32 = 0
    var nameBytes: UInt64 = 0
    var totalBytes: UInt64 = 0
    var builtAt: Double = 0
}

struct ASNV4Row {
    var start: UInt32 = 0
    var end: UInt32 = 0
    var asn: UInt32 = 0
    var org: UInt32 = 0
}

struct ASNV6Row {
    var startUpper: UInt64 = 0
    var startLower: UInt64 = 0
    var endUpper: UInt64 = 0
    var endLower: UInt64 = 0
    var asn: UInt32 = 0
    var org: UInt32 = 0
}

struct ASNOrgRecord {
    var nameOffset: UInt32 = 0
    var nameLength: UInt32 = 0
}

enum ASNIndexFormat {
    static let magic: UInt64 = {
        var value: UInt64 = 0
        for (offset, byte) in "FSASNIX1".utf8.enumerated() { value |= UInt64(byte) << (8 * UInt64(offset)) }
        return value
    }()
    static let version: UInt32 = 1
    static let headerBytes = 128
    static let noOrganization = UInt32.max

    struct Layout {
        let v4Offset: Int
        let v6Offset: Int
        let orgOffset: Int
        let nameOffset: Int
        let totalBytes: Int

        init(v4Count: Int, v6Count: Int, orgCount: Int, nameBytes: Int) {
            func align(_ value: Int) -> Int { (value + 7) & ~7 }
            v4Offset = headerBytes
            v6Offset = align(v4Offset + v4Count * MemoryLayout<ASNV4Row>.stride)
            orgOffset = align(v6Offset + v6Count * MemoryLayout<ASNV6Row>.stride)
            nameOffset = align(orgOffset + orgCount * MemoryLayout<ASNOrgRecord>.stride)
            totalBytes = nameOffset + nameBytes
        }
    }
}

/// A memory-mapped ASN index. Every accessor checks against the header counts,
/// so a corrupt file gives nil or a bounded wrong answer, never a read outside
/// the mapping.
final class ASNIndex: @unchecked Sendable {
    private let base: UnsafeRawPointer
    let byteCount: Int
    let v4Count: Int
    let v6Count: Int
    let orgCount: Int
    let nameBytes: Int
    let builtAt: Date
    private let v4Rows: UnsafePointer<ASNV4Row>
    private let v6Rows: UnsafePointer<ASNV6Row>
    private let orgs: UnsafePointer<ASNOrgRecord>
    private let names: UnsafePointer<UInt8>

    init(contentsOf url: URL) throws {
        guard MemoryLayout<ASNV4Row>.stride == 16,
              MemoryLayout<ASNV6Row>.stride == 40,
              MemoryLayout<ASNOrgRecord>.stride == 8,
              MemoryLayout<ASNIndexHeader>.size <= ASNIndexFormat.headerBytes else {
            throw IPGeoCache.GeoError("the ASN index record layout does not match the on-disk format")
        }
        let descriptor = open(url.path, O_RDONLY)
        guard descriptor >= 0 else {
            throw IPGeoCache.GeoError("cannot open the ASN index: \(String(cString: strerror(errno)))")
        }
        var info = stat()
        guard fstat(descriptor, &info) == 0 else {
            close(descriptor)
            throw IPGeoCache.GeoError("cannot stat the ASN index")
        }
        let size = Int(info.st_size)
        guard size > ASNIndexFormat.headerBytes else {
            close(descriptor)
            throw IPGeoCache.GeoError("the ASN index is too small to be valid (\(size) bytes)")
        }
        guard let mapped = mmap(nil, size, PROT_READ, MAP_PRIVATE, descriptor, 0), mapped != MAP_FAILED else {
            close(descriptor)
            throw IPGeoCache.GeoError("cannot map the ASN index")
        }
        close(descriptor)

        let pointer = UnsafeRawPointer(mapped)
        let header = pointer.loadUnaligned(as: ASNIndexHeader.self)
        func reject(_ message: String) -> Error {
            munmap(mapped, size)
            return IPGeoCache.GeoError(message)
        }
        guard header.magic == ASNIndexFormat.magic else { throw reject("the ASN index has the wrong magic") }
        guard header.formatVersion == ASNIndexFormat.version else {
            throw reject("the ASN index format version is \(header.formatVersion), expected \(ASNIndexFormat.version)")
        }
        guard header.v4Count <= IPASNCache.maxRangeRows, header.v6Count <= IPASNCache.maxRangeRows,
              header.orgCount <= IPASNCache.maxOrganizationCount, header.nameBytes <= IPASNCache.maxNameBytes else {
            throw reject("the ASN index header declares counts beyond the accepted ceilings")
        }
        let layout = ASNIndexFormat.Layout(v4Count: Int(header.v4Count), v6Count: Int(header.v6Count),
                                           orgCount: Int(header.orgCount), nameBytes: Int(header.nameBytes))
        guard Int(header.totalBytes) == size, layout.totalBytes == size else {
            throw reject("the ASN index is truncated or padded: header says \(header.totalBytes), layout says \(layout.totalBytes), file is \(size)")
        }

        base = pointer
        byteCount = size
        v4Count = Int(header.v4Count)
        v6Count = Int(header.v6Count)
        orgCount = Int(header.orgCount)
        nameBytes = Int(header.nameBytes)
        builtAt = Date(timeIntervalSince1970: header.builtAt)
        v4Rows = pointer.advanced(by: layout.v4Offset).assumingMemoryBound(to: ASNV4Row.self)
        v6Rows = pointer.advanced(by: layout.v6Offset).assumingMemoryBound(to: ASNV6Row.self)
        orgs = pointer.advanced(by: layout.orgOffset).assumingMemoryBound(to: ASNOrgRecord.self)
        names = pointer.advanced(by: layout.nameOffset).assumingMemoryBound(to: UInt8.self)
        madvise(UnsafeMutableRawPointer(mutating: pointer), size, MADV_RANDOM)
    }

    deinit {
        munmap(UnsafeMutableRawPointer(mutating: base), byteCount)
    }

    func entry(ipv4 address: UInt32) -> IPASNCache.Entry? {
        var lower = 0
        var upper = v4Count
        while lower < upper {
            let middle = (lower + upper) / 2
            if v4Rows[middle].start <= address { lower = middle + 1 } else { upper = middle }
        }
        guard lower > 0 else { return nil }
        let row = v4Rows[lower - 1]
        guard address <= row.end, row.start <= row.end else { return nil }
        let prefix = IPASNCache.prefixLength(ipv4: row.start, end: row.end)
        let startText = IPASNCache.ipv4Text(row.start)
        return IPASNCache.Entry(asn: row.asn,
                                organization: organization(row.org),
                                rangeStart: startText,
                                rangeEnd: IPASNCache.ipv4Text(row.end),
                                prefix: prefix.map { "\(startText)/\($0)" })
    }

    func entry(ipv6 value: IPv6Value) -> IPASNCache.Entry? {
        var lower = 0
        var upper = v6Count
        while lower < upper {
            let middle = (lower + upper) / 2
            let row = v6Rows[middle]
            let start = IPv6Value(upper: row.startUpper, lower: row.startLower)
            if start <= value { lower = middle + 1 } else { upper = middle }
        }
        guard lower > 0 else { return nil }
        let row = v6Rows[lower - 1]
        let start = IPv6Value(upper: row.startUpper, lower: row.startLower)
        let end = IPv6Value(upper: row.endUpper, lower: row.endLower)
        guard value <= end, start <= end else { return nil }
        let prefix = IPASNCache.prefixLength(ipv6: start, end: end)
        let startText = IPASNCache.ipv6Text(start)
        return IPASNCache.Entry(asn: row.asn,
                                organization: organization(row.org),
                                rangeStart: startText,
                                rangeEnd: IPASNCache.ipv6Text(end),
                                prefix: prefix.map { "\(startText)/\($0)" })
    }

    private func organization(_ index: UInt32) -> String? {
        guard index != ASNIndexFormat.noOrganization, Int(index) < orgCount else { return nil }
        let record = orgs[Int(index)]
        guard record.nameLength > 0, Int(record.nameOffset) + Int(record.nameLength) <= nameBytes else { return nil }
        return String(decoding: UnsafeBufferPointer(start: names.advanced(by: Int(record.nameOffset)),
                                                    count: Int(record.nameLength)), as: UTF8.self)
    }
}

// MARK: - Index building

extension IPASNCache {
    public struct BuildStats: Sendable {
        public let ipv4RangeCount: Int
        public let ipv6RangeCount: Int
        public let organizationCount: Int
        public let nameBytes: Int
        public let indexBytes: Int
        public let seconds: TimeInterval
    }

    /// Streams both CSVs (start, end, asn, organisation) into the binary
    /// index. Peak memory is the organisation table, not the database.
    static func buildIndex(ipv4CSV: URL, ipv6CSV: URL, to output: URL) throws -> BuildStats {
        let started = Date()
        let writer = try GeoIndexWriter(url: output)
        try writer.appendPadding(to: ASNIndexFormat.headerBytes)
        let row = GeoCSVRow()
        var orgRecords: [ASNOrgRecord] = []
        var names: [UInt8] = []
        var orgByName: [[UInt8]: UInt32] = [:]

        func organization(_ field: UnsafeBufferPointer<UInt8>) throws -> UInt32 {
            guard field.count > 0 else { return ASNIndexFormat.noOrganization }
            let key = Array(field.prefix(1024))
            if let known = orgByName[key] { return known }
            guard orgRecords.count < maxOrganizationCount, names.count + key.count <= maxNameBytes else {
                throw IPGeoCache.GeoError("the ASN organisation table exceeds its ceiling")
            }
            let index = UInt32(orgRecords.count)
            orgRecords.append(ASNOrgRecord(nameOffset: UInt32(names.count), nameLength: UInt32(key.count)))
            names.append(contentsOf: key)
            orgByName[key] = index
            return index
        }

        func asn(_ field: UnsafeBufferPointer<UInt8>) -> UInt32? {
            guard field.count > 0, field.count <= 10 else { return nil }
            var value: UInt64 = 0
            for byte in field {
                guard byte >= UInt8(ascii: "0"), byte <= UInt8(ascii: "9") else { return nil }
                value = value * 10 + UInt64(byte - UInt8(ascii: "0"))
            }
            return value <= UInt64(UInt32.max) ? UInt32(value) : nil
        }

        var v4Count = 0
        var previousV4End: UInt32?
        let v4Reader = try GeoLineReader(url: ipv4CSV, maxOutputBytes: ipv4Source.maxBytes)
        try v4Reader.forEachLine { line in
            guard line.count > 0 else { return }
            guard row.parse(line), row.count >= 4,
                  let start = IPGeoCache.ipv4Value(row.field(0)), let end = IPGeoCache.ipv4Value(row.field(1)),
                  start <= end, let number = asn(row.field(2)) else {
                throw IPGeoCache.GeoError("the IPv4 ASN database has a malformed row")
            }
            if let previous = previousV4End, start <= previous {
                throw IPGeoCache.GeoError("the IPv4 ASN database is not sorted or overlaps")
            }
            guard v4Count < maxRangeRows else {
                throw IPGeoCache.GeoError("the IPv4 ASN database exceeds \(maxRangeRows) rows")
            }
            try writer.append(ASNV4Row(start: start, end: end, asn: number, org: try organization(row.field(3))))
            v4Count += 1
            previousV4End = end
        }
        guard v4Count > 0 else { throw IPGeoCache.GeoError("the IPv4 ASN database is empty") }

        let layoutSoFar = ASNIndexFormat.Layout(v4Count: v4Count, v6Count: 0, orgCount: 0, nameBytes: 0)
        try writer.appendPadding(to: layoutSoFar.v6Offset)

        var v6Count = 0
        var previousV6End: IPv6Value?
        let v6Reader = try GeoLineReader(url: ipv6CSV, maxOutputBytes: ipv6Source.maxBytes)
        try v6Reader.forEachLine { line in
            guard line.count > 0 else { return }
            guard row.parse(line), row.count >= 4,
                  let start = IPGeoCache.ipv6Value(row.field(0)), let end = IPGeoCache.ipv6Value(row.field(1)),
                  start <= end, let number = asn(row.field(2)) else {
                throw IPGeoCache.GeoError("the IPv6 ASN database has a malformed row")
            }
            if let previous = previousV6End, start <= previous {
                throw IPGeoCache.GeoError("the IPv6 ASN database is not sorted or overlaps")
            }
            guard v6Count < maxRangeRows else {
                throw IPGeoCache.GeoError("the IPv6 ASN database exceeds \(maxRangeRows) rows")
            }
            try writer.append(ASNV6Row(startUpper: start.upper, startLower: start.lower,
                                              endUpper: end.upper, endLower: end.lower,
                                              asn: number, org: try organization(row.field(3))))
            v6Count += 1
            previousV6End = end
        }
        guard v6Count > 0 else { throw IPGeoCache.GeoError("the IPv6 ASN database is empty") }

        let layout = ASNIndexFormat.Layout(v4Count: v4Count, v6Count: v6Count,
                                           orgCount: orgRecords.count, nameBytes: names.count)
        try writer.appendPadding(to: layout.orgOffset)
        for record in orgRecords { try writer.append(record) }
        try writer.appendPadding(to: layout.nameOffset)
        try names.withUnsafeBytes { try writer.append($0) }

        var header = ASNIndexHeader()
        header.magic = ASNIndexFormat.magic
        header.formatVersion = ASNIndexFormat.version
        header.v4Count = UInt32(v4Count)
        header.v6Count = UInt32(v6Count)
        header.orgCount = UInt32(orgRecords.count)
        header.nameBytes = UInt64(names.count)
        header.totalBytes = UInt64(layout.totalBytes)
        header.builtAt = Date().timeIntervalSince1970
        try writer.finish(header: header)

        return BuildStats(ipv4RangeCount: v4Count, ipv6RangeCount: v6Count,
                          organizationCount: orgRecords.count, nameBytes: names.count,
                          indexBytes: layout.totalBytes, seconds: Date().timeIntervalSince(started))
    }
}
