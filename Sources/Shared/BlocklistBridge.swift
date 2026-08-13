import CryptoKit
import Foundation

/// Compact, versioned transport for the helper-owned blocklist.
///
/// The extension never receives the source strings. It keeps only 128-bit
/// SHA-256 fingerprints, which bound the resident index memory while retaining
/// constant-time membership checks. A fingerprint collision is
/// computationally infeasible for an untrusted list source.
public enum BlocklistBridge {
    public static let version: UInt16 = 1
    public static let maxEntries = 1_000_000
    public static let headerSize = 12
    public static let fingerprintSize = 16
    public static let maxSnapshotBytes = headerSize + maxEntries * fingerprintSize

    public struct Fingerprint: Hashable, Sendable {
        public let high: UInt64
        public let low: UInt64

        public init(high: UInt64, low: UInt64) {
            self.high = high
            self.low = low
        }
    }

    public enum Error: Swift.Error, CustomStringConvertible, Sendable {
        case invalidEntry(String)
        case invalidHeader
        case unsupportedVersion(UInt16)
        case invalidEntryCount
        case invalidLength
        case duplicateEntry
        case unsortedEntries

        public var description: String {
            switch self {
            case .invalidEntry(let value): return "invalid blocklist entry \(value)"
            case .invalidHeader: return "invalid blocklist snapshot header"
            case .unsupportedVersion(let value): return "unsupported blocklist snapshot version \(value)"
            case .invalidEntryCount: return "blocklist snapshot entry count exceeds the safety limit"
            case .invalidLength: return "invalid blocklist snapshot length"
            case .duplicateEntry: return "duplicate blocklist snapshot entry"
            case .unsortedEntries: return "blocklist snapshot entries are not sorted"
            }
        }
    }

    /// A process-local exact membership index over the compact transport.
    public struct Index: Sendable {
        private let fingerprints: Set<Fingerprint>

        public init(snapshotData: Data) throws {
            self.fingerprints = try decode(snapshotData)
        }

        public init(fingerprints: Set<Fingerprint>) {
            self.fingerprints = fingerprints
        }

        public static let empty = Self(fingerprints: [])

        /// Tests the literal IP first, then the hostname and its parent
        /// domains. The number of candidates is bounded by the DNS name limit.
        public func contains(remoteHost: String, remoteIP: String) -> Bool {
            if containsLiteral(remoteIP) { return true }
            for candidate in BlocklistBridge.hostCandidates(remoteHost) {
                if containsLiteral(candidate) { return true }
            }
            return false
        }

        private func containsLiteral(_ value: String) -> Bool {
            guard let fingerprint = BlocklistBridge.fingerprint(for: value) else { return false }
            return fingerprints.contains(fingerprint)
        }
    }

    /// An empty, valid snapshot is used whenever the helper has no usable
    /// blocklist. Empty data is reserved for the XPC "unchanged" response.
    public static var emptySnapshotData: Data {
        var data = Data()
        data.append(contentsOf: [0x46, 0x53, 0x42, 0x4C]) // FSBL
        append(UInt16(version).bigEndian, to: &data)
        append(UInt16(0).bigEndian, to: &data) // reserved
        append(UInt32(0).bigEndian, to: &data)
        return data
    }

    public static func encode(entries: Set<String>) throws -> Data {
        guard entries.count <= maxEntries else { throw Error.invalidEntryCount }
        var fingerprints = Set<Fingerprint>(minimumCapacity: entries.count)
        for entry in entries {
            guard let value = fingerprint(for: entry) else {
                throw Error.invalidEntry(entry)
            }
            fingerprints.insert(value)
        }
        return try encode(fingerprints: fingerprints)
    }

    public static func encode(fingerprints: Set<Fingerprint>) throws -> Data {
        guard fingerprints.count <= maxEntries else { throw Error.invalidEntryCount }
        let expectedSize = headerSize + fingerprints.count * fingerprintSize
        guard expectedSize <= maxSnapshotBytes else { throw Error.invalidLength }

        var data = Data()
        data.reserveCapacity(expectedSize)
        data.append(contentsOf: [0x46, 0x53, 0x42, 0x4C]) // FSBL
        append(UInt16(version).bigEndian, to: &data)
        append(UInt16(0).bigEndian, to: &data) // reserved
        append(UInt32(fingerprints.count).bigEndian, to: &data)
        for value in fingerprints.sorted(by: isOrderedBefore) {
            append(value.high.bigEndian, to: &data)
            append(value.low.bigEndian, to: &data)
        }
        return data
    }

    public static func decode(_ data: Data) throws -> Set<Fingerprint> {
        guard data.count >= headerSize, data.count <= maxSnapshotBytes else {
            throw Error.invalidLength
        }
        guard data[0] == 0x46, data[1] == 0x53, data[2] == 0x42, data[3] == 0x4C else {
            throw Error.invalidHeader
        }
        let snapshotVersion = readUInt16(data, at: 4)
        guard snapshotVersion == version else { throw Error.unsupportedVersion(snapshotVersion) }
        let count = Int(readUInt32(data, at: 8))
        guard count <= maxEntries else { throw Error.invalidEntryCount }
        guard count <= (Int.max - headerSize) / fingerprintSize,
              headerSize + count * fingerprintSize == data.count else {
            throw Error.invalidLength
        }

        var result = Set<Fingerprint>(minimumCapacity: count)
        var offset = headerSize
        var previous: Fingerprint?
        for _ in 0..<count {
            let value = Fingerprint(
                high: readUInt64(data, at: offset),
                low: readUInt64(data, at: offset + 8)
            )
            if let previous {
                if previous.high == value.high && previous.low == value.low {
                    throw Error.duplicateEntry
                }
                if !isOrderedBefore(previous, value) {
                    throw Error.unsortedEntries
                }
            }
            result.insert(value)
            previous = value
            offset += fingerprintSize
        }
        return result
    }

    /// Normalizes both source entries and flow values to the same form.
    public static func fingerprint(for raw: String) -> Fingerprint? {
        guard let value = normalized(raw) else { return nil }
        let bytes = Array(SHA256.hash(data: Data(value.utf8)))
        var high: UInt64 = 0
        var low: UInt64 = 0
        for byte in bytes.prefix(8) { high = (high << 8) | UInt64(byte) }
        for byte in bytes.dropFirst(8).prefix(8) { low = (low << 8) | UInt64(byte) }
        return Fingerprint(high: high, low: low)
    }

    private static func hostCandidates(_ raw: String) -> [String] {
        guard let value = normalized(raw),
              let kind = PFHostValidator.kind(for: value) else { return [] }
        if kind == .ip { return [value] }
        guard kind == .hostname else { return [] }

        var labels = value.split(separator: ".")
        guard labels.count >= 2 else { return [value] }
        var result = [value]
        while labels.count > 2 {
            labels.removeFirst()
            result.append(labels.joined(separator: "."))
        }
        return result
    }

    private static func normalized(_ raw: String) -> String? {
        var value = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if value.hasSuffix(".") { value.removeLast() }
        guard !value.isEmpty, value.utf8.count <= 253 else { return nil }
        return value
    }

    private static func isOrderedBefore(_ lhs: Fingerprint, _ rhs: Fingerprint) -> Bool {
        lhs.high == rhs.high ? lhs.low < rhs.low : lhs.high < rhs.high
    }

    private static func append<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
        withUnsafeBytes(of: value) { data.append(contentsOf: $0) }
    }

    private static func readUInt16(_ data: Data, at offset: Int) -> UInt16 {
        UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
    }

    private static func readUInt32(_ data: Data, at offset: Int) -> UInt32 {
        UInt32(data[offset]) << 24
            | UInt32(data[offset + 1]) << 16
            | UInt32(data[offset + 2]) << 8
            | UInt32(data[offset + 3])
    }

    private static func readUInt64(_ data: Data, at offset: Int) -> UInt64 {
        var value: UInt64 = 0
        for index in 0..<8 {
            value = (value << 8) | UInt64(data[offset + index])
        }
        return value
    }
}
