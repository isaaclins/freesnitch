import Foundation

public enum ProfileValidationError: Error, LocalizedError, Equatable, Sendable {
    case emptyName
    case nameTooLong(maximumBytes: Int)
    case nameContainsControlCharacter
    case reservedName(String)
    case duplicateName(String)
    case missingProfile(String)
    case missingBlocklist(UUID)
    case invalidGatewayMAC(String)

    public var errorDescription: String? {
        switch self {
        case .emptyName:
            return "The profile name cannot be empty."
        case .nameTooLong(let maximumBytes):
            return "The profile name is longer than \(maximumBytes) UTF-8 bytes."
        case .nameContainsControlCharacter:
            return "The profile name contains a control character."
        case .reservedName(let name):
            return "The profile name `\(name)` is reserved."
        case .duplicateName(let name):
            return "A profile named `\(name)` already exists."
        case .missingProfile(let name):
            return "The profile `\(name)` does not exist."
        case .missingBlocklist(let id):
            return "The blocklist `\(id.uuidString)` does not exist."
        case .invalidGatewayMAC(let detail):
            return "Invalid gateway MAC address: \(detail)."
        }
    }
}

public enum ProfileNameValidator {
    public static let maximumBytes = 256

    /// Trims only the outside of a display name. Names are not interpreted as
    /// paths, shell fragments, or patterns, and no regular expression is used.
    public static func normalized(_ raw: String) throws -> String {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { throw ProfileValidationError.emptyName }
        guard value.utf8.count <= maximumBytes else {
            throw ProfileValidationError.nameTooLong(maximumBytes: maximumBytes)
        }
        guard !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw ProfileValidationError.nameContainsControlCharacter
        }
        guard value.lowercased() != Profile.alwaysName else {
            throw ProfileValidationError.reservedName(Profile.alwaysName)
        }
        return value
    }
}

public enum GatewayMACError: Error, LocalizedError, Equatable, Sendable {
    case empty
    case tooLong(maximumBytes: Int)
    case wrongShape
    case nonHex
    case invalidGatewayAddress

    public var errorDescription: String? {
        switch self {
        case .empty:
            return "the value is empty"
        case .tooLong(let maximumBytes):
            return "the value is longer than \(maximumBytes) bytes"
        case .wrongShape:
            return "use six octets separated by colons or hyphens, three dotted groups, or twelve hex digits"
        case .nonHex:
            return "the address contains a non-hexadecimal character"
        case .invalidGatewayAddress:
            return "the address is all zeroes, broadcast, or multicast"
        }
    }
}

/// Bounded parser and canonical representation for a default gateway MAC.
/// This is deliberately independent of Wi-Fi metadata and Location Services.
public enum GatewayMAC {
    public static let maximumInputBytes = 64

    public static func normalized(_ raw: String) -> String? {
        try? canonical(raw)
    }

    public static func canonical(_ raw: String) throws -> String {
        guard raw.utf8.count <= maximumInputBytes else {
            throw GatewayMACError.tooLong(maximumBytes: maximumInputBytes)
        }
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { throw GatewayMACError.empty }

        let octets: [String]
        if value.contains(":"), !value.contains("-") {
            octets = value.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
            guard octets.count == 6, octets.allSatisfy({ $0.utf8.count == 2 }) else {
                throw GatewayMACError.wrongShape
            }
        } else if value.contains("-"), !value.contains(":") {
            octets = value.split(separator: "-", omittingEmptySubsequences: false).map(String.init)
            guard octets.count == 6, octets.allSatisfy({ $0.utf8.count == 2 }) else {
                throw GatewayMACError.wrongShape
            }
        } else if value.contains(".") {
            let groups = value.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
            guard groups.count == 3, groups.allSatisfy({ $0.utf8.count == 4 }) else {
                throw GatewayMACError.wrongShape
            }
            octets = groups.flatMap { group in
                let chars = Array(group)
                return [String(chars[0...1]), String(chars[2...3])]
            }
        } else {
            guard value.utf8.count == 12 else { throw GatewayMACError.wrongShape }
            let chars = Array(value)
            octets = stride(from: 0, to: chars.count, by: 2).map {
                String(chars[$0..<$0 + 2])
            }
        }

        var bytes: [UInt8] = []
        bytes.reserveCapacity(6)
        for octet in octets {
            guard octet.utf8.allSatisfy({
                ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 70) || ($0 >= 97 && $0 <= 102)
            }) else {
                throw GatewayMACError.nonHex
            }
            guard let byte = UInt8(octet, radix: 16) else {
                throw GatewayMACError.nonHex
            }
            bytes.append(byte)
        }

        guard bytes.count == 6,
              bytes.contains(where: { $0 != 0 }),
              bytes.contains(where: { $0 != 0xff }),
              bytes[0] & 1 == 0 else {
            throw GatewayMACError.invalidGatewayAddress
        }
        return bytes.map { String(format: "%02x", $0) }.joined(separator: ":")
    }
}

public enum BlocklistURLValidationError: Error, LocalizedError, Equatable, Sendable {
    case empty
    case tooLong(maximumBytes: Int)
    case malformed
    case httpsRequired
    case localhostFixtureRequiresInjection
    case credentialsNotAllowed
    case fragmentNotAllowed

    public var errorDescription: String? {
        switch self {
        case .empty:
            return "The blocklist URL cannot be empty."
        case .tooLong(let maximumBytes):
            return "The blocklist URL is longer than \(maximumBytes) UTF-8 bytes."
        case .malformed:
            return "The blocklist URL is malformed."
        case .httpsRequired:
            return "Blocklist URLs must use HTTPS."
        case .localhostFixtureRequiresInjection:
            return "HTTP is permitted only for an explicitly injected localhost test fixture."
        case .credentialsNotAllowed:
            return "Blocklist URLs cannot contain user credentials."
        case .fragmentNotAllowed:
            return "Blocklist URLs cannot contain a fragment."
        }
    }
}

public enum BlocklistURLValidator {
    public static let maximumBytes = 2048

    /// Production validation. HTTPS is mandatory. The optional localhost flag
    /// exists solely for an injected test fixture and is never enabled by the
    /// RuleStore production initializer or the helper refresh path.
    public static func validate(_ raw: String, allowLocalhostHTTPForInjectedTest: Bool = false) throws -> URL {
        guard !raw.isEmpty else { throw BlocklistURLValidationError.empty }
        guard raw.utf8.count <= maximumBytes else {
            throw BlocklistURLValidationError.tooLong(maximumBytes: maximumBytes)
        }
        guard let url = URL(string: raw),
              let scheme = url.scheme?.lowercased(),
              let host = url.host?.lowercased(),
              !host.isEmpty else {
            throw BlocklistURLValidationError.malformed
        }
        guard url.user == nil && url.password == nil else {
            throw BlocklistURLValidationError.credentialsNotAllowed
        }
        guard url.fragment == nil else {
            throw BlocklistURLValidationError.fragmentNotAllowed
        }

        if scheme == "https" {
            return url
        }
        if allowLocalhostHTTPForInjectedTest,
           scheme == "http",
           isLoopbackHost(host) {
            return url
        }
        if scheme == "http" && isLoopbackHost(host) {
            throw BlocklistURLValidationError.localhostFixtureRequiresInjection
        }
        throw BlocklistURLValidationError.httpsRequired
    }

    private static func isLoopbackHost(_ host: String) -> Bool {
        host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
    }
}
