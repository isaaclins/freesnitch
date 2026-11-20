import Foundation

public enum DoHUpstreamValidator {
    public static let remediation = "Use an HTTPS URL with a host, such as https://cloudflare-dns.com/dns-query."

    /// Why a DoH upstream was refused. The helper and the CLI log the
    /// English `reason`; the app maps each case to its own translated
    /// sentence, so the Settings message is fully in the app's language.
    public enum Rejection: Equatable, Sendable, CaseIterable {
        case empty
        case surroundingWhitespace
        case notAURL
        case notHTTPS
        case missingHost

        public var reason: String {
            switch self {
            case .empty: return "the URL is empty"
            case .surroundingWhitespace: return "the URL has leading or trailing whitespace"
            case .notAURL: return "the value is not a URL"
            case .notHTTPS: return "the URL scheme must be https"
            case .missingHost: return "the URL must include a host"
            }
        }
    }

    public static func rejection(for value: String) -> Rejection? {
        guard !value.isEmpty else { return .empty }
        guard value == value.trimmingCharacters(in: .whitespacesAndNewlines) else {
            return .surroundingWhitespace
        }
        guard let url = URL(string: value) else { return .notAURL }
        guard url.scheme?.lowercased() == "https" else { return .notHTTPS }
        guard let host = url.host, !host.isEmpty else { return .missingHost }
        return nil
    }

    public static func rejectionReason(for value: String) -> String? {
        rejection(for: value)?.reason
    }
}
