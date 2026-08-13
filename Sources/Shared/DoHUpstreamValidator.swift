import Foundation

public enum DoHUpstreamValidator {
    public static let remediation = "Use an HTTPS URL with a host, such as https://cloudflare-dns.com/dns-query."

    public static func rejectionReason(for value: String) -> String? {
        guard !value.isEmpty else { return "the URL is empty" }
        guard value == value.trimmingCharacters(in: .whitespacesAndNewlines) else {
            return "the URL has leading or trailing whitespace"
        }
        guard let url = URL(string: value) else { return "the value is not a URL" }
        guard url.scheme?.lowercased() == "https" else { return "the URL scheme must be https" }
        guard let host = url.host, !host.isEmpty else { return "the URL must include a host" }
        return nil
    }
}
