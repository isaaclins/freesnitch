import Foundation

/// A log line whose literal text is public and whose interpolated values are
/// private unless marked otherwise (#264).
///
/// The unified log shows a private value as `<private>` unless the user turns
/// on private data for FreeSnitch's subsystem (for example with a logging
/// profile). Host names, paths, addresses, resolver URLs, list names and error
/// descriptions therefore stay out of shared diagnostics by default, while the
/// fixed wording still says what failed.
///
///     PSLog.error(PSLog.dns, "no client answered the ask for '\(domain)'")       // domain is private
///     PSLog.error(PSLog.dns, "the ask table holds \(public: count) entries")       // a count is safe
///     PSLog.error(PSLog.helper, "Insights prune failed: \(error: error)")         // domain and code public, text private
public struct PSLogMessage: ExpressibleByStringInterpolation {
    /// Public text around the values: `texts.count == values.count + 1`.
    public let texts: [String]
    /// Private values, in order, between the public texts.
    public let values: [String]

    public init(stringLiteral value: String) {
        texts = [value]
        values = []
    }

    public init(stringInterpolation: StringInterpolation) {
        texts = stringInterpolation.texts
        values = stringInterpolation.values
    }

    /// A whole message that may hold private data, for example text built
    /// elsewhere from paths or tool output.
    public static func `private`(_ text: String) -> PSLogMessage { "\(text)" }

    /// The line as a reader without private data sees it.
    public var redacted: String { join { _ in "<private>" } }
    /// The line with every value, as a reader with private data on sees it.
    public var unredacted: String { join { $0 } }

    private func join(_ value: (String) -> String) -> String {
        var out = texts[0]
        for (index, item) in values.enumerated() { out += value(item) + texts[index + 1] }
        return out
    }

    public struct StringInterpolation: StringInterpolationProtocol {
        var texts: [String] = [""]
        var values: [String] = []

        public init(literalCapacity: Int, interpolationCount: Int) {}

        public mutating func appendLiteral(_ literal: String) { texts[texts.count - 1] += literal }

        /// Private by default: anything not marked public is redacted.
        public mutating func appendInterpolation<T>(_ value: T) {
            values.append(String(describing: value))
            texts.append("")
        }

        /// For values that carry no user data: counts, process ids, versions,
        /// states, flags, fixed names chosen by FreeSnitch.
        public mutating func appendInterpolation<T>(public value: T) {
            texts[texts.count - 1] += String(describing: value)
        }

        /// Splices in another message, keeping each part's privacy.
        public mutating func appendInterpolation(_ message: PSLogMessage) {
            appendLiteral(message.texts[0])
            for (index, value) in message.values.enumerated() {
                values.append(value)
                texts.append(message.texts[index + 1])
            }
        }

        /// The error's domain and code stay readable; its description, which
        /// can name files or hosts, is private.
        public mutating func appendInterpolation(error: Error) {
            let ns = error as NSError
            appendLiteral("[\(ns.domain) \(ns.code)] ")
            appendInterpolation(ns.localizedDescription)
        }
    }
}
