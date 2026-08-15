import Foundation

extension Error {
    /// `localizedDescription` already ends in a full stop for most Foundation
    /// and XPC errors, while the app appended one of its own, so the Recent
    /// activity list showed sentences ending in two. This returns the
    /// description with exactly one trailing full stop.
    var sentence: String {
        let text = localizedDescription.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return "An unknown error occurred." }
        if text.hasSuffix(".") || text.hasSuffix("!") || text.hasSuffix("?") { return text }
        return text + "."
    }
}
