import Foundation

/// Why the gateway could not be read or a profile could not be switched to.
/// The helper sends this code with its values instead of a finished sentence,
/// so the app words it in the user's language (#520).
public enum ProfileProblem: Codable, Hashable, Sendable {
    case toolLaunchFailed(tool: String, detail: String)
    case toolExitStatus(tool: String, status: Int32)
    case toolOutputTooLarge(tool: String, maximum: Int)
    case toolOutputNotText(tool: String)
    case noMACForGateway(String)
    case unrecognisedGatewayMAC
    case profileNotFound(String)
    case databaseBusy
    case databaseError(String)
    /// Anything without a code of its own. The detail is shown as is.
    case other(String)

    /// SQLite's primary result codes for a database that is in use: held by
    /// another connection (BUSY) or by a conflicting statement (LOCKED).
    private static let busyCodes: Set<Int> = [5, 6] // SQLITE_BUSY, SQLITE_LOCKED

    public init(_ error: Error) {
        if let read = error as? GatewayMACReadError, let problem = read.problem {
            self = problem
            return
        }
        if case RuleStore.StoreError.profileNotFound(let name)? = error as? RuleStore.StoreError {
            self = .profileNotFound(name)
            return
        }
        let nsError = error as NSError
        if nsError.domain == RuleStore.errorDomain {
            if let code = nsError.userInfo[RuleStore.sqliteResultCodeKey] as? Int,
               Self.busyCodes.contains(code & 0xff) {
                self = .databaseBusy
            } else {
                self = .databaseError(Self.clause(nsError.localizedDescription))
            }
            return
        }
        self = .other(Self.clause(error.localizedDescription))
    }

    /// The reason as a clause that sits mid-sentence, in the language of the
    /// process that asks: the app's language in the app, English in the
    /// helper's log.
    public var message: String {
        switch self {
        case .toolLaunchFailed(let tool, let detail):
            return String(localized: "\(tool) could not be started: \(detail)")
        case .toolExitStatus(let tool, let status):
            return String(localized: "\(tool) exited with status \(Int(status))")
        case .toolOutputTooLarge(let tool, let maximum):
            return String(localized: "\(tool) wrote more than \(maximum) bytes")
        case .toolOutputNotText(let tool):
            return String(localized: "\(tool) wrote output that is not text")
        case .noMACForGateway(let gateway):
            return String(localized: "no hardware address is known for the gateway \(gateway)")
        case .unrecognisedGatewayMAC:
            return String(localized: "the gateway's hardware address is not in a recognised form")
        case .profileNotFound(let name):
            return String(localized: "the profile \(name) no longer exists")
        case .databaseBusy:
            return String(localized: "the rule database is busy")
        case .databaseError(let detail):
            return String(localized: "the rule database reported an error (\(detail))")
        case .other(let detail):
            return detail
        }
    }

    /// Errors are whole sentences, but the reason sits mid-sentence, where a
    /// closing period would double up.
    private static func clause(_ text: String) -> String {
        var reason = text.trimmingCharacters(in: .whitespacesAndNewlines)
        while reason.hasSuffix(".") { reason.removeLast() }
        return reason
    }
}

/// An automatic switch that failed and is still being retried: the network's
/// bound profile is not active yet (#269).
public struct PendingNetworkSwitch: Codable, Hashable, Sendable {
    public var gatewayMAC: String
    public var profileName: String
    public var reason: ProfileProblem

    public init(gatewayMAC: String, profileName: String, reason: ProfileProblem) {
        self.gatewayMAC = gatewayMAC
        self.profileName = profileName
        self.reason = reason
    }

    /// The reason, worded where it is read (#520).
    public var problem: String { reason.message }
}
