import Foundation
import Security

/// Validates callers for XPC listeners that can change FreeSnitch state.
/// The same validator is used by the privileged helper and the network
/// extension so their trust boundary cannot drift.
public enum XPCPeerValidator {
    /// The only application identities permitted to use the privileged XPC
    /// surfaces in a Developer ID build. Keep this allowlist here, rather than
    /// copying a code requirement into each listener.
    public static let permittedPeerIdentifiers: [String] = [
        AppConstants.bundleIdGUI,
        AppConstants.bundleIdCLI
    ]

    /// Return true only for the signed FreeSnitch GUI or CLI. Ad-hoc/local
    /// builds remain usable during development, matching the existing helper
    /// behavior. The bypass is inactive as soon as this process has a team ID.
    public static func isTrustedGUI(_ connection: NSXPCConnection) -> Bool {
        trustedPeer(connection, requirement: peerRequirement())
    }

    /// Used by the extension to keep a CLI inspection connection from taking
    /// ownership of the GUI connection that receives interactive alerts.
    /// Ad-hoc clients cannot become a Developer ID CLI, so this only affects
    /// signed builds where the identifier can be read reliably.
    public static func isCLI(_ connection: NSXPCConnection) -> Bool {
        let id = identifier(of: connection)
        return id == AppConstants.bundleIdCLI || id == "FreeSnitchCLI"
    }

    /// Read the signed bundle identifier of an incoming peer when available.
    /// Ad-hoc builds still carry their target identifier in the code object.
    public static func identifier(of connection: NSXPCConnection) -> String? {
        guard let code = guestCode(for: connection) else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
              let staticCode else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode,
                                            SecCSFlags(rawValue: kSecCSSigningInformation),
                                            &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return nil }
        return dict[kSecCodeInfoIdentifier as String] as? String
    }

    /// Construct the code requirements used by the privileged XPC
    /// listeners. Keep this in shared code so the helper and extension cannot
    /// silently accept different client identities.
    private static func peerRequirement() -> SecRequirement? {
        requirement(for: permittedPeerIdentifiers)
    }

    private static func requirement(for identifiers: [String]) -> SecRequirement? {
        let identifierClause = identifiers
            .map { "identifier \"\($0)\"" }
            .joined(separator: " or ")
        let requirementText = "anchor apple generic"
            + " and (\(identifierClause))"
            + " and certificate leaf[subject.OU] = \"\(AppConstants.teamID)\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(requirementText as CFString, [], &requirement) == errSecSuccess else {
            return nil
        }
        return requirement
    }

    private static func trustedPeer(
        _ connection: NSXPCConnection,
        requirement: SecRequirement?
    ) -> Bool {
        switch selfSigningTeam {
        case .failure:
            // We could not read our own signature. That should never happen,
            // so treat it as hostile rather than waving every client through.
            return false
        case .success(let team) where team == nil:
            return true
        case .success:
            break
        }

        guard let code = guestCode(for: connection),
              let requirement else { return false }
        return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
    }

    private static func guestCode(for connection: NSXPCConnection) -> SecCode? {
        var code: SecCode?
        let attributes: [String: Any]
        if let tokenData = auditTokenData(for: connection) {
            attributes = [kSecGuestAttributeAudit as String: tokenData]
        } else {
            attributes = [kSecGuestAttributePid as String: connection.processIdentifier]
        }
        guard SecCodeCopyGuestWithAttributes(nil, attributes as CFDictionary, [], &code) == errSecSuccess else {
            return nil
        }
        return code
    }

    /// NSXPCConnection exposes the audit token only through KVC; fall back to
    /// the (racier) pid when that is unavailable.
    private static func auditTokenData(for connection: NSXPCConnection) -> Data? {
        guard connection.responds(to: NSSelectorFromString("auditToken")) else { return nil }
        guard let value = connection.value(forKey: "auditToken") as? NSValue else { return nil }
        var raw = audit_token_t()
        value.getValue(&raw, size: MemoryLayout<audit_token_t>.size)
        return withUnsafeBytes(of: &raw) { Data($0) }
    }

    /// This process's team identifier: `nil` for an ad-hoc/local build, or a
    /// failure if its signature cannot be read at all.
    private static let selfSigningTeam: Result<String?, NSError> = {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else {
            return .failure(NSError(domain: NSOSStatusErrorDomain, code: -1))
        }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
            return .failure(NSError(domain: NSOSStatusErrorDomain, code: -2))
        }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode,
                                            SecCSFlags(rawValue: kSecCSSigningInformation),
                                            &info) == errSecSuccess,
              let dict = info as? [String: Any] else {
            return .failure(NSError(domain: NSOSStatusErrorDomain, code: -3))
        }
        let team = dict["teamid"] as? String
        return .success((team?.isEmpty ?? true) ? nil : team)
    }()
}
