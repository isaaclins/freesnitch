import Foundation
import Security

/// Validates the GUI peer for XPC listeners that can change FreeSnitch state.
/// The same validator is used by the privileged helper and the network
/// extension so their trust boundary cannot drift.
public enum XPCPeerValidator {
    /// Return true only for the FreeSnitch GUI signed by the FreeSnitch team.
    /// Ad-hoc/local builds remain usable during development, matching the
    /// helper's existing behavior.
    public static func isTrustedGUI(_ connection: NSXPCConnection) -> Bool {
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

        var code: SecCode?
        let attributes: [String: Any]
        if let tokenData = auditTokenData(for: connection) {
            attributes = [kSecGuestAttributeAudit as String: tokenData]
        } else {
            attributes = [kSecGuestAttributePid as String: connection.processIdentifier]
        }
        guard SecCodeCopyGuestWithAttributes(nil, attributes as CFDictionary, [], &code) == errSecSuccess,
              let code else { return false }

        guard let requirement = guiRequirement() else { return false }
        return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
    }

    /// Construct the one code requirement used by every privileged XPC
    /// listener. Keep this in shared code so the helper and extension cannot
    /// silently accept different GUI identities.
    private static func guiRequirement() -> SecRequirement? {
        let requirementText = "anchor apple generic"
            + " and identifier \"\(AppConstants.bundleIdGUI)\""
            + " and certificate leaf[subject.OU] = \"\(AppConstants.teamID)\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(requirementText as CFString, [], &requirement) == errSecSuccess else {
            return nil
        }
        return requirement
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
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else {
            return .failure(NSError(domain: NSOSStatusErrorDomain, code: -3))
        }
        let team = dict["teamid"] as? String
        return .success((team?.isEmpty ?? true) ? nil : team)
    }()
}
