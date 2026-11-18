#if canImport(NetworkExtension)
import Foundation
import Security

/// Whether a flow's process is Apple's own system resolver, mDNSResponder
/// (#422). Checked against the running code, not the file on disk, through
/// the flow's audit token. An audit token names one process instance (it
/// carries the pid version), so a yes is remembered for that token: the
/// resolver is one long-lived process and its lookups pay the check once.
final class SystemResolverIdentity: @unchecked Sendable {
    private let lock = NSLock()
    private var verifiedToken: Data?
    private let requirement: SecRequirement? = {
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(RuleMatcher.systemResolverRequirement as CFString, [], &requirement) == errSecSuccess else {
            return nil
        }
        return requirement
    }()

    /// No token, no requirement or a failed check is a no: the flow then
    /// keeps the default mode like any other process.
    func isSigned(auditToken: Data?) -> Bool {
        guard let auditToken, let requirement else { return false }
        lock.lock()
        let known = verifiedToken == auditToken
        lock.unlock()
        if known { return true }

        var code: SecCode?
        let attributes = [kSecGuestAttributeAudit as String: auditToken] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code,
              SecCodeCheckValidity(code, [], requirement) == errSecSuccess else { return false }
        lock.lock()
        verifiedToken = auditToken
        lock.unlock()
        return true
    }
}
#endif
