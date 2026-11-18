#if canImport(NetworkExtension)
import Foundation
import Security

/// Whether a flow was sent by Apple's own system resolver, mDNSResponder
/// (#422): the sending process must be at the resolver's path and its
/// running code must pass the resolver's signature requirement, checked
/// through its audit token. An audit token names one process instance (it
/// carries the pid version), so the answer is remembered per token: the
/// resolver is one long-lived process, and its lookups pay the check once.
final class SystemResolverIdentity: @unchecked Sendable {
    private let lock = NSLock()
    /// The last few tokens and their answers. Small on purpose: almost every
    /// flow comes from a token already seen, and a miss only costs a check.
    private var answers: [Data: Bool] = [:]
    private var order: [Data] = []
    private let capacity = 32
    private let requirement: SecRequirement? = {
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(RuleMatcher.systemResolverRequirement as CFString, [], &requirement) == errSecSuccess else {
            return nil
        }
        return requirement
    }()

    /// No token, no requirement, or a failed check is a no: the flow then
    /// keeps the default mode like any other.
    func isSystemResolver(processAuditToken: Data?) -> Bool {
        guard let token = processAuditToken, let pid = Self.pid(from: token), pid > 0 else { return false }
        // The path is read first, so other processes never pay for a
        // signature check (and are never remembered).
        let path = Self.path(of: pid)
        guard path == RuleMatcher.systemResolverPath else { return false }
        lock.lock()
        let known = answers[token]
        lock.unlock()
        if let known { return known }

        var passes = false
        if let requirement {
            var code: SecCode?
            let attributes = [kSecGuestAttributeAudit as String: token] as CFDictionary
            if SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code {
                passes = SecCodeCheckValidity(code, [], requirement) == errSecSuccess
            }
        }
        let answer = RuleMatcher.isSystemResolver(senderPath: path, passesRequirement: passes)
        lock.lock()
        if answers.updateValue(answer, forKey: token) == nil {
            order.append(token)
            if order.count > capacity { answers.removeValue(forKey: order.removeFirst()) }
        }
        lock.unlock()
        return answer
    }

    static func pid(from token: Data) -> Int32? {
        guard token.count >= MemoryLayout<audit_token_t>.size else { return nil }
        var value = audit_token_t()
        _ = withUnsafeMutableBytes(of: &value) { token.copyBytes(to: $0, count: $0.count) }
        // val.5 is the pid, as in FilterDataProvider.auditTokenToPID.
        return Int32(bitPattern: value.val.5)
    }

    static func path(of pid: Int32) -> String {
        var buffer = [CChar](repeating: 0, count: 4096)
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        return length > 0 ? String(cString: buffer) : ""
    }
}
#endif
