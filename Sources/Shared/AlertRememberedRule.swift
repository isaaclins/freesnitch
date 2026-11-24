import Foundation

/// How much of a connection a remembered alert answer covers. The dialog
/// offers these three and the rule honours each of them (#129).
public enum AlertRememberScope: String, CaseIterable, Sendable {
    case anywhere
    case thisHost
    case thisAddressAndPort
}

extension Connection {
    /// The address and port a rule can be pinned to, when the connection has
    /// both. ICMP and flows macOS reports without a port carry 0, and a rule
    /// saved with no port covers the address on every port (#223): the alert
    /// must not offer "address and port" then, and nothing is saved for it.
    public var pinnedAddressAndPort: (ip: String, port: Int)? {
        let ip = remoteIP.trimmingCharacters(in: .whitespaces)
        guard !ip.isEmpty, !Connection.isUnspecifiedAddress(ip) else { return nil }
        guard remotePort > 0 && remotePort <= 65535 else { return nil }
        return (ip, remotePort)
    }

    /// 0.0.0.0 or :: in any spelling. A rule keyed on it matches nothing.
    static func isUnspecifiedAddress(_ text: String) -> Bool {
        var v4 = in_addr()
        if inet_pton(AF_INET, text, &v4) == 1 { return v4.s_addr == 0 }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, text, &v6) == 1 {
            return withUnsafeBytes(of: &v6) { $0.allSatisfy { $0 == 0 } }
        }
        return false
    }

    /// The scopes an alert for this connection can really be remembered at.
    public var availableRememberScopes: [AlertRememberScope] {
        AlertRememberScope.allCases.filter { $0 != .thisAddressAndPort || pinnedAddressAndPort != nil }
    }

    /// The rule a remembered alert answer creates, or nil when no rule is as
    /// narrow as what the user chose, in which case only this flow is answered.
    public func rememberedRule(scope: AlertRememberScope, allow: Bool,
                               profile: String, expiresAt: Date?) -> Rule? {
        let host = remoteHost.isEmpty ? remoteIP : remoteHost
        // A rule keyed on the unspecified address matches nothing, so it would
        // never stop the next prompt.
        let isUnspecified = host.isEmpty || Connection.isUnspecifiedAddress(host)
        // The destination has to travel INTO the rule, not merely into this
        // check. A rule carrying an empty host and no address loses both
        // destination tests in the matcher, because each is an `if let`, and
        // silently becomes "this process, anywhere": an allow would grant far
        // more than the user approved. See issue #64.
        // A numeric address in the name field is an address, not a name
        // (#224): the rule stores it as one.
        let (ruleHost, ruleIP) = rememberedHostDestination
        let usesAddress = ruleHost == nil
        let hasDestination = !(ruleHost ?? ruleIP ?? "").isEmpty
        // "Anywhere" is the one scope with no destination, and it is only safe
        // because the user asked for it by name. It still needs something to
        // key on, so without a process identity it narrows to the host rather
        // than becoming a rule that matches every flow on the Mac.
        let processIdentity = !(processBundleId ?? "").isEmpty || !processPath.isEmpty
        let effectiveScope = (scope == .anywhere && !processIdentity) ? .thisHost : scope
        if effectiveScope != .anywhere && (isUnspecified || !hasDestination) { return nil }

        var scopedHost: String?
        var scopedIP: String?
        var scopedPort: Int?
        let ruleScope: RuleScope
        switch effectiveScope {
        case .anywhere:
            ruleScope = .process
        case .thisHost:
            scopedHost = ruleHost
            scopedIP = ruleIP
            ruleScope = usesAddress ? .ip : .domain
        case .thisAddressAndPort:
            // Pinning to an address and port needs both. Without them no rule
            // is as narrow as the one asked for: the host would cover every
            // port, and a rule with no port covers the address on every port
            // (#223). Remember nothing, which never blocks or allows more than
            // the user chose.
            guard let pinned = pinnedAddressAndPort else { return nil }
            scopedIP = pinned.ip
            scopedPort = pinned.port
            ruleScope = .ip
        }
        return Rule(
            processBundleId: processBundleId,
            processTeamId: processTeamId,
            processPath: processPath,
            processName: processName,
            remoteHost: scopedHost,
            remoteIP: scopedIP,
            remotePort: scopedPort,
            direction: direction,
            action: allow ? .allow : .deny,
            scope: ruleScope,
            priority: 100,
            profile: profile,
            groupName: nil,
            notes: "Created from alert",
            temporary: expiresAt != nil,
            expiresAt: expiresAt
        )
    }
}
