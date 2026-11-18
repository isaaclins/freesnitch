import Foundation

/// A VPN that is connected right now, and what it does to name lookups (#424).
///
/// Read from the system's network state rather than guessed from interface
/// names alone: a VPN set up through macOS (Tailscale, WireGuard and the VPN
/// apps built on Network Extension) is a network
/// service with a `VPN` entry and, once connected, an interface. An `utun`
/// interface on its own is not a VPN: macOS opens several for iCloud Private
/// Relay, Back to My Mac leftovers and Continuity.
public struct ActiveVPN: Equatable, Sendable {
    /// The name the VPN gave its service ("Tailscale"), or nil when it set none.
    public let name: String?
    /// The tunnel interface, for example `utun4`.
    public let interface: String
    /// The DNS servers the VPN asks macOS to use.
    public let dnsServers: [String]
    /// The domains whose lookups the VPN takes, when it takes only some.
    public let matchDomains: [String]
    /// True when the VPN's DNS servers are the ones macOS uses for every
    /// lookup that no more specific domain claims.
    public let handlesAllLookups: Bool

    public init(name: String?, interface: String, dnsServers: [String], matchDomains: [String], handlesAllLookups: Bool) {
        self.name = name
        self.interface = interface
        self.dnsServers = dnsServers
        self.matchDomains = matchDomains
        self.handlesAllLookups = handlesAllLookups
    }

    /// "Tailscale", or "A VPN" when the VPN set no name.
    public var displayName: String {
        guard let name = name?.trimmingCharacters(in: .whitespacesAndNewlines), !name.isEmpty else { return "A VPN" }
        return name
    }

    /// True when some or all lookups go to this VPN's DNS servers.
    public var handlesSomeLookups: Bool {
        !dnsServers.isEmpty && (handlesAllLookups || !matchDomains.isEmpty)
    }
}

public enum VPNStatus {
    /// The keys `connectedVPNs(in:)` reads, as SCDynamicStore patterns.
    public static let storePatterns = [
        "State:/Network/Service/[^/]+/VPN",
        "State:/Network/Service/[^/]+/IPv4",
        "State:/Network/Service/[^/]+/IPv6",
        "State:/Network/Service/[^/]+/DNS",
        "Setup:/Network/Service/[^/]+",
    ]
    public static let globalDNSKey = "State:/Network/Global/DNS"

    /// The VPNs connected in a snapshot of the dynamic store, keyed as the
    /// store keys them (`State:/Network/Service/<id>/VPN` and so on), plus
    /// `State:/Network/Global/DNS`. Pure, so it is tested with the store
    /// contents of real VPNs.
    ///
    /// A service counts as a connected VPN when it has a `VPN` entry and an
    /// IPv4 or IPv6 entry naming its interface: macOS writes the address
    /// entries only while the tunnel is up. The VPN takes all lookups when the
    /// global DNS configuration came from it, or when its servers are the
    /// global servers.
    public static func connectedVPNs(in store: [String: Any]) -> [ActiveVPN] {
        let globalDNS = store[globalDNSKey] as? [String: Any]
        let globalServers = Set((globalDNS?["ServerAddresses"] as? [String]) ?? [])
        let globalSource = (globalDNS?["__CONFIGURATION_ID__"] as? String) ?? ""

        var result: [ActiveVPN] = []
        for key in store.keys.sorted() {
            guard let serviceID = serviceID(of: key, suffix: "/VPN") else { continue }
            let base = "State:/Network/Service/\(serviceID)"
            let interface = interfaceName(store["\(base)/IPv4"]) ?? interfaceName(store["\(base)/IPv6"])
            guard let interface else { continue }
            let setup = store["Setup:/Network/Service/\(serviceID)"] as? [String: Any]
            let dns = store["\(base)/DNS"] as? [String: Any]
            let servers = (dns?["ServerAddresses"] as? [String]) ?? []
            let rawMatch = (dns?["SupplementalMatchDomains"] as? [String] ?? [])
                .map { $0.trimmingCharacters(in: CharacterSet(charactersIn: ". ")) }
            // An empty match domain is the VPN claiming the default resolver,
            // as Tailscale does with MagicDNS on.
            let claimsDefault = rawMatch.contains("")
            let match = rawMatch.filter { !$0.isEmpty }
            let fromThisService = !globalSource.isEmpty && globalSource.contains(serviceID)
            // Same servers only counts for a VPN that claims no domains or
            // the default resolver: a split-DNS VPN may push the very
            // resolver the user set anyway.
            let sameServers = (match.isEmpty || claimsDefault) && !servers.isEmpty && !globalServers.isEmpty
                && globalServers.isSubset(of: Set(servers))
            result.append(ActiveVPN(name: setup?["UserDefinedName"] as? String,
                                    interface: interface,
                                    dnsServers: servers,
                                    matchDomains: match,
                                    handlesAllLookups: !servers.isEmpty && (fromThisService || sameServers)))
        }
        return result
    }

    private static func serviceID(of key: String, suffix: String) -> String? {
        let prefix = "State:/Network/Service/"
        guard key.hasPrefix(prefix), key.hasSuffix(suffix) else { return nil }
        let id = key.dropFirst(prefix.count).dropLast(suffix.count)
        return id.isEmpty || id.contains("/") ? nil : String(id)
    }

    private static func interfaceName(_ value: Any?) -> String? {
        guard let entry = value as? [String: Any],
              let name = entry["InterfaceName"] as? String, !name.isEmpty else { return nil }
        return name
    }

    // MARK: - What it means for FreeSnitch

    /// The VPN whose DNS takes every lookup, if any.
    public static func dnsOwner(_ vpns: [ActiveVPN]) -> ActiveVPN? {
        vpns.first { $0.handlesAllLookups }
    }

    /// One plain sentence on what the connected VPNs mean for FreeSnitch's
    /// rules, or nil when none is connected. Per-app rules are enforced by the
    /// content filter on each app's own connection, before macOS picks the
    /// interface it leaves by, so they hold inside the tunnel too.
    public static func rulesSummary(_ vpns: [ActiveVPN]) -> String? {
        guard let first = vpns.first else { return nil }
        let names = vpns.count == 1 ? "\(first.displayName) is" : "\(vpns.count) VPNs are"
        return "\(names) connected. Your rules still apply to every app's connections through the tunnel. "
            + "If the VPN stops connecting while FreeSnitch is on, check that neither the VPN app nor its network extension is denied in Rules."
    }

    /// What the connected VPNs mean for FreeSnitch's DNS protection, or nil
    /// when no VPN handles any lookups. `routesThroughProxy` is whether the
    /// Mac's lookups reach FreeSnitch's DNS proxy right now.
    public static func dnsSummary(_ vpns: [ActiveVPN], routesThroughProxy: Bool) -> String? {
        if let owner = dnsOwner(vpns), !routesThroughProxy {
            let servers = owner.dnsServers.joined(separator: ", ")
            var text = "\(owner.displayName) is handling DNS right now (\(servers)), so FreeSnitch's DNS blocking and upstream don't apply while it is connected."
            if isTailscale(owner) {
                text += " To use FreeSnitch's DNS while it is connected, turn off Use Tailscale DNS Settings in the Tailscale menu, then set this Mac's DNS server to 127.0.0.1 if it isn't already."
            } else {
                text += " To use FreeSnitch's DNS while it is connected, turn off the VPN's own DNS in its settings, if it has that option, then set this Mac's DNS server to 127.0.0.1 if it isn't already."
            }
            return text
        }
        let split = vpns.filter { !$0.handlesAllLookups && $0.handlesSomeLookups }
        guard !split.isEmpty else { return nil }
        return split.map { vpn in
            let domains = vpn.matchDomains.prefix(3).joined(separator: ", ")
            let more = vpn.matchDomains.count > 3 ? " and \(vpn.matchDomains.count - 3) more" : ""
            return "Lookups for \(domains)\(more) go to \(vpn.displayName), so FreeSnitch's DNS blocking doesn't apply to those names."
        }.joined(separator: " ")
    }

    /// Tailscale names its service "Tailscale" and serves MagicDNS from
    /// 100.100.100.100.
    public static func isTailscale(_ vpn: ActiveVPN) -> Bool {
        vpn.name?.lowercased().contains("tailscale") == true || vpn.dnsServers.contains("100.100.100.100")
    }
}
