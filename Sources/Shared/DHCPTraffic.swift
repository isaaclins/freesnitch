import Foundation

/// Whether a flow is address configuration (DHCP or DHCPv6), which the
/// Network Extension lets through ahead of every rule so a deny can never take
/// the Mac off the network (issue #186).
///
/// The port number alone is not enough (#293): an app's deny used to be
/// skipped for any connection whose destination port was 67, 68, 546 or 547,
/// whatever the transport and whoever was at the other end. Address
/// configuration is UDP between two well-known ports on both ends: a DHCP
/// client sends from 68 to 67 and hears back on 68, a DHCPv6 client from 546
/// to 547, and servers and relay agents use the same pairs (RFC 2131 section
/// 4.1, RFC 8415 section 7.2). An ordinary app talking to some service on one
/// of these port numbers comes from an ephemeral local port and keeps its
/// rules. Since macOS 10.14 any process may bind a port below 1024, so the
/// port pair alone is not proof either: it only counts when the app the flow
/// belongs to runs as root, as the system's DHCP client (configd) does.
public enum DHCPTraffic {
    public static let ipv4Ports: Set<Int> = [67, 68]
    public static let ipv6Ports: Set<Int> = [546, 547]

    /// Where a client sends before it has an address or a server: the IPv4
    /// limited broadcast (RFC 2131 section 4.1), and the DHCPv6 relay agents
    /// and servers multicast groups (RFC 8415 section 7.1).
    public static let ipv4ServerDiscovery: Set<String> = ["255.255.255.255"]
    public static let ipv6ServerDiscovery: Set<String> = ["ff02::1:2", "ff05::1:3"]

    /// `transportProtocol` is the IP protocol number (IPPROTO_UDP is 17).
    /// `senderIsRoot` is whether the flow's app runs with effective user id 0,
    /// or nil when the flow carries no audit token to tell: that keeps the
    /// port-pair answer, since a process cannot drop its own token, and the
    /// Mac must never lose its address over a missing one.
    ///
    /// When the flow's local port is not known (0), only a send to a DHCP
    /// server port on the discovery broadcast or multicast address counts:
    /// a client that reads as unbound must still get an address, and those
    /// destinations never leave the local network (link or site scope), so
    /// no app reaches a service on the internet through them.
    public static func isAddressConfiguration(transportProtocol: Int32, localPort: Int,
                                              remotePort: Int, remoteIP: String,
                                              senderIsRoot: Bool?) -> Bool {
        guard transportProtocol == Int32(IPPROTO_UDP) else { return false }
        let pairsUp = (ipv4Ports.contains(localPort) && ipv4Ports.contains(remotePort))
            || (ipv6Ports.contains(localPort) && ipv6Ports.contains(remotePort))
        if pairsUp { return senderIsRoot != false }
        guard localPort == 0 else { return false }
        let address = remoteIP.lowercased()
        return (remotePort == 67 && ipv4ServerDiscovery.contains(address))
            || (remotePort == 547 && ipv6ServerDiscovery.contains(address))
    }
}
