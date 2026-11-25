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
/// 4.1, RFC 8415 section 7.2). Binding a port below 1024 takes root, so an
/// ordinary app talking to some service on one of these port numbers comes
/// from an ephemeral local port and keeps its rules.
public enum DHCPTraffic {
    public static let ipv4Ports: Set<Int> = [67, 68]
    public static let ipv6Ports: Set<Int> = [546, 547]

    /// `transportProtocol` is the IP protocol number (IPPROTO_UDP is 17).
    /// A flow whose local port is not known (0) is not address configuration:
    /// a DHCP client binds its port before it sends anything.
    public static func isAddressConfiguration(transportProtocol: Int32, localPort: Int, remotePort: Int) -> Bool {
        guard transportProtocol == Int32(IPPROTO_UDP) else { return false }
        return (ipv4Ports.contains(localPort) && ipv4Ports.contains(remotePort))
            || (ipv6Ports.contains(localPort) && ipv6Ports.contains(remotePort))
    }
}
