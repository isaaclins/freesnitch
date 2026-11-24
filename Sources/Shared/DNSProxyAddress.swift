import Foundation

/// The addresses the helper's DNS proxy answers on, for the app to tell
/// whether this Mac's DNS settings reach it (#205).
///
/// The proxy binds exactly these two and nothing else, so another loopback
/// address such as 127.0.0.2, or one of the Mac's own network addresses,
/// never reaches it, however close it looks.
public enum DNSProxyAddress {
    public static let ipv4 = "127.0.0.1"
    public static let ipv6 = "::1"

    /// True when a DNS server set to `server` is answered by the proxy.
    public static func reachesProxy(_ server: String) -> Bool {
        server == ipv4 || server == ipv6
    }

    /// The servers in `resolvers` that are one of this Mac's own network
    /// addresses (`own`), loopback aside. Pointing DNS at one of those
    /// reached the proxy before #205 and now goes unanswered unless another
    /// DNS app listens there.
    public static func ownNetworkResolvers(_ resolvers: [String], own: Set<String>) -> [String] {
        resolvers.filter { server in
            !isLoopback(server) && own.contains(server)
        }
    }

    static func isLoopback(_ server: String) -> Bool {
        server == ipv6 || server.hasPrefix("127.")
    }
}
