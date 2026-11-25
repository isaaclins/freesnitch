#!/usr/bin/env bash
# The extension's DHCP exemption covers address configuration, not every
# flow that happens to use a DHCP port number (issue #293).
#
# An app's deny used to be skipped for any connection whose destination port
# was 67, 68, 546 or 547, over TCP or UDP, to any address. Now only UDP
# between the DHCP ports on both ends, from an app running as root (the
# system's DHCP client, configd), is exempt: any process may bind a low port
# since macOS 10.14, so the ports alone prove nothing. A DHCP client keeps
# working while an app reaching some service on one of those port numbers
# follows its rules. Compiled from the real shared source the extension uses.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-dhcp.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

SDK="$(xcrun --show-sdk-path)"
TARGET="arm64-apple-macos13.0"

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

@main
struct Verify {
    static var failures = 0
    static func check(_ condition: Bool, _ label: String) {
        if condition { print("dhcp exemption harness: PASS: \(label)") }
        else { failures += 1; print("dhcp exemption harness: FAIL: \(label)") }
    }

    static let udp = Int32(IPPROTO_UDP)
    static let tcp = Int32(IPPROTO_TCP)

    static func exempt(_ proto: Int32, local: Int, remote: Int, ip: String = "203.0.113.9", root: Bool? = true) -> Bool {
        DHCPTraffic.isAddressConfiguration(transportProtocol: proto, localPort: local, remotePort: remote,
                                           remoteIP: ip, senderIsRoot: root)
    }

    static func main() {
        // Address configuration stays exempt, client and server side, v4 and v6.
        check(exempt(udp, local: 68, remote: 67), "a DHCP client's request to a server is exempt")
        check(exempt(udp, local: 67, remote: 68), "a DHCP server's reply to a client is exempt")
        check(exempt(udp, local: 67, remote: 67), "a DHCP relay agent talking to a server is exempt")
        check(exempt(udp, local: 546, remote: 547), "a DHCPv6 client's request is exempt")
        check(exempt(udp, local: 547, remote: 546), "a DHCPv6 server's reply is exempt")
        check(exempt(udp, local: 547, remote: 547), "a DHCPv6 relay agent is exempt")

        // The report: an ordinary app on a DHCP port number keeps its rules.
        for port in [67, 68, 546, 547] {
            check(!exempt(tcp, local: 51234, remote: port), "TCP to port \(port) from an ephemeral port is not exempt")
            check(!exempt(udp, local: 51234, remote: port), "UDP to port \(port) from an ephemeral port is not exempt")
            check(!exempt(udp, local: 0, remote: port), "UDP to port \(port) with no known local port is not exempt")
            check(!exempt(tcp, local: port == 67 || port == 68 ? 68 : 546, remote: port),
                  "TCP between DHCP ports to \(port) is not address configuration")
        }
        // An app that binds a DHCP port itself (allowed for any user since
        // macOS 10.14) is not the system's DHCP client and keeps its rules.
        for (local, remote) in [(67, 67), (68, 67), (67, 68), (546, 547), (547, 547)] {
            check(!exempt(udp, local: local, remote: remote, root: false),
                  "a non-root app sending UDP \(local) -> \(remote) to an internet host is not exempt")
        }
        // No audit token to tell who sent it: the port pair still counts, so a
        // missing token never takes the Mac's address away.
        check(exempt(udp, local: 68, remote: 67, root: nil), "a DHCP pair with no audit token stays exempt")
        // Mixing the v4 and v6 port families is neither protocol.
        check(!exempt(udp, local: 68, remote: 547), "a DHCP client port to a DHCPv6 server port is not exempt")
        check(!exempt(udp, local: 546, remote: 67), "a DHCPv6 client port to a DHCP server port is not exempt")
        // A client whose port reads as unknown still gets an address: its
        // discovery goes to the local-link broadcast or DHCPv6 multicast.
        check(exempt(udp, local: 0, remote: 67, ip: "255.255.255.255"), "an unbound DHCP discover to the broadcast address is exempt")
        check(exempt(udp, local: 0, remote: 547, ip: "ff02::1:2"), "an unbound DHCPv6 solicit to ff02::1:2 is exempt")
        check(exempt(udp, local: 0, remote: 547, ip: "FF05::1:3"), "an unbound DHCPv6 message to ff05::1:3 is exempt, in any case")
        check(!exempt(tcp, local: 0, remote: 67, ip: "255.255.255.255"), "TCP to the broadcast address is not exempt")
        check(!exempt(udp, local: 0, remote: 68, ip: "255.255.255.255"), "unbound UDP to the client port on broadcast is not exempt")
        check(!exempt(udp, local: 51234, remote: 67, ip: "255.255.255.255"), "an ephemeral port to broadcast port 67 is not exempt")
        check(!exempt(udp, local: 0, remote: 547, ip: "2001:db8::1"), "unbound UDP to a unicast DHCPv6 port is not exempt")
        // Ordinary traffic was never exempt and still isn't.
        check(!exempt(udp, local: 68, remote: 443), "a DHCP client port to port 443 is not exempt")

        if failures > 0 { print("dhcp exemption harness: \(failures) failure(s)"); exit(1) }
        print("dhcp exemption harness: all checks passed")
    }
}
SWIFT

xcrun swiftc -O -sdk "$SDK" -target "$TARGET" -parse-as-library \
  -o "$TMP/run" \
  "$ROOT"/Sources/Shared/*.swift \
  "$TMP/verify.swift"
"$TMP/run"
