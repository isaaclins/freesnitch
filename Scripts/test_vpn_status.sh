#!/usr/bin/env bash
# Checks how FreeSnitch reads a connected VPN and what it says about it
# (issue #424). The store contents are the ones macOS writes for real VPNs:
# the Tailscale case was copied from `scutil` on a Mac with Tailscale
# connected (MagicDNS on), the others follow the same keys.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-vpn-status.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

@main
struct Verify {
    static var failures = 0

    static func check(_ name: String, _ condition: Bool) {
        print("vpn status harness: \(condition ? "PASS" : "FAIL"): \(name)")
        if !condition { failures += 1 }
    }

    static let wifi = "D62172FE-1024-4EA8-A33E-D8A2AE3C4F37"
    static let tailscale = "1C35F5E4-93CC-4B46-877B-3200FC3107A7"

    /// Wi-Fi with the router as resolver, as every case starts from.
    static func base() -> [String: Any] {
        [
            "State:/Network/Service/\(wifi)/IPv4": ["InterfaceName": "en1", "Addresses": ["192.168.1.20"]],
            "State:/Network/Service/\(wifi)/DNS": ["ServerAddresses": ["192.168.1.1"]],
            "Setup:/Network/Service/\(wifi)": ["UserDefinedName": "Wi-Fi"],
        ]
    }

    static func main() {
        // 1. Nothing connected: Wi-Fi alone is not a VPN.
        var store = base()
        store[VPNStatus.globalDNSKey] = ["ServerAddresses": ["192.168.1.1"], "__CONFIGURATION_ID__": "Default: 0"]
        check("Wi-Fi alone is not a VPN", VPNStatus.connectedVPNs(in: store).isEmpty)
        check("no VPN, nothing to say about rules", VPNStatus.rulesSummary([]) == nil)
        check("no VPN, nothing to say about DNS", VPNStatus.dnsSummary([], routesThroughProxy: false) == nil)

        // 2. Tailscale with MagicDNS, exactly as scutil showed it.
        store[VPNStatus.globalDNSKey] = [
            "ServerAddresses": ["100.100.100.100", "fd7a:115c:a1e0::53"],
            "SearchDomains": ["tailad5fc2.ts.net", "fritz.box"],
            "__CONFIGURATION_ID__": "Supplemental: \(tailscale) 0",
        ]
        store["State:/Network/Service/\(tailscale)/VPN"] = ["Status": 7]
        store["State:/Network/Service/\(tailscale)/IPv4"] = [
            "InterfaceName": "utun4", "Addresses": ["100.90.249.60"], "Router": "100.90.249.60", "ServerAddress": "127.0.0.1",
        ]
        store["State:/Network/Service/\(tailscale)/DNS"] = [
            "ServerAddresses": ["100.100.100.100", "fd7a:115c:a1e0::53"],
            "SearchDomains": ["tailad5fc2.ts.net"],
            "SupplementalMatchDomains": ["", "tailad5fc2.ts.net."],
        ]
        store["Setup:/Network/Service/\(tailscale)"] = ["UserDefinedName": "Tailscale"]
        let ts = VPNStatus.connectedVPNs(in: store)
        check("Tailscale is found", ts.count == 1)
        check("its name and tunnel are read", ts.first?.displayName == "Tailscale" && ts.first?.interface == "utun4")
        check("it handles every lookup", ts.first?.handlesAllLookups == true)
        check("it is recognised as Tailscale", ts.first.map(VPNStatus.isTailscale) == true)
        let tsDNS = VPNStatus.dnsSummary(ts, routesThroughProxy: false) ?? ""
        check("the DNS line says Tailscale is handling DNS and blocking doesn't apply",
              tsDNS.hasPrefix("Tailscale is handling DNS right now (100.100.100.100, fd7a:115c:a1e0::53), so FreeSnitch's DNS blocking"))
        check("the DNS line names the Tailscale switch that gives DNS back", tsDNS.contains("Use Tailscale DNS Settings"))
        check("the rules line says rules still apply in the tunnel",
              VPNStatus.rulesSummary(ts)?.hasPrefix("Tailscale is connected. Your rules still apply") == true)

        // 2b. The same, with a global configuration id that doesn't name the
        //     service: the empty match domain and the servers still say it
        //     takes every lookup.
        var unnamedSource = store
        unnamedSource[VPNStatus.globalDNSKey] = [
            "ServerAddresses": ["100.100.100.100", "fd7a:115c:a1e0::53"], "__CONFIGURATION_ID__": "Default: 0",
        ]
        check("Tailscale owns DNS without the service id in the global entry",
              VPNStatus.dnsOwner(VPNStatus.connectedVPNs(in: unnamedSource))?.displayName == "Tailscale")

        // 3. Tailscale without MagicDNS: connected, but DNS stays with Wi-Fi.
        var noDNS = store
        noDNS.removeValue(forKey: "State:/Network/Service/\(tailscale)/DNS")
        noDNS[VPNStatus.globalDNSKey] = ["ServerAddresses": ["192.168.1.1"], "__CONFIGURATION_ID__": "Default: 0"]
        let plain = VPNStatus.connectedVPNs(in: noDNS)
        check("a VPN without DNS is still listed", plain.count == 1 && plain.first?.handlesAllLookups == false)
        check("and nothing is claimed about DNS", VPNStatus.dnsSummary(plain, routesThroughProxy: false) == nil)

        // 4. Disconnected: macOS removes the address entries, the VPN entry stays.
        var down = store
        down.removeValue(forKey: "State:/Network/Service/\(tailscale)/IPv4")
        down[VPNStatus.globalDNSKey] = ["ServerAddresses": ["192.168.1.1"], "__CONFIGURATION_ID__": "Default: 0"]
        check("a VPN with no tunnel interface is not connected", VPNStatus.connectedVPNs(in: down).isEmpty)

        // 5. Split DNS (a WireGuard work tunnel for one domain), Mac pointed at FreeSnitch.
        var split = base()
        let wg = "A1B2C3D4-0000-4000-8000-00000000AAAA"
        split["State:/Network/Service/\(wg)/VPN"] = ["Status": 1]
        split["State:/Network/Service/\(wg)/IPv6"] = ["InterfaceName": "utun6", "Addresses": ["fd00:1::2"]]
        split["State:/Network/Service/\(wg)/DNS"] = ["ServerAddresses": ["10.8.0.1"], "SupplementalMatchDomains": ["corp.example.", "git.example"]]
        split["Setup:/Network/Service/\(wg)"] = ["UserDefinedName": "Work"]
        split[VPNStatus.globalDNSKey] = ["ServerAddresses": ["127.0.0.1"], "__CONFIGURATION_ID__": "Default: 0"]
        let work = VPNStatus.connectedVPNs(in: split)
        check("an IPv6-only tunnel is found", work.first?.interface == "utun6")
        check("a split-DNS VPN does not take every lookup", work.first?.handlesAllLookups == false)
        check("its match domains are cleaned", work.first?.matchDomains == ["corp.example", "git.example"])
        check("the DNS line names the domains that bypass FreeSnitch",
              VPNStatus.dnsSummary(work, routesThroughProxy: true)
                == "Lookups for corp.example, git.example go to Work, so FreeSnitch's DNS blocking doesn't apply to those names.")
        check("with the Mac not pointed at FreeSnitch a split-DNS VPN owns no DNS, so the general advice stays",
              VPNStatus.dnsOwner(work) == nil)
        check("and the domain sentence is still there to add to it",
              VPNStatus.dnsSummary(work, routesThroughProxy: false)?.hasPrefix("Lookups for corp.example") == true)

        // 5b. A split-DNS VPN that pushes the resolver the user set anyway
        //     doesn't take every lookup, and two split VPNs are both named.
        var sameResolver = split
        sameResolver["State:/Network/Service/\(wg)/DNS"] = ["ServerAddresses": ["1.1.1.1"], "SupplementalMatchDomains": ["corp.example"]]
        sameResolver[VPNStatus.globalDNSKey] = ["ServerAddresses": ["1.1.1.1"], "__CONFIGURATION_ID__": "Default: 0"]
        check("a split-DNS VPN with the user's own resolver does not own DNS",
              VPNStatus.dnsOwner(VPNStatus.connectedVPNs(in: sameResolver)) == nil)
        var twoSplit = split
        let wg2 = "A1B2C3D4-0000-4000-8000-00000000CCCC"
        twoSplit["State:/Network/Service/\(wg2)/VPN"] = ["Status": 1]
        twoSplit["State:/Network/Service/\(wg2)/IPv4"] = ["InterfaceName": "utun8"]
        twoSplit["State:/Network/Service/\(wg2)/DNS"] = ["ServerAddresses": ["10.9.0.1"], "SupplementalMatchDomains": ["lab.example"]]
        twoSplit["Setup:/Network/Service/\(wg2)"] = ["UserDefinedName": "Lab"]
        let twoLine = VPNStatus.dnsSummary(VPNStatus.connectedVPNs(in: twoSplit), routesThroughProxy: true) ?? ""
        check("two split-DNS VPNs are both named", twoLine.contains("go to Work") && twoLine.contains("lab.example go to Lab"))

        // 6. A full-tunnel VPN app with no name set and its own resolver,
        //    while the user had set the Mac's DNS to FreeSnitch: the VPN wins.
        var full = base()
        let app = "B1B2C3D4-0000-4000-8000-00000000BBBB"
        full["State:/Network/Service/\(app)/VPN"] = ["Status": 1]
        full["State:/Network/Service/\(app)/IPv4"] = ["InterfaceName": "utun7", "Addresses": ["10.64.0.5"]]
        full["State:/Network/Service/\(app)/DNS"] = ["ServerAddresses": ["10.64.0.1"]]
        full[VPNStatus.globalDNSKey] = ["ServerAddresses": ["10.64.0.1"], "__CONFIGURATION_ID__": "Default: \(app) 0"]
        let unnamed = VPNStatus.connectedVPNs(in: full)
        check("an unnamed VPN is called A VPN", unnamed.first?.displayName == "A VPN")
        check("a VPN whose service made the global DNS takes every lookup", unnamed.first?.handlesAllLookups == true)
        let unnamedDNS = VPNStatus.dnsSummary(unnamed, routesThroughProxy: false) ?? ""
        check("the generic DNS advice is used for a VPN that isn't Tailscale",
              unnamedDNS.hasPrefix("A VPN is handling DNS right now (10.64.0.1)") && unnamedDNS.contains("in its settings"))
        check("once lookups reach FreeSnitch, a full-DNS VPN gets no DNS warning",
              VPNStatus.dnsSummary(unnamed, routesThroughProxy: true) == nil)

        // 7. Two VPNs.
        var both = store
        both["State:/Network/Service/\(app)/VPN"] = ["Status": 1]
        both["State:/Network/Service/\(app)/IPv4"] = ["InterfaceName": "utun7"]
        check("two connected VPNs are both listed", VPNStatus.connectedVPNs(in: both).count == 2)
        check("and counted in the rules line", VPNStatus.rulesSummary(VPNStatus.connectedVPNs(in: both))?.hasPrefix("2 VPNs are connected.") == true)

        if failures > 0 {
            print("vpn status harness: \(failures) FAILURES")
            exit(1)
        }
        print("vpn status harness: PASS (all checks)")
    }
}
SWIFT

xcrun swiftc -O -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos13.0 -parse-as-library \
  -o "$TMP/run" "$ROOT"/Sources/Shared/*.swift "$TMP/verify.swift"
"$TMP/run"
