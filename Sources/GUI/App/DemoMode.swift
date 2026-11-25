import Foundation

/// `FREESNITCH_DEMO=1`: the app shows sample data for screenshots and review.
///
/// A demo can run on a Mac where FreeSnitch is really installed, under the same
/// bundle id. It must leave that install alone: no reads or saves of the real
/// content filter configuration (#388), no system extension requests, no helper
/// registration, repair or removal, no login item change and no files removed
/// (#389). Every place that does one of those checks this first.
enum DemoMode {
    static let isOn = ProcessInfo.processInfo.environment["FREESNITCH_DEMO"] == "1"

    /// `FREESNITCH_DEMO_VPN=1`: a sample Tailscale connection that handles
    /// DNS, for reviewing what the app says about VPNs (#424). Without it a
    /// demo shows no VPN, so the reviewer's own tunnel stays out of pictures.
    static let showsVPN = isOn && ProcessInfo.processInfo.environment["FREESNITCH_DEMO_VPN"] == "1"
    static let sampleVPN = ActiveVPN(name: "Tailscale", interface: "utun4",
                                     dnsServers: ["100.100.100.100", "fd7a:115c:a1e0::53"],
                                     matchDomains: [], handlesAllLookups: true)

    /// `FREESNITCH_DEMO_DNS=192.168.1.20,9.9.9.9`: the DNS servers a demo
    /// reports for this Mac, for reviewing what Settings says about them
    /// (#205). Without it a demo shows 192.168.1.1.
    static var sampleResolvers: [String]? {
        guard isOn, let list = ProcessInfo.processInfo.environment["FREESNITCH_DEMO_DNS"] else { return nil }
        let servers = list.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        return servers.isEmpty ? nil : servers
    }

    /// `FREESNITCH_DEMO_REFUSE_LIST_EDITS=1`: taking a name off a list is
    /// refused the way the helper refuses it once the list holds as many hand
    /// edits as it can keep, for reviewing what the Rules page says (#221).
    static var refusesListEdits: Bool {
        isOn && ProcessInfo.processInfo.environment["FREESNITCH_DEMO_REFUSE_LIST_EDITS"] == "1"
    }

    /// `FREESNITCH_DEMO_SETTINGS_PANE=dns` opens Settings on that pane.
    static var settingsPane: String? {
        isOn ? ProcessInfo.processInfo.environment["FREESNITCH_DEMO_SETTINGS_PANE"] : nil
    }
}
