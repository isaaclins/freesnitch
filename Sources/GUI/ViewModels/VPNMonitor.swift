import Foundation
import SystemConfiguration

/// The VPNs connected right now and the resolvers macOS uses, kept current
/// from the system's own change notifications (#424). Settings read both: a
/// VPN that connects while the window is open changes what FreeSnitch's DNS
/// protection covers, so the answer must not wait for the window to be
/// reopened.
@MainActor
final class VPNMonitor: ObservableObject {
    static let shared = VPNMonitor()

    @Published private(set) var vpns: [ActiveVPN] = []
    @Published private(set) var systemResolvers: [String] = []

    private var store: SCDynamicStore?
    private var source: CFRunLoopSource?

    private init() {
        var context = SCDynamicStoreContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(),
                                            retain: nil, release: nil, copyDescription: nil)
        let callback: SCDynamicStoreCallBack = { _, _, info in
            guard let info else { return }
            let monitor = Unmanaged<VPNMonitor>.fromOpaque(info).takeUnretainedValue()
            // The run loop source is on the main run loop, so this already
            // runs on the main thread.
            MainActor.assumeIsolated { monitor.refresh() }
        }
        if let store = SCDynamicStoreCreate(nil, "FreeSnitchVPNMonitor" as CFString, callback, &context) {
            let keys = [VPNStatus.globalDNSKey] as CFArray
            let patterns = VPNStatus.storePatterns as CFArray
            if SCDynamicStoreSetNotificationKeys(store, keys, patterns),
               let source = SCDynamicStoreCreateRunLoopSource(nil, store, 0) {
                CFRunLoopAddSource(CFRunLoopGetMain(), source, .commonModes)
                self.source = source
            }
            self.store = store
        }
        refresh()
    }

    /// Reads the store again. Also called when Settings appears, in case a
    /// notification was missed.
    func refresh() {
        if DemoMode.isOn {
            vpns = DemoMode.showsVPN ? [DemoMode.sampleVPN] : []
            systemResolvers = DemoMode.showsVPN ? DemoMode.sampleVPN.dnsServers : ["192.168.1.1"]
            return
        }
        guard let store else { vpns = []; systemResolvers = []; return }
        var snapshot = (SCDynamicStoreCopyMultiple(store, nil, VPNStatus.storePatterns as CFArray) as? [String: Any]) ?? [:]
        let global = SCDynamicStoreCopyValue(store, VPNStatus.globalDNSKey as CFString) as? [String: Any]
        snapshot[VPNStatus.globalDNSKey] = global
        let found = VPNStatus.connectedVPNs(in: snapshot)
        let resolvers = (global?["ServerAddresses"] as? [String]) ?? []
        if found != vpns { vpns = found }
        if resolvers != systemResolvers { systemResolvers = resolvers }
    }
}
