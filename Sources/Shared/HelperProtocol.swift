import Foundation

@objc public protocol HelperProtocol {
    /// The build of the running helper process, not the build on disk.
    func getVersion(reply: @escaping (String) -> Void)
    /// Restarts the helper with `launchctl kickstart -k` when the running
    /// process is older than the installed bundle, so an in-place update stops
    /// leaving a stale root daemon behind. Optional because a helper from
    /// before #36 does not have it; callers must fall back to telling the user
    /// the privileged command instead of unregistering anything.
    @objc optional func restartForUpdate(reply: @escaping (Bool, String?) -> Void)
    func getStatus(reply: @escaping (Data) -> Void)
    func setMode(rawValue: String, reply: @escaping (Bool, String?) -> Void)

    func reloadRules(rulesJSON: Data, reply: @escaping (Bool, String?) -> Void)
    func addRule(ruleJSON: Data, reply: @escaping (Bool, String?) -> Void)
    func removeRule(idString: String, reply: @escaping (Bool, String?) -> Void)
    /// Optional so an already-running older helper can answer other requests;
    /// clients must refuse policy sync when this getter is absent.
    @objc optional func getAuthoritativeSnapshot(reply: @escaping (Data) -> Void)
    /// Atomic replacement for the GUI import path. Older helpers do not have a
    /// safe replacement operation, so the GUI reports that rather than doing a
    /// sequence of stale-prone removals.
    @objc optional func replaceRules(rulesJSON: Data, reply: @escaping (Bool, String?) -> Void)
    func listRules(profile: String, reply: @escaping (Data) -> Void)

    func startMonitoring(reply: @escaping (Bool, String?) -> Void)
    /// Turns the enforcing parts on/off: the pf anchor and the DNS proxy.
    /// Off by default. FreeSnitch observes until the user opts in.
    func setEnforcementEnabled(_ enabled: Bool, reply: @escaping (Bool, String?) -> Void)
    func stopMonitoring(reply: @escaping (Bool, String?) -> Void)
    func currentConnections(reply: @escaping (Data) -> Void)
    func currentTrafficSample(reply: @escaping (Data) -> Void)
    func currentProcessUsage(reply: @escaping (Data) -> Void)

    func enableBlocklist(idString: String, enabled: Bool, reply: @escaping (Bool, String?) -> Void)
    func listBlocklists(reply: @escaping (Data) -> Void)
    func refreshBlocklists(reply: @escaping (Bool, String?) -> Void)
    @objc optional func getDoHUpstream(reply: @escaping (String) -> Void)
    func setDoHUpstream(url: String, reply: @escaping (Bool, String?) -> Void)

    func installPF(reply: @escaping (Bool, String?) -> Void)
    func uninstallPF(reply: @escaping (Bool, String?) -> Void)
    func flushAll(reply: @escaping (Bool, String?) -> Void)

    func recentBlocked(limit: Int, reply: @escaping (Data) -> Void)
    func recentDenied(limit: Int, reply: @escaping (Data) -> Void)

    func ingestObservationBatch(observationBatch: Data, reply: @escaping (Bool, String?) -> Void)
    func getInsightsRecordingEnabled(reply: @escaping (Bool) -> Void)
    func setInsightsRecordingEnabled(_ enabled: Bool, reply: @escaping (Bool, String?) -> Void)
    func purgeInsights(reply: @escaping (Bool, String?) -> Void)
}

@objc public protocol HelperClientProtocol {
    func notifyConnection(connectionJSON: Data)
    func notifyTraffic(sampleJSON: Data)
    func notifyProcessUsage(usageJSON: Data)
    func notifyAlert(connectionJSON: Data, reply: @escaping (Bool, Bool) -> Void)
    func notifyLog(level: String, message: String)
}

public enum HelperBridge {
    public static let machServiceName = AppConstants.xpcMachServiceName

    public static func remoteInterface() -> NSXPCInterface {
        let iface = NSXPCInterface(with: HelperProtocol.self)
        return iface
    }
    public static func exportedInterface() -> NSXPCInterface {
        let iface = NSXPCInterface(with: HelperClientProtocol.self)
        return iface
    }
}
