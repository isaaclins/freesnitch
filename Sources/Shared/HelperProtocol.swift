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
    /// One bounded page of a blocklist's entries, searched in the helper.
    /// Optional so an older helper simply does not answer it rather than
    /// breaking the connection (#79).
    @objc optional func queryBlocklistEntries(request: Data, reply: @escaping (Data, String?) -> Void)
    @objc optional func getDoHUpstream(reply: @escaping (String) -> Void)
    func setDoHUpstream(url: String, reply: @escaping (Bool, String?) -> Void)

    func installPF(reply: @escaping (Bool, String?) -> Void)
    func uninstallPF(reply: @escaping (Bool, String?) -> Void)
    func flushAll(reply: @escaping (Bool, String?) -> Void)

    func recentBlocked(limit: Int, reply: @escaping (Data) -> Void)
    func recentDenied(limit: Int, reply: @escaping (Data) -> Void)

    func ingestObservationBatch(observationBatch: Data, reply: @escaping (Bool, String?) -> Void)
    /// Bounded, paginated Insights read. Optional because a helper from before
    /// this feature does not have it; the GUI reports that rather than
    /// pretending it has no data. The reply carries an encoded `InsightsReport`
    /// and an error string, never both.
    @objc optional func queryInsights(request: Data, reply: @escaping (Data, String?) -> Void)
    /// One bounded profile command in, one whole profile snapshot out. Profile
    /// state is helper-owned, so the GUI never merges cached fragments.
    /// Optional because a helper predating profiles does not answer it, and the
    /// GUI must degrade rather than claim profiles are broken.
    @objc optional func handleProfileCommand(request: Data, reply: @escaping (Data, String?) -> Void)
    /// A bounded, in-memory prepared set for first-contact classification.
    /// The helper refreshes it off the verdict path; unavailable or stale data
    /// is an error so Alert mode keeps asking.
    @objc optional func getInsightsContactSnapshot(reply: @escaping (Data, String?) -> Void)
    /// Registers a connection alert the calling app is already presenting, so
    /// a process that does not own the extension's callback connection can see
    /// and answer it. The reply is deliberately long-lived: it carries the
    /// resolution and arrives when the alert is answered, withdrawn, or
    /// expires. The registry clamps that to less than the flow's own ask
    /// timeout, so this can never hold a flow longer than it already waits.
    /// Only the app may call it; the CLI is refused, exactly as it is refused
    /// notification-client status.
    @objc optional func registerPendingAlert(descriptor: Data, reply: @escaping (Data, String?) -> Void)
    /// The registering app answered the alert itself. This claims the entry so
    /// a later CLI answer is told the app already answered it.
    @objc optional func withdrawPendingAlert(idString: String, reply: @escaping (Bool, String?) -> Void)
    /// The pending alerts that can be answered right now, plus whether an app
    /// is attached at all. An empty list is never returned without a reason.
    @objc optional func listPendingAlerts(reply: @escaping (Data, String?) -> Void)
    /// Answers one pending alert exactly once and, when asked to remember,
    /// stores the rule through the same validated policy path as every other
    /// rule. An id that expired, was already answered, or never existed comes
    /// back with its specific state, not a generic failure.
    @objc optional func answerPendingAlert(request: Data, reply: @escaping (Data, String?) -> Void)

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
