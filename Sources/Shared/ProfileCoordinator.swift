import Foundation

/// Owns which profile is active, how a switch becomes visible, and how it is
/// undone.
///
/// Two invariants are structural rather than documented hopes:
///
/// 1. A switch changes only the policy that future flows are judged against.
///    There is no method here that enumerates, inspects, or drops established
///    flows, and none may be added: `handleNewFlow` in the network extension is
///    the only consumer of a policy change.
/// 2. Automatic switching happens only for a binding the user created with
///    `bindCurrentNetwork(toProfile:)`. An unknown gateway leaves the active
///    profile exactly where it is.
public final class ProfileCoordinator: @unchecked Sendable {
    public enum SwitchReason: String, Sendable {
        case user
        case network
        case undo
    }

    public struct SwitchResult: Sendable {
        public let reason: SwitchReason
        public let notice: ProfileSwitchNotice
        public let policy: ProfilePolicy
        public let previousProfile: String?

        public init(reason: SwitchReason,
                    notice: ProfileSwitchNotice,
                    policy: ProfilePolicy,
                    previousProfile: String?) {
            self.reason = reason
            self.notice = notice
            self.policy = policy
            self.previousProfile = previousProfile
        }
    }

    private let store: RuleStore
    private let watcher: GatewayMACWatcher
    private let lock = NSLock()
    private var undoTarget: String?
    private var switchHandler: ((SwitchResult) -> Void)?
    private var lastObservedGatewayMAC: String?

    public init(store: RuleStore, watcher: GatewayMACWatcher = GatewayMACWatcher()) {
        self.store = store
        self.watcher = watcher
    }

    /// Wiring point for the helper and the GUI: called after the active policy
    /// has already been committed, so a receiver only has to publish it.
    public var onSwitch: ((SwitchResult) -> Void)? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return switchHandler
        }
        set {
            lock.lock()
            switchHandler = newValue
            lock.unlock()
        }
    }

    public var activeProfileName: String {
        store.activeProfileName()
    }

    public func profiles() -> [Profile] {
        store.allProfiles()
    }

    public func currentPolicy() throws -> ProfilePolicy {
        try store.activeProfilePolicy()
    }

    /// The gateway MAC last read by the watcher, or a fresh read when nothing
    /// has been observed yet. Never a Wi-Fi name and never a location.
    public var currentGatewayMAC: String? {
        lock.lock()
        let cached = lastObservedGatewayMAC
        lock.unlock()
        if let cached { return cached }
        return refreshGatewayMAC()
    }

    /// Forces a read of the default gateway. Used by anything that acts on the
    /// network the user is on right now, so a stale cached reading can never
    /// be bound to a profile.
    @discardableResult
    public func refreshGatewayMAC() -> String? {
        let current = watcher.refresh()
        lock.lock()
        lastObservedGatewayMAC = current
        lock.unlock()
        return current
    }

    public var canUndo: Bool {
        lock.lock()
        defer { lock.unlock() }
        return undoTarget != nil
    }

    // MARK: - switching

    @discardableResult
    public func activate(profileName: String, reason: SwitchReason = .user) throws -> SwitchResult {
        let previousName = store.activeProfileName()
        let previousPolicy = try? store.profilePolicy(named: previousName)
        let activated = try store.setActiveProfile(name: profileName)
        let policy = try store.profilePolicy(named: activated.name)

        let changed = previousName != activated.name
        lock.lock()
        switch reason {
        case .undo:
            undoTarget = nil
        case .user, .network:
            undoTarget = changed ? previousName : undoTarget
        }
        let canUndoNow = undoTarget != nil
        let handler = switchHandler
        lock.unlock()

        let notice = ProfileSwitchNotice(
            activeProfile: activated.name,
            activeRuleCount: policy.activeRuleCount,
            pausedProfile: changed ? previousName : nil,
            // Always rules are never paused by a switch. Only the previous
            // profile's own layer stops applying.
            pausedRuleCount: changed ? (previousPolicy?.activeProfileRuleCount ?? 0) : 0,
            canUndo: canUndoNow
        )
        let result = SwitchResult(reason: reason,
                                  notice: notice,
                                  policy: policy,
                                  previousProfile: changed ? previousName : nil)
        handler?(result)
        return result
    }

    /// Reverses the most recent switch. Returns nil when there is nothing to
    /// undo, which is also what the notice reports through `canUndo`.
    @discardableResult
    public func undoLastSwitch() throws -> SwitchResult? {
        lock.lock()
        let target = undoTarget
        undoTarget = nil
        lock.unlock()
        guard let target else { return nil }
        return try activate(profileName: target, reason: .undo)
    }

    // MARK: - networks

    /// Explicit "use this here". This is the only way a binding is ever
    /// created; observing a network never writes one.
    @discardableResult
    public func bindCurrentNetwork(toProfile profileName: String) throws -> ProfileNetworkBinding {
        guard let mac = refreshGatewayMAC() else {
            throw ProfileValidationError.invalidGatewayMAC("no default gateway MAC is currently visible")
        }
        return try store.bindGatewayMAC(mac, toProfile: profileName)
    }

    @discardableResult
    public func bindNetwork(gatewayMAC: String, toProfile profileName: String) throws -> ProfileNetworkBinding {
        try store.bindGatewayMAC(gatewayMAC, toProfile: profileName)
    }

    public func unbindNetwork(gatewayMAC: String) throws {
        try store.unbindGatewayMAC(gatewayMAC)
    }

    public func bindings() -> [ProfileNetworkBinding] {
        store.allNetworkBindings()
    }

    public func binding(forCurrentNetwork: Bool = true) -> ProfileNetworkBinding? {
        guard forCurrentNetwork, let mac = currentGatewayMAC else { return nil }
        return store.networkBinding(forGatewayMAC: mac)
    }

    /// Starts observing the default gateway. Nothing switches unless the
    /// observed gateway MAC already has a user-created binding.
    public func startWatchingNetworks(every interval: TimeInterval = 5) {
        watcher.onChange = { [weak self] mac in
            guard let self else { return }
            _ = try? self.handleGatewayMACChange(mac)
        }
        watcher.start(every: interval)
    }

    public func stopWatchingNetworks() {
        watcher.stop()
        watcher.onChange = nil
    }

    /// Applies a network change. Returns nil when the gateway is unknown, so a
    /// new network can never silently impose a profile the user never chose.
    @discardableResult
    public func handleGatewayMACChange(_ rawMAC: String?) throws -> SwitchResult? {
        let mac = rawMAC.flatMap(GatewayMAC.normalized)
        lock.lock()
        lastObservedGatewayMAC = mac
        lock.unlock()
        guard let mac, let binding = store.networkBinding(forGatewayMAC: mac) else { return nil }
        guard binding.profileName != store.activeProfileName() else { return nil }
        return try activate(profileName: binding.profileName, reason: .network)
    }
}
