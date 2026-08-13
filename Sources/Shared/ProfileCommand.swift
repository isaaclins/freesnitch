import Foundation

/// One bounded request/response pair for everything the GUI needs to do with
/// profiles. A single XPC entry point keeps the privileged surface small and
/// keeps the helper's protocol change to one optional method.
public enum ProfileCommand: Codable, Sendable {
    case snapshot
    case createProfile(name: String, mode: AppMode, icon: String)
    case updateProfile(Profile)
    case deleteProfile(name: String)
    case setActiveProfile(name: String)
    case undoSwitch
    case setBlocklistEnabled(blocklistID: UUID, profileName: String, enabled: Bool)
    case addCustomBlocklist(name: String, url: String, profileName: String?)
    case updateBlocklistURL(blocklistID: UUID, url: String)
    case removeBlocklist(blocklistID: UUID)
    case refreshBlocklists
    case bindCurrentNetwork(profileName: String)
    case unbindNetwork(gatewayMAC: String)
}

/// A complete view of profile state. Every command answers with the same
/// shape, so the GUI never has to reconcile partial updates.
public struct ProfileSnapshot: Codable, Sendable {
    public var profiles: [Profile]
    public var activeProfile: String
    public var alwaysRuleCount: Int
    public var activeProfileRuleCount: Int
    public var blocklists: [BlocklistInfo]
    public var selectedBlocklistIDs: Set<UUID>
    public var bindings: [ProfileNetworkBinding]
    public var currentGatewayMAC: String?
    public var notice: ProfileSwitchNotice?
    public var canUndo: Bool

    public init(profiles: [Profile],
                activeProfile: String,
                alwaysRuleCount: Int,
                activeProfileRuleCount: Int,
                blocklists: [BlocklistInfo],
                selectedBlocklistIDs: Set<UUID>,
                bindings: [ProfileNetworkBinding],
                currentGatewayMAC: String?,
                notice: ProfileSwitchNotice?,
                canUndo: Bool) {
        self.profiles = profiles
        self.activeProfile = activeProfile
        self.alwaysRuleCount = alwaysRuleCount
        self.activeProfileRuleCount = activeProfileRuleCount
        self.blocklists = blocklists
        self.selectedBlocklistIDs = selectedBlocklistIDs
        self.bindings = bindings
        self.currentGatewayMAC = currentGatewayMAC
        self.notice = notice
        self.canUndo = canUndo
    }

    /// True when the current network is already bound to the active profile,
    /// which is what the "use this here" control reflects.
    public var currentNetworkIsBoundToActiveProfile: Bool {
        guard let mac = currentGatewayMAC else { return false }
        return bindings.contains { $0.gatewayMAC == mac && $0.profileName == activeProfile }
    }
}

public enum ProfileTransportBoundary {
    public static let maximumRequestBytes = 64 * 1024
    public static let maximumResponseBytes = 1024 * 1024

    public enum BoundsError: Error, LocalizedError, Equatable, Sendable {
        case requestTooLarge(bytes: Int, maximum: Int)
        case responseTooLarge(bytes: Int, maximum: Int)

        public var errorDescription: String? {
            switch self {
            case .requestTooLarge(let bytes, let maximum):
                return "The profile request is \(bytes) bytes, above the \(maximum)-byte limit."
            case .responseTooLarge(let bytes, let maximum):
                return "The profile response is \(bytes) bytes, above the \(maximum)-byte limit."
            }
        }
    }

    public static func validateRequestBytes(_ data: Data) throws {
        guard data.count <= maximumRequestBytes else {
            throw BoundsError.requestTooLarge(bytes: data.count, maximum: maximumRequestBytes)
        }
    }

    public static func validateResponseBytes(_ data: Data) throws {
        guard data.count <= maximumResponseBytes else {
            throw BoundsError.responseTooLarge(bytes: data.count, maximum: maximumResponseBytes)
        }
    }

    public static func encodeRequest(_ command: ProfileCommand) throws -> Data {
        let data = try FreeSnitchWireCodec.encode(command)
        try validateRequestBytes(data)
        return data
    }

    public static func decodeRequest(_ data: Data) throws -> ProfileCommand {
        try validateRequestBytes(data)
        return try FreeSnitchWireCodec.decode(ProfileCommand.self, from: data)
    }

    public static func encodeResponse(_ snapshot: ProfileSnapshot) throws -> Data {
        let data = try FreeSnitchWireCodec.encode(snapshot)
        try validateResponseBytes(data)
        return data
    }

    public static func decodeResponse(_ data: Data) throws -> ProfileSnapshot {
        try validateResponseBytes(data)
        return try FreeSnitchWireCodec.decode(ProfileSnapshot.self, from: data)
    }
}

/// Executes profile commands against the store. The helper owns one instance;
/// the test harness builds one directly, so the shipping logic is what is
/// tested rather than a copy.
public final class ProfileCommandService: @unchecked Sendable {
    private let store: RuleStore
    private let coordinator: ProfileCoordinator
    private let lock = NSLock()
    private var lastNotice: ProfileSwitchNotice?

    /// Called after a change that alters which deny lists apply. The helper
    /// wires this to its existing blocklist refresh.
    public var onBlocklistsChanged: (() -> Void)?
    /// Called after the active policy changed, so the helper can republish the
    /// authoritative snapshot. It affects new flows only; nothing here touches
    /// an established connection.
    public var onPolicyChanged: ((ProfilePolicy) -> Void)?

    public init(store: RuleStore, coordinator: ProfileCoordinator) {
        self.store = store
        self.coordinator = coordinator
        coordinator.onSwitch = { [weak self] result in
            guard let self else { return }
            self.lock.lock()
            self.lastNotice = result.notice
            self.lock.unlock()
            self.onBlocklistsChanged?()
            self.onPolicyChanged?(result.policy)
        }
    }

    public func handle(requestData: Data) -> (Data, String?) {
        do {
            let command = try ProfileTransportBoundary.decodeRequest(requestData)
            let snapshot = try execute(command)
            return (try ProfileTransportBoundary.encodeResponse(snapshot), nil)
        } catch {
            return (Data(), error.localizedDescription)
        }
    }

    @discardableResult
    public func execute(_ command: ProfileCommand) throws -> ProfileSnapshot {
        switch command {
        case .snapshot:
            break
        case .createProfile(let name, let mode, let icon):
            // A new profile inherits every Always rule immediately because
            // layering is computed, not copied. Nothing is duplicated here.
            _ = try store.createProfile(name: name, mode: mode, icon: icon)
        case .updateProfile(let profile):
            _ = try store.updateProfile(profile)
            notePolicyChange()
        case .deleteProfile(let name):
            _ = try store.deleteProfile(name: name)
            notePolicyChange()
        case .setActiveProfile(let name):
            _ = try coordinator.activate(profileName: name, reason: .user)
        case .undoSwitch:
            _ = try coordinator.undoLastSwitch()
        case .setBlocklistEnabled(let id, let profileName, let enabled):
            try store.setBlocklistEnabled(id: id, profileName: profileName, enabled: enabled)
            onBlocklistsChanged?()
        case .addCustomBlocklist(let name, let url, let profileName):
            _ = try store.addCustomBlocklist(name: name, url: url, profileName: profileName)
            onBlocklistsChanged?()
        case .updateBlocklistURL(let id, let url):
            _ = try store.updateBlocklistURL(id: id, url: url)
            onBlocklistsChanged?()
        case .removeBlocklist(let id):
            try store.deleteBlocklist(id: id)
            onBlocklistsChanged?()
        case .refreshBlocklists:
            onBlocklistsChanged?()
        case .bindCurrentNetwork(let profileName):
            _ = try coordinator.bindCurrentNetwork(toProfile: profileName)
        case .unbindNetwork(let gatewayMAC):
            try coordinator.unbindNetwork(gatewayMAC: gatewayMAC)
        }
        return try snapshot()
    }

    public func snapshot() throws -> ProfileSnapshot {
        let policy = try store.activeProfilePolicy()
        lock.lock()
        let notice = lastNotice
        lock.unlock()
        return ProfileSnapshot(
            profiles: store.allProfiles(),
            activeProfile: policy.profile.name,
            alwaysRuleCount: policy.alwaysRules.filter(\.enabled).count,
            activeProfileRuleCount: policy.activeProfileRuleCount,
            blocklists: try store.allBlocklists(forProfile: policy.profile.name),
            selectedBlocklistIDs: policy.selectedBlocklistIDs,
            bindings: store.allNetworkBindings(),
            currentGatewayMAC: coordinator.currentGatewayMAC,
            notice: notice,
            canUndo: coordinator.canUndo
        )
    }

    private func notePolicyChange() {
        guard let policy = try? store.activeProfilePolicy() else { return }
        onBlocklistsChanged?()
        onPolicyChanged?(policy)
    }
}
