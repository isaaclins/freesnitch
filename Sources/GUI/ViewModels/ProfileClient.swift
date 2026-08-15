import Foundation
import Combine

/// Delivers one encoded `ProfileCommand` to the privileged helper and returns
/// the encoded `ProfileSnapshot` or a message. Injected once at launch so this
/// view model never owns an XPC connection of its own.
typealias ProfileCommandTransport = @Sendable (Data, @escaping (Data, String?) -> Void) -> Void

/// Downloads every blocklist and answers when the download is finished.
///
/// It is separate from `ProfileCommandTransport` because the profile command of
/// the same name returns as soon as the refresh is scheduled, so it can report
/// that the request was accepted and never what came of it (#135).
typealias BlocklistRefreshTransport = @MainActor (@escaping @MainActor (Bool, String?) -> Void) -> Void

/// The GUI's view of profile state.
///
/// Deliberately independent of AppState: profile state is owned by the helper
/// and is refreshed as a whole, never merged from cached fragments.
@MainActor
final class ProfileClient: ObservableObject {
    static let shared = ProfileClient()

    @Published private(set) var snapshot: ProfileSnapshot?
    @Published private(set) var errorMessage: String?
    /// What the shared "refresh every list" is doing. Every control that can
    /// start one reads this, so a download that takes minutes is visible and
    /// its outcome is reported once, in the same words everywhere (#135).
    @Published private(set) var blocklistRefresh: BlocklistRefresh = .idle
    /// The most recent switch, shown until the user dismisses or undoes it.
    @Published var visibleNotice: ProfileSwitchNotice?
    @Published private(set) var isBusy = false

    enum BlocklistRefresh: Equatable {
        case idle
        case running
        case finished(String)
        case failed(String)
    }

    private var transport: ProfileCommandTransport?
    private var refreshTransport: BlocklistRefreshTransport?

    init() {}

    /// Handed over with the helper connection, like the command transport.
    func setBlocklistRefreshTransport(_ transport: BlocklistRefreshTransport?) {
        refreshTransport = transport
    }

    /// Call site for the app: hand over the helper transport once it exists.
    func setTransport(_ transport: ProfileCommandTransport?) {
        self.transport = transport
        guard transport != nil else { return }
        refresh()
    }

    /// Whether the helper is actually answering. A transport exists from the
    /// moment the app tries to connect, so on its own it says nothing about
    /// reachability: every profile control was enabled while the helper was
    /// unreachable, and clicking one produced a line of red text instead of an
    /// action (#98).
    func setHelperReachable(_ reachable: Bool) {
        guard helperReachable != reachable else { return }
        helperReachable = reachable
    }

    @Published private(set) var helperReachable = false

    /// Fills the view model with a snapshot the helper would normally supply,
    /// so the Profiles screen can be reviewed in demo mode. Never called
    /// outside FREESNITCH_DEMO; it only writes the published snapshot and
    /// sends nothing anywhere.
    func adoptDemoSnapshot(_ snapshot: ProfileSnapshot) {
        self.snapshot = snapshot
        self.demoMode = true
        // The transport is handed over before the demo snapshot is seeded, so
        // the first refresh has already failed against a helper that is not
        // there. That message is not about anything the demo can do (#98).
        self.errorMessage = nil
    }

    private var demoMode = false

    /// Applies a command to the seeded snapshot and answers the way the helper
    /// would: nil when it took, a message when it refused. Demo only: it
    /// touches nothing outside this object and never reaches the helper, pf, or
    /// the network.
    private func applyInDemo(_ command: ProfileCommand) -> String? {
        guard var snapshot else { return nil }
        errorMessage = nil
        switch command {
        case .snapshot, .refreshBlocklists, .undoSwitch:
            return nil
        case .createProfile(let name, let mode, let icon):
            let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return nil }
            guard !snapshot.profiles.contains(where: { $0.name.caseInsensitiveCompare(trimmed) == .orderedSame }) else {
                return "A profile named \(trimmed) already exists."
            }
            snapshot.profiles.append(Profile(name: trimmed, mode: mode, icon: icon))
        case .updateProfile(let profile):
            guard let index = snapshot.profiles.firstIndex(where: { $0.id == profile.id }) else { return nil }
            let previousName = snapshot.profiles[index].name
            snapshot.profiles[index] = profile
            if snapshot.activeProfile == previousName { snapshot.activeProfile = profile.name }
        case .deleteProfile(let name):
            guard name != Profile.defaultName else {
                return "The default profile cannot be deleted."
            }
            snapshot.profiles.removeAll { $0.name == name }
            if snapshot.activeProfile == name { snapshot.activeProfile = Profile.defaultName }
        case .setActiveProfile(let name):
            snapshot.activeProfile = name
        case .setBlocklistEnabled(let id, let profileName, let enabled):
            if let index = snapshot.blocklists.firstIndex(where: { $0.id == id }) {
                snapshot.blocklists[index].enabled = enabled
            }
            if enabled { snapshot.selectedBlocklistIDs.insert(id) } else { snapshot.selectedBlocklistIDs.remove(id) }
            if let index = snapshot.profiles.firstIndex(where: { $0.name == profileName }) {
                if enabled {
                    snapshot.profiles[index].blocklistIDs.insert(id)
                } else {
                    snapshot.profiles[index].blocklistIDs.remove(id)
                }
            }
        case .addCustomBlocklist(let name, let url, _):
            snapshot.blocklists.append(BlocklistInfo(name: name, url: url, enabled: true, lastUpdated: Date(), entryCount: 0))
        case .addLocalBlocklist(let name, let domains, _):
            snapshot.blocklists.append(BlocklistInfo(name: name, url: "", enabled: true,
                                                     lastUpdated: Date(), entryCount: domains.count))
        case .renameBlocklist(let id, let name):
            guard let index = snapshot.blocklists.firstIndex(where: { $0.id == id }) else { return nil }
            snapshot.blocklists[index].name = name
        case .addBlocklistEntries(let id, let domains):
            guard let index = snapshot.blocklists.firstIndex(where: { $0.id == id }) else { return nil }
            snapshot.blocklists[index].entryCount += domains.count
        case .removeBlocklistEntries(let id, let domains):
            guard let index = snapshot.blocklists.firstIndex(where: { $0.id == id }) else { return nil }
            snapshot.blocklists[index].entryCount = max(0, snapshot.blocklists[index].entryCount - domains.count)
        case .resetBlocklistEntries:
            return nil
        case .updateBlocklistURL(let id, let url):
            guard let index = snapshot.blocklists.firstIndex(where: { $0.id == id }) else { return nil }
            snapshot.blocklists[index].url = url
        case .removeBlocklist(let id):
            snapshot.blocklists.removeAll { $0.id == id }
            snapshot.selectedBlocklistIDs.remove(id)
        case .bindCurrentNetwork, .unbindNetwork:
            return nil
        }
        for index in snapshot.profiles.indices {
            snapshot.profiles[index].isActive = snapshot.profiles[index].name == snapshot.activeProfile
        }
        self.snapshot = snapshot
        return nil
    }

    var isAvailable: Bool { (transport != nil && helperReachable) || demoMode }

    /// Why the profile controls are disabled, for the one place that says so.
    var unavailableReason: String {
        transport == nil
            ? "Profiles live in the privileged helper. Approve the helper first, then reopen this window."
            : "FreeSnitch cannot reach the privileged helper, so profiles cannot be changed right now."
    }

    var profiles: [Profile] { snapshot?.profiles ?? [] }

    var activeProfileName: String { snapshot?.activeProfile ?? Profile.defaultName }

    var activeProfile: Profile? {
        profiles.first { $0.name == activeProfileName }
    }

    /// The label the menu bar shows. It is never empty, because a strict
    /// profile applying invisibly is the failure this feature exists to avoid.
    var menuBarLabel: String {
        isAvailable ? activeProfileName : "\(Profile.defaultName) (helper offline)"
    }

    var canUndo: Bool { snapshot?.canUndo ?? false }

    func refresh() {
        send(.snapshot)
    }

    func activate(profileName: String) {
        send(.setActiveProfile(name: profileName))
    }

    func undoSwitch() {
        send(.undoSwitch)
    }

    func createProfile(name: String, mode: AppMode, icon: String) {
        send(.createProfile(name: name, mode: mode, icon: icon))
    }

    func updateProfile(_ profile: Profile) {
        send(.updateProfile(profile))
    }

    func deleteProfile(name: String) {
        send(.deleteProfile(name: name))
    }

    /// One meaning: this list applies while `profileName` is the active
    /// profile. The helper recomputes the global enabled flag from exactly this
    /// selection, so nothing else in the GUI may write that flag (#135).
    func setBlocklist(_ id: UUID,
                      enabled: Bool,
                      profileName: String,
                      completion: ((Bool, String?) -> Void)? = nil) {
        send(.setBlocklistEnabled(blocklistID: id, profileName: profileName, enabled: enabled),
             completion: completion)
    }

    func addCustomBlocklist(name: String,
                            url: String,
                            profileName: String?,
                            completion: ((Bool, String?) -> Void)? = nil) {
        send(.addCustomBlocklist(name: name, url: url, profileName: profileName), completion: completion)
    }

    /// A list with no source, whose entries the user typed (#97).
    func addLocalBlocklist(name: String,
                           domains: [String],
                           profileName: String?,
                           completion: ((Bool, String?) -> Void)? = nil) {
        send(.addLocalBlocklist(name: name, domains: domains, profileName: profileName), completion: completion)
    }

    func renameBlocklist(_ id: UUID, name: String, completion: ((Bool, String?) -> Void)? = nil) {
        send(.renameBlocklist(blocklistID: id, name: name), completion: completion)
    }

    func updateBlocklistURL(_ id: UUID, url: String, completion: ((Bool, String?) -> Void)? = nil) {
        send(.updateBlocklistURL(blocklistID: id, url: url), completion: completion)
    }

    func addBlocklistEntries(_ id: UUID, domains: [String], completion: ((Bool, String?) -> Void)? = nil) {
        send(.addBlocklistEntries(blocklistID: id, domains: domains), completion: completion)
    }

    func removeBlocklistEntries(_ id: UUID, domains: [String]) {
        send(.removeBlocklistEntries(blocklistID: id, domains: domains))
    }

    func resetBlocklistEntries(_ id: UUID, completion: ((Bool, String?) -> Void)? = nil) {
        send(.resetBlocklistEntries(blocklistID: id), completion: completion)
    }

    func removeBlocklist(_ id: UUID) {
        send(.removeBlocklist(blocklistID: id))
    }

    /// The one path every "refresh the lists" control in the app takes, so they
    /// cannot report different things about the same download.
    func refreshBlocklists() {
        guard blocklistRefresh != .running else { return }
        // Demo mode has no helper and nothing to download: the seeded lists are
        // already everything they are going to be.
        guard !demoMode else {
            blocklistRefresh = .finished(refreshSummary())
            return
        }
        guard let refreshTransport else {
            blocklistRefresh = .failed(unavailableReason)
            return
        }
        blocklistRefresh = .running
        refreshTransport { [weak self] ok, message in
            guard let self else { return }
            guard ok else {
                self.blocklistRefresh = .failed(message ?? "The helper did not say why the download failed.")
                return
            }
            // The counts come from the helper's own snapshot afterwards, never
            // from what the GUI hoped the download did.
            self.send(.snapshot) { [weak self] read, readMessage in
                guard let self else { return }
                self.blocklistRefresh = read
                    ? .finished(self.refreshSummary())
                    : .failed(readMessage ?? "The lists were downloaded, but their new sizes could not be read.")
            }
        }
    }

    private func refreshSummary() -> String {
        let lists = snapshot?.blocklists ?? []
        let names = lists.reduce(0) { $0 + $1.entryCount }
        return "Updated \(lists.count) \(lists.count == 1 ? "list" : "lists"), \(names.formatted()) names in total."
    }

    /// Explicit "use this here". Nothing else in this class creates a binding.
    func bindCurrentNetwork(toProfile profileName: String) {
        send(.bindCurrentNetwork(profileName: profileName))
    }

    func unbindNetwork(gatewayMAC: String) {
        send(.unbindNetwork(gatewayMAC: gatewayMAC))
    }

    func dismissNotice() {
        visibleNotice = nil
    }

    private func send(_ command: ProfileCommand, completion: ((Bool, String?) -> Void)? = nil) {
        // Demo mode reports itself available, so every profile control is
        // enabled. Sending to a helper that is not there made those controls
        // inert: the sheet accepted a name and nothing happened (#98). In demo
        // mode the seeded snapshot is the helper, and nothing leaves this
        // object.
        if demoMode {
            let refusal = applyInDemo(command)
            report(refusal, to: completion)
            return
        }
        guard let transport else {
            report(unavailableReason, to: completion)
            return
        }
        let data: Data
        do {
            data = try ProfileTransportBoundary.encodeRequest(command)
        } catch {
            report(error.localizedDescription, to: completion)
            return
        }
        isBusy = true
        transport(data) { [weak self] payload, message in
            Task { @MainActor in
                guard let self else { return }
                // A request sent before the demo snapshot was seeded can still
                // fail against a helper that is not there. Its error is not
                // about anything the demo can do, and it landed as a red line
                // across the top of the Profiles page (#98).
                guard !self.demoMode else { return }
                self.isBusy = false
                if let message, !message.isEmpty {
                    self.report(message, to: completion)
                    return
                }
                do {
                    let snapshot = try ProfileTransportBoundary.decodeResponse(payload)
                    self.errorMessage = nil
                    let previousNotice = self.snapshot?.notice
                    self.snapshot = snapshot
                    if let notice = snapshot.notice, notice != previousNotice {
                        self.visibleNotice = notice
                    }
                    if snapshot.notice == nil { self.visibleNotice = nil }
                    completion?(true, nil)
                } catch {
                    self.report(error.localizedDescription, to: completion)
                }
            }
        }
    }

    /// A caller that passes a completion shows the failure where the action was
    /// taken. Publishing it as well would put the same sentence on the Profiles
    /// page, which is the only view that renders `errorMessage`, while the
    /// sheet the user is looking at said nothing (#135).
    private func report(_ failure: String?, to completion: ((Bool, String?) -> Void)?) {
        guard let completion else {
            if let failure { errorMessage = failure }
            return
        }
        completion(failure == nil, failure)
    }
}
