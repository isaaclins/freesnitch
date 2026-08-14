import Foundation
import Combine

/// Delivers one encoded `ProfileCommand` to the privileged helper and returns
/// the encoded `ProfileSnapshot` or a message. Injected once at launch so this
/// view model never owns an XPC connection of its own.
typealias ProfileCommandTransport = @Sendable (Data, @escaping (Data, String?) -> Void) -> Void

/// The GUI's view of profile state.
///
/// Deliberately independent of AppState: profile state is owned by the helper
/// and is refreshed as a whole, never merged from cached fragments.
@MainActor
final class ProfileClient: ObservableObject {
    static let shared = ProfileClient()

    @Published private(set) var snapshot: ProfileSnapshot?
    @Published private(set) var errorMessage: String?
    /// The most recent switch, shown until the user dismisses or undoes it.
    @Published var visibleNotice: ProfileSwitchNotice?
    @Published private(set) var isBusy = false

    private var transport: ProfileCommandTransport?

    init() {}

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

    /// Applies a command to the seeded snapshot. Demo only: it touches nothing
    /// outside this object and never reaches the helper, pf, or the network.
    private func applyInDemo(_ command: ProfileCommand) {
        guard var snapshot else { return }
        errorMessage = nil
        switch command {
        case .snapshot, .refreshBlocklists, .undoSwitch:
            return
        case .createProfile(let name, let mode, let icon):
            let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return }
            guard !snapshot.profiles.contains(where: { $0.name.caseInsensitiveCompare(trimmed) == .orderedSame }) else {
                errorMessage = "A profile named \(trimmed) already exists."
                return
            }
            snapshot.profiles.append(Profile(name: trimmed, mode: mode, icon: icon))
        case .updateProfile(let profile):
            guard let index = snapshot.profiles.firstIndex(where: { $0.id == profile.id }) else { return }
            let previousName = snapshot.profiles[index].name
            snapshot.profiles[index] = profile
            if snapshot.activeProfile == previousName { snapshot.activeProfile = profile.name }
        case .deleteProfile(let name):
            guard name != Profile.defaultName else {
                errorMessage = "The default profile cannot be deleted."
                return
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
        case .updateBlocklistURL(let id, let url):
            guard let index = snapshot.blocklists.firstIndex(where: { $0.id == id }) else { return }
            snapshot.blocklists[index].url = url
        case .removeBlocklist(let id):
            snapshot.blocklists.removeAll { $0.id == id }
            snapshot.selectedBlocklistIDs.remove(id)
        case .bindCurrentNetwork, .unbindNetwork:
            return
        }
        for index in snapshot.profiles.indices {
            snapshot.profiles[index].isActive = snapshot.profiles[index].name == snapshot.activeProfile
        }
        self.snapshot = snapshot
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

    func setBlocklist(_ id: UUID, enabled: Bool, profileName: String) {
        send(.setBlocklistEnabled(blocklistID: id, profileName: profileName, enabled: enabled))
    }

    func addCustomBlocklist(name: String, url: String, profileName: String?) {
        send(.addCustomBlocklist(name: name, url: url, profileName: profileName))
    }

    func removeBlocklist(_ id: UUID) {
        send(.removeBlocklist(blocklistID: id))
    }

    func refreshBlocklists() {
        send(.refreshBlocklists)
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

    private func send(_ command: ProfileCommand) {
        // Demo mode reports itself available, so every profile control is
        // enabled. Sending to a helper that is not there made those controls
        // inert: the sheet accepted a name and nothing happened (#98). In demo
        // mode the seeded snapshot is the helper, and nothing leaves this
        // object.
        if demoMode {
            applyInDemo(command)
            return
        }
        guard let transport else {
            errorMessage = unavailableReason
            return
        }
        let data: Data
        do {
            data = try ProfileTransportBoundary.encodeRequest(command)
        } catch {
            errorMessage = error.localizedDescription
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
                    self.errorMessage = message
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
                } catch {
                    self.errorMessage = error.localizedDescription
                }
            }
        }
    }
}
