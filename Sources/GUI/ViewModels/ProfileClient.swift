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

    /// Fills the view model with a snapshot the helper would normally supply,
    /// so the Profiles screen can be reviewed in demo mode. Never called
    /// outside FREESNITCH_DEMO; it only writes the published snapshot and
    /// sends nothing anywhere.
    func adoptDemoSnapshot(_ snapshot: ProfileSnapshot) {
        self.snapshot = snapshot
        self.demoMode = true
    }

    private var demoMode = false

    var isAvailable: Bool { transport != nil || demoMode }

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
        guard let transport else {
            errorMessage = "Profiles live in the privileged helper. Approve the helper first, then reopen this window."
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
