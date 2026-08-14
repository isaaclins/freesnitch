import SwiftUI

/// The Profiles tab: a place, how strict you are there, which deny lists apply,
/// which networks select it, and the rules that only apply there.
struct ProfilesSettingsView: View {
    @ObservedObject var profileClient: ProfileClient
    /// Which profile the detail pane is showing. Not the same thing as the
    /// active profile: reading a profile must not switch to it.
    @State private var selectedProfileName: String?
    @State private var showingCreateSheet = false
    @State private var newProfileName = ""
    @State private var newProfileMode: AppMode = .alert
    @State private var newBlocklistName = ""
    @State private var newBlocklistURL = ""
    @State private var blocklistError: String?

    /// Text fields stop at a readable measure instead of spanning the window
    /// (#88). A name is a few words; a URL is longer but still not a window.
    private static let nameFieldWidth: CGFloat = 200
    private static let urlFieldWidth: CGFloat = 340

    var body: some View {
        VStack(spacing: 0) {
            notices
            HStack(spacing: 0) {
                profileList
                    .frame(width: 220)
                Divider()
                detailPane
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .sheet(isPresented: $showingCreateSheet) { createSheet }
    }

    // MARK: Notices

    @ViewBuilder
    private var notices: some View {
        if let notice = profileClient.visibleNotice {
            ProfileSwitchBanner(notice: notice,
                                canUndo: profileClient.canUndo,
                                onUndo: { profileClient.undoSwitch() },
                                onDismiss: { profileClient.dismissNotice() })
                .padding(10)
        }
        if let message = profileClient.errorMessage {
            noticeText(message, tint: .red)
        }
        if !profileClient.isAvailable {
            // Says why every control on this page is disabled, in the same
            // words the controls themselves carry (#98).
            noticeText(profileClient.unavailableReason
                       + " The list fills in on its own once it connects.",
                       tint: .secondary)
        }
    }

    private func noticeText(_ text: String, tint: Color) -> some View {
        Text(text)
            .font(.caption)
            .foregroundStyle(tint)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
    }

    // MARK: The list

    /// The list of profiles, with the create and delete controls under it,
    /// which is where a Mac app keeps them.
    private var profileList: some View {
        HeaderedPane {
            PaneHeader("Profiles", count: profileClient.profiles.count)
        } content: {
            VStack(spacing: 0) {
                List(selection: $selectedProfileName) {
                    ForEach(profileClient.profiles) { profile in
                        HStack(spacing: 6) {
                            Image(systemName: profile.icon)
                                .foregroundStyle(Color.accentColor)
                            Text(profile.name).lineLimit(1)
                            Spacer(minLength: 4)
                            if profile.isActive {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundStyle(Color.green)
                                    .help("The active profile")
                            }
                        }
                        .tag(profile.name)
                    }
                }
                .listStyle(.inset)
                .contextMenu(forSelectionType: String.self) { names in
                    if let name = names.first, let profile = profile(named: name) {
                        Button("Activate") { profileClient.activate(profileName: name) }
                            .disabled(!profileClient.isAvailable || profile.isActive)
                        if name != Profile.defaultName {
                            Divider()
                            Button("Delete Profile", role: .destructive) {
                                profileClient.deleteProfile(name: name)
                            }
                            .disabled(!profileClient.isAvailable)
                        }
                    }
                }
                Divider()
                listFooter
            }
        }
    }

    private var listFooter: some View {
        HStack(spacing: 4) {
            Button {
                newProfileName = ""
                newProfileMode = .alert
                showingCreateSheet = true
            } label: {
                Image(systemName: "plus")
            }
            .buttonStyle(.borderless)
            .disabled(!profileClient.isAvailable)
            .help("Create a profile")
            Button {
                guard let name = selectedProfileName, name != Profile.defaultName else { return }
                profileClient.deleteProfile(name: name)
                selectedProfileName = Profile.defaultName
            } label: {
                Image(systemName: "minus")
            }
            .buttonStyle(.borderless)
            .disabled(!profileClient.isAvailable
                      || selectedProfileName == nil
                      || selectedProfileName == Profile.defaultName)
            .help(selectedProfileName == Profile.defaultName
                  ? "The default profile cannot be deleted."
                  : "Delete the selected profile")
            Spacer()
            Button("Refresh") { profileClient.refresh() }
                .buttonStyle(.borderless)
                .disabled(!profileClient.isAvailable)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
    }

    // MARK: The detail

    @ViewBuilder
    private var detailPane: some View {
        if let profile = selectedProfile {
            HeaderedPane {
                PaneHeader(profile.name) {
                    if profile.isActive {
                        PSChip("Active", color: PSTheme.accentGreen)
                    } else {
                        Button("Activate") { profileClient.activate(profileName: profile.name) }
                            .disabled(!profileClient.isAvailable)
                    }
                }
            } content: {
                profileDetail(profile)
            }
        } else {
            HeaderedPane {
                PaneHeader("Profile")
            } content: {
                VStack(spacing: 6) {
                    Spacer()
                    Image(systemName: "mappin.and.ellipse")
                        .font(.system(size: 32))
                        .foregroundStyle(.secondary)
                    Text("Select a profile to see what it applies.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
    }

    /// Mode, blocklists and network binding, all on screen at once, with the
    /// long list in the middle taking the slack (#88).
    private func profileDetail(_ profile: Profile) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            modeRow(profile)
            Divider()
            blocklistSection(profile)
            Divider()
            // The blocklist list above is the only part that should give way
            // when the window is short; the network binding is three lines and
            // must not be the thing that gets clipped off the bottom.
            networkSection(profile)
                .fixedSize(horizontal: false, vertical: true)
                .layoutPriority(1)
        }
    }

    private func modeRow(_ profile: Profile) -> some View {
        HStack(spacing: 10) {
            Picker("Strictness", selection: Binding(
                get: { profile.mode },
                set: { newValue in
                    var updated = profile
                    updated.mode = newValue
                    profileClient.updateProfile(updated)
                }
            )) {
                ForEach(AppMode.allCases, id: \.self) { mode in
                    Label(mode.title, systemImage: mode.symbol).tag(mode)
                }
            }
            .frame(maxWidth: 280)
            .disabled(!profileClient.isAvailable)
            Spacer(minLength: 8)
            Text(summary(profile))
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
    }

    private func summary(_ profile: Profile) -> String {
        let always = profileClient.snapshot?.alwaysRuleCount ?? 0
        return "Applies the \(always) Always rules plus this profile's own rules."
    }

    private func blocklistSection(_ profile: Profile) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            sectionHeader("Blocklists") {
                Button("Refresh Lists") { profileClient.refreshBlocklists() }
                    .buttonStyle(.borderless)
                    .disabled(!profileClient.isAvailable)
            }
            List {
                ForEach(profileClient.snapshot?.blocklists ?? []) { blocklist in
                    HStack(spacing: 8) {
                        Toggle("", isOn: Binding(
                            get: { profile.blocklistIDs.contains(blocklist.id) },
                            set: { profileClient.setBlocklist(blocklist.id, enabled: $0, profileName: profile.name) }
                        ))
                        .toggleStyle(.checkbox)
                        .labelsHidden()
                        .disabled(!profileClient.isAvailable)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(blocklist.name).lineLimit(1)
                            Text(blocklist.url)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                        }
                        Spacer(minLength: 6)
                        Text("\(blocklist.entryCount)")
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                        Button(role: .destructive) {
                            profileClient.removeBlocklist(blocklist.id)
                        } label: {
                            Image(systemName: "trash")
                        }
                        .buttonStyle(.borderless)
                        .disabled(!profileClient.isAvailable)
                    }
                }
            }
            .listStyle(.inset)
            .frame(maxHeight: .infinity)
            HStack(spacing: 8) {
                TextField("List name", text: $newBlocklistName)
                    .frame(maxWidth: Self.nameFieldWidth)
                TextField("https://example.org/hosts.txt", text: $newBlocklistURL)
                    .frame(maxWidth: Self.urlFieldWidth)
                Button("Add") { addCustomBlocklist(to: profile) }
                    .disabled(!profileClient.isAvailable)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 12)
            .padding(.bottom, 6)
            if let blocklistError {
                captionText(blocklistError, tint: .red)
            } else {
                captionText("Deny lists stack and filter DNS names only. Custom lists must use HTTPS.", tint: .secondary)
            }
        }
    }

    private func networkSection(_ profile: Profile) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            sectionHeader("Networks") {
                Button("Use \(profile.name) here") {
                    profileClient.bindCurrentNetwork(toProfile: profile.name)
                }
                .buttonStyle(.borderless)
                .disabled(!profileClient.isAvailable || profileClient.snapshot?.currentGatewayMAC == nil)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(gatewayLabel).font(.caption.monospaced()).foregroundStyle(.secondary)
                ForEach(bindings(for: profile)) { binding in
                    HStack(spacing: 6) {
                        Image(systemName: "point.3.connected.trianglepath.dotted")
                            .foregroundStyle(Color.accentColor)
                        Text(binding.gatewayMAC).font(.caption.monospaced())
                        Spacer(minLength: 6)
                        Button("Remove") { profileClient.unbindNetwork(gatewayMAC: binding.gatewayMAC) }
                            .buttonStyle(.borderless)
                            .disabled(!profileClient.isAvailable)
                    }
                }
                if bindings(for: profile).isEmpty {
                    Text("No network selects this profile yet.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 12)
            .padding(.bottom, 8)
            captionText("FreeSnitch recognises a network by the MAC address of its gateway. It never reads the Wi-Fi name and never asks for Location Services.",
                        tint: .secondary)
        }
    }

    private func sectionHeader<Trailing: View>(_ title: String,
                                               @ViewBuilder trailing: () -> Trailing) -> some View {
        HStack(spacing: 8) {
            Text(title).font(.subheadline.weight(.semibold))
            Spacer(minLength: 8)
            trailing()
        }
        .padding(.horizontal, 12)
        .padding(.top, 10)
        .padding(.bottom, 4)
    }

    private func captionText(_ text: String, tint: Color) -> some View {
        Text(text)
            .font(.caption)
            .foregroundStyle(tint)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 12)
            .padding(.bottom, 8)
    }

    // MARK: Creating

    /// Creating a profile is an action behind the plus button, not a form that
    /// sits on the page forever (#88).
    private var createSheet: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("New Profile").font(.headline)
            Text("A new profile is never empty: it inherits every Always rule immediately, without copying them.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Form {
                TextField("Name", text: $newProfileName)
                    .frame(maxWidth: Self.nameFieldWidth)
                Picker("Strictness", selection: $newProfileMode) {
                    ForEach(AppMode.allCases, id: \.self) { mode in
                        Label(mode.title, systemImage: mode.symbol).tag(mode)
                    }
                }
                .frame(maxWidth: 280)
            }
            HStack {
                Spacer()
                Button("Cancel") { showingCreateSheet = false }
                    .keyboardShortcut(.cancelAction)
                Button("Create") {
                    let name = newProfileName.trimmingCharacters(in: .whitespacesAndNewlines)
                    profileClient.createProfile(name: name, mode: newProfileMode, icon: "mappin.and.ellipse")
                    selectedProfileName = name
                    newProfileName = ""
                    showingCreateSheet = false
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!profileClient.isAvailable
                          || newProfileName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(20)
        .frame(width: 420)
    }

    private func addCustomBlocklist(to profile: Profile) {
        do {
            _ = try BlocklistURLValidator.validate(newBlocklistURL)
            blocklistError = nil
        } catch {
            blocklistError = error.localizedDescription
            return
        }
        profileClient.addCustomBlocklist(name: newBlocklistName,
                                         url: newBlocklistURL,
                                         profileName: profile.name)
        newBlocklistName = ""
        newBlocklistURL = ""
    }

    // MARK: Lookups

    private var selectedProfile: Profile? {
        if let selectedProfileName, let match = profile(named: selectedProfileName) {
            return match
        }
        return profileClient.profiles.first { $0.isActive } ?? profileClient.profiles.first
    }

    private func profile(named name: String) -> Profile? {
        profileClient.profiles.first { $0.name == name }
    }

    private func bindings(for profile: Profile) -> [ProfileNetworkBinding] {
        (profileClient.snapshot?.bindings ?? []).filter { $0.profileName == profile.name }
    }

    private var gatewayLabel: String {
        guard let mac = profileClient.snapshot?.currentGatewayMAC else {
            return "No gateway MAC visible on this network"
        }
        return "Current gateway \(mac)"
    }
}

/// The visible half of a switch: what is active, what stopped applying, and a
/// way back. Always rules are never paused, so they are never counted here.
struct ProfileSwitchBanner: View {
    let notice: ProfileSwitchNotice
    let canUndo: Bool
    let onUndo: () -> Void
    let onDismiss: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "arrow.triangle.2.circlepath")
                .foregroundColor(PSTheme.accentBlue)
            VStack(alignment: .leading, spacing: 2) {
                Text(notice.activeProfile).font(.body.weight(.semibold))
                Text(notice.message).font(.caption).foregroundColor(.secondary)
                Text("Connections that are already open are not affected.")
                    .font(.caption2).foregroundColor(.secondary)
            }
            Spacer()
            if canUndo {
                Button("Undo", action: onUndo)
            }
            Button(action: onDismiss) {
                Image(systemName: "xmark")
            }
            .buttonStyle(.borderless)
        }
        .padding(8)
        .background(PSTheme.bgTertiary)
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

/// The rule editor's Applies to control. New rules default to Always, which is
/// what keeps profiles small and comprehensible.
struct RuleAppliesToPicker: View {
    @Binding var profileName: String
    let activeProfileName: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Picker("Applies to", selection: $profileName) {
                Text("Always").tag(Profile.alwaysName)
                Text("Only in \(activeProfileName)").tag(activeProfileName)
            }
            .pickerStyle(.radioGroup)
            Text(profileName == Profile.alwaysName
                 ? "Applies in every profile. Almost every rule belongs here."
                 : "Applies only while \(activeProfileName) is the active profile.")
                .font(.caption).foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
