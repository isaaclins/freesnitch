import SwiftUI

/// The Profiles tab: a place, how strict you are there, which deny lists apply,
/// which networks select it, and the rules that only apply there.
struct ProfilesSettingsView: View {
    @ObservedObject var profileClient: ProfileClient
    @State private var newProfileName = ""
    @State private var newProfileMode: AppMode = .alert
    @State private var newBlocklistName = ""
    @State private var newBlocklistURL = ""
    @State private var blocklistError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            if let notice = profileClient.visibleNotice {
                ProfileSwitchBanner(notice: notice,
                                    canUndo: profileClient.canUndo,
                                    onUndo: { profileClient.undoSwitch() },
                                    onDismiss: { profileClient.dismissNotice() })
            }
            if let message = profileClient.errorMessage {
                Text(message).font(.caption).foregroundColor(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if !profileClient.isAvailable {
                Text("Profiles come from the privileged helper. Approve the helper in the General tab; this list fills in on its own once it connects.")
                    .font(.caption).foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(profileClient.profiles) { profile in
                        profileRow(profile)
                    }
                    Divider()
                    createProfileSection
                    Divider()
                    blocklistSection
                    Divider()
                    networkSection
                }
                .padding(.trailing, 4)
            }
        }
    }

    private var header: some View {
        HStack {
            Text("Profiles").font(.headline)
            Spacer()
            Text("Active: \(profileClient.activeProfileName)")
                .font(.caption).foregroundColor(.secondary)
            Button("Refresh") { profileClient.refresh() }
                .disabled(!profileClient.isAvailable)
        }
    }

    private func profileRow(_ profile: Profile) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Image(systemName: profile.icon)
                Text(profile.name).font(.body.weight(.medium))
                Spacer()
                if profile.isActive {
                    PSChip("Active", color: PSTheme.accentGreen)
                } else {
                    Button("Activate") { profileClient.activate(profileName: profile.name) }
                        .disabled(!profileClient.isAvailable)
                }
            }
            HStack {
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
                .frame(maxWidth: 260)
                .disabled(!profileClient.isAvailable)
                Spacer()
                if profile.name != Profile.defaultName {
                    Button(role: .destructive) {
                        profileClient.deleteProfile(name: profile.name)
                    } label: {
                        Text("Delete")
                    }
                    .disabled(!profileClient.isAvailable)
                }
            }
            Text(profileDescription(profile))
                .font(.caption).foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, 4)
    }

    private func profileDescription(_ profile: Profile) -> String {
        let always = profileClient.snapshot?.alwaysRuleCount ?? 0
        let boundNetworks = (profileClient.snapshot?.bindings ?? [])
            .filter { $0.profileName == profile.name }
            .count
        let networks = boundNetworks == 1 ? "1 network" : "\(boundNetworks) networks"
        return "Applies the \(always) Always rules plus this profile's own rules. \(profile.blocklistIDs.count) blocklists selected. \(networks) bound."
    }

    private var createProfileSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("New profile").font(.subheadline.weight(.semibold))
            Text("A new profile is never empty: it inherits every Always rule immediately, without copying them.")
                .font(.caption).foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                TextField("Name", text: $newProfileName)
                Picker("", selection: $newProfileMode) {
                    ForEach(AppMode.allCases, id: \.self) { mode in
                        Label(mode.title, systemImage: mode.symbol).tag(mode)
                    }
                }
                .labelsHidden()
                .frame(width: 140)
                Button("Create") {
                    profileClient.createProfile(name: newProfileName, mode: newProfileMode, icon: "mappin.and.ellipse")
                    newProfileName = ""
                }
                .disabled(!profileClient.isAvailable || newProfileName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
    }

    private var blocklistSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Blocklists in \(profileClient.activeProfileName)").font(.subheadline.weight(.semibold))
                Spacer()
                Button("Refresh Lists") { profileClient.refreshBlocklists() }
                    .disabled(!profileClient.isAvailable)
            }
            Text("Deny lists stack: any number can apply at once, and order never matters. They filter DNS names only.")
                .font(.caption).foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(profileClient.snapshot?.blocklists ?? []) { blocklist in
                HStack {
                    Toggle("", isOn: Binding(
                        get: { blocklist.enabled },
                        set: { profileClient.setBlocklist(blocklist.id, enabled: $0, profileName: profileClient.activeProfileName) }
                    ))
                    .labelsHidden()
                    VStack(alignment: .leading) {
                        Text(blocklist.name).font(.body)
                        Text(blocklist.url).font(.caption2).foregroundColor(.secondary).lineLimit(1)
                    }
                    Spacer()
                    Text("\(blocklist.entryCount)").font(.caption.monospacedDigit()).foregroundColor(.secondary)
                    Button(role: .destructive) { profileClient.removeBlocklist(blocklist.id) } label: {
                        Image(systemName: "trash")
                    }
                    .buttonStyle(.borderless)
                    .disabled(!profileClient.isAvailable)
                }
            }
            HStack {
                TextField("List name", text: $newBlocklistName)
                TextField("https://example.org/hosts.txt", text: $newBlocklistURL)
                Button("Add") { addCustomBlocklist() }
                    .disabled(!profileClient.isAvailable)
            }
            if let blocklistError {
                Text(blocklistError).font(.caption).foregroundColor(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text("Custom lists must use HTTPS.")
                .font(.caption).foregroundColor(.secondary)
        }
    }

    private func addCustomBlocklist() {
        do {
            _ = try BlocklistURLValidator.validate(newBlocklistURL)
            blocklistError = nil
        } catch {
            blocklistError = error.localizedDescription
            return
        }
        profileClient.addCustomBlocklist(name: newBlocklistName,
                                         url: newBlocklistURL,
                                         profileName: profileClient.activeProfileName)
        newBlocklistName = ""
        newBlocklistURL = ""
    }

    private var networkSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Networks").font(.subheadline.weight(.semibold))
            Text("FreeSnitch recognises a network by the MAC address of its gateway. It never reads the Wi-Fi name and never asks for Location Services. A network only ever selects a profile after you bind it here.")
                .font(.caption).foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Text(gatewayLabel).font(.caption.monospaced())
                Spacer()
                Button("Use \(profileClient.activeProfileName) here") {
                    profileClient.bindCurrentNetwork(toProfile: profileClient.activeProfileName)
                }
                .disabled(!profileClient.isAvailable || profileClient.snapshot?.currentGatewayMAC == nil)
            }
            ForEach(profileClient.snapshot?.bindings ?? []) { binding in
                HStack {
                    Image(systemName: "point.3.connected.trianglepath.dotted")
                    Text(binding.gatewayMAC).font(.caption.monospaced())
                    Text("selects").font(.caption).foregroundColor(.secondary)
                    Text(binding.profileName).font(.caption.weight(.medium))
                    Spacer()
                    Button("Remove") { profileClient.unbindNetwork(gatewayMAC: binding.gatewayMAC) }
                        .buttonStyle(.borderless)
                }
            }
        }
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
