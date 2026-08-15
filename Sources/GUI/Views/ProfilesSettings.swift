import SwiftUI

/// The Profiles tab: a place, how strict you are there, which deny lists apply,
/// which networks select it, and the rules that only apply there.
struct ProfilesSettingsView: View {
    @ObservedObject var profileClient: ProfileClient
    /// Only for the rule counts in the summary line, which come from the
    /// helper's rule list rather than from the profile snapshot.
    @EnvironmentObject var state: AppState
    /// Which profile the detail pane is showing. Not the same thing as the
    /// active profile: reading a profile must not switch to it.
    @State private var selectedProfileName: String?
    @State private var showingCreateSheet = false
    @State private var selectedBlocklistID: UUID?
    @State private var editingBlocklist: BlocklistInfo?
    @State private var showingAddBlocklist = false
    @State private var pendingBlocklistRemoval: BlocklistInfo?
    @State private var pendingProfileDeletion: String?
    @State private var newProfileName = ""
    @State private var newProfileMode: AppMode = .alert
    @State private var newProfileIcon = ProfileIcons.all[0]
    /// The profile being renamed, and the name being typed. Profiles could not
    /// be renamed at all, and every one of them carried the same fixed pin
    /// glyph, so the list was a column of identical rows (#137).
    @State private var renamingProfile: Profile?
    @State private var renameText = ""

    /// Text fields stop at a readable measure instead of spanning the window
    /// (#88). A name is a few words; a URL is longer but still not a window.
    private static let nameFieldWidth: CGFloat = 200

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
        .sheet(item: $renamingProfile) { profile in renameSheet(profile) }
        // A profile carries its own rules and its own networks, so deleting it
        // says what goes with it (#115).
        .confirmationDialog("Delete the profile \(pendingProfileDeletion ?? "")?",
                            isPresented: Binding(get: { pendingProfileDeletion != nil },
                                                 set: { if !$0 { pendingProfileDeletion = nil } }),
                            titleVisibility: .visible) {
            Button("Delete Profile", role: .destructive) {
                if let name = pendingProfileDeletion {
                    profileClient.deleteProfile(name: name)
                    if selectedProfileName == name { selectedProfileName = Profile.defaultName }
                }
                pendingProfileDeletion = nil
            }
            Button("Cancel", role: .cancel) { pendingProfileDeletion = nil }
        } message: {
            Text("Its rules, its blocklist choices and the networks that switch to it are deleted with it. The Always rules and the other profiles are untouched.")
        }
        .sheet(item: $editingBlocklist) { blocklist in
            BlocklistEditorView(blocklist: blocklist)
        }
        .sheet(isPresented: $showingAddBlocklist) {
            BlocklistEditorView(blocklist: nil)
        }
        // Removing a list takes it away from every profile at once, so it says
        // so before it happens (#101).
        .confirmationDialog("Remove \(pendingBlocklistRemoval?.name ?? "this blocklist")?",
                            isPresented: Binding(get: { pendingBlocklistRemoval != nil },
                                                 set: { if !$0 { pendingBlocklistRemoval = nil } }),
                            titleVisibility: .visible) {
            Button("Remove Blocklist", role: .destructive) {
                if let blocklist = pendingBlocklistRemoval {
                    profileClient.removeBlocklist(blocklist.id)
                }
                pendingBlocklistRemoval = nil
            }
            Button("Cancel", role: .cancel) { pendingBlocklistRemoval = nil }
        } message: {
            Text("The list is removed from every profile, not just this one. Its entries stop being blocked as soon as enforcement next applies.")
        }
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
                            Button("Rename…") {
                                renameText = profile.name
                                renamingProfile = profile
                            }
                            .disabled(!profileClient.isAvailable)
                        }
                        Menu("Symbol") {
                            ForEach(ProfileIcons.all, id: \.self) { symbol in
                                Button {
                                    var updated = profile
                                    updated.icon = symbol
                                    profileClient.updateProfile(updated)
                                } label: {
                                    Label(ProfileIcons.title(symbol), systemImage: symbol)
                                }
                            }
                        }
                        .disabled(!profileClient.isAvailable)
                        if name != Profile.defaultName {
                            Divider()
                            Button("Delete Profile\u{2026}", role: .destructive) {
                                pendingProfileDeletion = name
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
                    .accessibilityLabel("Create a profile")
            }
            .buttonStyle(.borderless)
            .disabled(!profileClient.isAvailable)
            .help("Create a profile")
            Button {
                guard let name = selectedProfileName, name != Profile.defaultName else { return }
                pendingProfileDeletion = name
            } label: {
                Image(systemName: "minus")
            }
            .accessibilityLabel("Delete the selected profile")
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
            summaryCaption(profile)
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
        }
        .padding(.horizontal, 12)
        .padding(.top, 12)
    }

    /// Under the control it describes, aligned with everything else on the
    /// page. Right-aligned in the same row as the picker, it was the only
    /// right-aligned thing on the page (#104).
    private func summaryCaption(_ profile: Profile) -> some View {
        Text(summary(profile))
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 12)
            .padding(.bottom, 10)
    }

    /// Both counts, for this profile, rather than the same sentence under every
    /// profile with only the shared number in it (#137).
    private func summary(_ profile: Profile) -> String {
        let always = profileClient.snapshot?.alwaysRuleCount ?? 0
        let own = state.rules.filter { $0.profile == profile.name && $0.enabled }.count
        let ownPart = own == 0
            ? "no rules of its own yet"
            : "\(own) rule\(own == 1 ? "" : "s") of its own"
        return "Applies the \(always) Always rule\(always == 1 ? "" : "s") and \(ownPart)."
    }

    private func blocklistSection(_ profile: Profile) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            sectionHeader("Blocklists") {
                // Bordered, like the Networks header, so the two section
                // headers on this page do not use two different button styles.
                Button("Refresh Lists") { profileClient.refreshBlocklists() }
                    .disabled(!profileClient.isAvailable
                              || profileClient.blocklistRefresh == .running)
            }
            // Selection, so the list can carry a context menu at all: a button
            // placed in a row never receives the click here, which is what the
            // per-row trash was (#101).
            List(selection: $selectedBlocklistID) {
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
                            Text(blocklist.url.isEmpty ? "Typed by you" : blocklist.url)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                        }
                        Spacer(minLength: 6)
                        // A list added from a URL has nothing in it until the
                        // next refresh, and a bare 0 never said whether that
                        // was an empty list or an undownloaded one (#135).
                        Text(blocklist.countLabel)
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                    .tag(blocklist.id)
                }
            }
            .listStyle(.inset)
            .frame(maxHeight: .infinity)
            .contextMenu(forSelectionType: UUID.self) { ids in
                if let id = ids.first, let blocklist = blocklistNamed(id) {
                    Button("Edit\u{2026}") { editingBlocklist = blocklist }
                        .disabled(!profileClient.isAvailable)
                    Button("Refresh Lists") { profileClient.refreshBlocklists() }
                        .disabled(!profileClient.isAvailable
                                  || profileClient.blocklistRefresh == .running)
                    Divider()
                    Button("Remove\u{2026}", role: .destructive) { pendingBlocklistRemoval = blocklist }
                        .disabled(!profileClient.isAvailable)
                }
            }
            // The list scrolls under this row, so it needs its own edge and
            // its own background or a half scrolled row bleeds through it.
            Divider()
            HStack(spacing: 8) {
                // One way to add a list, shared with the Rules sidebar. Two
                // different forms for the same thing, one of them a bare pair
                // of text fields, was two answers to one question (#101).
                Button {
                    editingBlocklist = nil
                    showingAddBlocklist = true
                } label: {
                    Label("Add custom blocklist", systemImage: "plus")
                        .font(.callout)
                }
                .buttonStyle(.borderless)
                .disabled(!profileClient.isAvailable)
                .help("Add a list of your own, from a URL or by typing its entries.")
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 12)
            .padding(.top, 6)
            .padding(.bottom, 6)
            .background(.background)
            BlocklistRefreshStatus(state: profileClient.blocklistRefresh)
                .padding(.horizontal, 12)
                .padding(.bottom, 4)
            captionText("Deny lists stack and filter DNS names only.", tint: .secondary)
        }
    }

    private func networkSection(_ profile: Profile) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            sectionHeader("Networks") {
                // Bordered, not borderless: these do something, and borderless
                // text in a header reads as a link (#104).
                Button("Use \(profile.name) here") {
                    profileClient.bindCurrentNetwork(toProfile: profile.name)
                }
                .controlSize(.small)
                .disabled(!profileClient.isAvailable || profileClient.snapshot?.currentGatewayMAC == nil)
                .help(profileClient.snapshot?.currentGatewayMAC == nil
                      ? "FreeSnitch cannot see this network's gateway yet."
                      : "Switch to \(profile.name) automatically on this network.")
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
                            .controlSize(.small)
                            .disabled(!profileClient.isAvailable)
                            .help("Stop selecting this profile on that network.")
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
                Picker("Symbol", selection: $newProfileIcon) {
                    ForEach(ProfileIcons.all, id: \.self) { symbol in
                        Label(ProfileIcons.title(symbol), systemImage: symbol).tag(symbol)
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
                    profileClient.createProfile(name: name, mode: newProfileMode, icon: newProfileIcon)
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

    /// Renaming carries the profile's rules, its blocklist choices and its
    /// network bindings with it: the store does that in one transaction. The
    /// default profile cannot be renamed, which is why the menu item is not
    /// offered for it.
    private func renameSheet(_ profile: Profile) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Rename \(profile.name)").font(.title3.weight(.semibold))
            Text("Its rules, blocklist choices and network bindings move with the name.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            TextField("Name", text: $renameText)
                .frame(maxWidth: Self.nameFieldWidth)
            HStack {
                Spacer()
                Button("Cancel") { renamingProfile = nil }
                    .keyboardShortcut(.cancelAction)
                Button("Rename") {
                    var updated = profile
                    updated.name = renameText.trimmingCharacters(in: .whitespacesAndNewlines)
                    profileClient.updateProfile(updated)
                    if selectedProfileName == profile.name { selectedProfileName = updated.name }
                    renamingProfile = nil
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!profileClient.isAvailable
                          || renameText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                          || renameText.trimmingCharacters(in: .whitespacesAndNewlines) == profile.name)
            }
        }
        .padding(20)
        .frame(width: 380)
    }

    private func blocklistNamed(_ id: UUID) -> BlocklistInfo? {
        profileClient.snapshot?.blocklists.first { $0.id == id }
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
                    .accessibilityLabel("Dismiss")
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
///
/// It offers every profile the helper knows, not just the one that happens to
/// be active: with two choices, a rule for a third profile could be neither
/// written nor moved anywhere in the app (#134).
struct RuleAppliesToPicker: View {
    @Binding var profileName: String
    let profiles: [Profile]
    let activeProfileName: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Picker("Applies to", selection: $profileName) {
                Text("Always").tag(Profile.alwaysName)
                ForEach(options, id: \.self) { name in
                    Text(name == activeProfileName ? "Only in \(name), which is active" : "Only in \(name)")
                        .tag(name)
                }
            }
            .pickerStyle(.radioGroup)
            Text(caption)
                .font(.caption).foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    /// The active profile is always offered, even before the helper has
    /// answered with the profile list, so this control is never a single
    /// choice.
    private var options: [String] {
        var names = profiles.map(\.name).filter { $0 != Profile.alwaysName }
        if !names.contains(activeProfileName) { names.append(activeProfileName) }
        return names
    }

    private var caption: String {
        if profileName == Profile.alwaysName {
            return "Applies in every profile. Almost every rule belongs here."
        }
        if profileName == activeProfileName {
            return "Applies only while \(profileName) is the active profile, which it is now."
        }
        return "Applies only while \(profileName) is the active profile. \(activeProfileName) is active, so this rule stays dormant for now."
    }
}

/// What the shared "refresh every list" is doing, wherever one can be started.
///
/// Every control drives the same call and reads the same state, so the Rules
/// page and the Profiles page cannot report different things about one download
/// (#135).
struct BlocklistRefreshStatus: View {
    let state: ProfileClient.BlocklistRefresh

    var body: some View {
        switch state {
        case .idle:
            EmptyView()
        case .running:
            HStack(spacing: 5) {
                ProgressView()
                    .controlSize(.small)
                Text("Downloading every list\u{2026}")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        case .finished(let summary):
            caption(summary, tint: .secondary)
        case .failed(let message):
            caption(message, tint: .orange)
        }
    }

    private func caption(_ text: String, tint: Color) -> some View {
        Text(text)
            .font(.caption)
            .foregroundStyle(tint)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// How a list's size reads before it has ever been downloaded, which is not the
/// same thing as a list that came back empty.
extension BlocklistInfo {
    var countLabel: String {
        if entryCount > 0 { return "\(entryCount)" }
        return lastUpdated == nil && !url.isEmpty ? "Not downloaded yet" : "0"
    }
}

/// The symbols a profile can wear.
///
/// Every profile was created with the same fixed pin, so the sidebar was a
/// column of identical rows and the menu bar showed the same glyph whichever
/// profile was active (#137). A short, named list beats a full symbol browser
/// here: these are places and situations, not arbitrary art.
enum ProfileIcons {
    static let all = [
        "house", "building.2", "airplane", "cup.and.saucer", "wifi",
        "lock.shield", "person.2", "gamecontroller", "briefcase", "mappin.and.ellipse"
    ]

    static func title(_ symbol: String) -> String {
        switch symbol {
        case "house": return "Home"
        case "building.2": return "Work"
        case "airplane": return "Travel"
        case "cup.and.saucer": return "Cafe"
        case "wifi": return "Public network"
        case "lock.shield": return "Locked down"
        case "person.2": return "Shared"
        case "gamecontroller": return "Play"
        case "briefcase": return "Client site"
        default: return "Place"
        }
    }
}
