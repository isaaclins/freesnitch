import SwiftUI

/// The menu bar extra's panel.
///
/// A status item popover is judged against Control Center and the Wi-Fi menu,
/// not against a window: one column, system materials, quiet section labels,
/// rows that highlight under the pointer, and no boxes drawn around things
/// that are not controls. This one used to be a fixed 380x540 slab of
/// hand-sized fonts with two coloured squares in its header, and it clipped
/// its own first and last rows because the content did not fit the frame it
/// was given (#91).
struct MenubarPopoverView: View {
    @EnvironmentObject var state: AppState
    let systemExtension: SystemExtensionManager
    @EnvironmentObject var windows: WindowManager
    let close: () -> Void
    @State private var showModePicker = false
    @State private var showProfilePicker = false
    @ObservedObject private var profileClient = ProfileClient.shared

    /// Control Center's panels are 320 points wide. So is this.
    private static let width: CGFloat = 320

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            HelperBanner(systemExtension: systemExtension, compact: true)
            if let notice = profileClient.visibleNotice {
                ProfileSwitchBanner(notice: notice,
                                    canUndo: profileClient.canUndo,
                                    onUndo: { profileClient.undoSwitch() },
                                    onDismiss: { profileClient.dismissNotice() })
                    .padding(.horizontal, 12)
                    .padding(.bottom, 6)
            }
            trafficSection
            activitySection
            Divider().padding(.top, 8)
            actions
        }
        // Width only. A fixed height made the popover overflow its own frame
        // and clip the header and the last menu item whenever a banner
        // appeared (#91); the panel is now as tall as what it has to say.
        .frame(width: Self.width)
    }

    // MARK: Header

    private var header: some View {
        HStack(spacing: 8) {
            ModeButton(mode: state.mode, showing: $showModePicker)
                .popover(isPresented: $showModePicker, arrowEdge: .bottom) {
                    ModePicker(current: state.mode) { m in
                        state.setMode(m)
                        showModePicker = false
                    }
                }
            profileChip
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 12)
        // The popover's arrow eats into the top of the content, so the header
        // needs more room above it than a window's would.
        .padding(.top, 14)
        .padding(.bottom, 10)
    }

    /// The active profile is always on screen. A strict profile applying
    /// silently is the same failure as #12, #13 and #17.
    ///
    /// It picks, rather than navigates. Sending the reader to the Profiles page
    /// to change a profile is a window and a page change for the one thing the
    /// chip is about, and the mode chip beside it already shows what this
    /// should be (#99).
    private var profileChip: some View {
        Button { showProfilePicker.toggle() } label: {
            HStack(spacing: 5) {
                Image(systemName: profileClient.activeProfile?.icon ?? "person.crop.circle")
                    .font(.caption)
                    .foregroundStyle(.tint)
                Text(profileClient.menuBarLabel)
                    .font(.subheadline)
                    .lineLimit(1)
                Image(systemName: "chevron.up.chevron.down")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 5)
            .background(.quaternary.opacity(0.6), in: Capsule())
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .help("The active profile. Click to switch.")
        .popover(isPresented: $showProfilePicker, arrowEdge: .bottom) {
            ProfilePicker(profiles: profileClient.profiles,
                          activeName: profileClient.activeProfileName,
                          isAvailable: profileClient.isAvailable,
                          unavailableReason: profileClient.unavailableReason,
                          onPick: { name in
                              profileClient.activate(profileName: name)
                              showProfilePicker = false
                          },
                          onManage: {
                              showProfilePicker = false
                              close()
                              windows.showProfiles()
                          })
        }
    }

    // MARK: Traffic

    /// The totals used to sit as coloured pills on top of the bars they
    /// describe, so the reading covered the data (#91). They belong in a
    /// legend, where the colour ties each number to its series.
    private var trafficSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 12) {
                legend(color: PSTheme.trafficOut, label: "Sent", value: PSFormat.bytes(state.totalOut))
                legend(color: PSTheme.trafficIn, label: "Received", value: PSFormat.bytes(state.totalIn))
                Spacer(minLength: 0)
            }
            ZStack(alignment: .bottom) {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(.quaternary.opacity(0.5))
                TrafficBarsChart(history: state.trafficHistory)
                    .padding(.horizontal, 8)
                    .padding(.top, 10)
                    .padding(.bottom, 18)
                HStack {
                    Text("5 minutes ago")
                    Spacer()
                    Text("now")
                }
                .font(.caption2)
                .foregroundStyle(.tertiary)
                .padding(.horizontal, 8)
                .padding(.bottom, 5)
            }
            .frame(height: 132)
        }
        .padding(.horizontal, 12)
    }

    private func legend(color: Color, label: String, value: String) -> some View {
        HStack(spacing: 5) {
            Circle().fill(color).frame(width: 7, height: 7)
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.caption.weight(.semibold))
                .monospacedDigit()
        }
        .accessibilityElement(children: .combine)
    }

    // MARK: Activity

    private var activitySection: some View {
        VStack(alignment: .leading, spacing: 0) {
            sectionLabel("Recent Network Activity")
            if state.topProcesses.isEmpty {
                Text("No traffic recorded yet.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 4)
            } else {
                ForEach(state.topProcesses.prefix(3)) { ps in
                    MenubarRow(action: { close(); windows.showNetworkMonitor() }) {
                        HStack(spacing: 8) {
                            if let icon = ps.icon {
                                Image(nsImage: icon).resizable().frame(width: 18, height: 18)
                            } else {
                                Image(systemName: "app.dashed")
                                    .foregroundStyle(.secondary)
                                    .frame(width: 18, height: 18)
                            }
                            Text(ps.name).lineLimit(1)
                            Spacer(minLength: 8)
                            Text(PSFormat.bytes(ps.total))
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                                .monospacedDigit()
                        }
                    }
                }
            }
            MenubarRow(action: { close(); windows.showNetworkMonitor() }) {
                HStack(spacing: 8) {
                    ZStack {
                        Circle().fill(state.deniedCount > 0 ? Color(nsColor: .systemRed) : Color.secondary)
                        Text("\(state.deniedCount)")
                            .font(.caption2.weight(.bold))
                            .foregroundStyle(.white)
                    }
                    .frame(width: 18, height: 18)
                    Text("Recently Denied")
                    Spacer(minLength: 8)
                    Image(systemName: "chevron.right")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
            }
        }
        .padding(.top, 10)
    }

    private func sectionLabel(_ text: String) -> some View {
        Text(text)
            .font(.caption.weight(.semibold))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 14)
            .padding(.bottom, 4)
    }

    // MARK: Actions

    private var actions: some View {
        VStack(alignment: .leading, spacing: 0) {
            MenubarRow(action: { close(); windows.showRulesManager() }) {
                menuLabel("Rules", symbol: "list.bullet.rectangle")
            }
            MenubarRow(action: { close(); windows.showNetworkMonitor() }) {
                menuLabel("Network Monitor", symbol: "globe")
            }
            MenubarRow(action: { close(); windows.showSettings() }) {
                menuLabel("Settings", symbol: "gearshape")
            }
        }
        .padding(.top, 4)
        .padding(.bottom, 8)
    }

    private func menuLabel(_ title: String, symbol: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: symbol)
                .foregroundStyle(.secondary)
                .frame(width: 18)
            Text(title)
            Spacer(minLength: 0)
        }
    }
}

/// A row in the panel: full width, highlighted under the pointer, the way an
/// item in a menu is. Plain text rows that did not react to the pointer were
/// the reason the panel read as a document rather than as a menu.
struct MenubarRow<Content: View>: View {
    let action: () -> Void
    @ViewBuilder var content: () -> Content
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            content()
                .font(.body)
                .padding(.horizontal, 8)
                .padding(.vertical, 5)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    RoundedRectangle(cornerRadius: 6, style: .continuous)
                        .fill(hovering ? AnyShapeStyle(.selection) : AnyShapeStyle(.clear))
                )
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 6)
        .onHover { hovering = $0 }
    }
}
/// The mode is the app's most consequential setting, so it reads as a control
/// with a value, like a pop-up button, rather than as a coloured tile.
struct ModeButton: View {
    let mode: AppMode
    @Binding var showing: Bool

    var body: some View {
        Button(action: { showing.toggle() }) {
            HStack(spacing: 5) {
                Image(systemName: mode.symbol)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(mode.tint)
                Text(mode.title)
                    .font(.subheadline.weight(.medium))
                    .lineLimit(1)
                Image(systemName: "chevron.up.chevron.down")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 5)
            .background(.quaternary.opacity(0.6), in: Capsule())
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .help("The filtering mode. Alert asks about new connections.")
    }

}
/// Choosing the profile, the same way the mode is chosen (#99).
struct ProfilePicker: View {
    let profiles: [Profile]
    let activeName: String
    let isAvailable: Bool
    let unavailableReason: String
    let onPick: (String) -> Void
    let onManage: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Profile")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .padding(.horizontal, 14)
                .padding(.top, 10)
                .padding(.bottom, 4)
            if profiles.isEmpty {
                Text(isAvailable ? "No profiles yet." : unavailableReason)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 14)
                    .padding(.bottom, 6)
            } else {
                ForEach(profiles) { profile in
                    MenubarRow(action: { onPick(profile.name) }) {
                        HStack(spacing: 8) {
                            Image(systemName: "checkmark")
                                .font(.caption.weight(.bold))
                                .opacity(profile.name == activeName ? 1 : 0)
                                .frame(width: 12)
                            Image(systemName: profile.icon)
                                .foregroundStyle(.tint)
                                .frame(width: 18)
                            Text(profile.name).lineLimit(1)
                            Spacer(minLength: 0)
                        }
                    }
                    .disabled(!isAvailable)
                }
                if !isAvailable {
                    Text(unavailableReason)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.horizontal, 14)
                        .padding(.top, 2)
                }
            }
            Divider().padding(.vertical, 4)
            MenubarRow(action: onManage) {
                HStack(spacing: 8) {
                    Spacer().frame(width: 12)
                    Image(systemName: "person.crop.circle")
                        .foregroundStyle(.secondary)
                        .frame(width: 18)
                    Text("Manage Profiles\u{2026}")
                    Spacer(minLength: 0)
                }
            }
        }
        .padding(.bottom, 8)
        .frame(width: 240)
    }
}

/// Choosing the mode, as a menu of choices with the current one ticked, which
/// is what a Mac shows when one of a few options is in force.
struct ModePicker: View {
    let current: AppMode
    let onPick: (AppMode) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Mode")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .padding(.horizontal, 14)
                .padding(.top, 10)
                .padding(.bottom, 4)
            ForEach(AppMode.allCases, id: \.self) { mode in
                pickerRow(mode)
            }
        }
        .padding(.bottom, 8)
        .frame(width: 240)
    }

    private func pickerRow(_ mode: AppMode) -> some View {
        MenubarRow(action: { onPick(mode) }) {
            HStack(spacing: 8) {
                Image(systemName: "checkmark")
                    .font(.caption.weight(.bold))
                    .opacity(current == mode ? 1 : 0)
                    .frame(width: 12)
                Image(systemName: mode.symbol)
                    .foregroundStyle(mode.tint)
                    .frame(width: 18)
                Text(mode.title)
                Spacer(minLength: 0)
            }
        }
    }
}

struct TrafficBarsChart: View {
    let history: [TrafficSample]
    var body: some View {
        GeometryReader { geo in
            let samples = Array(history.suffix(80))
            let count = max(samples.count, 1)
            let availW = geo.size.width
            let barW = max(2, (availW - CGFloat(count - 1) * 1.5) / CGFloat(count))
            let midY = geo.size.height / 2
            // One scale for both directions. Scaling each half against its own
            // maximum made the two sides of the chart incomparable, which is
            // the only thing a paired chart is for (#119).
            let peak = max(1, CGFloat(max(samples.map { $0.bytesIn }.max() ?? 1,
                                          samples.map { $0.bytesOut }.max() ?? 1)))
            ZStack(alignment: .center) {
                HStack(alignment: .center, spacing: 1.5) {
                    ForEach(0..<samples.count, id: \.self) { i in
                        let s = samples[i]
                        // The two directions carry the app's own traffic
                        // colours, the same ones the Network Monitor uses, so
                        // one glance means the same thing in both places.
                        VStack(spacing: 0) {
                            Rectangle()
                                .fill(PSTheme.trafficOut)
                                .frame(width: barW, height: max(2, CGFloat(s.bytesOut)/peak * midY * 0.95))
                            Rectangle()
                                .fill(PSTheme.trafficIn)
                                .frame(width: barW, height: max(2, CGFloat(s.bytesIn)/peak * midY * 0.95))
                        }
                    }
                }
            }
        }
    }
}
