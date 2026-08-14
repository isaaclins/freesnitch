import SwiftUI

/// The pages of the one main window (#63).
///
/// Every entry point, the menu bar popover, the app menu, first run and the
/// Dock, selects a page here instead of opening a window of its own. The
/// connection alert is deliberately not a page: it is an interrupt that has to
/// appear over whatever app the user is in, so it stays its own panel.
enum MainPage: String, CaseIterable, Identifiable {
    case monitor
    case rules
    case insights
    case profiles
    case settings

    var id: String { rawValue }

    var title: String {
        switch self {
        case .monitor: return "Network Monitor"
        case .rules: return "Rules"
        case .insights: return "Insights"
        case .profiles: return "Profiles"
        case .settings: return "Settings"
        }
    }

    var symbol: String {
        switch self {
        case .monitor: return "globe"
        case .rules: return "list.bullet.rectangle"
        case .insights: return "chart.bar"
        case .profiles: return "person.crop.circle"
        case .settings: return "gearshape"
        }
    }
}

/// The selected page, owned by the window manager and observed by the window's
/// content. Keeping it out of `@State` is what lets a menu action switch the
/// existing window instead of opening a new one.
@MainActor
final class MainWindowModel: ObservableObject {
    @Published var page: MainPage

    init(page: MainPage) {
        self.page = page
    }
}

/// The single window: a sidebar of destinations plus the selected page.
///
/// The pages are the existing views, hosted unchanged. This view owns
/// navigation only.
struct MainWindowView: View {
    @ObservedObject var model: MainWindowModel
    let systemExtension: SystemExtensionManager
    @State private var isSidebarVisible = true
    @ObservedObject private var profileClient = ProfileClient.shared

    var body: some View {
        // A plain HStack, deliberately, not NavigationSplitView.
        //
        // NavigationSplitView does not lay out correctly inside this app's
        // AppKit-owned NSWindow: it proposes no usable height to its children,
        // so the sidebar rows and the monitor tree rows both rendered at zero
        // height while every element still existed, correctly labelled, in the
        // accessibility tree. Only views that demanded space for themselves,
        // like the map, survived. That is issue #65, and it passed the entire
        // test suite and a Release build while the window was visibly blank.
        //
        // The app draws a fixed dark interface of its own anyway, so a system
        // sidebar bought us nothing here, and this also restores the collapse
        // affordance that NavigationSplitView could not give us without an
        // NSToolbar.
        HStack(spacing: 0) {
            if isSidebarVisible {
                sidebar
                    .frame(width: 200)
                    .background(PSTheme.bgSidebar)
                Divider().background(PSTheme.stroke)
            }
            detail
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .overlay(alignment: .topLeading) {
                    // Without the sidebar there would be no way back to it, so
                    // the reveal control only exists while it is hidden.
                    if !isSidebarVisible {
                        Button {
                            withAnimation(.easeInOut(duration: 0.15)) { isSidebarVisible = true }
                        } label: {
                            Image(systemName: "sidebar.left")
                                .foregroundColor(PSTheme.textMuted)
                                .padding(6)
                                .background(PSTheme.bgTertiary, in: RoundedRectangle(cornerRadius: 6))
                        }
                        .buttonStyle(.plain)
                        .help("Show the sidebar")
                        .padding(8)
                    }
                }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(PSTheme.bgPrimary)
        .preferredColorScheme(.dark)
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text("FreeSnitch")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(PSTheme.textMuted)
                Spacer()
                Button {
                    withAnimation(.easeInOut(duration: 0.15)) { isSidebarVisible = false }
                } label: {
                    Image(systemName: "sidebar.left")
                        .foregroundColor(PSTheme.textMuted)
                }
                .buttonStyle(.plain)
                .help("Hide the sidebar")
            }
            .padding(.horizontal, 12)
            .padding(.top, 10)
            .padding(.bottom, 6)

            ForEach(MainPage.allCases) { page in
                sidebarRow(page)
            }
            Spacer(minLength: 0)
        }
        .frame(maxHeight: .infinity, alignment: .top)
    }

    private func sidebarRow(_ page: MainPage) -> some View {
        let isSelected = model.page == page
        return Button {
            model.page = page
        } label: {
            HStack(spacing: 8) {
                Image(systemName: page.symbol)
                    .frame(width: 16)
                    .foregroundColor(isSelected ? PSTheme.accentBlue : PSTheme.textSecondary)
                Text(page.title)
                    .font(.system(size: 13))
                    .foregroundColor(isSelected ? PSTheme.textPrimary : PSTheme.textSecondary)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(isSelected ? PSTheme.accentBlue.opacity(0.16) : .clear,
                        in: RoundedRectangle(cornerRadius: 6))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 8)
    }

    @ViewBuilder
    private var detail: some View {
        switch model.page {
        case .monitor:
            NetworkMonitorView(systemExtension: systemExtension)
        case .rules:
            RulesManagerView(systemExtension: systemExtension)
        case .insights:
            InsightsView()
        case .profiles:
            ProfilesSettingsView(profileClient: profileClient)
                .padding(16)
                .background(PSTheme.bgPrimary)
        case .settings:
            SettingsView(systemExtension: systemExtension)
        }
    }
}
