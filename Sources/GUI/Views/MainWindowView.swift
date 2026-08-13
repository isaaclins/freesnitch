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
    @State private var columnVisibility: NavigationSplitViewVisibility = .all
    @ObservedObject private var profileClient = ProfileClient.shared

    var body: some View {
        NavigationSplitView(columnVisibility: $columnVisibility) {
            sidebar
        } detail: {
            detail
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .navigationTitle(model.page.title)
        }
        .navigationSplitViewStyle(.balanced)
        .preferredColorScheme(.dark)
    }

    private var sidebar: some View {
        List(selection: selection) {
            ForEach(MainPage.allCases) { page in
                Label(page.title, systemImage: page.symbol)
                    .tag(page)
            }
        }
        .listStyle(.sidebar)
        .navigationSplitViewColumnWidth(min: 180, ideal: 200, max: 260)
    }

    /// The list selection is optional because AppKit can clear it, but a
    /// window with no page is not a state this app has: an empty selection is
    /// ignored rather than blanking the window.
    private var selection: Binding<MainPage?> {
        Binding(get: { model.page },
                set: { newValue in if let newValue { model.page = newValue } })
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
