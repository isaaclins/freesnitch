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

    /// Whether the window's toolbar carries a search field on this page. Only
    /// the two pages with a long list to narrow do.
    var supportsSearch: Bool {
        switch self {
        case .monitor, .rules: return true
        case .insights, .profiles, .settings: return false
        }
    }

    var searchPlaceholder: String {
        switch self {
        case .monitor: return "Search apps and destinations"
        case .rules: return "Search rules"
        case .insights, .profiles, .settings: return "Search"
        }
    }
}

/// Shared geometry of the main window. The toolbar needs the same numbers the
/// content lays itself out with, so the window title can be aligned to the
/// content pane rather than to the window (#74).
enum MainWindowMetrics {
    static let sidebarWidth: CGFloat = 200
    /// The divider between the sidebar and the content.
    static let dividerWidth: CGFloat = 1
    /// What the pages pad their own headers by.
    static let contentInset: CGFloat = 12

    /// Window x of the content pane's leading edge.
    static func contentEdge(sidebarVisible: Bool) -> CGFloat {
        sidebarVisible ? sidebarWidth + dividerWidth : 0
    }
}

/// The selected page, owned by the window manager and observed by the window's
/// content. Keeping it out of `@State` is what lets a menu action switch the
/// existing window instead of opening a new one.
@MainActor
final class MainWindowModel: ObservableObject {
    @Published var page: MainPage
    /// Sidebar visibility and the search query live here rather than in the
    /// view, because the window's real `NSToolbar` drives both and a toolbar
    /// cannot reach into SwiftUI `@State`.
    @Published var isSidebarVisible = true
    @Published var searchText = ""
    /// Set by a page that carries a search field of its own, so the window
    /// does not show a second one in the toolbar searching the same thing
    /// (#96). The blocklist entries pane is the only such page today.
    @Published var contentOwnsSearch = false
    /// Bumped by Find. Whichever search field is on screen takes the caret.
    @Published var searchFocusToken = 0

    init(page: MainPage) {
        self.page = page
    }

    /// Whether the window's toolbar is the one carrying search right now.
    var toolbarOwnsSearch: Bool { page.supportsSearch && !contentOwnsSearch }
}

/// The single window: a sidebar of destinations plus the selected page.
///
/// The pages are the existing views, hosted unchanged. This view owns
/// navigation only.
struct MainWindowView: View {
    @ObservedObject var model: MainWindowModel
    let systemExtension: SystemExtensionManager
    @State private var sidebarAcceptsSelection = false
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
            if model.isSidebarVisible {
                sidebar.frame(width: MainWindowMetrics.sidebarWidth)
                Divider()
            }
            detail
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// A real sidebar `List` on a real `NSVisualEffectView`.
    ///
    /// The collapse control is gone from here: it is a toolbar item now, where
    /// Finder keeps it, so the sidebar starts at its first row and there is one
    /// control for hiding and showing rather than two that swap places.
    private var sidebar: some View {
        List(selection: pageSelection) {
            ForEach(MainPage.allCases) { page in
                Label(page.title, systemImage: page.symbol)
                    .tag(page)
            }
        }
        .listStyle(.sidebar)
        .scrollContentBackground(.hidden)
        // The material, and only the material, extends under the title bar.
        .background(VisualEffectView(material: .sidebar).ignoresSafeArea())
        .onAppear {
            DispatchQueue.main.async { sidebarAcceptsSelection = true }
        }
    }

    /// Writes are ignored until the list has appeared, because a freshly
    /// focused outline can report a selection of its own before anyone clicks,
    /// and here that would silently switch the window to another page.
    private var pageSelection: Binding<MainPage?> {
        Binding(
            get: { model.page },
            set: { newValue in
                guard sidebarAcceptsSelection else { return }
                guard let newValue, newValue != model.page else { return }
                model.page = newValue
            }
        )
    }

    @ViewBuilder
    private var detail: some View {
        switch model.page {
        case .monitor:
            NetworkMonitorView(systemExtension: systemExtension, searchText: $model.searchText)
        case .rules:
            RulesManagerView(systemExtension: systemExtension, window: model)
        case .insights:
            InsightsView(systemExtension: systemExtension)
        case .profiles:
            ProfilesSettingsView(profileClient: profileClient)
                .padding(16)
        case .settings:
            SettingsView(systemExtension: systemExtension)
        }
    }
}
