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
            if isSidebarVisible {
                sidebar.frame(width: 200)
                Divider()
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
                        }
                        .buttonStyle(.borderless)
                        .help("Show the sidebar")
                        .padding(8)
                    }
                }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(PSTheme.bgPrimary)
    }

    /// A real sidebar `List`, so the window's own navigation gets the same
    /// Finder metrics, selection and keyboard traversal as the pages inside it.
    /// Its material is supplied by `.listStyle(.sidebar)` and must not be
    /// painted over.
    private var sidebar: some View {
        VStack(spacing: 0) {
            // No app-name caption here: the window title bar already says
            // FreeSnitch, and Finder's sidebar starts at its first row. Only
            // the collapse control remains, aligned like a toolbar button.
            HStack {
                Spacer()
                Button {
                    withAnimation(.easeInOut(duration: 0.15)) { isSidebarVisible = false }
                } label: {
                    Image(systemName: "sidebar.left")
                }
                .buttonStyle(.borderless)
                .help("Hide the sidebar")
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)

            List(selection: pageSelection) {
                ForEach(MainPage.allCases) { page in
                    Label(page.title, systemImage: page.symbol)
                        .tag(page)
                }
            }
            .listStyle(.sidebar)
            .onAppear {
                DispatchQueue.main.async { sidebarAcceptsSelection = true }
            }
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
            NetworkMonitorView(systemExtension: systemExtension)
        case .rules:
            RulesManagerView(systemExtension: systemExtension)
        case .insights:
            InsightsView()
        case .profiles:
            ProfilesSettingsView(profileClient: profileClient)
                .padding(16)
        case .settings:
            SettingsView(systemExtension: systemExtension)
        }
    }
}
