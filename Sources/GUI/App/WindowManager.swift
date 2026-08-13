import AppKit
import SwiftUI
import Combine

/// A menu action needs an Objective-C target. WindowManager is a plain Swift
/// type, so the selector lives on this small object instead of reshaping the
/// window manager around AppKit's dispatch.
final class MenuActionTarget: NSObject {
    private let handler: () -> Void

    init(handler: @escaping () -> Void) {
        self.handler = handler
    }

    @objc func perform(_ sender: Any?) { handler() }
}

@MainActor
final class WindowManager {
    private let state: AppState
    private let systemExtension: SystemExtensionManager
    /// One window, five pages. Retained rather than weak so closing it and
    /// re-opening from the menu bar returns to the page you left.
    private var mainWindow: NSWindow?
    private let mainModel: MainWindowModel
    private var alertWindow: NSWindow?
    private var alertCancellable: AnyCancellable?
    private var pageCancellable: AnyCancellable?
    /// Menu items do not retain their target, so the Insights action object
    /// lives here for as long as the menu does.
    private var insightsMenuTarget: MenuActionTarget?
    private var menuTrackingObserver: NSObjectProtocol?
    private static let insightsMenuTitle = "Insights…"
    private static let mainWindowAutosaveName = "FreeSnitch.MainWindow"
    private static let selectedPageKey = "FreeSnitch.SelectedPage"

    init(state: AppState, systemExtension: SystemExtensionManager) {
        self.state = state
        self.systemExtension = systemExtension
        let stored = UserDefaults.standard.string(forKey: Self.selectedPageKey)
        self.mainModel = MainWindowModel(page: stored.flatMap(MainPage.init(rawValue:)) ?? .monitor)
        observeAlerts()
        observeSelectedPage()
        installInsightsMenuItem()
    }

    // MARK: - The one main window

    /// Brings the main window back on the page it was last left on.
    func showMainWindow() { show(mainModel.page) }

    func showNetworkMonitor() { show(.monitor) }

    func showRulesManager() { show(.rules) }

    func showInsights() { show(.insights) }

    func showProfiles() { show(.profiles) }

    func showSettings() { show(.settings) }

    /// Every entry point lands here: switch the existing window to the page
    /// and focus it. A second window is never created.
    private func show(_ page: MainPage) {
        mainModel.page = page
        let window = mainWindow ?? makeMainWindow()
        mainWindow = window
        window.subtitle = page.title
        focus(window)
    }

    private func makeMainWindow() -> NSWindow {
        makeWindow(
            title: "FreeSnitch",
            defaultSize: NSSize(width: 1200, height: 780),
            minSize: NSSize(width: 1040, height: 620),
            autosaveName: Self.mainWindowAutosaveName,
            content: MainWindowView(model: mainModel, systemExtension: systemExtension)
                .environmentObject(state)
        )
    }

    /// The page outlives the window, so it is persisted as it changes rather
    /// than on close: quitting with the window shut still reopens where the
    /// user was.
    private func observeSelectedPage() {
        pageCancellable = mainModel.$page
            .receive(on: RunLoop.main)
            .sink { [weak self] page in
                UserDefaults.standard.set(page.rawValue, forKey: Self.selectedPageKey)
                self?.mainWindow?.subtitle = page.title
            }
    }

    /// The app menu is built by SwiftUI commands, so the Insights item is
    /// inserted next to the other window commands here rather than competing
    /// with them for ownership of that menu. SwiftUI can rebuild that menu
    /// afterwards, so the item is also re-checked whenever a menu opens: an
    /// entry point that quietly disappears is the same as not having one.
    private func installInsightsMenuItem() {
        insightsMenuTarget = MenuActionTarget { [weak self] in
            Task { @MainActor in self?.showInsights() }
        }
        DispatchQueue.main.async { [weak self] in self?.ensureInsightsMenuItem() }
        menuTrackingObserver = NotificationCenter.default.addObserver(
            forName: NSMenu.didBeginTrackingNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.ensureInsightsMenuItem() }
        }
    }

    private func ensureInsightsMenuItem() {
        guard let target = insightsMenuTarget,
              let appMenu = NSApp.mainMenu?.items.first?.submenu,
              !appMenu.items.contains(where: { $0.title == Self.insightsMenuTitle }) else { return }
        let item = NSMenuItem(title: Self.insightsMenuTitle,
                              action: #selector(MenuActionTarget.perform(_:)),
                              keyEquivalent: "i")
        item.keyEquivalentModifierMask = [.command, .option]
        item.target = target
        let anchor = appMenu.items.firstIndex { $0.title.hasPrefix("Rules") }
        appMenu.insertItem(item, at: anchor.map { $0 + 1 } ?? appMenu.items.count)
    }

    // MARK: - Window factory

    private func makeWindow<Content: View>(
        title: String,
        defaultSize: NSSize,
        minSize: NSSize,
        autosaveName: String,
        content: Content
    ) -> NSWindow {
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: defaultSize),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        // A real title bar, because this is now the app's window rather than a
        // floating pane: the Dock, Mission Control and the Window menu all read
        // it. The app draws a fixed dark interface, so the frame is told to be
        // dark too instead of leaving a light title bar over dark content.
        window.title = title
        window.appearance = NSAppearance(named: .darkAqua)
        window.isReleasedWhenClosed = false
        window.minSize = minSize
        // Use `contentView` (NSHostingView) instead of `contentViewController`.
        // Assigning a hosting *controller* makes NSWindow resize itself to the
        // SwiftUI view's fitting size, which collapsed these windows to a
        // sliver. A hosting *view* keeps the size we set here, but only if we
        // also stop it exporting an intrinsic size: with `sizingOptions`
        // left at its default the window grew to the content's ideal height
        // (a 2101 pt tall Network Monitor) the moment a text-heavy banner was
        // added to it.
        let hosting = NSHostingView(rootView: content)
        hosting.sizingOptions = []
        hosting.autoresizingMask = [.width, .height]
        window.contentView = hosting
        window.setContentSize(defaultSize)

        // Persist + restore the window frame across launches. A stored frame
        // from a broken build can be larger than the screen, so fall back to a
        // centred default rather than restoring something unusable.
        window.setFrameAutosaveName(autosaveName)
        let visible = (window.screen ?? NSScreen.main)?.visibleFrame ?? .zero
        if !window.setFrameUsingName(autosaveName)
            || window.frame.width > visible.width + 1
            || window.frame.height > visible.height + 1 {
            window.setContentSize(defaultSize)
            window.center()
        }

        return window
    }

    private func focus(_ window: NSWindow) {
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    // MARK: - Connection alerts

    private func observeAlerts() {
        alertCancellable = state.$pendingAlerts
            .receive(on: RunLoop.main)
            .sink { [weak self] alerts in
                self?.syncAlertWindow(hasAlert: !alerts.isEmpty)
            }
    }

    private func syncAlertWindow(hasAlert: Bool) {
        if hasAlert {
            if alertWindow == nil { presentAlertWindow() }
        } else {
            alertWindow?.close()
            alertWindow = nil
        }
    }

    private func presentAlertWindow() {
        // Use a hosting *controller* so the panel auto-sizes to the alert's
        // content. Long process names and hostnames grow the card correctly.
        // (Reading NSHostingView.fittingSize before the view is laid out
        // returns zero and would clip the content.)
        let hosting = NSHostingController(rootView: AlertWindowContent().environmentObject(state))
        let window = NSPanel(contentViewController: hosting)
        window.styleMask = [.titled, .fullSizeContentView]
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.isReleasedWhenClosed = false
        window.level = .floating
        window.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        alertWindow = window
    }
}
