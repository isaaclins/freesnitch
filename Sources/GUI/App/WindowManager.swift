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
    /// The uninstall outlives every view that shows it. Held here so a step
    /// that is already under way survives the sheet being closed (#133).
    private let uninstallModel: UninstallFlowModel
    private var alertWindow: NSWindow?
    /// The alert is centred once, after its first real measurement.
    private var alertHasBeenCentered = false
    /// The last size the alert card reported for itself.
    private var alertContentSize: CGSize?
    private var mainToolbarController: MainToolbarController?
    private var alertCancellable: AnyCancellable?
    private var pageCancellable: AnyCancellable?
    /// Menu items do not retain their target, so the Insights action object
    /// lives here for as long as the menu does.
    private static let mainWindowAutosaveName = "FreeSnitch.MainWindow"
    private static let selectedPageKey = "FreeSnitch.SelectedPage"

    init(state: AppState, systemExtension: SystemExtensionManager) {
        self.state = state
        self.systemExtension = systemExtension
        let stored = UserDefaults.standard.string(forKey: Self.selectedPageKey)
        self.mainModel = MainWindowModel(page: stored.flatMap(MainPage.init(rawValue:)) ?? .monitor)
        self.uninstallModel = UninstallFlowModel(state: state, systemExtension: systemExtension)
        observeAlerts()
        observeSelectedPage()
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
    func showPage(_ page: MainPage) { show(page) }

    /// Find. Puts the caret in whichever search field the current page shows,
    /// the toolbar's or the one inside the pane (#96).
    func focusSearch() {
        if mainWindow == nil { show(mainModel.page) }
        mainWindow?.makeKeyAndOrderFront(nil)
        mainModel.searchFocusToken += 1
    }

    private func show(_ page: MainPage) {
        mainModel.page = page
        let window = mainWindow ?? makeMainWindow()
        mainWindow = window
        window.subtitle = page.title
        focus(window)
        // Re-assert on the next tick. Command-comma reaches us through the
        // SwiftUI Settings scene, and that scene's own window closing itself
        // afterwards clears this window's subtitle, so the title bar lost the
        // page name for exactly that one entry point.
        DispatchQueue.main.async { [weak window] in
            window?.subtitle = page.title
        }
    }

    private func makeMainWindow() -> NSWindow {
        let window = makeWindow(
            title: "FreeSnitch",
            defaultSize: NSSize(width: 1200, height: 780),
            // Fits the smallest display Apple ships, a 13 inch MacBook Air at
            // its most spacious scaled resolution, with room for the Dock and
            // the menu bar. 1040 by 620 did not (#123).
            minSize: NSSize(width: 900, height: 560),
            autosaveName: Self.mainWindowAutosaveName,
            windowClass: ToolbarLockedWindow.self,
            content: MainWindowView(model: mainModel,
                                    systemExtension: systemExtension,
                                    uninstall: uninstallModel)
                .environmentObject(state)
        )
        // A real toolbar, in the title bar, laid out by AppKit. The controller
        // has to be retained for as long as the window: it is the toolbar's
        // delegate and its search field's delegate.
        let controller = MainToolbarController(model: mainModel)
        mainToolbarController = controller
        window.toolbar = controller.makeToolbar()
        window.toolbarStyle = .unified
        // This toolbar carries the window's title, its sidebar control and its
        // search field, so a window without it has no title and no way to
        // search. AppKit persists the hidden state with the window, and it
        // could be reached from the toolbar's own contextual menu, so a single
        // stray right click left the app permanently disfigured (#90).
        // ToolbarLockedWindow refuses the command; this repairs a window that
        // was already stored in that state.
        window.toolbar?.isVisible = true
        // Finder's sidebar material runs the full height of the window, behind
        // the title bar, and the toolbar floats on top of it. That needs the
        // content view to own the title bar area and the title bar itself to
        // stop painting a background. The content still lays out below the
        // toolbar, because SwiftUI insets it by the window's safe area; only
        // the sidebar's material opts out of that inset.
        window.styleMask.insert(.fullSizeContentView)
        window.titlebarAppearsTransparent = true
        // AppKit draws its title right after the leading toolbar items, which
        // here is on top of the sidebar. The toolbar carries a title item of
        // its own that aligns to the content pane instead (#74). The window
        // still has a title and a subtitle: the Window menu, Mission Control
        // and the Dock all read them.
        window.titleVisibility = .hidden
        return window
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

    // MARK: - Window factory

    private func makeWindow<Content: View>(
        title: String,
        defaultSize: NSSize,
        minSize: NSSize,
        autosaveName: String,
        windowClass: NSWindow.Type = NSWindow.self,
        content: Content
    ) -> NSWindow {
        let window = windowClass.init(
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
        // No forced appearance. The app follows the system, like every
        // Apple app: choosing Light in System Settings must make FreeSnitch
        // light. Forcing dark was only tenable while every colour in the app
        // was a hardcoded dark value.
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
        alertHasBeenCentered = false
        alertContentSize = nil
        // A hosting *view*, not a hosting controller. A controller drives the
        // window from its own fitting size: AppKit turns that into a frame with
        // a title bar added on top, and re-applies it whenever anything else
        // sets the frame, so the panel always carried a title bar's worth of
        // dead space under the buttons and could not be told otherwise. The
        // card measures itself instead and the window follows it (#73).
        let hosting = NSHostingView(rootView: AlertWindowContent(onContentSize: { [weak self] size in
            self?.resizeAlertWindow(to: size)
        }).environmentObject(state))
        hosting.sizingOptions = []
        let window = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 440, height: 400),
                             styleMask: [.titled, .fullSizeContentView],
                             backing: .buffered,
                             defer: false)
        // A plain container between the window and the hosting view. Left as
        // the content view directly, the hosting view still published an
        // intrinsic size, the window adopted it as a *content* size, and the
        // title bar's height came back on top of the frame right after the
        // measurement had removed it. A plain NSView has no intrinsic size to
        // adopt.
        let container = NSView(frame: NSRect(x: 0, y: 0, width: 440, height: 400))
        hosting.frame = container.bounds
        hosting.autoresizingMask = [.width, .height]
        container.addSubview(hosting)
        window.contentView = container
        // Assigned before the view goes on screen: the card measures itself
        // during that first layout pass, and a measurement that arrives before
        // this is set is dropped and never repeated, because the size it
        // reports does not change afterwards.
        alertWindow = window
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.isReleasedWhenClosed = false
        window.level = .floating
        // The preference is the only thing that decides this. Hardcoding
        // canJoinAllSpaces made the switch in Settings do nothing (#119).
        let allSpaces = AppPreferences.defaults.object(forKey: AppPreferences.Key.alertsAllSpaces) as? Bool ?? true
        window.collectionBehavior = allSpaces
            ? [.canJoinAllSpaces, .fullScreenAuxiliary]
            : [.moveToActiveSpace, .fullScreenAuxiliary]
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        // The card may have measured itself before the window was on screen.
        if let measured = alertContentSize { resizeAlertWindow(to: measured) }
    }

    /// Sizes the panel to the card inside it.
    ///
    /// The panel is titled for window behaviour only, and its content ignores
    /// the safe area, so a title bar's worth of height was left over as dead
    /// space under the buttons: the hosting controller sizes the *content*,
    /// AppKit adds the title bar to the *frame*, and the content then fills the
    /// taller frame from the top. `fittingSize`, `sizeThatFits` and
    /// `contentLayoutRect` all report the padded height, so the only honest
    /// number is the one the content measures for itself (#73).
    private func resizeAlertWindow(to size: CGSize) {
        guard size.height > 1, size.width > 1 else { return }
        alertContentSize = size
        guard let window = alertWindow else { return }
        let frame = window.frame
        guard abs(frame.height - size.height) > 0.5 || abs(frame.width - size.width) > 0.5 else { return }
        // Grow and shrink from the top edge, so a card that changes height does
        // not crawl up the screen.
        window.setFrame(NSRect(x: frame.origin.x,
                               y: frame.maxY - size.height,
                               width: size.width,
                               height: size.height),
                        display: true)
        // The panel was centred at its pre-measurement height, so centre it
        // once more now that the height is real.
        if !alertHasBeenCentered {
            alertHasBeenCentered = true
            window.center()
        }
    }
}

