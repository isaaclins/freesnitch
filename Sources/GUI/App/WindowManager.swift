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
    private weak var networkMonitorWindow: NSWindow?
    private weak var rulesWindow: NSWindow?
    private weak var settingsWindow: NSWindow?
    private weak var insightsWindow: NSWindow?
    private var alertWindow: NSWindow?
    private var alertCancellable: AnyCancellable?
    /// Menu items do not retain their target, so the Insights action object
    /// lives here for as long as the menu does.
    private var insightsMenuTarget: MenuActionTarget?
    private var menuTrackingObserver: NSObjectProtocol?
    private static let insightsMenuTitle = "Insights…"

    init(state: AppState, systemExtension: SystemExtensionManager) {
        self.state = state
        self.systemExtension = systemExtension
        observeAlerts()
        installInsightsMenuItem()
    }

    // MARK: - Public windows

    func showNetworkMonitor() {
        if let w = networkMonitorWindow { focus(w); return }
        networkMonitorWindow = makeWindow(
            title: "Network Monitor",
            defaultSize: NSSize(width: 1100, height: 700),
            minSize: NSSize(width: 900, height: 550),
            autosaveName: "FreeSnitch.NetworkMonitor",
            content: NetworkMonitorView(systemExtension: systemExtension).environmentObject(state)
        )
    }

    func showRulesManager() {
        if let w = rulesWindow { focus(w); return }
        rulesWindow = makeWindow(
            title: "Rules",
            defaultSize: NSSize(width: 1000, height: 650),
            minSize: NSSize(width: 820, height: 500),
            autosaveName: "FreeSnitch.Rules",
            content: RulesManagerView(systemExtension: systemExtension).environmentObject(state)
        )
    }

    func showInsights() {
        if let w = insightsWindow { focus(w); return }
        insightsWindow = makeWindow(
            title: "Insights",
            defaultSize: NSSize(width: 1040, height: 680),
            minSize: NSSize(width: 860, height: 520),
            autosaveName: "FreeSnitch.Insights",
            content: InsightsView().environmentObject(state)
        )
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

    func showSettings() {
        if let w = settingsWindow { focus(w); return }
        // Created manually rather than via the SwiftUI `Settings` scene: the
        // `showSettingsWindow:` action is unreliable for `.accessory`
        // (menu-bar-only) apps and was the reason Settings never appeared.
        settingsWindow = makeWindow(
            title: "Settings",
            defaultSize: NSSize(width: 560, height: 460),
            minSize: NSSize(width: 560, height: 460),
            autosaveName: "FreeSnitch.Settings",
            content: SettingsView(systemExtension: systemExtension).environmentObject(state),
            resizable: false
        )
    }

    // MARK: - Window factory

    private func makeWindow<Content: View>(
        title: String,
        defaultSize: NSSize,
        minSize: NSSize,
        autosaveName: String,
        content: Content,
        resizable: Bool = true
    ) -> NSWindow {
        var style: NSWindow.StyleMask = [.titled, .closable, .miniaturizable, .fullSizeContentView]
        if resizable { style.insert(.resizable) }

        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: defaultSize),
            styleMask: style,
            backing: .buffered,
            defer: false
        )
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.title = title
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

        focus(window)
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
