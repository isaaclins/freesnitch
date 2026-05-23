import AppKit
import SwiftUI

@MainActor
final class WindowManager {
    private let state: AppState
    private weak var networkMonitorWindow: NSWindow?
    private weak var rulesWindow: NSWindow?
    private weak var alertWindow: NSWindow?

    init(state: AppState) { self.state = state }

    func showNetworkMonitor() {
        if let w = networkMonitorWindow {
            w.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true); return
        }
        let view = NetworkMonitorView().environmentObject(state)
        let hosting = NSHostingController(rootView: view)
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1100, height: 700),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.title = "Network Monitor"
        window.contentViewController = hosting
        window.minSize = NSSize(width: 900, height: 550)
        window.center()
        window.isReleasedWhenClosed = false
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        networkMonitorWindow = window
    }

    func showRulesManager() {
        if let w = rulesWindow {
            w.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true); return
        }
        let view = RulesManagerView().environmentObject(state)
        let hosting = NSHostingController(rootView: view)
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1000, height: 650),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.title = "Rules"
        window.contentViewController = hosting
        window.minSize = NSSize(width: 820, height: 500)
        window.center()
        window.isReleasedWhenClosed = false
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        rulesWindow = window
    }

    func showSettings() {
        NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
        NSApp.activate(ignoringOtherApps: true)
    }
}
