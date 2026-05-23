import AppKit
import SwiftUI
import Combine

@MainActor
final class MenubarController {
    private let state: AppState
    private let windows: WindowManager
    private var statusItem: NSStatusItem!
    private var popover: NSPopover!
    private var trafficCancellable: AnyCancellable?

    init(state: AppState, windows: WindowManager) {
        self.state = state
        self.windows = windows
    }

    func install() {
        statusItem = NSStatusBar.system.statusItem(withLength: 72)
        if let button = statusItem.button {
            button.imagePosition = .imageLeft
            button.action = #selector(handleClick(_:))
            button.target = self
            button.sendAction(on: [.leftMouseUp, .rightMouseUp])
        }

        popover = NSPopover()
        popover.behavior = .transient
        popover.animates = true
        let popoverView = MenubarPopoverView(close: { [weak self] in self?.popover.performClose(nil) })
            .environmentObject(state)
            .environmentObject(windows)
            .frame(width: 380, height: 540)
        popover.contentViewController = NSHostingController(rootView: popoverView)

        render()

        trafficCancellable = state.$trafficHistory
            .receive(on: RunLoop.main)
            .sink { [weak self] _ in self?.render() }
    }

    @objc private func handleClick(_ sender: AnyObject?) {
        guard let button = statusItem.button else { return }
        if let event = NSApp.currentEvent, event.type == .rightMouseUp {
            showContextMenu()
            return
        }
        if popover.isShown {
            popover.performClose(sender)
        } else {
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
            NSApp.activate(ignoringOtherApps: true)
        }
    }

    private func showContextMenu() {
        let menu = NSMenu()
        menu.addItem(makeItem("Network Monitor…", #selector(openMonitor), keyEq: "n"))
        menu.addItem(makeItem("Rules…", #selector(openRules), keyEq: "r"))
        menu.addItem(makeItem("Settings…", #selector(openSettings), keyEq: ","))
        menu.addItem(.separator())
        let modeMenu = NSMenu(title: "Mode")
        modeMenu.addItem(makeItem("Alert", #selector(modeAlert), keyEq: "", state: state.mode == .alert ? .on : .off))
        modeMenu.addItem(makeItem("Silent Allow", #selector(modeAllow), keyEq: "", state: state.mode == .silentAllow ? .on : .off))
        modeMenu.addItem(makeItem("Silent Deny", #selector(modeDeny), keyEq: "", state: state.mode == .silentDeny ? .on : .off))
        let modeItem = NSMenuItem(title: "Mode", action: nil, keyEquivalent: "")
        modeItem.submenu = modeMenu
        menu.addItem(modeItem)
        menu.addItem(.separator())
        menu.addItem(makeItem("Quit PureSnitch", #selector(quit), keyEq: "q"))
        statusItem.menu = menu
        statusItem.button?.performClick(nil)
        statusItem.menu = nil
    }

    private func makeItem(_ title: String, _ sel: Selector, keyEq: String, state: NSControl.StateValue = .off) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: sel, keyEquivalent: keyEq)
        item.target = self
        item.state = state
        return item
    }

    @objc private func openMonitor() { windows.showNetworkMonitor() }
    @objc private func openRules() { windows.showRulesManager() }
    @objc private func openSettings() { windows.showSettings() }
    @objc private func modeAlert() { state.setMode(.alert) }
    @objc private func modeAllow() { state.setMode(.silentAllow) }
    @objc private func modeDeny() { state.setMode(.silentDeny) }
    @objc private func quit() { NSApp.terminate(nil) }

    private func render() {
        guard let button = statusItem.button else { return }
        let image = makeStatusImage()
        button.image = image
        button.imagePosition = .imageOnly
        let formatter = NumberFormatter()
        formatter.maximumFractionDigits = 1
        button.toolTip = "↓ \(PSFormat.bytesPerSec(state.currentIn))  ↑ \(PSFormat.bytesPerSec(state.currentOut))"
    }

    private func makeStatusImage() -> NSImage {
        let history = Array(state.trafficHistory.suffix(20))
        let inSpeed = state.currentIn
        let outSpeed = state.currentOut
        let inText = compactSpeed(inSpeed)
        let outText = compactSpeed(outSpeed)
        let size = NSSize(width: 80, height: 22)
        let img = NSImage(size: size)
        img.lockFocus()
        defer { img.unlockFocus() }

        // text
        let attrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.monospacedDigitSystemFont(ofSize: 9, weight: .semibold),
            .foregroundColor: NSColor.white.withAlphaComponent(0.95)
        ]
        let inStr = NSAttributedString(string: inText, attributes: attrs.merging([.foregroundColor: NSColor(red: 1.0, green: 0.45, blue: 0.95, alpha: 1)]) { _, b in b })
        let outStr = NSAttributedString(string: outText, attributes: attrs.merging([.foregroundColor: NSColor(red: 0.45, green: 0.65, blue: 1.0, alpha: 1)]) { _, b in b })
        inStr.draw(at: NSPoint(x: 1, y: 11))
        outStr.draw(at: NSPoint(x: 1, y: 1))

        // bars
        let barAreaX: CGFloat = 38
        let barAreaW: CGFloat = 40
        let barCount = min(8, max(history.count, 1))
        let barW: CGFloat = (barAreaW - CGFloat(barCount - 1) * 1.0) / CGFloat(barCount)
        let maxIn: CGFloat = max(1, CGFloat(history.map { $0.bytesIn }.max() ?? 1))
        let maxOut: CGFloat = max(1, CGFloat(history.map { $0.bytesOut }.max() ?? 1))
        for i in 0..<barCount {
            guard i < history.count else { break }
            let h = history[history.count - barCount + i]
            let x = barAreaX + CGFloat(i) * (barW + 1)
            let topH = min(10, CGFloat(h.bytesIn) / maxIn * 10)
            let botH = min(10, CGFloat(h.bytesOut) / maxOut * 10)
            NSColor(red: 1.0, green: 0.45, blue: 0.95, alpha: 1).setFill()
            NSBezierPath(rect: NSRect(x: x, y: 11, width: barW, height: max(1, topH))).fill()
            NSColor(red: 0.45, green: 0.65, blue: 1.0, alpha: 1).setFill()
            NSBezierPath(rect: NSRect(x: x, y: 11 - max(1, botH), width: barW, height: max(1, botH))).fill()
        }
        img.isTemplate = false
        return img
    }

    private func compactSpeed(_ n: Int64) -> String {
        let b = Double(n)
        if b < 1024 { return "\(Int(b)) B/s" }
        if b < 1024 * 1024 { return String(format: "%.0f K/s", b/1024) }
        if b < 1024 * 1024 * 1024 { return String(format: "%.1f M/s", b/1024/1024) }
        return String(format: "%.1f G/s", b/1024/1024/1024)
    }
}

extension WindowManager: ObservableObject {}
