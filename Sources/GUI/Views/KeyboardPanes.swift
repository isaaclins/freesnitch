import SwiftUI
import AppKit

/// The panes of the Rules page, in Tab order (#85).
enum RulesPane: Int, CaseIterable, Hashable {
    case categories
    case table
    case inspector

    var accessibilityLabel: String {
        switch self {
        case .categories: return "Categories"
        case .table: return "Rules"
        case .inspector: return "Information"
        }
    }
}

/// Reports the AppKit window hosting a SwiftUI view, so a key handler can tell
/// its own window from any other window the app has open.
struct WindowReader: NSViewRepresentable {
    let onWindow: (NSWindow?) -> Void

    func makeNSView(context: Context) -> NSView {
        let view = NSView(frame: .zero)
        // The window is not set during makeNSView, so read it once the view has
        // actually been placed in a hierarchy.
        DispatchQueue.main.async { onWindow(view.window) }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        DispatchQueue.main.async { onWindow(nsView.window) }
    }
}

/// Tab and Shift-Tab traversal between panes.
///
/// This deployment target is macOS 13, which has no `onKeyPress`, and the key
/// view loop does not reach a SwiftUI `Table` hosted inside an AppKit-owned
/// window, so the page watches for Tab itself.
///
/// The monitor is deliberately timid. It only acts while its own window is key,
/// no sheet is up, and nothing is being typed into, so it cannot take Tab away
/// from a text field, the toolbar search field, or a modal dialog. Every other
/// event is returned untouched.
struct PaneTabTraversal: ViewModifier {
    let advance: (Bool) -> Void
    @State private var monitor: Any?
    @State private var hostWindow: NSWindow?

    private static let tabKeyCode: UInt16 = 48

    func body(content: Content) -> some View {
        content
            .background(WindowReader { hostWindow = $0 })
            .onAppear { install() }
            .onDisappear { remove() }
    }

    private func install() {
        guard monitor == nil else { return }
        monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
            guard event.keyCode == Self.tabKeyCode else { return event }
            let modifiers = event.modifierFlags.intersection(.deviceIndependentFlagsMask)
            guard modifiers.subtracting(.shift).isEmpty else { return event }
            guard let key = NSApp.keyWindow, key === hostWindow, key.attachedSheet == nil else { return event }
            // NSText covers the field editor, which is what a focused text
            // field or search field actually leaves as first responder.
            if key.firstResponder is NSText { return event }
            advance(modifiers.contains(.shift))
            return nil
        }
    }

    private func remove() {
        guard let monitor else { return }
        NSEvent.removeMonitor(monitor)
        self.monitor = nil
    }
}

extension View {
    func paneTabTraversal(_ advance: @escaping (Bool) -> Void) -> some View {
        modifier(PaneTabTraversal(advance: advance))
    }

    /// A focus ring for panes AppKit does not draw one for, matching the system
    /// ring closely enough to read as the same thing.
    ///
    /// The inset keeps the whole ring inside the pane. A pane flush with the
    /// window edge would otherwise have the outer half of its ring clipped away
    /// by the window, and the ring would look broken on one side.
    func paneFocusRing(_ focused: Bool) -> some View {
        overlay(
            RoundedRectangle(cornerRadius: 6)
                .strokeBorder(Color.accentColor, lineWidth: 3)
                .opacity(focused ? 0.6 : 0)
                .padding(2)
                .allowsHitTesting(false)
        )
    }
}
