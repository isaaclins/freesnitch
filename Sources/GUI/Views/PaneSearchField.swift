import AppKit
import SwiftUI

/// A real `NSSearchField` for a pane that does its own searching.
///
/// SwiftUI has no search field of its own on macOS: `.searchable` gives you the
/// window's toolbar, and a plain `TextField` is missing the magnifier, the
/// clear button, the rounded metrics and the Escape behaviour that make a Mac
/// search field recognisable. A blocklist of 300,000 names needs a field beside
/// the list it filters, not one at the far corner of the window (#96).
///
/// The field also takes focus on demand, which is what makes Command-F work
/// without a hidden text view or a focus hack.
struct PaneSearchField: NSViewRepresentable {
    @Binding var text: String
    var placeholder: String
    /// Increment to move the keyboard focus into this field.
    var focusToken: Int

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSSearchField {
        let field = NSSearchField()
        field.delegate = context.coordinator
        // Both, deliberately. A search field inside a SwiftUI hosting view did
        // not deliver `controlTextDidChange` at all, so the typed text never
        // reached the query and the list sat there unfiltered; the target and
        // action pair is what actually fires here.
        field.target = context.coordinator
        field.action = #selector(Coordinator.searchChanged(_:))
        field.placeholderString = placeholder
        field.sendsSearchStringImmediately = true
        field.sendsWholeSearchString = false
        field.controlSize = .regular
        field.focusRingType = .default
        return field
    }

    func updateNSView(_ field: NSSearchField, context: Context) {
        context.coordinator.parent = self
        if field.stringValue != text { field.stringValue = text }
        if field.placeholderString != placeholder { field.placeholderString = placeholder }
        guard context.coordinator.lastFocusToken != focusToken else { return }
        context.coordinator.lastFocusToken = focusToken
        // The first token arrives while the view is being installed, so the
        // window is asked for focus once the current pass is over.
        DispatchQueue.main.async {
            field.window?.makeFirstResponder(field)
        }
    }

    final class Coordinator: NSObject, NSSearchFieldDelegate {
        var parent: PaneSearchField
        var lastFocusToken: Int

        init(_ parent: PaneSearchField) {
            self.parent = parent
            self.lastFocusToken = parent.focusToken
        }

        func controlTextDidChange(_ notification: Notification) {
            guard let field = notification.object as? NSSearchField else { return }
            parent.text = field.stringValue
        }

        @objc func searchChanged(_ sender: NSSearchField) {
            parent.text = sender.stringValue
        }
    }
}
