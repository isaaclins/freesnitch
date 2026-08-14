import SwiftUI
import AppKit

/// A real `NSSearchField`.
///
/// SwiftUI has no search field of its own outside a navigation container, and
/// `.searchable` needs a navigation container this window deliberately does not
/// use (see the NavigationSplitView note in `MainWindowView`). A plain
/// `TextField` is not the same control: it has no magnifier, no clear button,
/// no search-field bezel, and no Escape-to-clear. Wrapping the AppKit control
/// gets all of that, plus whatever macOS does to it next, for free.
struct NativeSearchField: NSViewRepresentable {
    @Binding var text: String
    var placeholder: String = "Search"

    func makeNSView(context: Context) -> NSSearchField {
        let field = NSSearchField()
        field.placeholderString = placeholder
        field.delegate = context.coordinator
        field.sendsSearchStringImmediately = true
        field.sendsWholeSearchString = false
        return field
    }

    func updateNSView(_ nsView: NSSearchField, context: Context) {
        // Only write back when it actually differs, otherwise every keystroke
        // resets the insertion point to the end of the field.
        if nsView.stringValue != text {
            nsView.stringValue = text
        }
    }

    func makeCoordinator() -> Coordinator {
        Coordinator(text: $text)
    }

    final class Coordinator: NSObject, NSSearchFieldDelegate {
        private let text: Binding<String>

        init(text: Binding<String>) {
            self.text = text
        }

        func controlTextDidChange(_ notification: Notification) {
            guard let field = notification.object as? NSSearchField else { return }
            text.wrappedValue = field.stringValue
        }
    }
}
