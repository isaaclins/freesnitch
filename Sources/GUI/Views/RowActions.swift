import SwiftUI
import AppKit

/// The small actions several context menus need.
///
/// A context menu must run the same code as the button beside it, never a
/// second implementation of the same idea (#78). The decisions themselves stay
/// where they already live, in the controllers; only copying and revealing are
/// here, because nothing else owned them.
enum RowActions {
    static func copy(_ text: String) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(text, forType: .string)
    }

    /// Only offered when there is something on disk to point at, so the menu
    /// never carries an item that does nothing.
    static func canReveal(path: String?) -> Bool {
        guard let path, !path.isEmpty else { return false }
        return FileManager.default.fileExists(atPath: path)
    }

    static func revealInFinder(path: String?) {
        guard let path, !path.isEmpty else { return }
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }
}

/// A copy item that is only present when there is something to copy.
///
/// A literal title is a localized key, the way `Button("...")` takes one; a
/// String is shown as it is, so a caller can still pass `String(localized:)`.
struct CopyMenuItem: View {
    let title: Text
    let value: String?

    init(title: LocalizedStringKey, value: String?) {
        self.title = Text(title)
        self.value = value
    }

    @_disfavoredOverload
    init(title: String, value: String?) {
        self.title = Text(verbatim: title)
        self.value = value
    }

    var body: some View {
        if let value, !value.isEmpty {
            Button { RowActions.copy(value) } label: { title }
        }
    }
}
