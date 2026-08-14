import AppKit
import Combine
import SwiftUI

/// The window's real `NSToolbar`.
///
/// FreeSnitch used to draw its own toolbar inside the content: a row of
/// borderless glyphs and a text field on a tinted strip. That is a drawing of a
/// toolbar. A real one lives in the title bar, is laid out by the system, gets
/// the unified titlebar treatment, participates in full screen, keeps its
/// height and metrics across OS releases, and on macOS 26 and later is rendered
/// as Liquid Glass without this app asking for anything.
///
/// The search field in particular is an `NSSearchToolbarItem`, which is exactly
/// what Finder and Mail use: it collapses to a button when the window is narrow
/// and expands on click, which no hand-placed field does.
@MainActor
final class MainToolbarController: NSObject, NSToolbarDelegate, NSSearchFieldDelegate {
    private static let sidebarItemID = NSToolbarItem.Identifier("freesnitch.sidebar")
    private static let searchItemID = NSToolbarItem.Identifier("freesnitch.search")

    private let model: MainWindowModel
    private var cancellables: Set<AnyCancellable> = []
    private weak var toolbar: NSToolbar?
    private weak var searchField: NSSearchField?

    init(model: MainWindowModel) {
        self.model = model
        super.init()
    }

    func makeToolbar() -> NSToolbar {
        let toolbar = NSToolbar(identifier: "freesnitch.main")
        toolbar.delegate = self
        toolbar.allowsUserCustomization = false
        toolbar.displayMode = .iconOnly
        self.toolbar = toolbar

        // The search field only exists on pages that search. A field that is
        // present but inert on Settings would be worse than no field at all.
        model.$page
            .receive(on: RunLoop.main)
            .sink { [weak self] page in self?.apply(page) }
            .store(in: &cancellables)
        return toolbar
    }

    private func apply(_ page: MainPage) {
        guard let toolbar else { return }
        searchField?.placeholderString = page.searchPlaceholder
        if searchField?.stringValue.isEmpty == false {
            searchField?.stringValue = ""
            model.searchText = ""
        }
        let index = toolbar.items.firstIndex { $0.itemIdentifier == Self.searchItemID }
        if page.supportsSearch, index == nil {
            toolbar.insertItem(withItemIdentifier: Self.searchItemID, at: toolbar.items.count)
        } else if !page.supportsSearch, let index {
            toolbar.removeItem(at: index)
        }
    }

    // MARK: NSToolbarDelegate

    func toolbarDefaultItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        var identifiers: [NSToolbarItem.Identifier] = [Self.sidebarItemID, .flexibleSpace]
        if model.page.supportsSearch { identifiers.append(Self.searchItemID) }
        return identifiers
    }

    func toolbarAllowedItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        [Self.sidebarItemID, .flexibleSpace, Self.searchItemID]
    }

    func toolbar(_ toolbar: NSToolbar,
                 itemForItemIdentifier itemIdentifier: NSToolbarItem.Identifier,
                 willBeInsertedIntoToolbar flag: Bool) -> NSToolbarItem? {
        switch itemIdentifier {
        case Self.sidebarItemID:
            let item = NSToolbarItem(itemIdentifier: itemIdentifier)
            item.label = "Sidebar"
            item.paletteLabel = "Sidebar"
            item.toolTip = "Hide or show the sidebar"
            item.image = NSImage(systemSymbolName: "sidebar.left", accessibilityDescription: "Sidebar")
            item.target = self
            item.action = #selector(toggleSidebar)
            item.isNavigational = true
            return item
        case Self.searchItemID:
            let item = NSSearchToolbarItem(itemIdentifier: itemIdentifier)
            item.searchField.delegate = self
            item.searchField.placeholderString = model.page.searchPlaceholder
            item.searchField.sendsSearchStringImmediately = true
            item.searchField.sendsWholeSearchString = false
            searchField = item.searchField
            return item
        default:
            return nil
        }
    }

    @objc private func toggleSidebar() {
        model.isSidebarVisible.toggle()
    }

    // MARK: NSSearchFieldDelegate

    func controlTextDidChange(_ notification: Notification) {
        guard let field = notification.object as? NSSearchField else { return }
        model.searchText = field.stringValue
    }
}
