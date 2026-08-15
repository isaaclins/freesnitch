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
/// A window whose toolbar is structure rather than decoration.
///
/// The main window's toolbar holds the title, the sidebar control and the
/// search field. AppKit offers Hide Toolbar from the toolbar's own contextual
/// menu and remembers the answer, so one right click took the title, the search
/// and the sidebar button away for good and the window came back that way on
/// every later launch (#90). Finder, Mail and System Settings all refuse this
/// for the same reason: there is nothing left to show.
final class ToolbarLockedWindow: NSWindow {
    override func toggleToolbarShown(_ sender: Any?) {}

    override func validateUserInterfaceItem(_ item: NSValidatedUserInterfaceItem) -> Bool {
        switch item.action {
        case #selector(toggleToolbarShown(_:)), #selector(runToolbarCustomizationPalette(_:)):
            return false
        default:
            return super.validateUserInterfaceItem(item)
        }
    }
}

@MainActor
final class MainToolbarController: NSObject, NSToolbarDelegate, NSSearchFieldDelegate {
    private static let sidebarItemID = NSToolbarItem.Identifier("freesnitch.sidebar")
    private static let titleItemID = NSToolbarItem.Identifier("freesnitch.title")
    private static let searchItemID = NSToolbarItem.Identifier("freesnitch.search")

    private let model: MainWindowModel
    private var cancellables: Set<AnyCancellable> = []
    private weak var toolbar: NSToolbar?
    private weak var searchField: NSSearchField?
    private let titleView = ContentTitleView()

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
        // A page that carries its own search field takes the toolbar's away,
        // so the window never shows two fields searching different things
        // (#96).
        model.$contentOwnsSearch
            .receive(on: RunLoop.main)
            .sink { [weak self] _ in
                guard let self else { return }
                self.apply(self.model.page)
            }
            .store(in: &cancellables)
        // Find. The toolbar answers only while it is the one holding the
        // field; otherwise the pane's own field takes the caret.
        model.$searchFocusToken
            .dropFirst()
            .receive(on: RunLoop.main)
            .sink { [weak self] _ in self?.focusSearchField() }
            .store(in: &cancellables)
        // The title has to move with the sidebar, or hiding the sidebar leaves
        // it hanging in the middle of the content.
        model.$isSidebarVisible
            .combineLatest(model.$sidebarWidth)
            .receive(on: RunLoop.main)
            .sink { [weak self] visible, width in
                self?.titleView.contentEdge = MainWindowMetrics.contentEdge(sidebarVisible: visible,
                                                                            sidebarWidth: width)
            }
            .store(in: &cancellables)
        titleView.contentEdge = MainWindowMetrics.contentEdge(sidebarVisible: model.isSidebarVisible,
                                                              sidebarWidth: model.sidebarWidth)
        titleView.subtitle = model.page.title
        return toolbar
    }

    private func apply(_ page: MainPage) {
        guard let toolbar else { return }
        titleView.subtitle = page.title
        searchField?.placeholderString = page.searchPlaceholder
        if searchField?.stringValue.isEmpty == false {
            searchField?.stringValue = ""
            model.searchText = ""
        }
        let index = toolbar.items.firstIndex { $0.itemIdentifier == Self.searchItemID }
        if model.toolbarOwnsSearch, index == nil {
            toolbar.insertItem(withItemIdentifier: Self.searchItemID, at: toolbar.items.count)
        } else if !model.toolbarOwnsSearch, let index {
            toolbar.removeItem(at: index)
        }
    }

    private func focusSearchField() {
        guard model.toolbarOwnsSearch, let field = searchField else { return }
        field.window?.makeFirstResponder(field)
    }

    // MARK: NSToolbarDelegate

    func toolbarDefaultItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        var identifiers: [NSToolbarItem.Identifier] = [Self.sidebarItemID, Self.titleItemID, .flexibleSpace]
        if model.toolbarOwnsSearch { identifiers.append(Self.searchItemID) }
        return identifiers
    }

    func toolbarAllowedItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        [Self.sidebarItemID, Self.titleItemID, .flexibleSpace, Self.searchItemID]
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
        case Self.titleItemID:
            let item = NSToolbarItem(itemIdentifier: itemIdentifier)
            item.label = ""
            item.paletteLabel = "Title"
            item.view = titleView
            item.visibilityPriority = .high
            // macOS 26 puts every toolbar item on a piece of glass, grouped by
            // the type of its view. A window title is not a control and must
            // not sit in a capsule, and isBordered is the documented opt out
            // (WWDC25 "Build an AppKit app with the new design").
            item.isBordered = false
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

/// The window title and the page name, drawn inside the content area.
///
/// AppKit places the window title immediately after the leading toolbar items,
/// which on this window is over the sidebar, so the text straddled the seam
/// between two materials (#74). The usual answer is
/// `NSTrackingSeparatorToolbarItem`, which aligns toolbar items to a split view
/// divider, but it requires a real `NSSplitView` and this window's split is a
/// SwiftUI `HStack`.
///
/// So the title is a toolbar item that measures where it actually landed and
/// pads itself up to the content edge. Hiding the sidebar sets that edge to
/// zero and the title slides back beside the sidebar button, the way Finder's
/// does, without anyone computing toolbar item widths by hand.
final class ContentTitleView: NSView {
    private let titleLabel = NSTextField(labelWithString: "FreeSnitch")
    private let subtitleLabel = NSTextField(labelWithString: "")
    private let stack = NSStackView()
    private var leadingInset: NSLayoutConstraint!

    /// Window x of the content pane's leading edge.
    var contentEdge: CGFloat = 0 {
        didSet {
            guard contentEdge != oldValue else { return }
            updateInset()
        }
    }

    var subtitle: String = "" {
        didSet {
            guard subtitle != oldValue else { return }
            subtitleLabel.stringValue = subtitle
            subtitleLabel.isHidden = subtitle.isEmpty
        }
    }

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        titleLabel.font = .systemFont(ofSize: 13, weight: .semibold)
        titleLabel.textColor = .labelColor
        subtitleLabel.font = .systemFont(ofSize: 11, weight: .regular)
        subtitleLabel.textColor = .secondaryLabelColor
        for label in [titleLabel, subtitleLabel] {
            label.lineBreakMode = .byTruncatingTail
            label.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        }
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 0
        stack.translatesAutoresizingMaskIntoConstraints = false
        stack.addArrangedSubview(titleLabel)
        stack.addArrangedSubview(subtitleLabel)
        addSubview(stack)
        leadingInset = stack.leadingAnchor.constraint(equalTo: leadingAnchor)
        NSLayoutConstraint.activate([
            leadingInset,
            stack.centerYAnchor.constraint(equalTo: centerYAnchor),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor)
        ])
        frame = NSRect(x: 0, y: 0, width: Self.width, height: Self.height)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("not used") }

    private static let width: CGFloat = 320
    private static let height: CGFloat = 38

    override var intrinsicContentSize: NSSize {
        NSSize(width: Self.width, height: Self.height)
    }

    /// A toolbar item's view learns its own position only once the toolbar has
    /// placed it, so the inset is measured rather than assumed, and written
    /// only when it actually changed so this cannot drive a layout loop.
    ///
    /// This is called directly from every event that can move the title rather
    /// than through `needsLayout`: the toolbar builds its items before the
    /// window has a toolbar at all, so the first pass measures an origin of
    /// zero, and marking an unattached view as needing layout does not survive
    /// to the pass that finally places it.
    private func updateInset() {
        guard window != nil else { return }
        let originInWindow = convert(NSPoint.zero, to: nil).x
        let wanted = max(0, contentEdge - originInWindow + MainWindowMetrics.contentInset)
        guard abs(leadingInset.constant - wanted) > 0.5 else { return }
        leadingInset.constant = wanted
    }

    override func layout() {
        super.layout()
        updateInset()
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        updateInset()
        DispatchQueue.main.async { [weak self] in self?.updateInset() }
    }

    override func setFrameOrigin(_ newOrigin: NSPoint) {
        super.setFrameOrigin(newOrigin)
        updateInset()
    }

    override func setFrameSize(_ newSize: NSSize) {
        super.setFrameSize(newSize)
        updateInset()
    }

    /// The title bar is a drag region. A label that swallowed clicks would make
    /// the top of the window feel dead.
    override func hitTest(_ point: NSPoint) -> NSView? { nil }
}
