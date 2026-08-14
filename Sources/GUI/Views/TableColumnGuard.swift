import AppKit
import SwiftUI

/// Keeps a `Table`'s columns inside the pane that holds them.
///
/// SwiftUI's `Table` is an `NSTableView`, and an `NSTableView` left at its
/// default resizing style hands a dragged divider's growth to the table's total
/// width: the columns past the drag are pushed beyond the clip view, where they
/// are simply not drawn. In this app that meant Action and Status, the two
/// columns that say what a rule actually does, could be dragged off the edge
/// and there was no scroll bar to bring them back (#92).
///
/// `uniformColumnAutoresizingStyle` makes a drag redistribute the width it
/// takes among the other columns instead of growing the table, which is the
/// behaviour Mail and the Finder's list view have. The minimum widths declared
/// on the SwiftUI columns still hold, so a drag stops rather than crushing a
/// column to nothing.
///
/// It is applied as a background view because SwiftUI exposes none of this:
/// the view finds the table by walking the AppKit hierarchy it was planted in.
struct TableColumnGuard: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView { GuardView() }

    func updateNSView(_ nsView: NSView, context: Context) {}

    private final class GuardView: NSView {
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            guard window != nil else { return }
            // The table is a sibling of this view's ancestors, and SwiftUI
            // builds it after the background, so the search runs once the
            // current layout pass has finished.
            DispatchQueue.main.async { [weak self] in self?.constrainTable() }
        }

        private func constrainTable() {
            guard let table = Self.findTable(from: self) else { return }
            table.columnAutoresizingStyle = .uniformColumnAutoresizingStyle
            table.sizeLastColumnToFit()
        }

        /// Walks up a few levels and searches each ancestor's subtree. Four
        /// levels is enough to reach the scroll view that holds the table
        /// without scanning the whole window.
        private static func findTable(from view: NSView) -> NSTableView? {
            var ancestor: NSView? = view
            for _ in 0..<4 {
                guard let current = ancestor else { return nil }
                if let table = firstTable(in: current) { return table }
                ancestor = current.superview
            }
            return nil
        }

        private static func firstTable(in view: NSView) -> NSTableView? {
            if let table = view as? NSTableView { return table }
            for subview in view.subviews {
                if let table = firstTable(in: subview) { return table }
            }
            return nil
        }
    }
}
