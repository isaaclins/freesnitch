import SwiftUI
import AppKit

/// The draggable edge of a resizable pane.
///
/// This is an `NSView` rather than a SwiftUI `DragGesture` because the gesture
/// never saw the press. The handle sits in the seam beside a `Table`, which is
/// a real `NSTableView` inside an `NSScrollView`, and AppKit hit testing in
/// that seam wins against a SwiftUI shape: hover never fired and neither did
/// the drag. An `NSView` is on the same footing as its neighbours, and it gets
/// a proper cursor rect instead of push and pop bookkeeping on every hover.
struct PaneResizeHandle: NSViewRepresentable {
    /// The pointer's horizontal offset, in points, from where the drag began.
    /// Left is negative, the way AppKit reports it.
    let onDrag: (CGFloat) -> Void
    let onEnd: () -> Void

    func makeNSView(context: Context) -> HandleView {
        let view = HandleView()
        view.onDrag = onDrag
        view.onEnd = onEnd
        return view
    }

    func updateNSView(_ nsView: HandleView, context: Context) {
        nsView.onDrag = onDrag
        nsView.onEnd = onEnd
    }

    final class HandleView: NSView {
        var onDrag: ((CGFloat) -> Void)?
        var onEnd: (() -> Void)?
        private var startX: CGFloat = 0

        override func resetCursorRects() {
            addCursorRect(bounds, cursor: .resizeLeftRight)
        }

        override func mouseDown(with event: NSEvent) {
            startX = event.locationInWindow.x
        }

        override func mouseDragged(with event: NSEvent) {
            onDrag?(event.locationInWindow.x - startX)
        }

        override func mouseUp(with event: NSEvent) {
            onEnd?()
        }

        /// The handle is a pointer target, not a stop on the keyboard's tour of
        /// the window.
        override var acceptsFirstResponder: Bool { false }

        override var isFlipped: Bool { true }
    }
}
