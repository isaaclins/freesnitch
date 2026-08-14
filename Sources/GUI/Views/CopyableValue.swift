import AppKit
import SwiftUI

/// A value in an inspector that copies itself when clicked.
///
/// Every field in the Information pane is something the reader wants somewhere
/// else: a path into a terminal, a bundle id into a bug report, a host into a
/// browser. Apple's own inspectors treat these as one-click copies rather than
/// asking the reader to drag-select text in a 240 point pane, and they confirm
/// it in place instead of opening anything (#94).
///
/// The confirmation replaces the value for a moment and then the value returns.
/// Nothing is dismissed, nothing has to be acknowledged, and the pane does not
/// change size while it happens.
struct CopyableValue: View {
    let value: String
    /// Copied instead of the displayed text when the two differ, for a field
    /// that is shown short but is worth copying in full.
    var copyValue: String?

    @State private var copied = false
    @State private var hovering = false

    var body: some View {
        if value.isEmpty {
            Text(value)
        } else {
            Button(action: copy) {
                Text(copied ? "Copied" : value)
                    .foregroundStyle(copied ? AnyShapeStyle(Color.accentColor) : AnyShapeStyle(.primary))
                    .multilineTextAlignment(.trailing)
                    .padding(.horizontal, 4)
                    .padding(.vertical, 1)
                    .background(
                        RoundedRectangle(cornerRadius: 4)
                            .fill(Color.primary.opacity(hovering && !copied ? 0.08 : 0))
                    )
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .onHover { hovering = $0 }
            .help(copied ? "Copied" : "Copy \(value)")
            .accessibilityLabel(value)
            .accessibilityHint("Copies this value")
        }
    }

    private func copy() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(copyValue ?? value, forType: .string)
        withAnimation(.easeOut(duration: 0.12)) { copied = true }
        // Long enough to read, short enough that the value is back before the
        // reader looks for it again.
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
            withAnimation(.easeIn(duration: 0.2)) { copied = false }
        }
    }
}
