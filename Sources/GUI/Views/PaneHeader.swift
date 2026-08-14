import SwiftUI

/// One header band, shared by every pane on a page.
///
/// The bands used to be built ad hoc: each pane wrapped its own title in its
/// own padding, so the heights came out a point or two apart, the titles sat on
/// different baselines, and the divider under each header landed at a different
/// y. Where those dividers met the vertical divider between panes, the lines
/// missed each other and left a notch (#77).
///
/// So the height is a constant rather than something derived from the text.
/// Padding around a font is rounded per font and per control, which is exactly
/// what made the bands disagree; a fixed height and a centred row cannot.
struct PaneHeader<Trailing: View>: View {
    let title: String
    var count: Int?
    @ViewBuilder var trailing: () -> Trailing

    /// Every pane header on a page is this tall, to the pixel.
    static var height: CGFloat { 30 }

    var body: some View {
        HStack(spacing: 8) {
            Text(title)
                .font(.headline)
                .lineLimit(1)
            if let count {
                Text("\(count)")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
            Spacer(minLength: 8)
            trailing()
        }
        .padding(.horizontal, 12)
        .frame(height: Self.height)
        .frame(maxWidth: .infinity)
        .background(.bar)
    }
}

extension PaneHeader where Trailing == EmptyView {
    init(_ title: String, count: Int? = nil) {
        self.init(title: title, count: count) { EmptyView() }
    }
}

extension PaneHeader {
    init(_ title: String, count: Int? = nil, @ViewBuilder trailing: @escaping () -> Trailing) {
        self.init(title: title, count: count, trailing: trailing)
    }
}

/// A pane: one header band, the divider under it, then content. Using this
/// everywhere is what keeps the dividers on one line across the window.
struct HeaderedPane<Header: View, Content: View>: View {
    @ViewBuilder var header: () -> Header
    @ViewBuilder var content: () -> Content

    var body: some View {
        VStack(spacing: 0) {
            header()
            Divider()
            content()
        }
    }
}
