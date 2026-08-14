import SwiftUI

/// The one shape FreeSnitch uses to say something is wrong or worth knowing.
///
/// It replaces the full-bleed coloured strips this app used to paint across the
/// top of a panel. macOS does not have edge-to-edge status bands: System
/// Settings states a problem in a rounded, lightly tinted card inside the
/// content, and a card can sit next to other cards without the window turning
/// into a stack of coloured bars.
///
/// The tint carries severity and nothing else. Text stays in the system label
/// colours so it keeps its contrast in both appearances.
struct NoticeCard: View {
    let title: String
    var detail: String? = nil
    let icon: String
    let tint: Color
    var compact: Bool = false
    var actionTitle: String? = nil
    var action: (() -> Void)? = nil

    var body: some View {
        Group {
            if compact {
                // 380pt of popover minus an inline button leaves the text a
                // column three words wide, so the button drops to its own line
                // and the sentence gets the whole width (#91).
                VStack(alignment: .leading, spacing: 8) {
                    message
                    if actionTitle != nil {
                        HStack { Spacer(minLength: 0); button }
                    }
                }
            } else {
                // The icon rides with the first line of text, the button is
                // centred on the card. Aligning the whole row to the top left
                // the button hanging above its own centre line (#93).
                HStack(alignment: .center, spacing: 10) {
                    message
                    Spacer(minLength: 8)
                    button
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(compact ? 10 : 12)
        .background(tint.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(tint.opacity(0.25), lineWidth: 1)
        )
    }

    private var message: some View {
        HStack(alignment: detail == nil ? .center : .top, spacing: 10) {
            Image(systemName: icon)
                .foregroundStyle(tint)
                .font(compact ? .callout : .title3)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(compact ? .caption.weight(.semibold) : .callout.weight(.semibold))
                    .fixedSize(horizontal: false, vertical: true)
                if let detail {
                    Text(detail)
                        .font(compact ? .caption2 : .callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    @ViewBuilder
    private var button: some View {
        if let actionTitle, let action {
            Button(actionTitle, action: action)
                .buttonStyle(.borderedProminent)
                .controlSize(compact ? .small : .regular)
        }
    }
}
