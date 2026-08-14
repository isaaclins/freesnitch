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
            Spacer(minLength: 8)
            if let actionTitle, let action {
                Button(actionTitle, action: action)
                    .buttonStyle(.borderedProminent)
                    .controlSize(compact ? .small : .regular)
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
}
