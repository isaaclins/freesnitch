import SwiftUI

struct ConnectionAlertView: View {
    @EnvironmentObject var state: AppState
    let alert: AppState.PendingAlert
    @State private var remember: Bool = true
    /// The narrow answer is the default, because the wide one is the expensive
    /// mistake. These two are read by `resolveAlert` and shape the rule; they
    /// used to be decoration (#129).
    @State private var scope: AppState.RememberScope = .thisHost
    @State private var duration: AppState.RememberDuration = .forever

    /// What today has looked like, as a sentence rather than a colon label
    /// with two counts glued to it (#118).
    private var todaySummary: String? {
        let asked = state.firstContactAskedToday
        let allowed = state.knownContactsAllowedToday
        guard asked > 0 || allowed > 0 else { return nil }
        let askedPart = "asked about \(asked) new connection\(asked == 1 ? "" : "s")"
        guard allowed > 0 else { return "Today FreeSnitch has \(askedPart)." }
        return "Today FreeSnitch has \(askedPart) and silently allowed \(allowed) it already knew."
    }

    /// What is behind this dialog. A question that is one of several should say
    /// so, and an overflow that was allowed without asking should not be
    /// discoverable only by reading the code (#130).
    private var queueSummary: String? {
        var parts: [String] = []
        let waiting = state.pendingAlerts.count - 1
        if waiting > 0 { parts.append("\(waiting) more question\(waiting == 1 ? "" : "s") waiting") }
        let overflow = state.overflowAllowedToday
        if overflow > 0 {
            parts.append("\(overflow) connection\(overflow == 1 ? " was" : "s were") allowed today because the queue was full")
        }
        guard !parts.isEmpty else { return nil }
        return parts.joined(separator: ", ") + "."
    }

    /// What the answer will actually create, in the same words the Rules table
    /// uses, so the two can be recognised as the same thing.
    private var ruleSummary: String {
        let name = processName
        let host = alert.connection.remoteHost.isEmpty
            ? alert.connection.remoteIP
            : alert.connection.remoteHost
        let where_: String
        switch scope {
        case .anywhere: where_ = "any destination"
        case .thisHost: where_ = host.isEmpty ? "this destination" : host
        case .thisAddressAndPort:
            let address = alert.connection.remoteIP.isEmpty ? host : alert.connection.remoteIP
            where_ = "\(address) on port \(alert.connection.remotePort)"
        }
        let howLong: String
        switch duration {
        case .forever: howLong = "until you remove it"
        case .oneDay: howLong = "for 24 hours"
        case .oneHour: howLong = "for 1 hour"
        }
        return "Creates a rule for \(name) reaching \(where_), \(howLong)."
    }

    /// Shaped like a macOS permission dialog, because that is exactly what it
    /// is: the app's own icon, one sentence saying who wants what, the details
    /// under it, and the two answers at the bottom right with the safe one
    /// reachable by Escape.
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .center, spacing: 14) {
                // 128pt, a full app icon. This panel interrupts you to ask one
                // question, and the single most important word in it is which
                // app is asking, so the icon carries it at full size instead of
                // sitting next to the text as a thumbnail.
                appIcon
                    .frame(width: 128, height: 128)
                VStack(alignment: .leading, spacing: 4) {
                    Text(processName)
                        .font(.title.weight(.semibold))
                        .lineLimit(2)
                        .minimumScaleFactor(0.7)
                    Text("wants to connect to")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }

            // Zero spacing: the port is part of the address, not a second
            // field, so it must not float away from the colon.
            HStack(spacing: 0) {
                Text(destination)
                    .font(.body.weight(.medium))
                    .textSelection(.enabled)
                if alert.connection.remotePort > 0 {
                    Text(verbatim: ":\(alert.connection.remotePort)")
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                }
                Spacer(minLength: 0)
            }
            .padding(10)
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))

            if let context = state.firstContactContext(for: alert.connection) {
                Text(context)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            // Nothing to report is reported as nothing, not as two zeroes.
            if let todaySummary {
                Text(todaySummary)
                    .font(.footnote)
                    .foregroundStyle(.tertiary)
            }
            if let queueSummary {
                Label(queueSummary, systemImage: "clock.badge.exclamationmark")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            // `.columns` aligns the labels in one column and the controls in
            // another, which is what a Mac dialog does and what three
            // hand-stacked rows never quite manage.
            Form {
                Toggle("Remember this decision", isOn: $remember)
                Picker("Applies to", selection: $scope) {
                    ForEach(AppState.RememberScope.allCases) { s in Text(s.title).tag(s) }
                }.disabled(!remember)
                Picker("Expires", selection: $duration) {
                    ForEach(AppState.RememberDuration.allCases) { d in Text(d.title).tag(d) }
                }.disabled(!remember)
                // The rule in one sentence, so the answer can be checked before
                // it is given rather than found later in the Rules table.
                if remember {
                    Text(ruleSummary)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .formStyle(.columns)

            HStack(spacing: 12) {
                Spacer(minLength: 0)
                // Standard buttons. The red and green pills this used to have
                // were the only two of their kind on the system: macOS says
                // "which one is the default" with the accent fill, and says
                // everything else with the words on the button.
                Button("Deny") { state.resolveAlert(alert, allow: false, remember: remember, scope: scope, duration: duration) }
                    .keyboardShortcut(.cancelAction)
                Button("Allow") { state.resolveAlert(alert, allow: true, remember: remember, scope: scope, duration: duration) }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding(20)
        .frame(width: 440)
    }

    private var processName: String {
        alert.connection.processName.isEmpty ? "Unknown" : alert.connection.processName
    }

    private var destination: String {
        alert.connection.remoteHost.isEmpty ? alert.connection.remoteIP : alert.connection.remoteHost
    }

    /// The asking app's real icon, the way every macOS permission dialog
    /// identifies who is asking. The shield only appears when the app cannot be
    /// located on this Mac, which is itself worth seeing.
    @ViewBuilder private var appIcon: some View {
        if let icon = AppIcon.resolve(bundleId: alert.connection.processBundleId,
                                      path: alert.connection.processPath,
                                      name: alert.connection.processName) {
            Image(nsImage: icon)
                .resizable()
                .aspectRatio(contentMode: .fit)
        } else {
            Image(systemName: "shield.lefthalf.filled")
                .resizable()
                .aspectRatio(contentMode: .fit)
                .foregroundStyle(Color.accentColor)
        }
    }
}

struct AlertOverlayContainer: View {
    @EnvironmentObject var state: AppState
    var body: some View {
        ZStack {
            if let alert = state.pendingAlerts.first {
                Color.black.opacity(0.35).ignoresSafeArea()
                ConnectionAlertView(alert: alert).environmentObject(state)
            }
        }
    }
}

/// Content for the standalone floating alert panel (no dimming backdrop).
/// Shows the first pending alert; updates to the next one as each is resolved.
/// Carries the size the alert card actually wants out to the window that hosts
/// it. Nothing else can supply it: see `WindowManager.resizeAlertWindow`.
struct AlertContentSizeKey: PreferenceKey {
    static var defaultValue: CGSize = .zero
    static func reduce(value: inout CGSize, nextValue: () -> CGSize) {
        let next = nextValue()
        if next.height > 0 { value = next }
    }
}

struct AlertWindowContent: View {
    @EnvironmentObject var state: AppState
    var onContentSize: (CGSize) -> Void = { _ in }

    var body: some View {
        Group {
            if let alert = state.pendingAlerts.first {
                ConnectionAlertView(alert: alert).environmentObject(state)
            } else {
                Color.clear.frame(width: 440, height: 1)
            }
        }
        // Measured at its natural height rather than at whatever height the
        // window happens to have, so the number reported back is the one the
        // card wants and not the one it was given.
        .fixedSize(horizontal: false, vertical: true)
        .background(
            GeometryReader { proxy in
                Color.clear.preference(key: AlertContentSizeKey.self, value: proxy.size)
            }
        )
        .onPreferenceChange(AlertContentSizeKey.self) { onContentSize($0) }
        .frame(maxHeight: .infinity, alignment: .top)
        // The panel has a title bar for window behaviour only: it is
        // transparent, has no title and no buttons. Without this, SwiftUI still
        // inset the content by its height, so the gap above the icon was the
        // padding plus a title bar while the gap on the left was the padding
        // alone, and the panel was that much taller than it needed to be.
        .ignoresSafeArea()
    }
}
