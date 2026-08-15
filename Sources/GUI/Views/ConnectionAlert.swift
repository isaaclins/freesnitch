import SwiftUI

struct ConnectionAlertView: View {
    @EnvironmentObject var state: AppState
    let alert: AppState.PendingAlert
    @State private var remember: Bool = true
    @State private var scope: AlertScope = .anyConnection
    @State private var duration: AlertDuration = .forever

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

    /// The raw value is storage, the title is interface text. Showing the
    /// raw value put lowercase fragments in a pop-up menu (#118).
    enum AlertScope: String, CaseIterable, Identifiable {
        case anyConnection = "any connection"
        case thisHost = "this host"
        case thisIPandPort = "this IP and port"
        var id: String { rawValue }
        var title: String {
            switch self {
            case .anyConnection: return "Any connection"
            case .thisHost: return "This host"
            case .thisIPandPort: return "This IP and port"
            }
        }
    }
    enum AlertDuration: String, CaseIterable, Identifiable {
        case forever = "Forever"
        case session = "Until quit"
        case oneHour = "1 hour"
        case oneDay = "24 hours"
        var id: String { rawValue }
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

            // `.columns` aligns the labels in one column and the controls in
            // another, which is what a Mac dialog does and what three
            // hand-stacked rows never quite manage.
            Form {
                Toggle("Remember this decision", isOn: $remember)
                Picker("Scope", selection: $scope) {
                    ForEach(AlertScope.allCases) { s in Text(s.title).tag(s) }
                }.disabled(!remember)
                Picker("Duration", selection: $duration) {
                    ForEach(AlertDuration.allCases) { d in Text(d.rawValue).tag(d) }
                }.disabled(!remember)
            }
            .formStyle(.columns)

            HStack(spacing: 12) {
                Spacer(minLength: 0)
                // Standard buttons. The red and green pills this used to have
                // were the only two of their kind on the system: macOS says
                // "which one is the default" with the accent fill, and says
                // everything else with the words on the button.
                Button("Deny") { state.resolveAlert(alert, allow: false, remember: remember) }
                    .keyboardShortcut(.cancelAction)
                Button("Allow") { state.resolveAlert(alert, allow: true, remember: remember) }
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
