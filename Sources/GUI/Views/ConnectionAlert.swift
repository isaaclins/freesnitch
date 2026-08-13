import SwiftUI

struct ConnectionAlertView: View {
    @EnvironmentObject var state: AppState
    let alert: AppState.PendingAlert
    @State private var remember: Bool = true
    @State private var scope: AlertScope = .anyConnection
    @State private var duration: AlertDuration = .forever

    enum AlertScope: String, CaseIterable, Identifiable {
        case anyConnection = "any connection"
        case thisHost = "this host"
        case thisIPandPort = "this IP and port"
        var id: String { rawValue }
    }
    enum AlertDuration: String, CaseIterable, Identifiable {
        case forever = "Forever"
        case session = "Until quit"
        case oneHour = "1 hour"
        case oneDay = "24 hours"
        var id: String { rawValue }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 32))
                    .foregroundColor(PSTheme.accent)
                VStack(alignment: .leading, spacing: 2) {
                    Text(alert.connection.processName.isEmpty ? "Unknown" : alert.connection.processName)
                        .font(.system(size: 16, weight: .bold)).foregroundColor(PSTheme.textPrimary)
                    Text("wants to connect to").font(.system(size: 12)).foregroundColor(PSTheme.textSecondary)
                }
                Spacer()
            }
            HStack(spacing: 8) {
                Image(systemName: "globe.americas").foregroundColor(PSTheme.accentBlue)
                Text(alert.connection.remoteHost.isEmpty ? alert.connection.remoteIP : alert.connection.remoteHost)
                    .font(.system(size: 14, weight: .semibold)).foregroundColor(PSTheme.textPrimary)
                if alert.connection.remotePort > 0 {
                    Text(":\(alert.connection.remotePort)").font(.system(size: 13, weight: .regular)).foregroundColor(PSTheme.textSecondary)
                }
                Spacer()
            }
            .padding(10)
            .background(PSTheme.bgTertiary)
            .clipShape(RoundedRectangle(cornerRadius: 8))

            if let context = state.firstContactContext(for: alert.connection) {
                Text(context)
                    .font(.system(size: 11)).foregroundColor(PSTheme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text("Today: \(state.firstContactAskedToday) asked, \(state.knownContactsAllowedToday) silently allowed (already known)")
                .font(.system(size: 10)).foregroundColor(PSTheme.textMuted)

            VStack(alignment: .leading, spacing: 6) {
                Toggle("Remember this decision", isOn: $remember)
                    .toggleStyle(.checkbox)
                    .foregroundColor(PSTheme.textPrimary)
                Picker("Scope", selection: $scope) {
                    ForEach(AlertScope.allCases) { s in Text(s.rawValue).tag(s) }
                }.disabled(!remember)
                Picker("Duration", selection: $duration) {
                    ForEach(AlertDuration.allCases) { d in Text(d.rawValue).tag(d) }
                }.disabled(!remember)
            }

            HStack {
                Button("Deny") { state.resolveAlert(alert, allow: false, remember: remember) }
                    .keyboardShortcut(.cancelAction)
                    .buttonStyle(.borderedProminent)
                    .tint(.red)
                Spacer()
                Button("Allow") { state.resolveAlert(alert, allow: true, remember: remember) }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .tint(.green)
            }
        }
        .padding(18)
        .frame(width: 440)
        .background(PSTheme.bgPrimary)
        .preferredColorScheme(.dark)
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
struct AlertWindowContent: View {
    @EnvironmentObject var state: AppState
    var body: some View {
        Group {
            if let alert = state.pendingAlerts.first {
                ConnectionAlertView(alert: alert).environmentObject(state)
            } else {
                Color.clear.frame(width: 440, height: 1)
            }
        }
    }
}
