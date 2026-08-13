import SwiftUI
import AppKit

/// The uninstall flow, reachable from Settings.
///
/// Under System Integrity Protection the app is the only component macOS lets
/// deactivate its own system extension: `systemextensionsctl uninstall` refuses
/// to run at all. So this view drives the deactivation and then states, without
/// decoration, which of the remaining steps it cannot perform and which of them
/// need administrator rights.
///
/// This is a deliberate, user-initiated teardown. It is NOT the repair path and
/// shares no code with it: it never unregisters, boots out, or kickstarts the
/// privileged helper. Removing that service is the user's own switch in System
/// Settings. Doing it silently on someone's behalf is the incident in #24.
struct UninstallView: View {
    @EnvironmentObject var state: AppState
    @ObservedObject var systemExtension: SystemExtensionManager

    @State private var removeDatabase = false
    @State private var acknowledged = false
    @State private var confirming = false
    @State private var startedAt: Date?

    private var appPath: String { "/Applications/FreeSnitch.app" }
    private var supportPath: String { "/Library/Application Support/FreeSnitch" }
    private var databasePath: String { "\(supportPath)/freesnitch.sqlite" }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                header
                Divider()
                if startedAt == nil {
                    plan
                    consent
                } else {
                    progress
                    remainingSteps
                }
            }
            .padding(.vertical, 4)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .confirmationDialog("Uninstall FreeSnitch?",
                            isPresented: $confirming,
                            titleVisibility: .visible) {
            Button("Turn Off Filtering and Deactivate the Extension", role: .destructive) {
                beginUninstall()
            }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text("This turns off enforcement, disables the content filter, and asks macOS to deactivate the FreeSnitch network extension. Your Mac stops being filtered by FreeSnitch immediately. The helper and the app are removed by you afterwards, with the commands shown next.")
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Remove FreeSnitch from this Mac").font(.headline)
            Text("FreeSnitch installs a privileged helper and a network system extension. Under System Integrity Protection only this app can deactivate the extension, so start here rather than deleting the app.")
                .font(.caption).foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: - Before confirmation

    private var plan: some View {
        VStack(alignment: .leading, spacing: 10) {
            labelledList(title: "FreeSnitch does this itself",
                         items: ["Turns enforcement off, so the pf anchor and the DNS proxy stop.",
                                 "Disables the content filter configuration.",
                                 "Asks macOS to deactivate the network extension, which usually completes only after a reboot."])
            labelledList(title: "You do this, with administrator rights",
                         items: ["Switch FreeSnitch off in System Settings > General > Login Items & Extensions. That is what removes the privileged helper; FreeSnitch never removes its own service for you.",
                                 "Run the commands shown after confirmation to flush the shared pf anchor and delete the app."])
            Toggle("Also delete the stored policy database", isOn: $removeDatabase)
            keptAndDeleted
        }
    }

    private var keptAndDeleted: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Deleted").font(.caption.bold())
            bullet("\(appPath), the app bundle including the helper and the extension binaries")
            bullet("\(supportPath)/Insights, the recorded traffic observations")
            if removeDatabase {
                bullet("\(databasePath), your rules, profiles and blocklists. This file can exceed 300 MB. It cannot be recovered.")
            }
            Text("Kept").font(.caption.bold()).padding(.top, 4)
            if !removeDatabase {
                bullet("\(databasePath), your rules, profiles and blocklists. Reinstalling FreeSnitch picks them up again.")
            }
            bullet("The empty puresnitch pf anchor file, because /etc/pf.conf still references it. Removing it while pf.conf points at it would strand your firewall configuration.")
            bullet("Legacy PureSnitch user data, which FreeSnitch never touches.")
        }
        .font(.caption)
        .foregroundColor(.secondary)
        .fixedSize(horizontal: false, vertical: true)
    }

    private var consent: some View {
        VStack(alignment: .leading, spacing: 8) {
            Divider()
            Toggle("I understand this turns off the FreeSnitch firewall on this Mac", isOn: $acknowledged)
                .toggleStyle(.checkbox)
            HStack {
                Button("Uninstall FreeSnitch…", role: .destructive) { confirming = true }
                    .disabled(!acknowledged)
                Text(acknowledged ? "You will be asked to confirm once more." : "Tick the box above first.")
                    .font(.caption).foregroundColor(.secondary)
            }
        }
    }

    // MARK: - After confirmation

    private var progress: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: statusIcon).foregroundColor(statusTint)
                VStack(alignment: .leading, spacing: 3) {
                    Text(statusTitle).font(.subheadline.weight(.semibold))
                    Text(statusDetail).font(.caption).foregroundColor(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            HStack {
                Button("Open Network Extensions") { systemExtension.openNetworkExtensionsSettings() }
                Button("Open Login Items") { state.helper.openLoginItemsSettings() }
            }
        }
    }

    /// Reports the answer macOS gave, never the fact that a request was
    /// accepted. `.deactivating` means no answer has arrived yet.
    private var statusTitle: String {
        switch systemExtension.uninstallState {
        case .idle, .deactivating: return "Waiting for macOS to answer"
        case .notInstalled: return "No extension was registered from this app"
        case .pendingReboot: return "Deactivation finishes after a restart"
        case .removed: return "macOS reports the extension is gone"
        case .failed: return "macOS refused the deactivation"
        }
    }

    private var statusDetail: String {
        switch systemExtension.uninstallState {
        case .idle, .deactivating:
            return "The deactivation request was submitted. That is not the same as removal, so nothing is claimed until the system reports back. Approving the prompt in System Settings, if one appears, lets it proceed."
        case .notInstalled:
            return "This build has no embedded system extension, or macOS holds no record for \(AppConstants.bundleIdNetExt). There is nothing to deactivate. The steps below still apply to the helper, the app, and the data."
        case .pendingReboot:
            return "macOS accepted the request but still holds a record for \(AppConstants.bundleIdNetExt). It is removed at the next restart. Until then `systemextensionsctl list` keeps showing it, and the app must stay where it is. Restart, then continue below."
        case .removed:
            return "A properties request finds no record for \(AppConstants.bundleIdNetExt) any more. Continue with the steps below."
        case .failed(let message):
            return "\(message) The extension is still registered. Do not delete the app yet: that leaves a registered extension whose bundle is gone. Retry after a restart, or check `systemextensionsctl list`."
        }
    }

    private var statusIcon: String {
        switch systemExtension.uninstallState {
        case .idle, .deactivating: return "hourglass"
        case .notInstalled: return "info.circle.fill"
        case .pendingReboot: return "arrow.clockwise.circle.fill"
        case .removed: return "checkmark.circle.fill"
        case .failed: return "xmark.octagon.fill"
        }
    }

    private var statusTint: Color {
        switch systemExtension.uninstallState {
        case .removed: return PSTheme.accentGreen
        case .failed: return PSTheme.accentRed
        default: return PSTheme.accentYellow
        }
    }

    private var remainingSteps: some View {
        VStack(alignment: .leading, spacing: 10) {
            Divider()
            Text("What is left, in order").font(.subheadline.weight(.semibold))
            step(1, "Switch FreeSnitch off in System Settings > General > Login Items & Extensions. This removes the privileged helper's registration. FreeSnitch deliberately does not do this for you.")
            step(2, "Restart your Mac if the status above says the deactivation finishes after a restart. Deleting the app before that leaves macOS holding an extension record whose bundle is gone.")
            step(3, "Run these commands in Terminal. Every line needs administrator rights, which is what `sudo` asks for. They flush only the shared puresnitch anchor, they never disable pf globally.")
            commandBlock
            step(4, "Confirm nothing is left: `systemextensionsctl list | grep freesnitch` should print no FreeSnitch row.")
        }
    }

    private var commandBlock: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(commands)
                .font(.caption.monospaced())
                .textSelection(.enabled)
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(PSTheme.accent.opacity(0.08))
                .cornerRadius(6)
            HStack {
                Button("Copy Commands") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(commands, forType: .string)
                }
                Text(removeDatabase
                     ? "Includes deleting \(databasePath). That is permanent."
                     : "Keeps \(databasePath) so a reinstall finds your rules.")
                    .font(.caption).foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    /// The same work the shipped script does, spelled out for people who
    /// installed from the DMG and have no checkout. Order matters: the pf
    /// anchor is flushed while the app is still on disk.
    private var commands: String {
        var lines = [
            "sudo /sbin/pfctl -a puresnitch -F all",
            "sudo /sbin/pfctl -a puresnitch -f /dev/null",
            "sudo /bin/rm -rf \"\(supportPath)/Insights\"",
        ]
        if removeDatabase {
            lines.append("sudo /bin/rm -f \"\(databasePath)\"")
        }
        lines.append("sudo /bin/rm -rf \"\(appPath)\"")
        lines.append("")
        lines.append("# From a source checkout, this does the same with the safety guards:")
        lines.append("sudo bash Scripts/uninstall_freesnitch.sh --yes\(removeDatabase ? " --remove-database" : "")")
        return lines.joined(separator: "\n")
    }

    // MARK: - Actions

    private func beginUninstall() {
        startedAt = Date()
        // Enforcement first: the pf anchor and DNS proxy belong to the helper,
        // and the user asked for the firewall to stop. This is the same path
        // the Enforcement toggle uses; nothing here unregisters the helper.
        if state.enforcementEnabled {
            state.enforcementEnabled = false
        }
        state.appendLog(level: "info", message: "User-initiated uninstall: deactivating the network extension.")
        systemExtension.deactivateForUninstall()
    }

    // MARK: - Small pieces

    private func labelledList(title: String, items: [String]) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption.bold())
            ForEach(items, id: \.self) { bullet($0) }
        }
        .font(.caption)
        .foregroundColor(.secondary)
        .fixedSize(horizontal: false, vertical: true)
    }

    private func bullet(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Text("•")
            Text(text).fixedSize(horizontal: false, vertical: true)
        }
    }

    private func step(_ number: Int, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text("\(number).").font(.caption.monospacedDigit().bold())
            Text(text).font(.caption).fixedSize(horizontal: false, vertical: true)
        }
        .foregroundColor(.secondary)
    }
}
