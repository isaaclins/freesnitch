import SwiftUI
import AppKit

/// The state and the actions of a user-initiated uninstall.
///
/// This is an object owned by `WindowManager`, not `@State` on a page, because
/// the teardown is irreversible and runs in steps that wait on macOS. While it
/// lived on the Settings page, clicking another sidebar row mid-teardown threw
/// away the progress and the screen that says what is still left to do (#133).
/// Here the flow keeps its place even if the sheet is closed between the
/// deactivation and the removal.
///
/// This is a deliberate, user-confirmed teardown. It is NOT the repair path and
/// shares no code with it. It is also the one and only place in FreeSnitch that
/// unregisters the privileged helper: doing that silently, outside an uninstall
/// the user asked for, is the incident in #24.
@MainActor
final class UninstallFlowModel: ObservableObject {
    enum FinishState: Equatable {
        case idle
        case working
        /// Everything the app can remove is gone; only quitting is left.
        case done
        /// The automated removal did not happen, so the commands are offered
        /// as a fallback rather than as the plan.
        case failed(String)
    }

    @Published var isPresented = false
    @Published var removeDatabase = false
    @Published var acknowledged = false
    @Published var confirming = false
    @Published private(set) var startedAt: Date?
    @Published var finishState: FinishState = .idle

    private let state: AppState
    private let systemExtension: SystemExtensionManager

    init(state: AppState, systemExtension: SystemExtensionManager) {
        self.state = state
        self.systemExtension = systemExtension
    }

    var hasStarted: Bool { startedAt != nil }

    /// Closing is refused while the privileged step is in flight, because that
    /// one cannot be resumed halfway, and after it succeeded, because by then
    /// the only honest way out of a trashed app is to quit it.
    var canClose: Bool {
        switch finishState {
        case .working, .done: return false
        case .idle, .failed: return true
        }
    }

    func present() { isPresented = true }

    func begin() {
        startedAt = Date()
        // Enforcement first: the pf anchor and the DNS proxy belong to the
        // helper, and the user asked for the firewall to stop. This is the same
        // path the Enforcement toggle uses.
        if state.enforcementEnabled {
            state.enforcementEnabled = false
        }
        state.appendLog(level: "info", message: "User-initiated uninstall: deactivating the network extension.")
        systemExtension.deactivateForUninstall()
    }

    /// The part that used to be homework: unregister the helper, then remove
    /// the root-owned data and the app itself behind one authorization prompt,
    /// then the user's own files, which need no authorization at all.
    func finish() {
        finishState = .working
        if let problem = state.helper.unregisterDaemonForUninstall() {
            // Not fatal: the removal below still takes the bundle away, and the
            // launchd record for a missing bundle is inert. Recorded so the
            // failure is not silent.
            state.appendLog(level: "error",
                            message: "Uninstall could not unregister the helper: \(problem)")
        }
        let alsoDatabase = removeDatabase
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let outcome = PrivilegedUninstall.run(removingDatabase: alsoDatabase)
            Task { @MainActor in
                guard let self else { return }
                switch outcome {
                case .success:
                    PrivilegedUninstall.removeUserData()
                    // Finder moves the bundle, not us. That is what makes
                    // macOS remove the embedded system extension; deleting the
                    // bundle directly strands it.
                    PrivilegedUninstall.trashApplicationBundle { problem in
                        if let problem {
                            self.finishState = .failed("FreeSnitch removed its helper and data, but could not move itself to the Trash: \(problem) Drag FreeSnitch from Applications to the Trash in Finder to finish, which is also what removes the system extension.")
                            return
                        }
                        self.state.appendLog(level: "info", message: "Uninstall completed; the app was moved to the Trash.")
                        self.finishState = .done
                    }
                case .failure(.cancelled):
                    self.finishState = .idle
                case .failure(.failed(let reason)):
                    self.finishState = .failed(reason)
                }
            }
        }
    }

    /// The last step of the uninstall, and the only one left once the bundle is
    /// in the Trash: a copy of FreeSnitch that keeps running from there still
    /// owns a menu bar item and still holds its XPC connections open.
    func quit() {
        NSApp.terminate(nil)
    }
}

/// The Uninstall pane of Settings. The flow itself is a sheet, so this page is
/// the door to it and nothing more.
struct UninstallView: View {
    @ObservedObject var flow: UninstallFlowModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Remove FreeSnitch from this Mac").font(.headline)
                Text("FreeSnitch installs a privileged helper and a network system extension. Under System Integrity Protection only this app can deactivate the extension, so start here rather than deleting the app.")
                    .font(.caption).foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Divider()
            Text(flow.hasStarted
                 ? "An uninstall is already under way. It keeps its place, so you can pick it up where you left it."
                 : "The uninstall runs in its own window, in one pass, and tells you what it is doing at each step.")
                .font(.caption).foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button(flow.hasStarted ? "Continue removing FreeSnitch…" : "Uninstall FreeSnitch…",
                   role: .destructive) { flow.present() }
            Spacer(minLength: 0)
        }
        .padding(16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
    }
}

/// The uninstall itself, presented as a sheet on the main window.
///
/// A sheet rather than a page: the window's sidebar cannot be reached while it
/// is up, so a misclick can no longer abandon a half-finished teardown, and the
/// state behind it belongs to `UninstallFlowModel` rather than to this view.
///
/// Under System Integrity Protection the app is the only component macOS lets
/// deactivate its own system extension: `systemextensionsctl uninstall` refuses
/// to run at all. So this drives the deactivation and then states, without
/// decoration, what happened.
struct UninstallFlowSheet: View {
    @EnvironmentObject var state: AppState
    @ObservedObject var flow: UninstallFlowModel
    @ObservedObject var systemExtension: SystemExtensionManager

    private var appPath: String { "/Applications/FreeSnitch.app" }
    private var supportPath: String { "/Library/Application Support/FreeSnitch" }
    private var databasePath: String { "\(supportPath)/freesnitch.sqlite" }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
                .padding(.horizontal, 20)
                .padding(.top, 20)
                .padding(.bottom, 12)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if !flow.hasStarted {
                        plan
                        consent
                    } else {
                        progress
                        remainingSteps
                    }
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            Divider()
            footer
                .padding(.horizontal, 20)
                .padding(.vertical, 14)
        }
        .frame(width: 620, height: 560)
        // The teardown must not be dismissed out from under itself while the
        // authorization prompt is up or once the bundle is already gone.
        .interactiveDismissDisabled(!flow.canClose)
        .confirmationDialog("Uninstall FreeSnitch?",
                            isPresented: $flow.confirming,
                            titleVisibility: .visible) {
            Button("Turn off filtering and deactivate the extension", role: .destructive) {
                flow.begin()
            }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text("This turns off enforcement, removes the content filter configuration, and asks macOS to deactivate the FreeSnitch network extension. Your Mac stops being filtered by FreeSnitch immediately. The next step unregisters the privileged helper and removes the data and the app, asking you to authorize that once.")
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Remove FreeSnitch from this Mac").font(.headline)
            Text("Under System Integrity Protection only this app can deactivate its own network extension, so the uninstall runs from here rather than from Finder.")
                .font(.caption).foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: - Before confirmation

    private var plan: some View {
        VStack(alignment: .leading, spacing: 10) {
            labelledList(title: "FreeSnitch does this itself, in this order",
                         items: ["Turns enforcement off, so the pf anchor and the DNS proxy stop.",
                                 "Removes the content filter configuration and asks macOS to deactivate the network extension, which usually completes only after a restart.",
                                 "Unregisters the privileged helper, which is what takes it out of System Settings > General > Login Items & Extensions. An uninstall you confirmed is the only place FreeSnitch removes its own service.",
                                 "Flushes the shared puresnitch pf anchor and deletes its data, behind one authorization prompt.",
                                 "Moves FreeSnitch to the Trash through Finder, which is what makes macOS remove the network extension.",
                                 "Quits, when you press the button that says so."])
            labelledList(title: "You do this",
                         items: ["Authorize the single prompt macOS shows. Nothing here needs Terminal.",
                                 "Restart the Mac if macOS reports that the extension goes away only after a restart."])
            Toggle("Also delete the stored policy database", isOn: $flow.removeDatabase)
            keptAndDeleted
        }
    }

    private var keptAndDeleted: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Deleted").font(.caption.bold())
            bullet("\(appPath), the app bundle including the helper and the extension binaries")
            bullet("\(supportPath)/Insights, the recorded traffic observations")
            bullet("FreeSnitch's own files in your home folder: its group container, its application support folder and its preferences")
            if flow.removeDatabase {
                bullet("\(databasePath), your rules, profiles and blocklists. This file can exceed 300 MB. It cannot be recovered.")
            }
            Text("Kept").font(.caption.bold()).padding(.top, 4)
            if !flow.removeDatabase {
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
            Toggle("I understand this turns off the FreeSnitch firewall on this Mac", isOn: $flow.acknowledged)
                .toggleStyle(.checkbox)
            Text(flow.acknowledged ? "You will be asked to confirm once more." : "Select the checkbox above first.")
                .font(.caption).foregroundColor(.secondary)
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
        case .removed: return Color(nsColor: .systemGreen)
        case .failed: return Color(nsColor: .systemRed)
        default: return Color(nsColor: .systemYellow)
        }
    }

    private var remainingSteps: some View {
        VStack(alignment: .leading, spacing: 10) {
            Divider()
            switch flow.finishState {
            case .idle:
                Text("Finish removing FreeSnitch").font(.subheadline.weight(.semibold))
                Text("FreeSnitch unregisters the privileged helper, flushes its firewall anchor, deletes its data and moves itself to the Trash. macOS asks you to authorize that once. Nothing here needs Terminal.")
                    .font(.caption).foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Text(flow.removeDatabase
                     ? "Includes deleting \(databasePath). That is permanent."
                     : "Keeps \(databasePath) so a reinstall finds your rules.")
                    .font(.caption).foregroundColor(.secondary)
            case .working:
                ProgressView("Removing FreeSnitch…").controlSize(.small)
            case .done:
                Text("FreeSnitch has been removed").font(.subheadline.weight(.semibold))
                Text("The helper is unregistered, the data is gone, and FreeSnitch is in your Trash. macOS removes the network extension as part of that move.")
                    .font(.caption).foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                step(1, "Check it worked: `systemextensionsctl list` should print no FreeSnitch row. If it still does, macOS did not complete the removal.")
                step(2, "If a FreeSnitch row remains, open System Settings > General > Login Items & Extensions, click the i next to Network Extensions, and choose Delete Extension. A restart also clears records left in this state.")
                step(3, "Quit FreeSnitch. The copy in your Trash is still running, and quitting is what removes its menu bar item.")
            case .failed(let reason):
                Text("FreeSnitch could not finish removing itself").font(.subheadline.weight(.semibold))
                Text(reason)
                    .font(.caption).foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Text("Or remove it by hand with these commands. They flush only the shared puresnitch anchor and never disable pf globally.")
                    .font(.caption).foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                commandBlock
            }
        }
    }

    // MARK: - Footer

    /// One row for the action that moves the flow on and the way out of it, so
    /// the primary button is always in the same place.
    private var footer: some View {
        HStack(spacing: 10) {
            if flow.canClose {
                Button(flow.hasStarted ? "Close" : "Cancel") { flow.isPresented = false }
                    .keyboardShortcut(.cancelAction)
            }
            if flow.hasStarted && flow.canClose {
                Text("Closing keeps the uninstall where it is; Settings brings it back.")
                    .font(.caption).foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            primaryAction
        }
    }

    @ViewBuilder
    private var primaryAction: some View {
        if !flow.hasStarted {
            Button("Uninstall FreeSnitch…", role: .destructive) { flow.confirming = true }
                .disabled(!flow.acknowledged)
        } else {
            switch flow.finishState {
            case .idle:
                Button("Remove FreeSnitch") { flow.finish() }
                    .keyboardShortcut(.defaultAction)
            case .working:
                ProgressView().controlSize(.small)
            case .done:
                Button("Quit FreeSnitch") { flow.quit() }
                    .keyboardShortcut(.defaultAction)
            case .failed:
                Button("Try again") { flow.finish() }
                    .keyboardShortcut(.defaultAction)
            }
        }
    }

    private var commandBlock: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(commands)
                .font(.caption.monospaced())
                .textSelection(.enabled)
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.accentColor.opacity(0.08))
                .cornerRadius(6)
            HStack {
                Button("Copy commands") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(commands, forType: .string)
                }
                Text(flow.removeDatabase
                     ? "Includes deleting \(databasePath). That is permanent."
                     : "Keeps \(databasePath) so a reinstall finds your rules.")
                    .font(.caption).foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    /// Fallback only, shown after the automated removal failed.
    ///
    /// This deliberately no longer mentions `Scripts/uninstall_freesnitch.sh`:
    /// that file only exists in a source checkout, so telling someone who
    /// installed from the DMG to run it was an instruction that could not be
    /// followed. Order matters: the pf anchor is flushed while the app is
    /// still on disk.
    private var commands: String {
        var lines = [
            "sudo /sbin/pfctl -a puresnitch -F all",
            "sudo /sbin/pfctl -a puresnitch -f /dev/null",
            "sudo /bin/rm -rf \"\(supportPath)/Insights\"",
        ]
        if flow.removeDatabase {
            lines.append("sudo /bin/rm -f \"\(databasePath)\"")
        }
        return lines.joined(separator: "\n")
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
