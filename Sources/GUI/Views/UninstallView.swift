import SwiftUI
import AppKit
import Combine

/// The state and the actions of a user-initiated uninstall.
///
/// This is an object owned by `WindowManager`, not `@State` on a page, because
/// the teardown is irreversible and runs in steps that wait on macOS. While it
/// lived on the Settings page, clicking another sidebar row mid-teardown threw
/// away the progress (#133).
///
/// After one confirmation the whole uninstall runs by itself, in this order
/// (#391): turn enforcement off; remove the content filter configuration and
/// deactivate the network extension, and wait for macOS to answer; unregister
/// the helper; flush the pf anchor and delete the data behind one password
/// prompt; move the app to the Trash; quit. The helper and the app are only
/// touched once macOS confirmed the extension is stopped, because an app
/// removed while its extension still runs leaves that extension behind.
///
/// This is a deliberate, user-confirmed teardown. It is NOT the repair path and
/// shares no code with it. It is also the one and only place in FreeSnitch that
/// unregisters the privileged helper: doing that silently, outside an uninstall
/// the user asked for, is the incident in #24.
@MainActor
final class UninstallFlowModel: ObservableObject {
    enum Phase: Equatable {
        /// Nothing has happened yet.
        case ready
        /// Filter off, extension deactivation submitted, waiting for macOS.
        case removingFilter
        /// Helper, pf anchor and data, behind one password prompt.
        case removingHelper
        case movingToTrash
        /// Everything is gone; macOS clears the stopped extension's record at
        /// the next restart. Shown instead of quitting at once, so the one
        /// sentence about the restart can be read.
        case doneUntilRestart
        case failed(Failure)
    }

    enum Failure: Equatable {
        /// macOS kept the network extension. Nothing else was removed.
        case filterKept(String)
        /// The person cancelled the password prompt.
        case passwordCancelled
        /// The privileged step failed.
        case helperKept(String)
        /// Everything is removed except the app bundle itself.
        case appKept(String)
    }

    @Published var isPresented = false
    @Published var removeDatabase = false
    @Published var confirming = false
    @Published private(set) var phase: Phase = .ready

    private let state: AppState
    private let systemExtension: SystemExtensionManager
    private var extensionAnswer: AnyCancellable?
    private let demo = ProcessInfo.processInfo.environment["FREESNITCH_DEMO"] == "1"

    init(state: AppState, systemExtension: SystemExtensionManager) {
        self.state = state
        self.systemExtension = systemExtension
        extensionAnswer = systemExtension.$uninstallState
            .receive(on: DispatchQueue.main)
            .sink { [weak self] answer in self?.extensionAnswered(answer) }
    }

    var hasStarted: Bool { phase != .ready }

    var isWorking: Bool {
        switch phase {
        case .removingFilter, .removingHelper, .movingToTrash: return true
        default: return false
        }
    }

    /// Closing is refused while a step is running and once the app is gone,
    /// because by then the only honest way out is to quit.
    var canClose: Bool {
        switch phase {
        case .ready: return true
        case .failed(.appKept): return false
        case .failed: return true
        default: return false
        }
    }

    func present() { isPresented = true }

    /// The one confirmed action. Everything after it runs by itself.
    func start() {
        phase = .removingFilter
        if demo { runDemo(); return }
        // Enforcement first: the pf anchor and the DNS proxy belong to the
        // helper, and the user asked for the firewall to stop. This is the
        // same path the Enforcement toggle uses.
        if state.enforcementEnabled {
            state.enforcementEnabled = false
        }
        state.appendLog(level: "info", message: "Uninstall: turning off and removing the network filter.")
        if systemExtension.uninstallState.extensionIsGone {
            removeHelperAndData()
            return
        }
        systemExtension.deactivateForUninstall()
    }

    func retry() {
        guard case .failed(let failure) = phase else { return }
        switch failure {
        case .filterKept: start()
        case .passwordCancelled, .helperKept: removeHelperAndData()
        case .appKept: quit()
        }
    }

    private func extensionAnswered(_ answer: SystemExtensionManager.UninstallState) {
        guard phase == .removingFilter, !demo else { return }
        switch answer {
        case .idle, .deactivating:
            return
        case .failed(let reason):
            state.appendLog(level: "error", message: "Uninstall: macOS kept the network extension: \(reason)")
            phase = .failed(.filterKept(reason))
        case .notInstalled, .pendingReboot, .removed:
            removeHelperAndData()
        }
    }

    /// Unregister the helper, then remove the root-owned data behind one
    /// authorization prompt, then the user's own files, then the app.
    private func removeHelperAndData() {
        phase = .removingHelper
        if demo { return }
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
                    self.moveToTrash()
                case .failure(.cancelled):
                    self.phase = .failed(.passwordCancelled)
                case .failure(.failed(let reason)):
                    self.state.appendLog(level: "error", message: "Uninstall could not remove the helper and data: \(reason)")
                    self.phase = .failed(.helperKept(reason))
                }
            }
        }
    }

    private func moveToTrash() {
        phase = .movingToTrash
        PrivilegedUninstall.trashApplicationBundle { [weak self] problem in
            guard let self else { return }
            if let problem {
                self.phase = .failed(.appKept(problem))
                return
            }
            self.finish()
        }
    }

    private func finish() {
        if systemExtension.uninstallState == .pendingReboot {
            phase = .doneUntilRestart
        } else {
            quit()
        }
    }

    /// Ends the process outright. `NSApp.terminate` runs the app's whole
    /// shutdown from a bundle that is already in the Trash, and that is where
    /// 1.1.0 hung until it was force quit (#391). Nothing is left to save at
    /// this point, so there is nothing for an orderly shutdown to do. The menu
    /// bar item goes with the process.
    func quit() {
        exit(0)
    }

    // MARK: - Demo

    /// `FREESNITCH_DEMO=1` walks through the screens without touching the
    /// system. `FREESNITCH_DEMO_UNINSTALL` picks the ending: `restart`
    /// (default), `quit`, `refused`, `cancelled` or `trash`.
    private func runDemo() {
        let ending = ProcessInfo.processInfo.environment["FREESNITCH_DEMO_UNINSTALL"] ?? "restart"
        let hold = Double(ProcessInfo.processInfo.environment["FREESNITCH_DEMO_UNINSTALL_HOLD"] ?? "") ?? 1.5
        DispatchQueue.main.asyncAfter(deadline: .now() + hold) { [weak self] in
            guard let self else { return }
            if ending == "refused" {
                self.phase = .failed(.filterKept("The operation couldn’t be completed."))
                return
            }
            self.phase = .removingHelper
            DispatchQueue.main.asyncAfter(deadline: .now() + hold) {
                if ending == "cancelled" { self.phase = .failed(.passwordCancelled); return }
                self.phase = .movingToTrash
                DispatchQueue.main.asyncAfter(deadline: .now() + hold) {
                    switch ending {
                    case "trash": self.phase = .failed(.appKept("You don’t have permission to access “Applications”."))
                    case "quit": self.quit()
                    default: self.phase = .doneUntilRestart
                    }
                }
            }
        }
    }
}

/// The Uninstall pane of Settings. The flow itself is a sheet, so this page is
/// the door to it and nothing more.
struct UninstallView: View {
    @ObservedObject var flow: UninstallFlowModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Uninstall FreeSnitch").font(.headline)
                Text("Removes FreeSnitch and everything it installed from this Mac.")
                    .font(.caption).foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Button(flow.hasStarted ? "Continue Uninstalling…" : "Uninstall FreeSnitch…",
                   role: .destructive) { flow.present() }
            Spacer(minLength: 0)
        }
        .padding(16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
    }
}

/// The uninstall itself, presented as a sheet on the main window, so a
/// misclick on the sidebar cannot abandon a half-finished teardown.
struct UninstallFlowSheet: View {
    @ObservedObject var flow: UninstallFlowModel
    @ObservedObject var systemExtension: SystemExtensionManager

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 14) {
                content
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            // While a step runs there is nothing to press, so no button row.
            if !flow.isWorking || showsApprovalButton {
                Divider()
                footer
                    .padding(.horizontal, 20)
                    .padding(.vertical, 14)
            }
        }
        .frame(width: 460)
        .fixedSize(horizontal: false, vertical: true)
        .interactiveDismissDisabled(!flow.canClose)
        .confirmationDialog("Uninstall FreeSnitch?",
                            isPresented: $flow.confirming,
                            titleVisibility: .visible) {
            Button("Uninstall", role: .destructive) { flow.start() }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text("FreeSnitch stops protecting this Mac right away.")
        }
    }

    /// While macOS waits for the person to allow the removal, the way there
    /// is the one thing to press.
    private var showsApprovalButton: Bool {
        flow.phase == .removingFilter && systemExtension.uninstallNeedsApproval
    }

    @ViewBuilder
    private var content: some View {
        switch flow.phase {
        case .ready:
            Text("Uninstall FreeSnitch").font(.headline)
            Text("This turns off FreeSnitch and removes everything it installed: its network filter, its background helper and its firewall rules. Then FreeSnitch moves itself to the Trash and quits.")
                .fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 2) {
                Toggle("Also delete my rules and profiles", isOn: $flow.removeDatabase)
                    .toggleStyle(.checkbox)
                Text(flow.removeDatabase
                     ? "They can’t be recovered."
                     : "They are kept, so they come back if you install FreeSnitch again.")
                    .font(.caption).foregroundColor(.secondary)
                    .padding(.leading, 20)
            }
        case .removingFilter, .removingHelper, .movingToTrash:
            Text("Uninstalling FreeSnitch").font(.headline)
            steps
        case .doneUntilRestart:
            headline("FreeSnitch is uninstalled", icon: "checkmark.circle.fill", tint: Color(nsColor: .systemGreen))
            Text("FreeSnitch isn’t filtering anything now, and macOS finishes removing it the next time you restart.")
                .fixedSize(horizontal: false, vertical: true)
        case .failed(let failure):
            failureText(failure)
        }
    }

    private var steps: some View {
        VStack(alignment: .leading, spacing: 10) {
            stepRow("Turning off the network filter", done: flow.phase != .removingFilter,
                    active: flow.phase == .removingFilter,
                    note: flow.phase == .removingFilter && systemExtension.uninstallNeedsApproval
                        ? "macOS is asking you to allow this in System Settings." : nil)
            stepRow("Removing the helper and firewall rules",
                    done: flow.phase == .movingToTrash,
                    active: flow.phase == .removingHelper,
                    note: flow.phase == .removingHelper ? "Enter your password when macOS asks." : nil)
            stepRow("Moving FreeSnitch to the Trash", done: false,
                    active: flow.phase == .movingToTrash, note: nil)
        }
    }

    private func stepRow(_ title: String, done: Bool, active: Bool, note: String?) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Group {
                if done {
                    Image(systemName: "checkmark.circle.fill").foregroundColor(Color(nsColor: .systemGreen))
                } else if active {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: "circle").foregroundColor(.secondary)
                }
            }
            .frame(width: 16)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).foregroundColor(done || active ? .primary : .secondary)
                if let note {
                    Text(note).font(.caption).foregroundColor(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    @ViewBuilder
    private func failureText(_ failure: UninstallFlowModel.Failure) -> some View {
        switch failure {
        case .filterKept(let reason):
            failureHeadline(reason == SystemExtensionManager.noAnswer
                            ? "macOS didn’t answer FreeSnitch’s request to remove its network filter"
                            : "macOS didn’t let FreeSnitch remove its network filter")
            Text("Nothing else was removed. Try again. If it keeps failing, restart your Mac and try once more.")
                .fixedSize(horizontal: false, vertical: true)
            reasonText(reason)
        case .passwordCancelled:
            failureHeadline("The password prompt was cancelled")
            Text("The network filter is already removed. Try again to remove the rest.")
                .fixedSize(horizontal: false, vertical: true)
        case .helperKept(let reason):
            failureHeadline("FreeSnitch couldn’t remove its helper and firewall rules")
            Text("The network filter is already removed. Try again to remove the rest.")
                .fixedSize(horizontal: false, vertical: true)
            reasonText(reason)
        case .appKept(let reason):
            failureHeadline("FreeSnitch couldn’t move itself to the Trash")
            Text("Everything else is removed. Drag FreeSnitch from Applications to the Trash to finish.")
                .fixedSize(horizontal: false, vertical: true)
            reasonText(reason)
        }
    }

    private func failureHeadline(_ text: String) -> some View {
        headline(text, icon: "exclamationmark.triangle.fill", tint: Color(nsColor: .systemOrange))
    }

    private func headline(_ text: String, icon: String, tint: Color) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Image(systemName: icon).foregroundColor(tint)
            Text(text).fixedSize(horizontal: false, vertical: true)
        }
        .font(.headline)
    }

    /// What macOS said, kept apart from FreeSnitch's own sentence.
    private func reasonText(_ reason: String) -> some View {
        Text(reason)
            .font(.caption).foregroundColor(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    // MARK: - Footer

    private var footer: some View {
        HStack(spacing: 10) {
            if showsApprovalButton {
                Button("Open System Settings") { systemExtension.openNetworkExtensionsSettings() }
            }
            Spacer(minLength: 8)
            if flow.canClose {
                Button(flow.hasStarted ? "Close" : "Cancel") { flow.isPresented = false }
                    .keyboardShortcut(.cancelAction)
            }
            primaryAction
        }
    }

    @ViewBuilder
    private var primaryAction: some View {
        switch flow.phase {
        case .ready:
            Button("Uninstall…", role: .destructive) { flow.confirming = true }
                .keyboardShortcut(.defaultAction)
        case .removingFilter, .removingHelper, .movingToTrash:
            EmptyView()
        case .doneUntilRestart, .failed(.appKept):
            Button("Quit FreeSnitch") { flow.quit() }
                .keyboardShortcut(.defaultAction)
        case .failed:
            Button("Try Again") { flow.retry() }
                .keyboardShortcut(.defaultAction)
        }
    }
}
