import SwiftUI
import AppKit

/// The one piece of UI that keeps FreeSnitch honest: when the privileged helper
/// isn't approved or isn't reachable, every panel in the app reads zero. Before
/// this banner existed that state was indistinguishable from "the app is
/// broken", which is exactly what users reported.
struct HelperBanner: View {
    @EnvironmentObject var state: AppState
    @ObservedObject var systemExtension: SystemExtensionManager
    /// Compact variant for the menu-bar popover.
    var compact: Bool = false

    var body: some View {
        VStack(spacing: 0) {
            // A helper running from another copy explains a version mismatch
            // too, and there Repair Helper would only restart that other copy,
            // so this banner replaces the helper banner below (#418).
            // A copy outside Applications shows Move first: that is the step
            // that helps it, and the other copy's warning would hide it.
            if state.helperInstallState != .wrongLocation,
               let info = BannerInfo(helperOtherCopy: state.helperOtherCopyPath,
                                     thisCopy: InstallLocation.runningOriginal.path) {
                banner(info)
            } else if let info = BannerInfo(installState: state.helperInstallState,
                                     connected: state.helperConnected,
                                     needsRepair: state.helperNeedsRepair,
                                     versionState: state.helperVersionState,
                                     repairState: state.helperRepairState,
                                     repairRunning: state.helperRepairRunning) {
                banner(info)
            }
            if let info = BannerInfo(extensionStatus: systemExtension.status,
                                     snapshotStatus: state.filterSnapshotStatus) {
                banner(info)
            }
            // A firewall that will not come back after a restart looked exactly
            // like a healthy one: this state was computed and rendered nowhere
            // (#131). It stays on screen until it is resolved.
            if let info = BannerInfo(persistenceDegraded: state.filterPersistenceDegraded,
                                     unsavableReason: state.filterPersistenceUnsavable,
                                     liveRulesReady: state.filterSnapshotStatus.isReady
                                        && state.filterSnapshotStatus.generation == state.authoritativeSnapshotGeneration
                                        && state.filterSnapshotStatus.epoch == state.authoritativeSnapshotEpoch,
                                     recoveryMessage: state.filterRecoveryMessage) {
                banner(info)
            }
        }
    }

    /// An inset notice card, not a full-bleed coloured slab: see `NoticeCard`,
    /// which every panel now shares so a warning looks the same everywhere.
    private func banner(_ info: BannerInfo) -> some View {
        NoticeCard(title: info.title,
                   detail: info.detail,
                   icon: info.icon,
                   tint: info.tint,
                   compact: compact,
                   actionTitle: info.action?.title,
                   actionEnabled: info.action?.isEnabled ?? true,
                   action: info.action.map { action in
                       { action.run(state, systemExtension) }
                   })
            .padding(.horizontal, compact ? 8 : 12)
            .padding(.vertical, compact ? 6 : 10)
    }
}

private struct BannerAction {
    let title: String
    var isEnabled = true
    let run: @MainActor (AppState, SystemExtensionManager) -> Void

    /// Repair Helper, or a disabled "Repairing…" while an attempt is still
    /// running, so a second click can't start another one (#216).
    static func repair(running: Bool) -> BannerAction {
        if running {
            return BannerAction(title: String(localized: "Repairing…"), isEnabled: false) { _, _ in }
        }
        return BannerAction(title: String(localized: "Repair Helper")) { state, _ in state.helper.repairHelper() }
    }
}

@MainActor
private struct BannerInfo {
    let icon: String
    let tint: Color
    let title: String
    let detail: String
    let action: BannerAction?

    /// launchd runs the helper from the copy that registered it. After
    /// FreeSnitch is moved or copied to /Applications, that can be an older
    /// copy the user no longer opens (#418). Nothing here changes the
    /// registration: unregistering an enabled helper can remove it (#24).
    init?(helperOtherCopy: String?, thisCopy: String) {
        guard let other = helperOtherCopy else { return nil }
        icon = "square.on.square"
        tint = Color.orange
        title = String(localized: "The helper runs from another copy of FreeSnitch")
        detail = HelperOtherCopyMessage.detail(other: other, this: thisCopy)
        action = BannerAction(title: String(localized: "Show in Finder")) { _, _ in
            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: other)])
        }
    }

    /// Returns nil when everything is healthy, so there is no banner or noise.
    init?(installState: HelperInstallState,
          connected: Bool,
          needsRepair: Bool,
          versionState: HelperVersionState,
          repairState: HelperRepairState,
          repairRunning: Bool) {
        // An attempt that holds the gate counts as running even when an
        // automatic update message replaced its state meanwhile (#216).
        let repairInProgress = repairRunning || repairState == .inProgress
        // A copy outside Applications shows the Move banner first: Repair
        // can't work from there (its location guard refuses), moving can (#412).
        if case .mismatch(let helperVersion, let appVersion) = versionState, installState != .wrongLocation {
            icon = "wrench.and.screwdriver.fill"
            tint = Color.orange
            title = String(localized: "The running helper is not the installed build")
            switch repairState {
            case .inProgress:
                detail = String(localized: "The helper process is running v\(helperVersion), but the installed app is v\(appVersion). Waiting for you to authorize the restart. FreeSnitch only restarts the existing service; it never unregisters it.")
            case .manualRequired(let reason):
                detail = String(localized: "The helper process is running v\(helperVersion), but the installed app is v\(appVersion). Helper-side fixes are not active. \(reason) The current pf anchor is left in place.")
            case .idle:
                detail = String(localized: "The helper process is running v\(helperVersion), but the installed app is v\(appVersion), so helper-side fixes are not active and traffic may not be filtered. Repair Helper restarts it for you; macOS will ask you to authorize it.")
            }
            action = .repair(running: repairInProgress)
            return
        }

        switch installState {
        case .enabled where connected:
            return nil
        case .enabled where needsRepair:
            icon = "wrench.and.screwdriver.fill"
            tint = Color.orange
            title = String(localized: "The helper needs repairing")
            if repairInProgress {
                detail = String(localized: "It is approved but not responding. FreeSnitch is restarting it; authorize the restart when macOS asks. The enabled service is never unregistered and your approval stays intact.")
            } else {
                detail = String(localized: "It is approved but not responding. Repair Helper restarts it for you, and macOS will ask you to authorize that. It is non-destructive: the enabled service is never unregistered and your approval stays intact.")
            }
            action = .repair(running: repairInProgress)
        case .enabled:
            icon = "hourglass"
            tint = Color.orange
            title = String(localized: "Connecting to the FreeSnitch helper…")
            detail = String(localized: "The helper is approved but hasn't answered yet. This usually clears within a few seconds.")
            action = nil
        case .requiresApproval:
            icon = "exclamationmark.triangle.fill"
            tint = Color.orange
            title = String(localized: "FreeSnitch needs your approval to monitor traffic")
            detail = String(localized: "Open System Settings under General > Login Items & Extensions and switch FreeSnitch on under \"Allow in the Background\". Until then no connections, rules or traffic can be shown.")
            action = BannerAction(title: String(localized: "Open Login Items")) { state, _ in state.helper.openLoginItemsSettings() }
        case .notRegistered:
            icon = "bolt.horizontal.circle.fill"
            tint = Color.orange
            title = String(localized: "The FreeSnitch helper isn't registered yet")
            detail = String(localized: "The helper runs the traffic monitor and the firewall rules. Register it from this signed app, then approve it in System Settings if macOS asks.")
            action = BannerAction(title: String(localized: "Register Helper")) { state, _ in state.helper.registerDaemon() }
        case .unknown:
            icon = "questionmark.circle.fill"
            tint = Color.orange
            title = String(localized: "The FreeSnitch helper state is unknown")
            detail = String(localized: "Refresh the helper state or run the CLI diagnostics. No registration change was attempted.")
            action = BannerAction(title: String(localized: "Check Again")) { state, _ in state.helper.refreshInstallState(); state.helper.ping() }
        case .wrongLocation where InstallLocation.stuckInstalledCopy != nil:
            // Already in Applications, but macOS runs it from a temporary
            // copy; a move would only reopen this same copy (#375).
            icon = "arrow.down.app.fill"
            tint = Color.red
            title = InstallLocation.stuckCopyTitle
            detail = String(localized: "macOS runs the copy in Applications from a temporary location, so it won't install the helper. \(InstallLocation.reinstallAdvice)")
            action = BannerAction(title: InstallLocation.stuckCopyButton) { _, _ in
                if let installed = InstallLocation.stuckInstalledCopy {
                    InstallLocation.stuckCopyAction(installed, confirm: true)
                }
            }
        case .wrongLocation:
            icon = "arrow.down.app.fill"
            tint = Color.red
            let fromHome = InstallLocation.isInUserApplications(InstallLocation.runningOriginal)
            if fromHome {
                title = String(localized: "Copy FreeSnitch to the main Applications folder")
                detail = String(localized: "\(InstallLocation.userApplicationsReason) FreeSnitch can copy itself there and reopen.")
            } else {
                title = String(localized: "Move FreeSnitch to your Applications folder")
                detail = String(localized: "macOS refuses to install background helpers for apps launched from a disk image or the Downloads folder. FreeSnitch can move itself into Applications and reopen from there.")
            }
            action = BannerAction(title: fromHome ? String(localized: "Copy to Applications") : String(localized: "Move to Applications")) { _, _ in
                InstallLocation.moveToApplications()
            }
        case .notFound:
            icon = "exclamationmark.triangle.fill"
            tint = Color.orange
            title = String(localized: "macOS cannot find the FreeSnitch helper registration")
            if HelperClient.hasBundledHelper {
                detail = String(localized: "This signed app still contains the helper declaration and executable, but SMAppService lost or cannot find its registration record. Background App Activity may still show FreeSnitch as on while launchd has no service. Register it again; toggling that switch alone is not sufficient.")
                action = BannerAction(title: String(localized: "Register Helper")) { state, _ in state.helper.registerDaemon() }
            } else {
                detail = String(localized: "This app copy does not contain both the helper declaration and executable, so registration cannot be attempted. Install the signed FreeSnitch release again.")
                action = nil
            }
        case .failed(let message):
            icon = "xmark.octagon.fill"
            tint = Color.red
            title = String(localized: "Helper installation failed")
            // The message already says what macOS reported and what to do,
            // including the move advice only when it applies (#409).
            detail = message
            action = BannerAction(title: String(localized: "Retry")) { state, _ in state.helper.registerDaemon() }
        }
    }

    /// The extension accepted the policy but it could not be saved. Until a
    /// save succeeds, the next start refuses saved rules older than the ones
    /// it last enforced and fails open (#213).
    /// The technical reason stays in the log; the banner says what it means,
    /// except for an encode failure with no known cause, whose error text is
    /// the only thing it can say (#341).
    /// `unsavableReason` is set when the current rules can never be kept for
    /// the next start (#320): sending them again cannot help, so the banner
    /// says what a restart does instead and offers no retry.
    init?(persistenceDegraded: Bool, unsavableReason: String? = nil,
          liveRulesReady: Bool, recoveryMessage: String?) {
        guard persistenceDegraded || recoveryMessage != nil else { return nil }
        icon = "externaldrive.badge.exclamationmark"
        tint = Color.orange
        if persistenceDegraded, let unsavableReason {
            title = String(localized: "The current rules won't survive a restart")
            // Only claim the rules are in use when the extension holds them
            // (the filter may be off while rules still sync).
            detail = [unsavableReason,
                      liveRulesReady ? String(localized: "The filter is using them now.") : nil,
                      // The reason carries its own advice: removing rules
                      // only helps when the count or size is the cause (#341).
                      String(localized: "After the Mac or the filter restarts, the per-process filter lets every connection through until FreeSnitch is open and sends them again.", comment: "\"them\" is the current firewall rules"),
                      recoveryMessage]
                .compactMap { $0?.isEmpty == false ? $0 : nil }
                .joined(separator: " ")
            // Sending the rules again can't make them fit, but it is still the
            // way out of a filter recovery shown alongside.
            action = recoveryMessage == nil
                ? nil
                : BannerAction(title: String(localized: "Send Rules Again")) { state, _ in state.syncSharedRules() }
            return
        }
        title = persistenceDegraded
            ? String(localized: "FreeSnitch could not save the current rules")
            : String(localized: "The network filter needs attention")
        let base = persistenceDegraded
            ? (liveRulesReady
                ? String(localized: "The filter is using them now, but after a restart it may not have them until FreeSnitch sends them again.")
                : String(localized: "After a restart the filter may use older saved rules until FreeSnitch sends them again."))
            : ""
        detail = [base, recoveryMessage]
            .compactMap { $0?.isEmpty == false ? $0 : nil }
            .joined(separator: " ")
        action = BannerAction(title: String(localized: "Send Rules Again")) { state, _ in state.syncSharedRules() }
    }

    init?(extensionStatus: SystemExtensionManager.Status,
          snapshotStatus: SharedRuleBridge.SnapshotStatus) {
        switch extensionStatus {
        case .idle:
            return nil
        case .activating:
            icon = "hourglass"
            tint = Color.orange
            title = String(localized: "Starting the FreeSnitch firewall")
            detail = String(localized: "The network extension is starting. Filtering is not active until the extension is approved and receives the current rule snapshot.")
            action = nil
        case .needsApproval:
            icon = "exclamationmark.triangle.fill"
            tint = Color.orange
            title = String(localized: "FreeSnitch needs approval to filter traffic")
            detail = String(localized: "The network extension is staged but not approved. Until you approve it under General > Login Items & Extensions > Network Extensions, FreeSnitch can monitor traffic but cannot filter connections or show alerts.")
            action = BannerAction(title: String(localized: "Open Network Extensions")) { _, manager in
                manager.openNetworkExtensionsSettings()
            }
        case .unsupported:
            icon = "xmark.octagon.fill"
            tint = Color.red
            title = String(localized: "Network filtering is unavailable in this build")
            detail = String(localized: "This copy of FreeSnitch does not include a supported Network Extension. Traffic monitoring can continue, but the firewall is not filtering connections.")
            action = nil
        case .failed(let message):
            icon = "xmark.octagon.fill"
            tint = Color.red
            title = String(localized: "FreeSnitch is not filtering traffic")
            detail = String(localized: "The network extension failed: \(message)")
            action = nil
        case .active:
            switch snapshotStatus.state {
            case .ready:
                return nil
            case .unavailable:
                icon = "exclamationmark.shield.fill"
                tint = Color.orange
                title = String(localized: "FreeSnitch is not filtering traffic")
                detail = String(localized: "The network extension is active, but it has not received a rule snapshot. FreeSnitch is monitoring traffic only until the rules are delivered.")
                action = nil
            case .invalid:
                icon = "xmark.octagon.fill"
                tint = Color.red
                title = String(localized: "FreeSnitch could not deliver its rules")
                let reason = snapshotStatus.message ?? String(localized: "the rule snapshot was rejected")
                detail = String(localized: "The network extension is active, but its rule snapshot is invalid: \(reason). FreeSnitch is not filtering traffic.")
                action = nil
            }
        }
    }
}
