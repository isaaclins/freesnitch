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
            if let info = BannerInfo(installState: state.helperInstallState,
                                     connected: state.helperConnected,
                                     needsRepair: state.helperNeedsRepair,
                                     versionState: state.helperVersionState,
                                     repairState: state.helperRepairState) {
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
                   action: info.action.map { action in
                       { action.run(state, systemExtension) }
                   })
            .padding(.horizontal, compact ? 8 : 12)
            .padding(.vertical, compact ? 6 : 10)
    }
}

private struct BannerAction {
    let title: String
    let run: @MainActor (AppState, SystemExtensionManager) -> Void
}

@MainActor
private struct BannerInfo {
    let icon: String
    let tint: Color
    let title: String
    let detail: String
    let action: BannerAction?

    /// Returns nil when everything is healthy, so there is no banner or noise.
    init?(installState: HelperInstallState,
          connected: Bool,
          needsRepair: Bool,
          versionState: HelperVersionState,
          repairState: HelperRepairState) {
        if case .mismatch(let helperVersion, let appVersion) = versionState {
            icon = "wrench.and.screwdriver.fill"
            tint = Color.orange
            title = "The running helper is not the installed build"
            switch repairState {
            case .inProgress:
                detail = "The helper process is running v\(helperVersion), but the installed app is v\(appVersion). Waiting for you to authorize the restart. FreeSnitch only restarts the existing service; it never unregisters it."
            case .manualRequired(let reason):
                detail = "The helper process is running v\(helperVersion), but the installed app is v\(appVersion). Helper-side fixes are not active. \(reason) The current pf anchor is left in place."
            case .idle:
                detail = "The helper process is running v\(helperVersion), but the installed app is v\(appVersion), so helper-side fixes are not active and traffic may not be filtered. Repair Helper restarts it for you; macOS will ask you to authorize it."
            }
            action = BannerAction(title: "Repair Helper") { state, _ in state.helper.repairHelper() }
            return
        }

        switch installState {
        case .enabled where connected:
            return nil
        case .enabled where needsRepair:
            icon = "wrench.and.screwdriver.fill"
            tint = Color.orange
            title = "The helper needs repairing"
            detail = "It is approved but not responding. Repair Helper restarts it for you, and macOS will ask you to authorize that. It is non-destructive: the enabled service is never unregistered and your approval stays intact."
            action = BannerAction(title: "Repair Helper") { state, _ in state.helper.repairHelper() }
        case .enabled:
            icon = "hourglass"
            tint = Color.orange
            title = "Connecting to the FreeSnitch helper…"
            detail = "The helper is approved but hasn't answered yet. This usually clears within a few seconds."
            action = nil
        case .requiresApproval:
            icon = "exclamationmark.triangle.fill"
            tint = Color.orange
            title = "FreeSnitch needs your approval to monitor traffic"
            detail = "Open System Settings under General > Login Items & Extensions and switch FreeSnitch on under \"Allow in the Background\". Until then no connections, rules or traffic can be shown."
            action = BannerAction(title: "Open Login Items") { state, _ in state.helper.openLoginItemsSettings() }
        case .notRegistered:
            icon = "bolt.horizontal.circle.fill"
            tint = Color.orange
            title = "The FreeSnitch helper isn't registered yet"
            detail = "The helper runs the traffic monitor and the firewall rules. Register it from this signed app, then approve it in System Settings if macOS asks."
            action = BannerAction(title: "Register Helper") { state, _ in state.helper.registerDaemon() }
        case .unknown:
            icon = "questionmark.circle.fill"
            tint = Color.orange
            title = "The FreeSnitch helper state is unknown"
            detail = "Refresh the helper state or run the CLI diagnostics. No registration change was attempted."
            action = BannerAction(title: "Check Again") { state, _ in state.helper.refreshInstallState(); state.helper.ping() }
        case .wrongLocation where InstallLocation.stuckInstalledCopy != nil:
            // Already in Applications, but macOS runs it from a temporary
            // copy; a move would only reopen this same copy (#375).
            icon = "arrow.down.app.fill"
            tint = Color.red
            title = InstallLocation.stuckCopyTitle
            detail = "macOS runs the copy in Applications from a temporary location, so it won't install the helper. \(InstallLocation.reinstallAdvice)"
            action = BannerAction(title: InstallLocation.stuckCopyButton) { _, _ in
                if let installed = InstallLocation.stuckInstalledCopy {
                    InstallLocation.stuckCopyAction(installed)
                }
            }
        case .wrongLocation:
            icon = "arrow.down.app.fill"
            tint = Color.red
            title = "Move FreeSnitch to your Applications folder"
            detail = "macOS refuses to install background helpers for apps launched from a disk image or the Downloads folder. FreeSnitch can move itself into Applications and reopen from there."
            action = BannerAction(title: "Move to Applications") { _, _ in
                InstallLocation.moveToApplications()
            }
        case .notFound:
            icon = "exclamationmark.triangle.fill"
            tint = Color.orange
            title = "macOS cannot find the FreeSnitch helper registration"
            if HelperClient.hasBundledHelper {
                detail = "This signed app still contains the helper declaration and executable, but SMAppService lost or cannot find its registration record. Background App Activity may still show FreeSnitch as on while launchd has no service. Register it again; toggling that switch alone is not sufficient."
                action = BannerAction(title: "Register Helper") { state, _ in state.helper.registerDaemon() }
            } else {
                detail = "This app copy does not contain both the helper declaration and executable, so registration cannot be attempted. Install the signed FreeSnitch release again."
                action = nil
            }
        case .failed(let message):
            icon = "xmark.octagon.fill"
            tint = Color.red
            title = "Helper installation failed"
            detail = "\(message) Move FreeSnitch into /Applications and try again."
            action = BannerAction(title: "Retry") { state, _ in state.helper.registerDaemon() }
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
            title = "The current rules won't survive a restart"
            // Only claim the rules are in use when the extension holds them
            // (the filter may be off while rules still sync).
            detail = [unsavableReason,
                      liveRulesReady ? "The filter is using them now." : nil,
                      // The reason carries its own advice: removing rules
                      // only helps when the count or size is the cause (#341).
                      "After the Mac or the filter restarts, the per-process filter lets every connection through until FreeSnitch is open and sends them again.",
                      recoveryMessage]
                .compactMap { $0?.isEmpty == false ? $0 : nil }
                .joined(separator: " ")
            // Sending the rules again can't make them fit, but it is still the
            // way out of a filter recovery shown alongside.
            action = recoveryMessage == nil
                ? nil
                : BannerAction(title: "Send Rules Again") { state, _ in state.syncSharedRules() }
            return
        }
        title = persistenceDegraded
            ? "FreeSnitch could not save the current rules"
            : "The network filter needs attention"
        let base = persistenceDegraded
            ? (liveRulesReady
                ? "The filter is using them now, but after a restart it may not have them until FreeSnitch sends them again."
                : "After a restart the filter may use older saved rules until FreeSnitch sends them again.")
            : ""
        detail = [base, recoveryMessage]
            .compactMap { $0?.isEmpty == false ? $0 : nil }
            .joined(separator: " ")
        action = BannerAction(title: "Send Rules Again") { state, _ in state.syncSharedRules() }
    }

    init?(extensionStatus: SystemExtensionManager.Status,
          snapshotStatus: SharedRuleBridge.SnapshotStatus) {
        switch extensionStatus {
        case .idle:
            return nil
        case .activating:
            icon = "hourglass"
            tint = Color.orange
            title = "Starting the FreeSnitch firewall"
            detail = "The network extension is starting. Filtering is not active until the extension is approved and receives the current rule snapshot."
            action = nil
        case .needsApproval:
            icon = "exclamationmark.triangle.fill"
            tint = Color.orange
            title = "FreeSnitch needs approval to filter traffic"
            detail = "The network extension is staged but not approved. Until you approve it under General > Login Items & Extensions > Network Extensions, FreeSnitch can monitor traffic but cannot filter connections or show alerts."
            action = BannerAction(title: "Open Network Extensions") { _, manager in
                manager.openNetworkExtensionsSettings()
            }
        case .unsupported:
            icon = "xmark.octagon.fill"
            tint = Color.red
            title = "Network filtering is unavailable in this build"
            detail = "This copy of FreeSnitch does not include a supported Network Extension. Traffic monitoring can continue, but the firewall is not filtering connections."
            action = nil
        case .failed(let message):
            icon = "xmark.octagon.fill"
            tint = Color.red
            title = "FreeSnitch is not filtering traffic"
            detail = "The network extension failed: \(message)"
            action = nil
        case .active:
            switch snapshotStatus.state {
            case .ready:
                return nil
            case .unavailable:
                icon = "exclamationmark.shield.fill"
                tint = Color.orange
                title = "FreeSnitch is not filtering traffic"
                detail = "The network extension is active, but it has not received a rule snapshot. FreeSnitch is monitoring traffic only until the rules are delivered."
                action = nil
            case .invalid:
                icon = "xmark.octagon.fill"
                tint = Color.red
                title = "FreeSnitch could not deliver its rules"
                let reason = snapshotStatus.message ?? "the rule snapshot was rejected"
                detail = "The network extension is active, but its rule snapshot is invalid: \(reason). FreeSnitch is not filtering traffic."
                action = nil
            }
        }
    }
}
