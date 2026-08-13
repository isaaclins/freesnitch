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
        }
    }

    private func banner(_ info: BannerInfo) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: info.icon)
                .foregroundColor(info.tint)
                .font(.system(size: compact ? 12 : 14, weight: .semibold))
            VStack(alignment: .leading, spacing: 3) {
                Text(info.title)
                    .font(.system(size: compact ? 11 : 12, weight: .semibold))
                    .foregroundColor(PSTheme.textPrimary)
                Text(info.detail)
                    .font(.system(size: compact ? 10 : 11))
                    .foregroundColor(PSTheme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            if let action = info.action {
                Button(action.title) { action.run(state, systemExtension) }
                    .buttonStyle(.borderedProminent)
                    .controlSize(compact ? .small : .regular)
            }
        }
        .padding(.horizontal, compact ? 10 : 14)
        .padding(.vertical, compact ? 8 : 10)
        .background(info.tint.opacity(0.12))
        .overlay(Rectangle().frame(height: 1).foregroundColor(info.tint.opacity(0.35)), alignment: .bottom)
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
            tint = PSTheme.accentYellow
            title = "The FreeSnitch helper version does not match"
            switch repairState {
            case .inProgress:
                detail = "The running helper is v\(helperVersion), but this app is v\(appVersion). Helper-side fixes are not active yet. FreeSnitch is trying to restart it without changing the existing pf anchor."
            case .manualRequired(let reason):
                detail = "The running helper is v\(helperVersion), but this app is v\(appVersion). Helper-side fixes are not active. \(reason) Run `\(HelperRecovery.kickstartCommand)` in Terminal. The current pf anchor is left in place while the helper is restarted."
            case .idle:
                detail = "The running helper is v\(helperVersion), but this app is v\(appVersion). Helper-side fixes are not active. FreeSnitch will try to restart the helper automatically."
            }
            action = BannerAction(title: "Repair Helper") { state, _ in state.helper.repairHelper() }
            return
        }

        switch installState {
        case .enabled where connected:
            return nil
        case .enabled where needsRepair:
            icon = "wrench.and.screwdriver.fill"
            tint = PSTheme.accentYellow
            title = "The helper needs repairing"
            detail = "It is approved but either not responding or left over from an older FreeSnitch, usually after an in-place update. Repairing re-installs the background helper; macOS will ask you to approve it once more in Login Items."
            action = BannerAction(title: "Repair Helper") { state, _ in state.helper.repairHelper() }
        case .enabled:
            icon = "hourglass"
            tint = PSTheme.accentYellow
            title = "Connecting to the FreeSnitch helper…"
            detail = "The helper is approved but hasn't answered yet. This usually clears within a few seconds."
            action = nil
        case .requiresApproval:
            icon = "exclamationmark.triangle.fill"
            tint = PSTheme.accentYellow
            title = "FreeSnitch needs your approval to monitor traffic"
            detail = "Open System Settings under General > Login Items & Extensions and switch FreeSnitch on under \"Allow in the Background\". Until then no connections, rules or traffic can be shown."
            action = BannerAction(title: "Open Login Items") { state, _ in state.helper.openLoginItemsSettings() }
        case .notRegistered, .unknown:
            icon = "bolt.horizontal.circle.fill"
            tint = PSTheme.accentYellow
            title = "The FreeSnitch helper isn't installed yet"
            detail = "The helper runs the traffic monitor and the firewall rules. Install it to start seeing connections."
            action = BannerAction(title: "Install Helper") { state, _ in state.helper.registerDaemon() }
        case .wrongLocation:
            icon = "arrow.down.app.fill"
            tint = PSTheme.accentRed
            title = "Move FreeSnitch to your Applications folder"
            detail = "macOS refuses to install background helpers for apps launched from a disk image or the Downloads folder. Drag FreeSnitch.app into Applications, then open it from there."
            action = BannerAction(title: "Reveal in Finder") { _, _ in
                NSWorkspace.shared.activateFileViewerSelecting([Bundle.main.bundleURL])
            }
        case .notFound:
            icon = "xmark.octagon.fill"
            tint = PSTheme.accentRed
            title = "The helper is missing from this copy of FreeSnitch"
            detail = "This build has no privileged helper bundled. Download FreeSnitch again from the official releases page."
            action = nil
        case .failed(let message):
            icon = "xmark.octagon.fill"
            tint = PSTheme.accentRed
            title = "Helper installation failed"
            detail = "\(message) Move FreeSnitch into /Applications and try again."
            action = BannerAction(title: "Retry") { state, _ in state.helper.registerDaemon() }
        }
    }

    init?(extensionStatus: SystemExtensionManager.Status,
          snapshotStatus: SharedRuleBridge.SnapshotStatus) {
        switch extensionStatus {
        case .idle:
            return nil
        case .activating:
            icon = "hourglass"
            tint = PSTheme.accentYellow
            title = "Starting the FreeSnitch firewall"
            detail = "The network extension is starting. Filtering is not active until the extension is approved and receives the current rule snapshot."
            action = nil
        case .needsApproval:
            icon = "exclamationmark.triangle.fill"
            tint = PSTheme.accentYellow
            title = "FreeSnitch needs approval to filter traffic"
            detail = "The network extension is staged but not approved. Until you approve it under General > Login Items & Extensions > Network Extensions, FreeSnitch can monitor traffic but cannot filter connections or show alerts."
            action = BannerAction(title: "Open Network Extensions") { _, manager in
                manager.openNetworkExtensionsSettings()
            }
        case .unsupported:
            icon = "xmark.octagon.fill"
            tint = PSTheme.accentRed
            title = "Network filtering is unavailable in this build"
            detail = "This copy of FreeSnitch does not include a supported Network Extension. Traffic monitoring can continue, but the firewall is not filtering connections."
            action = nil
        case .failed(let message):
            icon = "xmark.octagon.fill"
            tint = PSTheme.accentRed
            title = "FreeSnitch is not filtering traffic"
            detail = "The network extension failed: \(message)"
            action = nil
        case .active:
            switch snapshotStatus.state {
            case .ready:
                return nil
            case .unavailable:
                icon = "exclamationmark.shield.fill"
                tint = PSTheme.accentYellow
                title = "FreeSnitch is not filtering traffic"
                detail = "The network extension is active, but it has not received a rule snapshot. FreeSnitch is monitoring traffic only until the rules are delivered."
                action = nil
            case .invalid:
                icon = "xmark.octagon.fill"
                tint = PSTheme.accentRed
                title = "FreeSnitch could not deliver its rules"
                let reason = snapshotStatus.message ?? "the rule snapshot was rejected"
                detail = "The network extension is active, but its rule snapshot is invalid: \(reason). FreeSnitch is not filtering traffic."
                action = nil
            }
        }
    }
}
