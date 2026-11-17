import Foundation
import AppKit
import SystemExtensions
import NetworkExtension
import os.log

/// Drives the per-process firewall: activates the embedded Network System
/// Extension, enables the content filter via NEFilterManager, and opens the XPC
/// channel so the extension can prompt the user (reusing the connection-alert
/// UI). Mirrors Apple's "SimpleFirewall" sample.
@MainActor
final class SystemExtensionManager: NSObject, ObservableObject {
    enum Status: Equatable {
        case idle
        case activating
        case needsApproval
        case active
        case unsupported
        case failed(String)
    }

    /// What macOS actually reported about removing the extension.
    ///
    /// Deactivation is a deliberate, user-initiated uninstall, never a repair
    /// (see #24), and it commonly finishes only after a reboot. Accepting the
    /// request is not success, so there is no state for "we asked": the value
    /// only moves past `.deactivating` when the system answers.
    enum UninstallState: Equatable {
        case idle
        case deactivating
        case notInstalled
        case pendingReboot
        case removed
        case failed(String)
    }

    private enum RequestKind {
        case activation
        case deactivation
        case properties
    }

    @Published var status: Status = .idle
    @Published var uninstallState: UninstallState = .idle
    @Published var snapshotStatus = SharedRuleBridge.SnapshotStatus.unavailable(
        "Network extension IPC is not connected."
    )

    private weak var state: AppState?
    private let extensionIdentifier = AppConstants.bundleIdNetExt
    private let log = OSLog(subsystem: AppConstants.bundleIdGUI, category: "sysext")
    private var bridge: AppCommunicationBridge?
    private var requestKind: RequestKind = .activation
    private var filterConfigurationActive = false
    /// The boot-policy save cycle's decisions: queue, bounded retries of a
    /// failed save (#213), the enable request and cancellations (#310).
    private var persistenceCycle = SharedRuleBridge.BootPolicySaveCycle()
    /// True once the current rules being too big for the boot policy has been
    /// written to the logs. Kept here, not in the banner state, and not keyed
    /// on the reason text (it carries the rule count): every rule edit over
    /// the limit fails to encode again, and it is logged once per change of
    /// state, not once per edit (#342).
    private var unsavableLogged = false
    /// Ends the boot-policy save cycle's turn on `filterPreferences`.
    private var persistenceCycleDone: (() -> Void)?
    /// Every load-then-save on the shared NEFilterManager (boot-policy saves,
    /// turning the filter off, removing it, restarting it) waits here for the
    /// one before it, so the last thing asked for is what gets saved (#309).
    private let filterPreferences = FilterPreferencesLine()
    private var persistenceWorkItem: DispatchWorkItem?
    /// Whether the filter is turned off (by the app, or in System Settings) or
    /// has no configuration, as last seen. A failed boot-policy save then has no
    /// restart to affect: it is logged, but the could-not-save banner stays
    /// down, and turning the filter on saves the current rules again (#321).
    private var filterOff = FilterOffState()
    /// Bumped whenever the filter is turned off or removed, so an enabling
    /// save that was already running can tell it was overtaken and must not
    /// report the firewall as active (#318).
    private var filterTurnOffs = 0
    /// Bounded, spaced automatic recovery from an extension that is holding a
    /// policy it will not let the helper replace (#70).
    private var snapshotRecovery = FilterRestartRecovery()
    private var filterRestartInFlight = false

    init(state: AppState) {
        self.state = state
        super.init()
        state.filterSnapshotStatusHandler = { [weak self] snapshotStatus in
            self?.recordSnapshotStatus(snapshotStatus)
        }
        state.filterSnapshotPersistenceHandler = { [weak self] snapshot in
            self?.requestPersistedSnapshot(snapshot)
        }
        // The filter can be turned on or off in System Settings too. Without
        // this, a failure before the next save cycle's load (an encode over
        // the size limit, or a failed load) would go by a stale answer (#321).
        NotificationCenter.default.addObserver(forName: .NEFilterConfigurationDidChange,
                                               object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor [weak self] in self?.refreshFilterOffState() }
        }
    }

    private func apply(_ change: FilterOffState.Change) {
        switch change {
        case .none:
            break
        case .clearBanner:
            // Nothing restarts with these rules while it is off.
            state?.clearFilterPersistenceFailure()
        case .saveCurrentRules:
            // Turned on outside the app: save the current rules again, as
            // turning it on in the app does.
            state?.syncSharedRules()
        }
    }

    /// Reads whether the filter is on, in its turn on the preferences line,
    /// so `filterOff` follows changes made outside the app. It only reads.
    private func refreshFilterOffState() {
        filterPreferences.run { [weak self] done in
            NEFilterManager.shared().loadFromPreferences { error in
                DispatchQueue.main.async {
                    guard let self else { done(); return }
                    let mgr = NEFilterManager.shared()
                    guard error == nil, !self.persistenceCycle.enableRequested else { done(); return }
                    let change = self.filterOff.observed(configured: mgr.providerConfiguration != nil,
                                                         enabled: mgr.isEnabled, fromOutside: true)
                    done()
                    self.apply(change)
                }
            }
        }
    }

    private var hasEmbeddedExtension: Bool {
        let dir = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/SystemExtensions")
        guard let urls = try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) else { return false }
        return urls.contains { $0.pathExtension == "systemextension" }
    }

    /// Activate the extension (no-op if this build doesn't embed one).
    func activate() {
        guard hasEmbeddedExtension else {
            status = .unsupported
            return
        }
        status = .activating
        requestKind = .activation
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: extensionIdentifier, queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func deactivate() {
        disableFilter()
        guard hasEmbeddedExtension else { return }
        requestKind = .deactivation
        let request = OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: extensionIdentifier, queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Entry point for the uninstall flow in Settings. Under SIP the app is the
    /// only component macOS allows to deactivate this extension, so this is the
    /// real removal path, not a convenience wrapper.
    ///
    /// It touches the extension and the content filter only. Unregistering the
    /// privileged helper is a later step of the same flow, and that flow is the
    /// only place FreeSnitch is allowed to do it: unregistering the service
    /// outside an uninstall the user confirmed is the failure #24 was filed for.
    func deactivateForUninstall() {
        uninstallState = .deactivating
        guard hasEmbeddedExtension else {
            // Nothing was ever staged from this bundle, so there is no OS
            // answer to wait for. Still drop the filter configuration.
            removeFilterConfiguration { }
            uninstallState = .notInstalled
            return
        }
        // Remove the filter configuration and WAIT for it, then deactivate.
        //
        // Both halves of that sentence were wrong before. The configuration was
        // only disabled, not removed, so network preferences still held a
        // NEFilterProviderConfiguration pointing at this extension, and macOS
        // keeps an extension record alive while something still references it,
        // which is a large part of why uninstalling always ended in "waiting to
        // uninstall on reboot". And the deactivation request was submitted
        // without waiting for the asynchronous save, so the two raced.
        removeFilterConfiguration { [weak self] in
            guard let self else { return }
            self.requestKind = .deactivation
            let request = OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: self.extensionIdentifier,
                                                                       queue: .main)
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    /// Removes the content filter configuration entirely, for uninstall.
    ///
    /// Distinct from `disableFilter`, which deliberately keeps the
    /// configuration installed so enforcement can be switched back on without
    /// re-approving anything. Removal is only correct when the user is taking
    /// FreeSnitch off the machine.
    ///
    /// The completion runs on the main queue in every path, including the
    /// failure paths: an uninstall that stalls because a preferences call
    /// errored would be worse than one that continues and reports.
    private func removeFilterConfiguration(completion: @escaping () -> Void) {
        unsavableLogged = false
        cancelPendingPersistence()
        filterTurnOffs &+= 1
        persistenceCycle.dropEnableRequest()
        filterPreferences.run { [weak self] done in
            NEFilterManager.shared().loadFromPreferences { error in
                DispatchQueue.main.async {
                    guard let self else { done(); completion(); return }
                    let mgr = NEFilterManager.shared()
                    if error != nil {
                        self.recordFilterDiagnostic(state: "unknown",
                                                    detail: "Could not read the content filter preferences while removing them.")
                        done()
                        completion()
                        return
                    }
                    mgr.removeFromPreferences { removeError in
                        DispatchQueue.main.async {
                            if let removeError {
                                self.recordFilterDiagnostic(state: "unknown",
                                                            detail: "The content filter configuration could not be removed: \(removeError.sentence)")
                            } else {
                                self.recordFilterDiagnostic(state: "removed",
                                                            detail: "The content filter configuration was removed.")
                                // No filter is left to save rules for, so a warning
                                // about an earlier failed save no longer applies (#311).
                                self.state?.clearFilterPersistenceFailure()
                                // A turn-on asked for meanwhile waits behind this
                                // and decides the state, not this late answer.
                                self.filterOff.turnedOff(turnOnPending: self.persistenceCycle.enableRequested)
                            }
                            done()
                            completion()
                        }
                    }
                }
            }
        }
    }

    /// Asks the system whether a record for the extension still exists, so the
    /// UI can report what macOS holds rather than what we requested.
    private func checkExtensionPresence() {
        requestKind = .properties
        let request = OSSystemExtensionRequest.propertiesRequest(forExtensionWithIdentifier: extensionIdentifier, queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Opens the System Settings location where a staged system extension is
    /// approved. The query selects Network Extensions on current macOS; the
    /// parent pane remains the fallback for releases that do not understand it.
    func openNetworkExtensionsSettings() {
        let networkExtensionsURL = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension?NetworkExtensions")
        let loginItemsURL = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension")
        if let networkExtensionsURL, NSWorkspace.shared.open(networkExtensionsURL) { return }
        if let loginItemsURL { NSWorkspace.shared.open(loginItemsURL) }
    }

    // MARK: - Content filter configuration

    private func enableFilter() {
        // A snapshot kept for a retry is never the policy activation saves:
        // only the helper's fresh answer below may enable the filter.
        dropScheduledSave()
        persistenceCycle.requestEnable()
        filterOff.turnedOn()
        // AppState fetches the helper-owned snapshot and invokes the
        // persistence callback only after it has updated its display cache.
        // There is no cached-rule fallback during activation.
        state?.syncSharedRules()
    }

    /// Queue the newest policy for NEFilterManager.providerConfiguration. The
    /// manager is the sole persistence owner. Saves are serialized because
    /// NEFilterManager's load/save callbacks are asynchronous, and a newer
    /// request always remains pending until the older save completes. The
    /// decisions live in `SharedRuleBridge.BootPolicySaveCycle`; this only
    /// talks to the system and carries them out.
    private func requestPersistedSnapshot(_ snapshot: SharedRuleBridge.Snapshot) {
        do {
            persistenceCycle.enqueue(try SharedRuleBridge.encodeBootSnapshot(snapshot))
            unsavableLogged = false
            schedulePersistence(immediate: persistenceCycle.enableRequested)
        } catch {
            // This policy cannot be kept for the next start (for example it is
            // over the boot policy's rule limit), but the extension enforces it
            // live all the same (#320). The cycle drops an older snapshot kept
            // for a retry and a save in flight, and removes the saved policy
            // instead of leaving an older one behind: the next start then fails
            // open until this app sends the live rules. Turning the filter on
            // goes ahead with the live policy.
            dropScheduledSave()
            persistenceCycle.queueRemoval()
            let reason = Self.unsavableReason(SharedRuleBridge.BootSnapshotProblem(error, ruleCount: snapshot.rules.count),
                                              error: error)
            // Without the per-process filter there is nothing to keep for a
            // restart: no banner and no log (it would only flash, #342). The
            // removal still runs, so an installed but disabled filter never
            // starts with older rules.
            if filterConfigurationActive || persistenceCycle.enableRequested {
                // Each rule edit over the limit lands here again: the banner
                // follows every edit, the logs only the change of state.
                let firstTime = !unsavableLogged
                unsavableLogged = true
                recordPersistenceFailure("encode", error: error, unsavable: reason, writeLog: firstTime)
            }
            schedulePersistence(immediate: persistenceCycle.enableRequested)
        }
    }

    private func schedulePersistence(immediate: Bool, after retryDelay: TimeInterval? = nil) {
        persistenceWorkItem?.cancel()
        let work = DispatchWorkItem { [weak self] in
            Task { @MainActor [weak self] in
                self?.flushPersistence()
            }
        }
        persistenceWorkItem = work
        let delay = retryDelay ?? (immediate ? 0 : 0.2)
        DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: work)
    }

    private func flushPersistence() {
        // Activation waits for a successful helper getter before it can save
        // or enable the filter: the cycle starts only with a snapshot queued.
        guard persistenceCycle.begin() != nil else { return }
        // Waits for a turn-off, removal or restart that was asked for earlier
        // to finish saving, and makes one asked for later wait for this cycle.
        filterPreferences.run { [weak self] done in
            guard let self else { done(); return }
            self.persistenceCycleDone = done
            self.runPersistenceCycle()
        }
    }

    private func runPersistenceCycle() {
        let load = persistenceCycle.currentLoad
        let turnOffsAtLoad = filterTurnOffs
        let mgr = NEFilterManager.shared()
        mgr.loadFromPreferences { [weak self] loadError in
            DispatchQueue.main.async {
                guard let self else { return }
                // Before the cycle may drop it: a removal of the saved policy
                // that fails while the filter isn't in use shows no banner (#349).
                let removalQueued = self.persistenceCycle.queue.peekNewest == SharedRuleBridge.bootSnapshotRemoval
                let decision = self.persistenceCycle.afterLoad(
                    load, loadFailed: loadError != nil,
                    configurationExists: mgr.providerConfiguration != nil,
                    hasSavedPolicy: mgr.providerConfiguration?.vendorConfiguration?[SharedRuleBridge.bootSnapshotVendorConfigurationKey] != nil)
                let save: SharedRuleBridge.BootPolicySaveCycle.Save
                switch decision {
                case .save(let decided):
                    save = decided
                case .loadFailed(let failActivation, let next):
                    self.endPersistenceTurn()
                    if let loadError {
                        if removalQueued && self.state?.filterPersistenceUnsavable == nil {
                            // A removal while the filter isn't in use: no banner
                            // was shown for it, so none for this (#349).
                            os_log("Loading the filter configuration to remove the saved boot policy failed: %{public}@",
                                   log: self.log, type: .info, loadError.sentence)
                        } else {
                            // While the newest rules are over the limit, the pending
                            // save is the removal: keep the over-limit banner (#340).
                            self.recordPersistenceFailure("load", error: loadError,
                                                          unsavable: self.unsavableLogged ? self.state?.filterPersistenceUnsavable : nil)
                        }
                        if failActivation {
                            self.fail("filter load: \(loadError.localizedDescription)")
                        }
                    }
                    self.carryOut(next, removal: removalQueued)
                    return
                case .cancelledLoadFailed(let next):
                    // The filter was turned on, off or removed meanwhile; this
                    // load no longer matters and must not raise a warning or
                    // fail an activation that has not run yet.
                    self.endPersistenceTurn()
                    os_log("A cancelled boot policy load failed: %{public}@", log: self.log, type: .info,
                           loadError?.sentence ?? "")
                    self.carryOut(next, removal: removalQueued)
                    return
                case .stop(.noConfiguration):
                    self.endPersistenceTurn()
                    // Nothing to save rules for, so an earlier save-failure
                    // warning no longer applies (#311).
                    self.state?.clearFilterPersistenceFailure()
                    self.filterOff.turnedOff(turnOnPending: false)
                    return
                case .stop(.cancelledDuringLoad):
                    self.endPersistenceTurn()
                    self.noticeFilterOff(mgr)
                    return
                case .stop:
                    self.endPersistenceTurn()
                    return
                case .nothingToRemove(let next):
                    self.endPersistenceTurn()
                    self.noticeFilterOff(mgr)
                    self.carryOut(next, removal: true)
                    return
                }
                if !save.enable {
                    self.noticeFilterOff(mgr)
                }

                let shouldEnable = save.enable
                let removesBootSnapshot = save.removesSavedPolicy
                let configuration = mgr.providerConfiguration ?? NEFilterProviderConfiguration()
                configuration.filterSockets = true
                configuration.filterPackets = false
                if let snapshotData = save.pending?.data {
                    var vendorConfiguration = configuration.vendorConfiguration ?? [:]
                    if removesBootSnapshot {
                        vendorConfiguration.removeValue(forKey: SharedRuleBridge.bootSnapshotVendorConfigurationKey)
                    } else {
                        vendorConfiguration[SharedRuleBridge.bootSnapshotVendorConfigurationKey] = snapshotData
                    }
                    configuration.vendorConfiguration = vendorConfiguration
                }
                mgr.providerConfiguration = configuration
                if shouldEnable {
                    mgr.localizedDescription = "FreeSnitch"
                    mgr.isEnabled = true
                }
                mgr.saveToPreferences { saveError in
                    DispatchQueue.main.async {
                        let result = self.persistenceCycle.afterSave(save, saveFailed: saveError != nil)
                        self.endPersistenceTurn()
                        // Turned off or removed while this enabling save
                        // was running: the turn-off is saved after it, so
                        // this save must not report the firewall as on (#318).
                        let completion = FilterSaveCompletion.decide(enabling: shouldEnable,
                                                                     turnOffsAtLoad: turnOffsAtLoad,
                                                                     turnOffsNow: self.filterTurnOffs,
                                                                     enableRequestedNow: self.persistenceCycle.enableRequested,
                                                                     saveFailed: saveError != nil)
                        if completion == .stayedOff {
                            self.filterConfigurationActive = false
                            self.status = .idle
                            self.state?.appendLog(level: "info",
                                                  message: "The filter was turned off while it was being turned on; it stays off.")
                        }
                        if let saveError {
                            if removesBootSnapshot && self.state?.filterPersistenceUnsavable == nil {
                                // A removal while the filter isn't in use: no
                                // banner was shown for it, so none for this.
                                os_log("Removing the saved boot policy failed: %{public}@", log: self.log, type: .info,
                                       saveError.sentence)
                            } else if result.reportFailure {
                                // A failed removal is still about rules that
                                // can't be kept: keep that reason and banner.
                                self.recordPersistenceFailure("save", error: saveError,
                                                              unsavable: removesBootSnapshot ? self.state?.filterPersistenceUnsavable : nil)
                            } else {
                                // The filter was turned on, off or removed
                                // meanwhile; this save no longer matters and
                                // must not bring the warning back.
                                os_log("A cancelled boot policy save failed: %{public}@", log: self.log, type: .info,
                                       saveError.sentence)
                            }
                            if result.failActivation && completion == .failed {
                                self.fail("filter save: \(saveError.localizedDescription)")
                            }
                        } else {
                            if result.removedSavedPolicy {
                                // The live rules could not be kept for the next
                                // start; the warning stays until a policy that
                                // can be kept is saved.
                                let reason = self.state?.filterPersistenceUnsavable ?? "The current rules could not be saved for the next start."
                                if save.hadSavedPolicy {
                                    let message = "Removed the saved rules for the next start. \(reason) "
                                        + "After a restart the per-process filter lets every connection through until FreeSnitch sends the current rules."
                                    self.state?.appendLog(level: "info", message: message)
                                    os_log("%{public}@", log: self.log, type: .info, message)
                                }
                                if completion == .active || self.filterConfigurationActive {
                                    self.recordFilterDiagnostic(state: "degraded", detail: "The content filter is enabled, but no valid boot policy could be persisted. Future starts will fail open.")
                                }
                            } else if result.savedPolicy {
                                if result.clearWarning {
                                    self.state?.clearFilterPersistenceFailure()
                                }
                                if completion == .active || self.filterConfigurationActive {
                                    self.recordFilterDiagnostic(state: "installed-enabled", detail: "The content filter configuration is installed and enabled.")
                                }
                            }
                            if completion == .active {
                                self.filterConfigurationActive = true
                                self.filterOff.turnedOn()
                                self.status = .active
                                // Deliberately does NOT touch `helperConnected`: the
                                // content filter and privileged helper are separate.
                                self.state?.appendLog(level: "info", message: "Per-process firewall active.")
                                self.registerIPC()
                            }
                        }
                        // A failed save kept for a retry: schedule it, or say
                        // once that the retries are used up.
                        self.carryOut(result.next, removal: removesBootSnapshot)
                        // Newer work, or an enable request, arrived during
                        // this cycle: start another one now.
                        if result.runAgainNow {
                            self.schedulePersistence(immediate: true)
                        }
                    }
                }
            }
        }
    }

    /// The save cycle's turn on `filterPreferences` is over: the next
    /// preferences operation may run.
    private func endPersistenceTurn() {
        let done = persistenceCycleDone
        persistenceCycleDone = nil
        done?()
    }

    /// Cancels the timer of a queued save or retry; the cycle decides what
    /// stays queued.
    private func dropScheduledSave() {
        persistenceWorkItem?.cancel()
        persistenceWorkItem = nil
    }

    /// Drops a queued or scheduled boot-policy save. Used when the filter is
    /// turned off or removed, so a late retry can neither enable nor recreate
    /// it. Also invalidates a save already in flight: if it fails, it can no
    /// longer be put back and retried.
    private func cancelPendingPersistence() {
        dropScheduledSave()
        persistenceCycle.cancel()
    }

    /// A save cycle that is not turning the filter on found it configured:
    /// turned off here or in System Settings, the saved rules only matter once
    /// it is turned on, and that saves the current ones again (#321).
    private func noticeFilterOff(_ mgr: NEFilterManager) {
        self.apply(self.filterOff.observed(configured: true, enabled: mgr.isEnabled,
                                           fromOutside: false))
    }

    /// `removal` says the save that failed removes the saved boot policy
    /// because the rules are over its limit; Send Rules Again can't fix that.
    private func carryOut(_ next: SharedRuleBridge.BootPolicySaveCycle.Next, removal: Bool) {
        switch next {
        case .none:
            break
        case .now:
            schedulePersistence(immediate: true)
        case .retry(let delay):
            os_log("Retrying the boot policy save in %{public}.0f s (attempt %{public}ld)", log: log, type: .info,
                   delay, persistenceCycle.retry.attempts)
            schedulePersistence(immediate: false, after: delay)
        case .retriesUsedUp:
            let retries = persistenceCycle.retry.delays.count
            if removal && state?.filterPersistenceUnsavable == nil {
                // The filter isn't in use, so no banner was shown for this
                // removal: keep it out of the activity log (#349).
                os_log("The older saved rules could not be removed after %{public}ld retries. FreeSnitch tries again with the next rule change or when the app restarts.",
                       log: log, type: .info, retries)
                return
            }
            let message = removal
                ? "The older saved rules could still not be removed after \(retries) retries. "
                    + "FreeSnitch tries again with the next rule change or when the app restarts."
                : "The current rules are still not saved for the next start after \(retries) retries. "
                    + "FreeSnitch saves them again with the next rule change, with Send Rules Again, or when the app restarts."
            state?.appendLog(level: "error", message: message)
            os_log("%{public}@", log: log, type: .error, message)
        }
    }

    /// What the banner says about rules that could not be kept for the next
    /// start. Only a size or count problem is solved by removing rules; for
    /// anything else it says what happened instead (#341).
    static func unsavableReason(_ problem: SharedRuleBridge.BootSnapshotProblem, error: Error) -> String {
        switch problem {
        case .tooManyRules(let count, let maximum):
            return "There are \(count) rules and at most \(maximum) can be kept for the next start. "
                + "Remove some rules to keep them across restarts."
        case .tooLarge(_, let maximumBytes):
            return "The rules take up more than the \(maximumBytes / 1024) KB that can be kept for the next start. "
                + "Remove some rules or shorten long notes to keep them across restarts."
        case .datedInFuture:
            return "They are dated later than the Mac's clock, which happens when the clock is set back. "
                + "This fixes itself the next time the rules are saved, for example with the next rule change."
        case .other:
            return "They could not be saved for the next start: \(error.sentence)"
        }
    }

    /// `unsavable` says why the current rules can't be kept for the next
    /// start; a retry or Send Rules Again cannot fix that (#320).
    private func recordPersistenceFailure(_ operation: String, error: Error, unsavable: String? = nil,
                                          writeLog: Bool = true) {
        let detail = "Persisted boot policy \(operation) failed: \(error.sentence) Live filtering remains unchanged. "
            + (unsavable == nil
                ? "If the filter restarts before a save succeeds, it normally skips saved rules older than the ones it last enforced and allows everything until this app sends the current ones."
                : "FreeSnitch removes the saved policy, so after a restart the filter allows everything until this app sends the current rules.")
        if !filterOff.saveFailureShowsBanner {
            // Nothing restarts with these rules while the filter is off, so
            // the banner's warning does not apply; keep it in the log only.
            let offDetail = "Persisted boot policy \(operation) failed while the filter is off: \(error.sentence) "
                + "Turning the filter on saves the current rules again."
            if writeLog {
                state?.appendLog(level: "error", message: offDetail)
                os_log("%{public}@", log: log, type: .error, offDetail)
            }
            return
        }
        recordFilterDiagnostic(state: "degraded", detail: detail)
        state?.recordFilterPersistenceFailure(detail, unsavable: unsavable, writeLog: writeLog)
        if writeLog { os_log("%{public}@", log: log, type: .error, detail) }
    }

    private func disableFilter() {
        // Turned back on while still over the limit is a new state: log it.
        unsavableLogged = false
        cancelPendingPersistence()
        // Turning the filter on and then off before the helper answered must
        // not let that answer turn it back on.
        persistenceCycle.dropEnableRequest()
        filterTurnOffs &+= 1
        // A save cycle already loading or saving finishes first; this load
        // then sees what it wrote and the off is saved last (#309).
        filterPreferences.run { [weak self] done in
            NEFilterManager.shared().loadFromPreferences { error in
                DispatchQueue.main.async {
                    guard let self else { done(); return }
                    let mgr = NEFilterManager.shared()
                    guard error == nil else {
                        self.recordFilterDiagnostic(state: "unknown", detail: "Could not read the content filter preferences while disabling them.")
                        done()
                        return
                    }
                    mgr.isEnabled = false
                    mgr.saveToPreferences { saveError in
                        DispatchQueue.main.async {
                            if let saveError {
                                self.recordFilterDiagnostic(state: "unknown", detail: "The content filter could not be disabled: \(saveError.sentence)")
                            } else {
                                self.recordFilterDiagnostic(state: "installed-disabled", detail: "The content filter configuration is installed but disabled.")
                                // With the filter off there is nothing to restart with
                                // these rules; turning it on saves the current ones again.
                                self.state?.clearFilterPersistenceFailure()
                                // A turn-on asked for meanwhile waits behind this
                                // and decides the state, not this late answer.
                                self.filterOff.turnedOff(turnOnPending: self.persistenceCycle.enableRequested)
                            }
                            done()
                        }
                    }
                }
            }
        }
    }

    private func recordFilterDiagnostic(state: String, detail: String) {
        AppPreferences.set(state, forKey: AppPreferences.Key.filterConfigurationState, notify: false)
        AppPreferences.set(detail, forKey: AppPreferences.Key.filterConfigurationDetail, notify: false)
    }

    private func registerIPC() {
        guard let state else { return }
        let bridge = AppCommunicationBridge(state: state)
        self.bridge = bridge
        IPCConnection.shared.register(delegate: bridge) { [weak self] ok, remoteStatus in
            DispatchQueue.main.async {
                guard let self else { return }
                state.appendLog(level: ok ? "info" : "error",
                                message: ok ? "Connected to network extension." : "Extension IPC unavailable.")
                self.recordSnapshotStatus(remoteStatus)
                // The extension starts with no in-memory snapshot, so hand the
                // current one over as soon as the link is up, not only after a
                // later rule or mode change.
                if ok { state.syncSharedRules() }
            }
        }
    }

    /// Clears an extension that refused the helper's authoritative policy.
    ///
    /// The refusal lives entirely in the provider's memory, so restarting the
    /// provider is the whole remedy and a reboot is never the answer. This
    /// deliberately does not deactivate the system extension, does not remove
    /// the filter configuration, and never touches the privileged helper.
    private func recoverFromSnapshotRejection(_ snapshotStatus: SharedRuleBridge.SnapshotStatus) {
        switch snapshotRecovery.decide(for: snapshotStatus) {
        case .notNeeded, .waitForCooldown:
            return
        case .exhausted:
            state?.recordFilterRecovery(SharedRuleBridge.snapshotRecoveryExhaustedRemediation)
        case .restartFilter:
            state?.recordFilterRecovery(
                "The network extension refused the current rules. Restarting the extension's filter to recover; "
                + "restarting the Mac is not required."
            )
            restartFilterProvider()
        }
    }

    /// Stops and restarts the content filter, which is what ends the provider
    /// process and with it the policy it was holding. The configuration stays
    /// installed throughout, so no approval is needed again.
    private func restartFilterProvider() {
        guard !filterRestartInFlight else { return }
        filterRestartInFlight = true
        // Waits for any earlier preferences operation, so a turn-off asked for
        // before the restart is loaded below, and one asked for after it is
        // saved after the restart's own saves (#309).
        filterPreferences.run { [weak self] done in
            guard let self else { done(); return }
            self.runFilterRestart(done: done)
        }
    }

    private func runFilterRestart(done: @escaping () -> Void) {
        let mgr = NEFilterManager.shared()
        mgr.loadFromPreferences { [weak self] loadError in
            DispatchQueue.main.async {
                guard let self else { done(); return }
                if let loadError {
                    self.finishFilterRestart(failure: "read", error: loadError, done: done)
                    return
                }
                guard mgr.isEnabled else {
                    // The filter was turned off (or removed) while the restart
                    // waited. Restarting it would turn it back on.
                    self.filterRestartInFlight = false
                    done()
                    return
                }
                mgr.isEnabled = false
                mgr.saveToPreferences { stopError in
                    DispatchQueue.main.async {
                        if let stopError {
                            self.finishFilterRestart(failure: "stop", error: stopError, done: done)
                            return
                        }
                        mgr.localizedDescription = "FreeSnitch"
                        mgr.isEnabled = true
                        mgr.saveToPreferences { startError in
                            DispatchQueue.main.async {
                                if let startError {
                                    self.finishFilterRestart(failure: "start", error: startError, done: done)
                                    return
                                }
                                self.filterRestartInFlight = false
                                self.recordFilterDiagnostic(state: "installed-enabled",
                                                            detail: "The content filter was restarted to clear a rejected policy snapshot.")
                                done()
                                // The restarted provider holds no policy, so
                                // the helper's snapshot is delivered again
                                // through the ordinary authoritative path.
                                self.state?.syncSharedRules()
                            }
                        }
                    }
                }
            }
        }
    }

    private func finishFilterRestart(failure operation: String, error: Error, done: () -> Void) {
        filterRestartInFlight = false
        let detail = "The network extension filter could not be restarted (\(operation): \(error.localizedDescription)). "
            + SharedRuleBridge.snapshotRecoveryExhaustedRemediation
        recordFilterDiagnostic(state: "degraded", detail: detail)
        state?.recordFilterRecovery(detail)
        os_log("%{public}@", log: log, type: .error, detail)
        done()
    }

    private func recordSnapshotStatus(_ snapshotStatus: SharedRuleBridge.SnapshotStatus) {
        self.snapshotStatus = snapshotStatus
        if snapshotStatus.isReady {
            snapshotRecovery.noteHealthy()
            state?.recordFilterRecovery(nil)
        } else {
            recoverFromSnapshotRejection(snapshotStatus)
        }
        if !snapshotStatus.isReady,
           persistenceCycle.abandonEnableIfIdle() {
            fail("filter snapshot unavailable: \(snapshotStatus.message ?? "the helper returned no authoritative policy")")
            return
        }
        guard filterConfigurationActive else { return }
        if snapshotStatus.isReady {
            status = .active
            return
        }
        let detail = snapshotStatus.message ?? "no snapshot has been received"
        status = .failed("filter snapshot unavailable: \(detail)")
    }

    private func fail(_ message: String) {
        status = .failed(message)
        state?.appendLog(level: "error", message: message)
        os_log("%{public}@", log: log, type: .error, message)
    }
}

extension SystemExtensionManager: OSSystemExtensionRequestDelegate {
    nonisolated func request(_ request: OSSystemExtensionRequest,
                             didFinishWithResult result: OSSystemExtensionRequest.Result) {
        Task { @MainActor in
            if self.requestKind == .properties { return }
            guard self.requestKind == .activation else {
                if result == .completed {
                    self.filterConfigurationActive = false
                    self.status = .idle
                    // A completed deactivation is the system's answer, but the
                    // record can still be present and only drop at reboot. Ask
                    // before telling the user it is gone.
                    self.uninstallState = .deactivating
                    self.checkExtensionPresence()
                } else {
                    self.state?.appendLog(level: "info", message: "Network extension deactivation finishes after reboot.")
                    self.uninstallState = .pendingReboot
                }
                return
            }
            guard result == .completed else {
                self.state?.appendLog(level: "info", message: "Network extension activation finishes after reboot.")
                return
            }
            // The request remains pending while approval is outstanding. A
            // completed activation is the first point at which saving the
            // content-filter preferences is permitted.
            self.state?.appendLog(level: "info", message: "Network extension approved and active; installing filter configuration.")
            self.enableFilter()
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        Task { @MainActor in
            let missing = (error as? OSSystemExtensionError)?.code == .extensionNotFound
            switch self.requestKind {
            case .activation:
                self.fail("Extension activation failed: \(error.localizedDescription)")
            case .deactivation:
                if missing {
                    self.uninstallState = .notInstalled
                } else {
                    self.uninstallState = .failed(error.localizedDescription)
                }
                self.state?.appendLog(level: "info",
                                      message: "Network extension deactivation returned: \(error.localizedDescription)")
            case .properties:
                // The system has no record left to describe. That is the only
                // evidence available that the extension is actually gone.
                self.uninstallState = missing ? .removed : .pendingReboot
            }
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest,
                             foundProperties properties: [OSSystemExtensionProperties]) {
        Task { @MainActor in
            guard self.requestKind == .properties else { return }
            let records = properties.filter { $0.bundleIdentifier == self.extensionIdentifier }
            if records.isEmpty {
                self.uninstallState = .removed
            } else {
                self.uninstallState = .pendingReboot
            }
        }
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in
            guard self.requestKind != .deactivation else {
                // Removal can need approval too. Do not repaint the firewall
                // status as "waiting to be switched on" while the user is
                // switching it off.
                self.state?.appendLog(level: "info",
                                      message: "macOS is asking you to approve removing the FreeSnitch network extension. Approve it in System Settings > General > Login Items & Extensions > Network Extensions.")
                return
            }
            self.status = .needsApproval
            self.state?.appendLog(level: "info",
                                  message: "Approve FreeSnitch in System Settings > General > Login Items & Extensions > Network Extensions, then it will start filtering.")
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest,
                             actionForReplacingExtension existing: OSSystemExtensionProperties,
                             withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        return .replace
    }
}

/// App-side XPC object the extension calls to ask the user about a paused flow.
/// Bridges into the existing connection-alert UI via AppState.
final class AppCommunicationBridge: NSObject, AppCommunication {
    private weak var state: AppState?
    init(state: AppState) { self.state = state }

    func promptUser(flowJSON: Data, responseHandler: @escaping (Bool, Bool) -> Void) {
        guard let conn = try? JSONDecoder().decode(Connection.self, from: flowJSON) else {
            responseHandler(true, false); return
        }
        Task { @MainActor in
            guard let state = self.state else { responseHandler(true, false); return }
            state.presentAlert(for: conn, reply: responseHandler)
        }
    }

    func recordObservationBatch(observationBatch: Data, responseHandler: @escaping (Bool) -> Void) {
        guard observationBatch.count <= InsightsLimits.maxBatchBytes else {
            responseHandler(false)
            return
        }
        guard let state else {
            responseHandler(false)
            return
        }
        Task { @MainActor in
            responseHandler(state.helper.ingestObservationBatch(observationBatch))
        }
    }
}
