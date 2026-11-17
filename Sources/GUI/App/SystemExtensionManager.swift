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
    private var persistenceQueue = SharedRuleBridge.NewestWriteWinsQueue()
    private var persistenceInFlight = false
    /// Ends the boot-policy save cycle's turn on `filterPreferences`.
    private var persistenceCycleDone: (() -> Void)?
    /// Every load-then-save on the shared NEFilterManager (boot-policy saves,
    /// turning the filter off, removing it, restarting it) waits here for the
    /// one before it, so the last thing asked for is what gets saved (#309).
    private let filterPreferences = FilterPreferencesLine()
    private var persistenceWorkItem: DispatchWorkItem?
    private var enableFilterRequested = false
    /// Automatic retries of a failed boot-policy save (#213). Bounded and
    /// spaced; reset by a successful save or a newer policy.
    private var persistenceRetry = SharedRuleBridge.RetrySchedule()
    /// Bumped whenever pending saves are cancelled, so a cycle that was
    /// already running can tell its result no longer matters.
    private var persistenceCancellations = 0
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
        cancelPendingPersistence()
        enableFilterRequested = false
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
        cancelPendingPersistence()
        enableFilterRequested = true
        // AppState fetches the helper-owned snapshot and invokes the
        // persistence callback only after it has updated its display cache.
        // There is no cached-rule fallback during activation.
        state?.syncSharedRules()
    }

    /// Queue the newest policy for NEFilterManager.providerConfiguration. The
    /// manager is the sole persistence owner. Saves are serialized because
    /// NEFilterManager's load/save callbacks are asynchronous, and a newer
    /// request always remains pending until the older save completes.
    private func requestPersistedSnapshot(_ snapshot: SharedRuleBridge.Snapshot,
                                          immediate: Bool = false) {
        do {
            persistenceQueue.enqueue(try SharedRuleBridge.encodeBootSnapshot(snapshot))
            persistenceRetry.reset()
            schedulePersistence(immediate: immediate || enableFilterRequested)
        } catch {
            // This policy cannot be saved (for example it is over the boot
            // policy size limit). An older snapshot still queued for a retry
            // must not be saved instead and clear the warning: drop it, and
            // invalidate a save in flight.
            cancelPendingPersistence()
            recordPersistenceFailure("encode", error: error)
            if enableFilterRequested {
                // Activation waits for this policy and it will never arrive
                // in a savable form: say so instead of waiting forever.
                enableFilterRequested = false
                fail("filter snapshot could not be saved: \(error.localizedDescription)")
            }
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
        guard !persistenceInFlight else { return }
        // Activation waits for a successful helper getter before it can save
        // or enable the filter. An enable request without a pending snapshot
        // is a fetch failure, not permission to persist stale GUI state.
        guard persistenceQueue.hasPending else { return }
        persistenceInFlight = true
        // Waits for a turn-off, removal or restart that was asked for earlier
        // to finish saving, and makes one asked for later wait for this cycle.
        filterPreferences.run { [weak self] done in
            guard let self else { done(); return }
            self.persistenceCycleDone = done
            self.runPersistenceCycle()
        }
    }

    private func runPersistenceCycle() {
        let generationAtLoad = persistenceQueue.generation
        let cancellationsAtLoad = persistenceCancellations
        let mgr = NEFilterManager.shared()
        mgr.loadFromPreferences { [weak self] loadError in
            DispatchQueue.main.async {
                guard let self else { return }
                if let loadError, self.persistenceCancellations != cancellationsAtLoad {
                    // The filter was turned on, off or removed meanwhile; this
                    // load no longer matters and must not raise a warning or
                    // fail an activation that has not run yet.
                    self.endPersistenceCycle()
                    os_log("A cancelled boot policy load failed: %{public}@", log: self.log, type: .info,
                           loadError.sentence)
                    if self.persistenceQueue.hasPending || self.enableFilterRequested {
                        self.schedulePersistence(immediate: true)
                    }
                    return
                }
                if let loadError {
                    self.endPersistenceCycle()
                    self.recordPersistenceFailure("load", error: loadError)
                    if self.enableFilterRequested {
                        self.fail("filter load: \(loadError.localizedDescription)")
                        let hasNewerSnapshot = self.persistenceQueue.hasNewerWork(since: generationAtLoad)
                        self.persistenceQueue.discardThrough(generationAtLoad)
                        if hasNewerSnapshot {
                            self.schedulePersistence(immediate: true)
                        }
                    } else if self.persistenceQueue.hasNewerWork(since: generationAtLoad) {
                        self.schedulePersistence(immediate: true)
                    } else {
                        // The snapshot was never taken, so it is still
                        // pending. Leaving the older saved policy as the last
                        // word is the bug in #213: try again.
                        self.schedulePersistenceRetry()
                    }
                    return
                }

                let shouldEnable = self.enableFilterRequested
                if shouldEnable && !self.persistenceQueue.hasPending {
                    // The filter was turned on while this cycle was loading,
                    // which cleared the queue. Only the helper's fresh answer
                    // may enable it; its arrival starts the next cycle.
                    self.endPersistenceCycle()
                    return
                }
                if !shouldEnable && mgr.providerConfiguration == nil {
                    // No filter is configured (never enabled, or removed for
                    // uninstall). A boot policy save must not create one.
                    self.endPersistenceCycle()
                    self.persistenceQueue.discardThrough(self.persistenceQueue.generation)
                    // Nothing to save rules for, so an earlier save-failure
                    // warning no longer applies (#311).
                    self.state?.clearFilterPersistenceFailure()
                    return
                }
                let pending = self.persistenceQueue.takeNewest()
                let snapshotData = pending?.data
                if !shouldEnable && pending == nil {
                    // Turned off or removed while this cycle was loading:
                    // there is nothing to save, and writing the configuration
                    // loaded before would race that change.
                    self.endPersistenceCycle()
                    return
                }
                self.enableFilterRequested = false
                let configuration = mgr.providerConfiguration ?? NEFilterProviderConfiguration()
                configuration.filterSockets = true
                configuration.filterPackets = false
                if let snapshotData {
                    var vendorConfiguration = configuration.vendorConfiguration ?? [:]
                    vendorConfiguration[SharedRuleBridge.bootSnapshotVendorConfigurationKey] = snapshotData
                    configuration.vendorConfiguration = vendorConfiguration
                }
                mgr.providerConfiguration = configuration
                if shouldEnable {
                    mgr.localizedDescription = "FreeSnitch"
                    mgr.isEnabled = true
                }
                mgr.saveToPreferences { saveError in
                    DispatchQueue.main.async {
                        self.endPersistenceCycle()
                        var retryScheduled = false
                        if let saveError {
                            if self.persistenceCancellations == cancellationsAtLoad {
                                self.recordPersistenceFailure("save", error: saveError)
                            } else {
                                // The filter was turned on, off or removed
                                // meanwhile; this save no longer matters and
                                // must not bring the warning back.
                                os_log("A cancelled boot policy save failed: %{public}@", log: self.log, type: .info,
                                       saveError.sentence)
                            }
                            if shouldEnable {
                                self.fail("filter save: \(saveError.localizedDescription)")
                            } else if let pending,
                                      self.persistenceQueue.requeueFailed(pending) {
                                // Nothing newer arrived during the save, so
                                // the saved policy is still older than the one
                                // being enforced. Keep this one and retry.
                                retryScheduled = self.schedulePersistenceRetry()
                            }
                        } else {
                            if snapshotData != nil {
                                // Only a save of the newest policy clears the
                                // warning; an older one finishing late does not.
                                if let pending, !self.persistenceQueue.hasNewerWork(since: pending.generation) {
                                    self.persistenceRetry.reset()
                                    self.state?.clearFilterPersistenceFailure()
                                }
                                if shouldEnable || self.filterConfigurationActive {
                                    self.recordFilterDiagnostic(state: "installed-enabled", detail: "The content filter configuration is installed and enabled.")
                                }
                            } else if shouldEnable {
                                self.recordFilterDiagnostic(state: "degraded", detail: "The content filter is enabled, but no valid boot policy could be persisted. Future starts will fail open.")
                            }
                            if shouldEnable {
                                self.filterConfigurationActive = true
                                self.status = .active
                                // Deliberately does NOT touch `helperConnected`: the
                                // content filter and privileged helper are separate.
                                self.state?.appendLog(level: "info", message: "Per-process firewall active.")
                                self.registerIPC()
                            }
                        }

                        // A request that arrived while load/save was in flight
                        // cannot be folded into the completed system write.
                        // Start another serialized cycle for that newer data.
                        // A spaced retry already owns the requeued snapshot;
                        // only an enable request may jump ahead of it.
                        if self.enableFilterRequested
                            || (!retryScheduled && self.persistenceQueue.hasNewerWork(since: generationAtLoad)) {
                            self.schedulePersistence(immediate: true)
                        }
                    }
                }
            }
        }
    }

    /// The boot-policy save cycle is over: the next preferences operation may
    /// run, and a new cycle may start.
    private func endPersistenceCycle() {
        persistenceInFlight = false
        let done = persistenceCycleDone
        persistenceCycleDone = nil
        done?()
    }

    /// Drops a queued or scheduled boot-policy save. Used when the filter is
    /// turned on (only a fresh helper answer may be saved then), turned off,
    /// or removed, so a late retry can neither enable nor recreate it.
    private func cancelPendingPersistence() {
        persistenceCancellations &+= 1
        persistenceWorkItem?.cancel()
        persistenceWorkItem = nil
        // Invalidates a save that is already in flight too: if it fails, it
        // can no longer be put back and retried, so it can neither enable nor
        // rewrite a filter the user just turned on, off or removed.
        persistenceQueue.invalidateAll()
        persistenceRetry.reset()
    }

    @discardableResult
    private func schedulePersistenceRetry() -> Bool {
        guard let delay = persistenceRetry.nextDelay() else {
            let message = "The current rules are still not saved for the next start after \(persistenceRetry.delays.count) retries. "
                + "FreeSnitch saves them again with the next rule change, with Send Rules Again, or when the app restarts."
            state?.appendLog(level: "error", message: message)
            os_log("%{public}@", log: log, type: .error, message)
            return false
        }
        os_log("Retrying the boot policy save in %{public}.0f s (attempt %{public}ld)", log: log, type: .info,
               delay, persistenceRetry.attempts)
        schedulePersistence(immediate: false, after: delay)
        return true
    }

    private func recordPersistenceFailure(_ operation: String, error: Error) {
        let detail = "Persisted boot policy \(operation) failed: \(error.sentence) Live filtering remains unchanged. "
            + "If the filter restarts before a save succeeds, it normally skips saved rules older than the ones it last enforced and allows everything until this app sends the current ones."
        recordFilterDiagnostic(state: "degraded", detail: detail)
        state?.recordFilterPersistenceFailure(detail)
        os_log("%{public}@", log: log, type: .error, detail)
    }

    private func disableFilter() {
        cancelPendingPersistence()
        // Turning the filter on and then off before the helper answered must
        // not let that answer turn it back on.
        enableFilterRequested = false
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
           enableFilterRequested,
           !persistenceQueue.hasPending,
           !persistenceInFlight {
            enableFilterRequested = false
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
