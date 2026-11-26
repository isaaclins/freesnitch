import Foundation

// The helper runs from inside the app bundle, so its text lookups would find
// the app's translations and follow the Mac's system language. Its messages go
// into logs and back to the app mixed with English, so it speaks English only.
// This must run before anything looks up localized text.
UserDefaults.standard.setVolatileDomain(["AppleLanguages": ["en"]], forName: UserDefaults.argumentDomain)

// Freeze the identity of the bundle this process is launching from, before any
// update can replace it on disk. Everything the helper reports as its running
// version comes from this capture.
AppBundleIdentity.captureRunningIdentity()

PSLog.info(PSLog.helper, "FreeSnitchHelper starting running=\(public: HelperService.runningVersion) installed=\(public: HelperService.installedVersion) pid=\(public: getpid())")

let listener = NSXPCListener(machServiceName: AppConstants.xpcMachServiceName)

// `service` MUST outlive this scope. NSXPCListener holds its delegate weakly,
// so when the HelperService was created inside a `do { }` block it was
// deallocated the moment the block ended, the delegate went nil, and the
// listener then rejected *every* incoming connection
// ("Peer connection was rejected by the listener"). The app therefore showed
// zero traffic and zero rules even after the user approved the daemon.
let service: HelperService
do {
    service = try HelperService(listener: listener)
} catch {
    PSLog.error(PSLog.helper, "service init failed: \(error: error)")
    exit(1)
}
service.start()

// #71: if FreeSnitch.app is dragged to the Trash, this daemon must stop holding
// a pf anchor and a DNS proxy for an app that no longer exists. It stands down;
// it never unregisters itself and never deletes the policy database.
HelperBundleWatchdog.shared.startWatching(service: service)

dispatchMain()
