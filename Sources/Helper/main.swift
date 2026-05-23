import Foundation

PSLog.info(PSLog.helper, "PureSnitchHelper starting v\(AppConstants.version) pid=\(getpid())")

let listener = NSXPCListener(machServiceName: AppConstants.xpcMachServiceName)

do {
    let service = try HelperService(listener: listener)
    service.start()
} catch {
    PSLog.error(PSLog.helper, "service init failed: \(error)")
    exit(1)
}

dispatchMain()
