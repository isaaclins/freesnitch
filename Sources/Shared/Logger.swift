import Foundation
import os.log

public enum PSLog {
    public static let app = OSLog(subsystem: AppConstants.bundleIdGUI, category: "app")
    public static let helper = OSLog(subsystem: AppConstants.bundleIdGUI, category: "helper")
    public static let dns = OSLog(subsystem: AppConstants.bundleIdGUI, category: "dns")
    public static let pf = OSLog(subsystem: AppConstants.bundleIdGUI, category: "pf")
    public static let netmon = OSLog(subsystem: AppConstants.bundleIdGUI, category: "netmon")
    public static let netext = OSLog(subsystem: AppConstants.bundleIdGUI, category: "netext")

    public static func info(_ log: OSLog, _ msg: String) { os_log("%{public}@", log: log, type: .info, msg) }
    /// Default level: written to the log store, unlike `info`, so it is still
    /// there after a restart. For records a user may need later, such as which
    /// rules an import deleted (#247).
    public static func notice(_ log: OSLog, _ msg: String) { os_log("%{public}@", log: log, type: .default, msg) }
    public static func error(_ log: OSLog, _ msg: String) { os_log("%{public}@", log: log, type: .error, msg) }
    public static func debug(_ log: OSLog, _ msg: String) { os_log("%{public}@", log: log, type: .debug, msg) }
}
