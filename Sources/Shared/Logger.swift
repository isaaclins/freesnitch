import Foundation
import os.log

public enum PSLog {
    public static let app = OSLog(subsystem: AppConstants.bundleIdGUI, category: "app")
    public static let helper = OSLog(subsystem: AppConstants.bundleIdGUI, category: "helper")
    public static let dns = OSLog(subsystem: AppConstants.bundleIdGUI, category: "dns")
    public static let pf = OSLog(subsystem: AppConstants.bundleIdGUI, category: "pf")
    public static let netmon = OSLog(subsystem: AppConstants.bundleIdGUI, category: "netmon")
    public static let netext = OSLog(subsystem: AppConstants.bundleIdGUI, category: "netext")

    /// Interpolated values are private in the unified log unless marked
    /// `\(public: ...)`; see `PSLogMessage` (#264).
    public static func info(_ log: OSLog, _ msg: PSLogMessage) { write(log, .info, msg) }
    /// Default level: written to the log store, unlike `info`, so it is still
    /// there after a restart. For records a user may need later, such as which
    /// rules an import deleted (#247).
    public static func notice(_ log: OSLog, _ msg: PSLogMessage) { write(log, .default, msg) }
    public static func error(_ log: OSLog, _ msg: PSLogMessage) { write(log, .error, msg) }
    public static func debug(_ log: OSLog, _ msg: PSLogMessage) { write(log, .debug, msg) }

    /// os_log needs a literal format, so each value count has its own. Values
    /// past the fourth are folded, with the text between them, into the last
    /// private argument.
    static func write(_ log: OSLog, _ type: OSLogType, _ msg: PSLogMessage) {
        var t = msg.texts
        var v = msg.values
        if v.count > 4 {
            var tail = v[3]
            for index in 4..<v.count { tail += t[index] + v[index] }
            t = Array(t[0...3]) + [t[t.count - 1]]
            v = Array(v[0...2]) + [tail]
        }
        switch v.count {
        case 0:
            os_log("%{public}@", log: log, type: type, t[0])
        case 1:
            os_log("%{public}@%{private}@%{public}@", log: log, type: type, t[0], v[0], t[1])
        case 2:
            os_log("%{public}@%{private}@%{public}@%{private}@%{public}@", log: log, type: type,
                   t[0], v[0], t[1], v[1], t[2])
        case 3:
            os_log("%{public}@%{private}@%{public}@%{private}@%{public}@%{private}@%{public}@",
                   log: log, type: type, t[0], v[0], t[1], v[1], t[2], v[2], t[3])
        default:
            os_log("%{public}@%{private}@%{public}@%{private}@%{public}@%{private}@%{public}@%{private}@%{public}@",
                   log: log, type: type, t[0], v[0], t[1], v[1], t[2], v[2], t[3], v[3], t[4])
        }
    }
}
