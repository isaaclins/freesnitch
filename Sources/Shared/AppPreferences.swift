import Foundation

/// Preferences that belong to the GUI bundle but can also be changed by the
/// bundled CLI. Keeping the suite and notification name shared lets a running
/// GUI adopt a CLI change without inventing another firewall control channel.
public enum AppPreferences {
    public static let suiteName = AppConstants.bundleIdGUI
    public static let changeNotification = "io.isaaclins.freesnitch.preferences.changed"

    public enum Key {
        public static let mode = "PSMode"
        public static let filterConfigurationState = "PSFilterConfigurationState"
        public static let filterConfigurationDetail = "PSFilterConfigurationDetail"
        public static let enforcement = "PSEnforcementEnabled"
        public static let showSpeeds = "PSShowSpeedsInMenuBar"
        public static let alertsAllSpaces = "PSShowAlertsOnAllSpaces"
    }

    public static var defaults: UserDefaults {
        // The shipped CLI runs from Contents/MacOS inside the GUI app bundle,
        // so standard already names the GUI domain. A standalone development
        // CLI needs the explicit suite instead.
        if Bundle.main.bundleIdentifier == AppConstants.bundleIdGUI {
            return UserDefaults.standard
        }
        return UserDefaults(suiteName: suiteName) ?? UserDefaults.standard
    }

    public static func bool(forKey key: String) -> Bool {
        defaults.bool(forKey: key)
    }

    public static func string(forKey key: String) -> String? {
        defaults.string(forKey: key)
    }

    public static func set(_ value: String, forKey key: String, notify: Bool = true) {
        defaults.set(value, forKey: key)
        defaults.synchronize()
        postChange(key: key, value: value, notify: notify)
    }

    public static func set(_ value: Bool, forKey key: String, notify: Bool = true) {
        defaults.set(value, forKey: key)
        defaults.synchronize()
        postChange(key: key, value: value, notify: notify)
    }

    private static func postChange(key: String, value: Any, notify: Bool) {
        guard notify else { return }
        DistributedNotificationCenter.default().postNotificationName(
            Notification.Name(changeNotification),
            object: nil,
            userInfo: [key: value],
            deliverImmediately: true
        )
    }
}
