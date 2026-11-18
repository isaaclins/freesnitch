import Foundation

/// `FREESNITCH_DEMO=1`: the app shows sample data for screenshots and review.
///
/// A demo can run on a Mac where FreeSnitch is really installed, under the same
/// bundle id. It must leave that install alone: no reads or saves of the real
/// content filter configuration (#388), no system extension requests, no helper
/// registration, repair or removal, no login item change and no files removed
/// (#389). Every place that does one of those checks this first.
enum DemoMode {
    static let isOn = ProcessInfo.processInfo.environment["FREESNITCH_DEMO"] == "1"
}
