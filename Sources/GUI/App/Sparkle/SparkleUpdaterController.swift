import Sparkle

@MainActor
final class SparkleUpdaterController {
    /// One updater for the whole app: the app menu command and the About page
    /// have to drive the same one, and starting two would schedule two update
    /// checks (#139).
    static let shared = SparkleUpdaterController()

    private let standardController: SPUStandardUpdaterController

    init() {
        standardController = SPUStandardUpdaterController(
            // The window-less run brew starts to remove the network
            // extension starts nothing else (#391).
            startingUpdater: !CommandLine.arguments.contains(AppDelegate.removeNetworkExtensionArgument),
            updaterDelegate: nil,
            userDriverDelegate: nil
        )
    }

    var updater: SPUUpdater {
        standardController.updater
    }
}
