import Sparkle

@MainActor
final class SparkleUpdaterController {
    private let standardController: SPUStandardUpdaterController

    init() {
        standardController = SPUStandardUpdaterController(
            startingUpdater: true,
            updaterDelegate: nil,
            userDriverDelegate: nil
        )
    }

    var updater: SPUUpdater {
        standardController.updater
    }
}
