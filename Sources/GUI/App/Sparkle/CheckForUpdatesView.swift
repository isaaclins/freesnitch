import Combine
import Sparkle
import SwiftUI

@MainActor
private final class CheckForUpdatesViewModel: ObservableObject {
    @Published var canCheckForUpdates = false

    init(updater: SPUUpdater) {
        updater.publisher(for: \.canCheckForUpdates)
            .assign(to: &$canCheckForUpdates)
    }
}

/// Updates where a Mac user looks for them: next to the version number.
///
/// The only way to check was the app menu, and whether FreeSnitch checked on
/// its own was not stated anywhere, on an app whose own helper breaks on an
/// in-place update (#139).
@MainActor
struct UpdaterSettingsView: View {
    @ObservedObject private var viewModel: CheckForUpdatesViewModel
    @State private var automatic: Bool
    private let updater: SPUUpdater

    init() {
        self.init(updater: SparkleUpdaterController.shared.updater)
    }

    init(updater: SPUUpdater) {
        self.updater = updater
        viewModel = CheckForUpdatesViewModel(updater: updater)
        _automatic = State(initialValue: updater.automaticallyChecksForUpdates)
    }

    var body: some View {
        VStack(spacing: 8) {
            Button("Check for Updates…") { updater.checkForUpdates() }
                .disabled(!viewModel.canCheckForUpdates)
            Toggle("Check for updates automatically", isOn: $automatic)
                .toggleStyle(.checkbox)
                .onChange(of: automatic) { newValue in
                    updater.automaticallyChecksForUpdates = newValue
                }
            if let last = updater.lastUpdateCheckDate {
                Text("Last checked \(last.formatted(date: .abbreviated, time: .shortened)).")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

struct CheckForUpdatesView: View {
    @ObservedObject private var viewModel: CheckForUpdatesViewModel
    private let updater: SPUUpdater

    init(updater: SPUUpdater) {
        self.updater = updater
        viewModel = CheckForUpdatesViewModel(updater: updater)
    }

    var body: some View {
        Button("Check for Updates…") {
            updater.checkForUpdates()
        }
        .disabled(!viewModel.canCheckForUpdates)
    }
}
