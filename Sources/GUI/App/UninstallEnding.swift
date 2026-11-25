import Foundation

/// How an uninstall ends once the app bundle is in the Trash.
///
/// Kept apart from `UninstallFlowModel` so the decision can be checked without
/// a real helper, extension or bundle (Scripts/test_uninstall_ending.sh).
///
/// The helper's launchd registration is the one step whose failure does not
/// stop the uninstall: by then the pf anchor is flushed and the data is gone,
/// so stopping would only leave the app behind as well. But a failure there
/// must not end on a screen that says everything is removed, or on a silent
/// quit (#215). The person is told what is left and how to remove it.
enum UninstallEnding: Equatable {
    /// Everything is gone; nothing left to read, so the app quits.
    case quit
    /// Everything is gone; macOS clears the stopped extension at the next
    /// restart.
    case doneUntilRestart
    /// Everything else is gone, but the helper is still registered with
    /// macOS. Carries what macOS said.
    case helperLeft(String)

    static func after(helperProblem: String?, extensionPendingReboot: Bool) -> UninstallEnding {
        if let helperProblem { return .helperLeft(helperProblem) }
        return extensionPendingReboot ? .doneUntilRestart : .quit
    }
}
