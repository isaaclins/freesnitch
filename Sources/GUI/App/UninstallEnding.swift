import Foundation

/// How an uninstall ends once the app bundle is in the Trash.
///
/// Kept apart from `UninstallFlowModel` so the decision can be checked without
/// a real helper, extension or bundle (Scripts/test_uninstall_ending.sh).
///
/// The helper's launchd registration and the person's own files are the steps
/// whose failure does not stop the uninstall: by then the pf anchor is flushed
/// and the root-owned data is gone, so stopping would only leave the app
/// behind as well. But a failure there must not end on a screen that says
/// everything is removed, or on a silent quit (#215, #272). The person is told
/// what is left and how to remove it.
enum UninstallEnding: Equatable {
    /// What an uninstall could not remove.
    struct Leftovers: Equatable {
        /// What macOS said when it kept the helper registered, or nil.
        var helper: String?
        /// The person's own FreeSnitch files still on disk, as shown to them.
        var userData: [String]

        var isEmpty: Bool { helper == nil && userData.isEmpty }
    }

    /// Everything is gone; nothing left to read, so the app quits.
    case quit
    /// Everything is gone; macOS clears the stopped extension at the next
    /// restart.
    case doneUntilRestart
    /// Everything else is gone, but the helper is still registered with
    /// macOS, or some of the person's files are still on disk, or both.
    case leftBehind(Leftovers)

    /// Whether a failed unregister really left the helper behind. An error is
    /// not proof by itself: a helper that was never registered (#409) makes
    /// unregister fail too. Only a registration macOS still lists counts,
    /// otherwise the ending would send people to remove a helper that isn't
    /// there. Returns what macOS said when it is left behind.
    static func helperLeftBehind(unregisterError: String?, stillListed: Bool) -> String? {
        guard let unregisterError, stillListed else { return nil }
        return unregisterError
    }

    static func after(helperProblem: String?, userDataLeft: [String],
                      extensionPendingReboot: Bool) -> UninstallEnding {
        let leftovers = Leftovers(helper: helperProblem, userData: userDataLeft)
        if !leftovers.isEmpty { return .leftBehind(leftovers) }
        return extensionPendingReboot ? .doneUntilRestart : .quit
    }
}

/// Deleting the person's own FreeSnitch files during an uninstall.
///
/// Kept here, without AppKit, so Scripts/test_uninstall_ending.sh can run it
/// against real files that refuse to be deleted.
enum UninstallCleanup {
    /// Removes each target and returns the ones still on disk afterwards.
    ///
    /// A target counts as removed only once it is checked to be gone, not
    /// because `removeItem` returned: a folder with one locked file inside
    /// loses everything else and stays, and that must be reported, not
    /// dropped (#272). The check does not follow a symbolic link, so a link
    /// that was removed is not mistaken for its target, and only "no such
    /// file" counts as gone: a path that can't even be looked at is reported.
    static func remove(_ targets: [URL], fileManager: FileManager = .default) -> [URL] {
        for target in targets {
            try? fileManager.removeItem(at: target)
        }
        return targets.filter { !isGone($0) }
    }

    private static func isGone(_ url: URL) -> Bool {
        var info = stat()
        if lstat(url.path, &info) == 0 { return false }
        return errno == ENOENT || errno == ENOTDIR
    }
}
