import AppKit
import Foundation

/// Performs the privileged half of an uninstall, behind one authorization
/// prompt, the way any consumer application removes itself.
///
/// Why this exists: the Uninstall screen used to print a list of `sudo`
/// commands and tell the user to run them in Terminal, including
/// `sudo bash Scripts/uninstall_freesnitch.sh`, a script that only exists in a
/// source checkout. Anyone who installed from the DMG was handed instructions
/// that could not be followed at all. An uninstaller that cannot uninstall is
/// not an uninstaller.
///
/// Everything this touches is a fixed, absolute, compile-time path, the same
/// set the shipped script guards with `assert_exact_path`. Nothing here is
/// assembled from a bundle path, a preference, or any other value that varies
/// at runtime, so this cannot be steered into deleting something else.
enum PrivilegedUninstall {
    enum Failure: Error, Equatable {
        case cancelled
        case failed(String)
    }

    /// Flush the shared anchor, then remove root-owned data, then the app.
    ///
    /// Order matters: the anchor is flushed while the app is still on disk,
    /// and the bundle goes last because the helper binary lives inside it.
    ///
    /// The anchor is flushed, never deleted, and pf is never disabled
    /// globally: `/etc/pf.conf` still references the `puresnitch` anchor, and
    /// removing the file while pf.conf points at it would strand the user's
    /// firewall configuration.
    private static let keepDatabase = """
    do shell script "/sbin/pfctl -a puresnitch -F all; \
    /sbin/pfctl -a puresnitch -f /dev/null; \
    /bin/rm -rf '/Library/Application Support/FreeSnitch/Insights'" with administrator privileges
    """

    /// The same, plus the policy database. Separate constant rather than a
    /// flag spliced into a string, so both forms stay literal and auditable.
    private static let removeDatabase = """
    do shell script "/sbin/pfctl -a puresnitch -F all; \
    /sbin/pfctl -a puresnitch -f /dev/null; \
    /bin/rm -rf '/Library/Application Support/FreeSnitch/Insights'; \
    /bin/rm -f '/Library/Application Support/FreeSnitch/freesnitch.sqlite'" with administrator privileges
    """

    /// Hand the app bundle to Finder instead of deleting it.
    ///
    /// This is the whole reason the privileged script above no longer touches
    /// `/Applications/FreeSnitch.app`. Moving an app that hosts a system
    /// extension to the Trash **through Finder** is what triggers macOS's own
    /// extension removal. Objective Development document exactly this for
    /// Little Snitch, and warn in the same breath not to remove such an app
    /// "by any other means (like Terminal ...) because otherwise macOS won't
    /// remove the system extension".
    ///
    /// `/bin/rm -rf` on the bundle, which is what this used to do, is that
    /// forbidden path: it takes the app away and leaves the extension
    /// installed, which is the opposite of uninstalling.
    static func trashApplicationBundle(completion: @escaping (String?) -> Void) {
        let bundleURL = Bundle.main.bundleURL
        NSWorkspace.shared.recycle([bundleURL]) { _, error in
            DispatchQueue.main.async {
                completion(error?.localizedDescription)
            }
        }
    }

    /// Blocks on the authorization prompt; call it off the main thread.
    static func run(removingDatabase: Bool) -> Result<Void, Failure> {
        let source = removingDatabase ? removeDatabase : keepDatabase
        guard let appleScript = NSAppleScript(source: source) else {
            return .failure(.failed("The uninstall could not be prepared."))
        }
        var errorInfo: NSDictionary?
        appleScript.executeAndReturnError(&errorInfo)
        guard let errorInfo else { return .success(()) }

        let code = (errorInfo[NSAppleScript.errorNumber] as? Int) ?? 0
        if code == -128 { return .failure(.cancelled) }
        let message = (errorInfo[NSAppleScript.errorMessage] as? String)
            ?? "The privileged uninstall did not complete."
        return .failure(.failed(message))
    }

    /// User-level leftovers. No authorization needed, so this is separate:
    /// asking for a password to delete files the user already owns would be
    /// theatre.
    static func removeUserData() {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let targets = [
            home.appendingPathComponent("Library/Group Containers/BHAF4L4726.io.isaaclins.freesnitch"),
            home.appendingPathComponent("Library/Application Support/FreeSnitch"),
            home.appendingPathComponent("Library/Preferences/io.isaaclins.freesnitch.plist")
        ]
        for target in targets {
            try? FileManager.default.removeItem(at: target)
        }
    }
}
