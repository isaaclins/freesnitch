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

    /// The privileged steps, by the exit code each one stops the script with.
    /// `do shell script` reports a command's exit status as the error number.
    enum Step: Int, CaseIterable {
        case emptyAnchorFile = 81
        case flushAnchor = 82
        case loadEmptyAnchor = 83
        case commandLink = 84
        case insights = 85
        case database = 86

        /// What was left, said so the person knows what is still on the Mac.
        var failureDescription: String {
            switch self {
            case .emptyAnchorFile:
                return String(localized: "FreeSnitch couldn’t empty the firewall rules file macOS loads at startup.")
            case .flushAnchor, .loadEmptyAnchor:
                return String(localized: "FreeSnitch couldn’t clear its firewall rules from the packet filter.")
            case .commandLink:
                return String(localized: "FreeSnitch couldn’t remove the freesnitch command from /usr/local/bin.")
            case .insights:
                return String(localized: "FreeSnitch couldn’t delete its connection history.")
            case .database:
                return String(localized: "FreeSnitch couldn’t delete its rules database.")
            }
        }
    }

    /// Flush the shared anchor, then remove root-owned data, then the app.
    ///
    /// Order matters: the anchor is flushed while the app is still on disk,
    /// and the bundle goes last because the helper binary lives inside it.
    ///
    /// The anchor is emptied and flushed, never deleted, and pf is never
    /// disabled globally: `/etc/pf.conf` still references the `puresnitch`
    /// anchor, and removing the file while pf.conf points at it would strand
    /// the user's firewall configuration. Emptying the file matters as much as
    /// the flush: pf.conf loads it at boot, and so does any VPN or tool that
    /// reloads pf.conf, so rules left in it came back after FreeSnitch was
    /// gone (issue #192).
    ///
    /// The `freesnitch` command link from Settings > Command Line goes too, but
    /// only while it still points into the app: a file the user put there
    /// themselves is left alone (#423).
    ///
    /// Every step ends in `|| exit <code>`, so the first one that fails stops
    /// the script and reports which step it was. They used to be joined by
    /// plain semicolons, and the exit status was that of the last command
    /// only: a pf flush that failed was hidden by a removal that worked, and
    /// the app moved itself to the Trash and said it was gone (#271). The
    /// codes are the cases of `Step`.
    private static let keepDatabase = """
    do shell script "if [ -f /etc/pf.anchors/puresnitch ]; then /bin/echo '# FreeSnitch pf anchor - FreeSnitch was uninstalled, so it holds no rules.' > /etc/pf.anchors/puresnitch || exit 81; fi; \
    /sbin/pfctl -a puresnitch -F all || exit 82; \
    /sbin/pfctl -a puresnitch -f /dev/null || exit 83; \
    if /usr/bin/readlink /usr/local/bin/freesnitch | /usr/bin/grep -qxF /Applications/FreeSnitch.app/Contents/Helpers/freesnitch; then /bin/rm -f /usr/local/bin/freesnitch || exit 84; fi; \
    /bin/rm -rf '/Library/Application Support/FreeSnitch/Insights' || exit 85" with administrator privileges
    """

    /// The same, plus the policy database. Separate constant rather than a
    /// flag spliced into a string, so both forms stay literal and auditable.
    /// The database goes with its SQLite companion files: in WAL mode recent
    /// writes live in `-wal` beside it until a checkpoint, so deleting only
    /// the main file left policy records behind (#237).
    private static let removeDatabase = """
    do shell script "if [ -f /etc/pf.anchors/puresnitch ]; then /bin/echo '# FreeSnitch pf anchor - FreeSnitch was uninstalled, so it holds no rules.' > /etc/pf.anchors/puresnitch || exit 81; fi; \
    /sbin/pfctl -a puresnitch -F all || exit 82; \
    /sbin/pfctl -a puresnitch -f /dev/null || exit 83; \
    if /usr/bin/readlink /usr/local/bin/freesnitch | /usr/bin/grep -qxF /Applications/FreeSnitch.app/Contents/Helpers/freesnitch; then /bin/rm -f /usr/local/bin/freesnitch || exit 84; fi; \
    /bin/rm -rf '/Library/Application Support/FreeSnitch/Insights' || exit 85; \
    /bin/rm -f '/Library/Application Support/FreeSnitch/freesnitch.sqlite' '/Library/Application Support/FreeSnitch/freesnitch.sqlite-wal' '/Library/Application Support/FreeSnitch/freesnitch.sqlite-shm' '/Library/Application Support/FreeSnitch/freesnitch.sqlite-journal' || exit 86" with administrator privileges
    """

    /// Move the app bundle to the Trash instead of deleting it.
    ///
    /// The network extension is already stopped by the time this runs: the
    /// uninstall only gets here after macOS answered the deactivation request.
    /// Moving the app to the Trash used to be what made macOS remove an
    /// embedded system extension too, and Objective Development still tell
    /// Little Snitch users to uninstall that way, but since macOS 15.3 it no
    /// longer does. The explicit deactivation before this is the removal; the
    /// Trash keeps the app recoverable rather than deleted outright.
    static func trashApplicationBundle(completion: @escaping (String?) -> Void) {
        // A demo never moves the real app to the Trash (#389).
        guard !DemoMode.isOn else { completion(nil); return }
        let bundleURL = Bundle.main.bundleURL
        NSWorkspace.shared.recycle([bundleURL]) { _, error in
            DispatchQueue.main.async {
                completion(error?.localizedDescription)
            }
        }
    }

    /// Blocks on the authorization prompt; call it off the main thread.
    static func run(removingDatabase: Bool) -> Result<Void, Failure> {
        // A demo never runs the privileged removal (#389).
        guard !DemoMode.isOn else { return .success(()) }
        let source = removingDatabase ? removeDatabase : keepDatabase
        guard let appleScript = NSAppleScript(source: source) else {
            return .failure(.failed(String(localized: "The uninstall could not be prepared.")))
        }
        var errorInfo: NSDictionary?
        appleScript.executeAndReturnError(&errorInfo)
        guard let errorInfo else { return .success(()) }

        let code = (errorInfo[NSAppleScript.errorNumber] as? Int) ?? 0
        if code == -128 { return .failure(.cancelled) }
        let message = (errorInfo[NSAppleScript.errorMessage] as? String)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return .failure(.failed(failureReason(code: code, message: message)))
    }

    /// The sentence the Uninstall screen shows for a failed run: which step
    /// stopped it, then what the command itself said, if anything (#271).
    static func failureReason(code: Int, message: String) -> String {
        guard let step = Step(rawValue: code) else {
            return message.isEmpty ? String(localized: "The privileged uninstall did not complete.") : message
        }
        return message.isEmpty ? step.failureDescription : step.failureDescription + "\n" + message
    }

    /// User-level leftovers. No authorization needed, so this is separate:
    /// asking for a password to delete files the user already owns would be
    /// theatre.
    static func removeUserData() {
        // A demo never deletes the real install's data (#389).
        guard !DemoMode.isOn else { return }
        let home = FileManager.default.homeDirectoryForCurrentUser
        let targets = [
            home.appendingPathComponent("Library/Group Containers/BHAF4L4726.io.isaaclins.freesnitch"),
            home.appendingPathComponent("Library/Application Support/FreeSnitch"),
            home.appendingPathComponent("Library/Preferences/io.isaaclins.freesnitch.plist")
        ]
        for target in targets {
            try? FileManager.default.removeItem(at: target)
        }
        // The preferences daemon keeps its own copy and would write the plist
        // back; dropping the domain is what actually forgets it.
        UserDefaults.standard.removePersistentDomain(forName: AppConstants.bundleIdGUI)
    }
}
