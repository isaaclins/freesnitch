import Foundation

/// Runs the one privileged recovery action FreeSnitch is allowed to perform on
/// its own behalf, behind the standard macOS authorization prompt.
///
/// Why this exists: the app used to detect that the running helper was older
/// than the installed app, state it clearly, and then tell the user to open
/// Terminal and paste a `sudo` command. That is not a repair, it is a
/// diagnosis with homework, and it left the Mac unfiltered until the homework
/// was done (#69). A button labelled "Repair Helper" has to actually repair.
///
/// What keeps this safe is that there is nothing to inject. The command is a
/// compile-time constant, never assembled from a version string, a path, a
/// preference, or anything else that varies at runtime, so this type cannot be
/// turned into a general "run something as root" facility by a later change
/// that merely passes a different argument.
enum PrivilegedRepair {
    enum Failure: Error, Equatable {
        /// The user dismissed the authorization prompt. Not an error worth
        /// shouting about: they said no, and saying no must be free.
        case cancelled
        case failed(String)
    }

    /// `launchctl kickstart -k` on the helper's launchd service, as root.
    ///
    /// Deliberately a restart and never a bootout or an unregister: #24 showed
    /// that unregistering an enabled helper can remove the service outright,
    /// which is exactly why automatic replacement was disabled in the first
    /// place. Restarting an already-registered service leaves the registration
    /// and the user's approval untouched.
    private static let script =
        "do shell script \"/bin/launchctl kickstart -k system/io.isaaclins.freesnitch.helper\" with administrator privileges"

    /// Blocks on the authorization prompt, so never call this on the main
    /// thread. `HelperClient` hops to a utility queue before calling.
    static func kickstartHelper() -> Result<Void, Failure> {
        guard let appleScript = NSAppleScript(source: script) else {
            return .failure(.failed("The recovery action could not be prepared."))
        }
        var errorInfo: NSDictionary?
        appleScript.executeAndReturnError(&errorInfo)
        guard let errorInfo else { return .success(()) }

        // -128 is userCanceledErr: the authorization sheet was dismissed.
        let code = (errorInfo[NSAppleScript.errorNumber] as? Int) ?? 0
        if code == -128 { return .failure(.cancelled) }
        let message = (errorInfo[NSAppleScript.errorMessage] as? String)
            ?? "The privileged restart did not complete."
        return .failure(.failed(message))
    }
}
