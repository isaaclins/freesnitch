import Foundation

/// The `freesnitch` command: where it lives, whether Terminal can find it, and
/// the one privileged step that makes it findable (#423).
///
/// The executable stays inside the bundle. The helper checks its signature and
/// identifier, so a copy elsewhere is not trusted; what gets installed is a
/// symlink, the way VS Code installs `code`. The CLI resolves the link back to
/// the bundle before it identifies itself.
///
/// Both privileged commands are compile-time constants with fixed paths, like
/// `PrivilegedRepair`. The link is only offered when FreeSnitch runs from
/// `/Applications`, so the target never has to be assembled from the running
/// bundle's path.
enum CommandLineTool {
    /// Where the installed link goes. `/usr/local/bin` is on every Mac's
    /// default `PATH` through `/etc/paths`, also on Apple silicon.
    static let linkPath = "/usr/local/bin/freesnitch"
    /// The tool inside the installed app, the link's only accepted target.
    static let installedToolPath = "/Applications/FreeSnitch.app/Contents/Helpers/freesnitch"
    /// Where Homebrew's own `bin` links would be, so a link made there (by a
    /// cask `binary` stanza, or by hand) counts as set up too.
    static let otherLinkPaths = ["/opt/homebrew/bin/freesnitch"]
    static let guideURL = URL(string: "https://github.com/isaaclins/freesnitch/blob/main/docs/CLI.md")!

    /// Commands worth trying first, each with what it answers.
    static let examples: [(title: String, command: String)] = [
        ("Show what FreeSnitch is doing", "freesnitch status"),
        ("List your rules", "freesnitch rules list"),
        ("All commands", "freesnitch --help")
    ]

    enum LinkState: Equatable {
        /// A link at `path` points at the installed tool.
        case installed(path: String)
        /// Nothing at `linkPath`, and no other link to the tool.
        case notInstalled
        /// Something FreeSnitch did not make sits at `linkPath`. Never
        /// replaced: it may be the user's own script or another tool.
        case occupied(detail: String)
    }

    /// Reads what is at each path without following anything but the link
    /// itself. Pure apart from the file system it is given, for the tests.
    static func linkState(linkPath: String = linkPath,
                          otherLinkPaths: [String] = otherLinkPaths,
                          target: String = installedToolPath,
                          fileManager: FileManager = .default) -> LinkState {
        for path in [linkPath] + otherLinkPaths {
            if let destination = try? fileManager.destinationOfSymbolicLink(atPath: path),
               destination == target {
                return .installed(path: path)
            }
        }
        // attributesOfItem does not follow a link, so a dangling link to
        // somewhere else still counts as occupied.
        guard (try? fileManager.attributesOfItem(atPath: linkPath)) != nil else {
            return .notInstalled
        }
        if let destination = try? fileManager.destinationOfSymbolicLink(atPath: linkPath) {
            return .occupied(detail: "\(linkPath) already links to \(destination).")
        }
        return .occupied(detail: "\(linkPath) already exists and is not FreeSnitch's.")
    }

    /// The link can only point at `/Applications/FreeSnitch.app`, so it is
    /// offered only when that is the copy running and the tool is inside it.
    static func canInstall(running: URL = InstallLocation.runningOriginal,
                           fileManager: FileManager = .default) -> Bool {
        running.resolvingSymlinksInPath().path == "/Applications/FreeSnitch.app"
            && fileManager.isExecutableFile(atPath: installedToolPath)
    }

    /// The tool inside whichever copy is running, for the copyable full path.
    /// A demo shows where a real install keeps it, not the build folder.
    static var runningToolPath: String {
        DemoMode.isOn
            ? installedToolPath
            : Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/freesnitch").path
    }

    enum Failure: Error, Equatable {
        /// The password prompt was dismissed. Saying no is free.
        case cancelled
        case failed(String)
    }

    /// `ln` without `-f`: if anything appeared at the path since the state was
    /// read, the command fails instead of replacing it. `-h` keeps it from
    /// following a link to a folder planted there and linking inside that.
    private static let installScript =
        "do shell script \"/bin/mkdir -p /usr/local/bin && /bin/ln -sh /Applications/FreeSnitch.app/Contents/Helpers/freesnitch /usr/local/bin/freesnitch\" with administrator privileges"

    /// Removes the link only while it still points at the installed tool.
    private static let removeScript =
        "do shell script \"if /usr/bin/readlink /usr/local/bin/freesnitch | /usr/bin/grep -qxF /Applications/FreeSnitch.app/Contents/Helpers/freesnitch; then /bin/rm -f /usr/local/bin/freesnitch; fi\" with administrator privileges"

    /// Blocks on the password prompt; call it off the main thread.
    static func install() -> Result<Void, Failure> {
        // A demo never writes to the real /usr/local/bin.
        guard !DemoMode.isOn else { return .success(()) }
        return run(installScript, fallback: "The command could not be installed.")
    }

    /// Blocks on the password prompt; call it off the main thread.
    static func remove() -> Result<Void, Failure> {
        // A demo never writes to the real /usr/local/bin.
        guard !DemoMode.isOn else { return .success(()) }
        return run(removeScript, fallback: "The command could not be removed.")
    }

    private static func run(_ source: String, fallback: String) -> Result<Void, Failure> {
        guard let appleScript = NSAppleScript(source: source) else {
            return .failure(.failed(fallback))
        }
        var errorInfo: NSDictionary?
        appleScript.executeAndReturnError(&errorInfo)
        guard let errorInfo else { return .success(()) }
        // -128 is userCanceledErr: the authorization sheet was dismissed.
        let code = (errorInfo[NSAppleScript.errorNumber] as? Int) ?? 0
        if code == -128 { return .failure(.cancelled) }
        return .failure(.failed((errorInfo[NSAppleScript.errorMessage] as? String) ?? fallback))
    }
}
