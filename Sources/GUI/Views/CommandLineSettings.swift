import SwiftUI

/// Settings > Command Line: says the `freesnitch` command exists, sets it up
/// for Terminal, and hands over the first commands to try (#423).
///
/// Before this, nothing in the app mentioned the CLI at all, and the only way
/// to learn about it was the docs folder of the repository.
struct CommandLineSettingsView: View {
    @State private var linkState = CommandLineTool.linkState()
    @State private var working = false
    @State private var failure: String?
    /// A demo never touches /usr/local/bin, so it remembers the answer here
    /// instead, which is enough to show both states.
    /// `FREESNITCH_DEMO_CLI=installed` starts in the installed state, for
    /// screenshots of both.
    @State private var demoInstalled = ProcessInfo.processInfo.environment["FREESNITCH_DEMO_CLI"] == "installed"

    private var state: CommandLineTool.LinkState {
        if DemoMode.isOn {
            return demoInstalled ? .installed(path: CommandLineTool.linkPath) : .notInstalled
        }
        return linkState
    }

    private var canInstall: Bool { DemoMode.isOn || CommandLineTool.canInstall() }

    var body: some View {
        Form {
            Section("Command-line tool") {
                Text("Most of what FreeSnitch does can also be done from Terminal with the `freesnitch` command: check its status, change the mode, manage rules and blocklists, and answer alerts. Scripts can use it too, since every command can answer in JSON.")
                    .fixedSize(horizontal: false, vertical: true)
                LabeledContent("Status") {
                    Text(statusText)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.trailing)
                }
                actionRow
                if let failure {
                    Label(failure, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
                // Markdown, so the command and paths read as code.
                Text(LocalizedStringKey(explanation))
                    .font(.caption).foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Section("Try it") {
                ForEach(CommandLineTool.examples, id: \.command) { example in
                    HStack(alignment: .firstTextBaseline, spacing: 12) {
                        Text(example.title)
                        Spacer(minLength: 8)
                        CopyableValue(value: example.command)
                            .font(.system(.body, design: .monospaced))
                    }
                }
                Text("Click a command to copy it, then paste it into Terminal.")
                    .font(.caption).foregroundColor(.secondary)
                HStack(alignment: .firstTextBaseline, spacing: 12) {
                    Text("Without installing")
                    Spacer(minLength: 8)
                    CopyableValue(value: CommandLineTool.runningToolPath)
                        .font(.system(.caption, design: .monospaced))
                }
                LabeledContent("Every command and option") {
                    Link("Command-line guide", destination: CommandLineTool.guideURL)
                }
            }
        }
        .formStyle(.grouped)
        .onAppear(perform: refresh)
        // Coming back from Terminal, where the user may have made or removed
        // the link by hand, has to show the new answer.
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didBecomeKeyNotification)) { _ in
            refresh()
        }
    }

    @ViewBuilder
    private var actionRow: some View {
        switch state {
        case .installed(let path) where path == CommandLineTool.linkPath:
            LabeledContent("In Terminal") {
                Button("Remove Command…", action: remove).disabled(working)
            }
        case .notInstalled where canInstall:
            LabeledContent("In Terminal") {
                Button("Install Command…", action: install).disabled(working)
            }
        default:
            EmptyView()
        }
    }

    private var statusText: String {
        switch state {
        case .installed(let path): return "Installed at \(path)"
        case .notInstalled: return "Not installed"
        case .occupied: return "Not installed"
        }
    }

    private var explanation: String {
        switch state {
        case .installed(let path) where path == CommandLineTool.linkPath:
            return "Type `freesnitch` in any Terminal window. `\(path)` is a link to the tool inside FreeSnitch.app, so it updates with the app. Uninstalling FreeSnitch removes it too."
        case .installed:
            return "Type `freesnitch` in any Terminal window. FreeSnitch did not make this link, so it leaves it as it is."
        case .notInstalled where canInstall:
            return "Install Command adds `\(CommandLineTool.linkPath)`, a link to the tool inside FreeSnitch.app. macOS asks for your password once. You can remove it here at any time, and uninstalling FreeSnitch removes it too."
        case .notInstalled:
            return "FreeSnitch can set up the command once it runs from the Applications folder. Until then, use the full path below."
        case .occupied(let detail):
            return "\(detail) FreeSnitch leaves it alone. Use the full path below, or remove that file yourself and come back here."
        }
    }

    private func refresh() { linkState = CommandLineTool.linkState() }

    private func install() { perform(CommandLineTool.install, installs: true) }

    private func remove() { perform(CommandLineTool.remove, installs: false) }

    private func perform(_ action: @escaping () -> Result<Void, CommandLineTool.Failure>, installs: Bool) {
        working = true
        failure = nil
        DispatchQueue.global(qos: .userInitiated).async {
            let result = action()
            DispatchQueue.main.async {
                working = false
                switch result {
                case .success:
                    if DemoMode.isOn { demoInstalled = installs }
                case .failure(.cancelled):
                    break
                case .failure(.failed(let message)):
                    failure = message
                }
                refresh()
            }
        }
    }
}
