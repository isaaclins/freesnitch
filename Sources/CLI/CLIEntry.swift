import Foundation
import Darwin

@main
struct FreeSnitchCLI {
    static func main() async {
        let arguments = Array(CommandLine.arguments.dropFirst())
        do {
            let invocation = try CLIParser.parse(arguments)
            switch invocation.command {
            case .help(let topic):
                CLIOutput.writeStdout(Data((CLIHelp.text(for: topic) + "\n").utf8))
                return
            case .version:
                let report = VersionReport(version: AppConstants.version,
                                           cliBundleIdentifier: AppConstants.bundleIdCLI)
                if arguments.contains("--json") {
                    let envelope = CLIEnvelope<VersionReport>.success(command: "version", data: report)
                    CLIOutput.writeStdout(CLIOutput.encode(envelope))
                } else {
                    CLIOutput.writeStdout(Data("FreeSnitch CLI \(report.version) (\(report.cliBundleIdentifier))\n".utf8))
                }
                return
            default:
                break
            }

            let result = try await CLIRunner(invocation: invocation).run()
            CLIOutput.success(command: invocation.name, result: result, json: invocation.json)
            exit(Int32(result.exitCode.rawValue))
        } catch let error as CLIError {
            let command = commandName(from: arguments)
            CLIOutput.failure(command: command, error: error, json: arguments.contains("--json"))
            exit(Int32(error.exitCode.rawValue))
        } catch {
            let cliError = CLIError(.internalFailure,
                                    message: "Unexpected CLI failure: \(error.localizedDescription).",
                                    remediation: "Run `freesnitch doctor` and report the command plus stderr output.")
            let command = commandName(from: arguments)
            CLIOutput.failure(command: command, error: cliError, json: arguments.contains("--json"))
            exit(Int32(cliError.exitCode.rawValue))
        }
    }

    private static func commandName(from arguments: [String]) -> String {
        let values = arguments.filter { $0 != "--json" && $0 != "--yes" }
        return values.prefix { !$0.hasPrefix("-") }.joined(separator: " ").isEmpty
            ? "unknown"
            : values.prefix { !$0.hasPrefix("-") }.joined(separator: " ")
    }
}
