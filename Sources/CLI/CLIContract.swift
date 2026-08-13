import Foundation

/// The CLI contract is intentionally independent from human rendering. Scripts
/// can rely on the envelope and exit codes while the terminal presentation can
/// continue to improve.
enum CLIExitCode: Int {
    case success = 0
    case invalidArgument = 64
    case refused = 65
    case helperUnreachable = 66
    case helperVersionMismatch = 67
    case extensionNotApproved = 68
    case filterConfigurationMissing = 69
    case snapshotMissing = 70
    case pfAnchorFailure = 71
    case operationFailed = 72
    case internalFailure = 73

    var name: String {
        switch self {
        case .success: return "success"
        case .invalidArgument: return "invalid_argument"
        case .refused: return "refused"
        case .helperUnreachable: return "helper_unreachable"
        case .helperVersionMismatch: return "helper_version_mismatch"
        case .extensionNotApproved: return "extension_not_approved"
        case .filterConfigurationMissing: return "filter_configuration_missing"
        case .snapshotMissing: return "snapshot_missing"
        case .pfAnchorFailure: return "pf_anchor_failure"
        case .operationFailed: return "operation_failed"
        case .internalFailure: return "internal_failure"
        }
    }
}

struct CLIError: Error {
    let exitCode: CLIExitCode
    let code: String
    let message: String
    let remediation: String?
    /// The version the helper process reported before the identity check
    /// refused it, so a stale helper can be named in reports instead of being
    /// rendered as a plain unreachable helper.
    let observedHelperVersion: String?

    init(_ exitCode: CLIExitCode,
         code: String? = nil,
         message: String,
         remediation: String? = nil,
         observedHelperVersion: String? = nil) {
        self.exitCode = exitCode
        self.code = code ?? exitCode.name
        self.message = message
        self.remediation = remediation
        self.observedHelperVersion = observedHelperVersion
    }
}

struct CLIErrorPayload: Encodable {
    let code: String
    let message: String
    let remediation: String?
    let exitCode: Int
}

struct CLIEnvelope<T: Encodable>: Encodable {
    static var schema: String { "freesnitch.cli.v1" }

    let schema: String
    let command: String
    let ok: Bool
    let exitCode: Int
    let data: T?
    let error: CLIErrorPayload?

    static func success(command: String, data: T, exitCode: CLIExitCode = .success) -> Self {
        Self(schema: Self.schema, command: command, ok: exitCode == .success, exitCode: exitCode.rawValue, data: data, error: nil)
    }

    static func failure(command: String, error: CLIError, data: T? = nil) -> Self {
        Self(schema: Self.schema,
             command: command,
             ok: false,
             exitCode: error.exitCode.rawValue,
             data: data,
             error: CLIErrorPayload(code: error.code,
                                    message: error.message,
                                    remediation: error.remediation,
                                    exitCode: error.exitCode.rawValue))
    }
}

struct EmptyPayload: Encodable {}

struct AnyEncodable: Encodable {
    private let encodeValue: (Encoder) throws -> Void

    init<T: Encodable>(_ value: T) {
        encodeValue = value.encode(to:)
    }

    func encode(to encoder: Encoder) throws {
        try encodeValue(encoder)
    }
}

struct CommandResult {
    let data: AnyEncodable
    let human: String
    let exitCode: CLIExitCode
    let error: CLIError?

    init<T: Encodable>(data: T, human: String, exitCode: CLIExitCode = .success, error: CLIError? = nil) {
        self.data = AnyEncodable(data)
        self.human = human
        self.exitCode = exitCode
        self.error = error
    }
}

enum CLIJSON {
    static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }

    static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let value = try decoder.singleValueContainer()
            let string = try value.decode(String.self)
            let fractional = ISO8601DateFormatter()
            fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let date = fractional.date(from: string) { return date }
            let plain = ISO8601DateFormatter()
            plain.formatOptions = [.withInternetDateTime]
            if let date = plain.date(from: string) { return date }
            throw DecodingError.dataCorruptedError(in: value, debugDescription: "invalid ISO 8601 date")
        }
        return decoder
    }

    static func encode<T: Encodable>(_ value: T) throws -> Data {
        try encoder().encode(value)
    }

    static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        try decoder().decode(type, from: data)
    }

    static func date(_ string: String) -> Date? {
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = fractional.date(from: string) { return date }
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        return plain.date(from: string)
    }
}

enum CLIOutput {
    static func success(command: String, result: CommandResult, json: Bool) {
        if json {
            if result.exitCode == .success {
                let envelope = CLIEnvelope<AnyEncodable>.success(command: command, data: result.data)
                writeStdout(encode(envelope))
            } else {
                let error = result.error ?? CLIError(result.exitCode,
                                                      message: "The command completed with \(result.exitCode.name).",
                                                      remediation: "Run `freesnitch doctor` for the relevant recovery steps.")
                let envelope = CLIEnvelope<AnyEncodable>.failure(command: command, error: error, data: result.data)
                writeStdout(encode(envelope))
                writeStderr("freesnitch: \(error.message)\n")
            }
        } else {
            writeStdout(Data((result.human + "\n").utf8))
            if result.exitCode != .success, let error = result.error {
                writeStderr("freesnitch: \(error.message)\n")
            }
        }
    }

    static func failure(command: String, error: CLIError, json: Bool) {
        if json {
            let envelope = CLIEnvelope<EmptyPayload>.failure(command: command, error: error)
            writeStdout(encode(envelope))
        }
        var message = "freesnitch: \(error.message)"
        if let remediation = error.remediation {
            message += "\nWhat to do: \(remediation)"
        }
        writeStderr(message + "\n")
    }

    static func encode<T: Encodable>(_ value: T) -> Data {
        (try? CLIJSON.encode(value)) ?? Data("{\"error\":\"could not encode CLI response\"}\n".utf8)
    }

    static func writeStdout(_ data: Data) {
        FileHandle.standardOutput.write(data)
    }

    static func writeStderr(_ string: String) {
        FileHandle.standardError.write(Data(string.utf8))
    }
}

func humanBool(_ value: Bool) -> String { value ? "on" : "off" }

func canonicalMode(_ mode: AppMode) -> String {
    switch mode {
    case .alert: return "alert"
    case .silentAllow: return "silent-allow"
    case .silentDeny: return "silent-deny"
    }
}

func modeLabel(_ mode: AppMode) -> String {
    switch mode {
    case .alert: return "Alert"
    case .silentAllow: return "Silent Allow"
    case .silentDeny: return "Silent Deny"
    }
}

func parseMode(_ value: String) -> AppMode? {
    switch value.lowercased() {
    case "alert": return .alert
    case "silent-allow", "silentallow": return .silentAllow
    case "silent-deny", "silentdeny": return .silentDeny
    default: return nil
    }
}

func parseToggle(_ value: String) -> Bool? {
    switch value.lowercased() {
    case "on", "yes", "true", "1", "enable", "enabled": return true
    case "off", "no", "false", "0", "disable", "disabled": return false
    default: return nil
    }
}
