#!/usr/bin/env bash
# The `--json` envelope (#233): every response carries both `data` and `error`,
# and the one that does not apply is an explicit null, as docs/CLI.md promises.
# Built from the real CLI and shared sources; nothing here talks to a helper.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-cli-envelope.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/check.swift" <<'SWIFT'
import Foundation

@main
struct Check {
    static func object(_ data: Data) -> [String: Any] {
        (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
    }

    static func main() {
        var failures: [String] = []
        func expect(_ ok: Bool, _ message: String) { if !ok { failures.append(message) } }
        func isNull(_ value: Any?) -> Bool { value is NSNull }

        let keys: Set<String> = ["schema", "command", "ok", "exitCode", "data", "error"]
        let unreachable = CLIError(.helperUnreachable,
                                   message: "The helper could not be reached.",
                                   remediation: "Approve FreeSnitch in Login Items.")

        // A success: `error` is present and null.
        let success = object(try! CLIJSON.encode(
            CLIEnvelope<AnyEncodable>.success(command: "status", data: AnyEncodable(["filter": "on"]))))
        expect(Set(success.keys) == keys, "a success must carry exactly the documented keys, got \(success.keys.sorted())")
        expect(isNull(success["error"]), "a success must carry `error: null`")
        expect((success["data"] as? [String: String])?["filter"] == "on", "a success must keep its data")
        expect(success["ok"] as? Bool == true && success["exitCode"] as? Int == 0, "a success must be ok with exit code 0")

        // An empty payload is still an object, not null.
        let empty = object(try! CLIJSON.encode(CLIEnvelope<EmptyPayload>.success(command: "rules add", data: EmptyPayload())))
        expect(empty["data"] is [String: Any], "an empty payload must encode as {}")
        expect(isNull(empty["error"]), "an empty success must carry `error: null`")

        // An ordinary failure (parse or helper failure path): `data` is present and null.
        let failure = object(try! CLIJSON.encode(CLIEnvelope<EmptyPayload>.failure(command: "rules list", error: unreachable)))
        expect(Set(failure.keys) == keys, "a failure must carry exactly the documented keys, got \(failure.keys.sorted())")
        expect(isNull(failure["data"]), "a failure must carry `data: null`")
        let error = failure["error"] as? [String: Any] ?? [:]
        expect(error["code"] as? String == "helper_unreachable", "a failure must name its error code")
        expect(error["exitCode"] as? Int == 66 && failure["exitCode"] as? Int == 66, "a failure must carry exit code 66")
        expect(failure["ok"] as? Bool == false, "a failure must not be ok")

        // A report that failed (doctor, partial mutation) keeps both.
        let report = object(try! CLIJSON.encode(
            CLIEnvelope<AnyEncodable>.failure(command: "doctor", error: unreachable, data: AnyEncodable(["checks": 3]))))
        expect((report["data"] as? [String: Int])?["checks"] == 3, "a failing report must keep its data")
        expect(report["error"] is [String: Any], "a failing report must carry its error")

        // A payload that cannot be encoded still yields a whole envelope.
        let broken = object(CLIOutput.encodingFailure(command: "status"))
        expect(Set(broken.keys) == keys, "an encoding failure must still carry exactly the documented keys, got \(broken.keys.sorted())")
        expect(isNull(broken["data"]) && broken["command"] as? String == "status", "an encoding failure must keep the command and carry `data: null`")
        expect((broken["error"] as? [String: Any])?["code"] as? String == "internal_failure", "an encoding failure must report internal_failure")
        expect(broken["exitCode"] as? Int == 73 && broken["ok"] as? Bool == false, "an encoding failure must carry exit code 73")

        guard failures.isEmpty else {
            failures.forEach { FileHandle.standardError.write(Data("cli envelope: FAIL: \($0)\n".utf8)) }
            exit(1)
        }
        print("cli envelope: PASS")
    }
}
SWIFT

# shellcheck disable=SC2046
xcrun swiftc -parse-as-library -o "$TMP/run" \
  $(ls "$ROOT"/Sources/CLI/*.swift | grep -v '/CLIEntry.swift$') \
  "$ROOT"/Sources/Shared/*.swift "$TMP/check.swift"
"$TMP/run"
