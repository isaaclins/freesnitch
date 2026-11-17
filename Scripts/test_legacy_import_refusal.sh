#!/usr/bin/env bash
# Replays issue #344: an app from before #300 sends the old import request
# (replaceRules(rulesJSON:reply:)) to a helper from after it. Before the fix the
# helper's interface no longer had that selector, so the request was dropped
# and the old app, which has no timeout, waited forever.
#
# The harness compiles the shipping Sources/Shared code, so the helper side of
# the connection uses the real HelperProtocol. The old app side declares the
# protocol exactly as the app shipped it before #300. Both talk over a real
# NSXPCConnection (anonymous listener) in one process. The helper's method
# body cannot be compiled on its own, so static checks pin that it only
# refuses and never writes.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-legacy-import.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() { printf 'legacy import refusal: FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'legacy import refusal: PASS: %s\n' "$*"; }

HELPER="$ROOT/Sources/Helper/HelperService.swift"
body="$(awk '/func legacyReplaceRules\(rulesJSON/,/^    }$/' "$HELPER")"
[ -n "$body" ] || fail "the helper does not answer the old import request"
printf '%s\n' "$body" | grep -Fq 'reply(false, HelperBridge.legacyImportRefusal)' \
  || fail "the helper does not refuse the old import request with the update message"
if printf '%s\n' "$body" | grep -Eq 'mutatePolicy|applyRules|reply\(true'; then
  fail "the helper's answer to the old import request can write rules"
fi
pass "the helper only refuses the old import request and writes nothing"

cat > "$TMP/main.swift" <<'SWIFT'
import Foundation

/// The app's view of the helper before #300, reduced to the import request.
@objc protocol PreUpdateHelperProtocol {
    @objc optional func replaceRules(rulesJSON: Data, reply: @escaping (Bool, String?) -> Void)
}

/// Stands in for the helper object behind the real HelperProtocol interface.
/// NSXPC dispatches by selector, so only the two import requests are needed;
/// the legacy answer does what HelperService's does (checked statically above).
final class NewHelper: NSObject {
    var legacyCalls = 0
    var newImportCalls = 0
    @objc(replaceRulesWithRulesJSON:reply:)
    func legacyReplaceRules(rulesJSON _: Data, reply: @escaping (Bool, String?) -> Void) {
        legacyCalls += 1
        reply(false, HelperBridge.legacyImportRefusal)
    }
    @objc func replaceRules(rulesJSON _: Data, expectedRemovedIDsJSON _: Data, reply: @escaping (Bool, String?) -> Void) {
        newImportCalls += 1
        reply(true, nil)
    }
}

final class Delegate: NSObject, NSXPCListenerDelegate {
    let helper = NewHelper()
    func listener(_: NSXPCListener, shouldAcceptNewConnection c: NSXPCConnection) -> Bool {
        c.exportedInterface = HelperBridge.remoteInterface()
        c.exportedObject = helper
        c.resume()
        return true
    }
}

let listener = NSXPCListener.anonymous()
let delegate = Delegate()
listener.delegate = delegate
listener.resume()

let conn = NSXPCConnection(listenerEndpoint: listener.endpoint)
conn.remoteObjectInterface = NSXPCInterface(with: PreUpdateHelperProtocol.self)
conn.resume()

var answer: (Bool, String?)?
let done = DispatchSemaphore(value: 0)
// The old app's call: no timeout and a no-op error handler.
let proxy = conn.remoteObjectProxyWithErrorHandler { _ in } as! PreUpdateHelperProtocol
proxy.replaceRules?(rulesJSON: Data("[]".utf8)) { ok, message in
    answer = (ok, message)
    done.signal()
}

var failures = 0
func check(_ name: String, _ condition: Bool) {
    if condition { print("legacy import refusal: PASS: \(name)") }
    else { failures += 1; print("legacy import refusal: FAIL: \(name)") }
}
let answered = done.wait(timeout: .now() + 10) == .success
check("an app from before the update gets an answer to its import", answered)
check("the answer is a refusal", answer?.0 == false)
check("the refusal tells the user to reopen FreeSnitch and that nothing was imported",
      answer?.1 == HelperBridge.legacyImportRefusal
      && (answer?.1 ?? "").contains("Quit and reopen FreeSnitch")
      && (answer?.1 ?? "").contains("Nothing was imported"))
check("the old request reached the refusal, not the new import", delegate.helper.legacyCalls == 1 && delegate.helper.newImportCalls == 0)
conn.invalidate()
if failures > 0 { exit(1) }
SWIFT

swiftc -suppress-warnings "$ROOT"/Sources/Shared/*.swift "$TMP/main.swift" -lsqlite3 -o "$TMP/verify" \
  || fail "the harness does not compile"
"$TMP/verify" || fail "an app from before the update does not get a clear refusal"
pass "an app from before the update is refused instead of waiting"
