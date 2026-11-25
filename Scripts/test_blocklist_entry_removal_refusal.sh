#!/usr/bin/env bash
# Replays #221: the helper refuses to take a name off a list, and the Rules
# page must say so.
#
# Compiled from the shipping ProfileClient and the real helper-side command
# handler and RuleStore, wired together the way the XPC transport wires them.
# A list is filled to its hand-edit limit, then one more name is removed
# through ProfileClient. The refusal must reach the caller's completion with
# the store's reason, must not land only in ProfileClient.errorMessage (which
# only the Profiles page shows), and the name must still be on the list. The
# Rules page must pass a completion and show what it gets.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-entry-removal.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() { printf 'entry removal refusal: FAIL: %s\n' "$*" >&2; exit 1; }

# The Rules page passes a completion and shows the refusal where the name was
# removed, with the helper's reason.
RULES="$ROOT/Sources/GUI/Views/RulesManager.swift"
python3 - "$RULES" <<'PY' || fail "the Rules page does not show a refused removal"
import re, sys
src = open(sys.argv[1]).read()
m = re.search(r'func removeEntry\(_ domain: String, from blocklist: BlocklistInfo\) \{(.*?)\n    \}\n', src, re.S)
assert m, "removeEntry is missing"
body = m.group(1)
assert re.search(r'removeBlocklistEntries\(blocklist\.id, domains: \[domain\]\) \{ ok, message in', body), "no completion"
assert 'guard !ok else { return }' in body and 'showError(' in body and 'message ??' in body, "refusal not shown"
assert 'onRemoveEntry: { domain in removeEntry(domain, from: blocklist) }' in src, "entries view not wired to removeEntry"
PY

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

@MainActor
func remove(_ client: ProfileClient, _ id: UUID, _ name: String) async -> (Bool, String?) {
    await withCheckedContinuation { done in
        client.removeBlocklistEntries(id, domains: [name]) { ok, message in done.resume(returning: (ok, message)) }
    }
}

@main
struct Verify {
    @MainActor
    static func main() async {
        var failures: [String] = []
        func expect(_ ok: Bool, _ message: String) { if !ok { failures.append(message) } }

        let path = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("freesnitch-entry-removal-\(UUID().uuidString).sqlite")
        defer { try? FileManager.default.removeItem(atPath: path) }
        let limit = BlocklistEdits.maximumEntries
        let names = (0...limit + 1).map { "n\($0).example" }
        guard let store = try? RuleStore(path: path),
              let list = try? store.addLocalBlocklist(name: "Mine", domains: Array(names.prefix(limit))) else {
            print("entry removal refusal: FAIL: could not set up the store"); exit(1)
        }
        // Everything removed up to the limit: the same state the issue starts in.
        let atLimit = (0..<limit).map { "gone\($0).example" }
        do { _ = try store.removeBlocklistEntries(id: list.id, domains: atLimit) } catch {
            print("entry removal refusal: FAIL: could not reach the limit: \(error)"); exit(1)
        }
        let handler = ProfileCommandService(store: store, coordinator: ProfileCoordinator(store: store))
        let client = ProfileClient()
        client.setTransport { data, reply in
            let (payload, message) = handler.handle(requestData: data)
            reply(payload, message)
        }
        client.setHelperReachable(true)

        let target = names[0]
        let (ok, message) = await remove(client, list.id, target)
        expect(!ok, "a removal past the edit limit was reported as done")
        expect(message?.contains("\(limit)") == true || message?.contains(limit.formatted()) == true,
               "the refusal did not carry the helper's reason: \(message ?? "nil")")
        expect(client.errorMessage == nil,
               "the refusal also landed in errorMessage, which only the Profiles page shows")
        let still = store.blocklistEntries(blocklistID: list.id, search: target, offset: 0, limit: 10).entries
        expect(still.contains(target), "the refused name is no longer on the list")

        // A removal that the store accepts still reports success.
        try? store.clearBlocklistEdits(id: list.id)
        let (ok2, message2) = await remove(client, list.id, target)
        expect(ok2 && message2 == nil, "an accepted removal was reported as refused: \(message2 ?? "nil")")
        expect(store.blocklistEntries(blocklistID: list.id, search: target, offset: 0, limit: 10).entries.isEmpty,
               "an accepted removal left the name on the list")

        if failures.isEmpty {
            print("entry removal refusal: PASS")
        } else {
            for f in failures { print("entry removal refusal: FAIL: \(f)") }
            exit(1)
        }
    }
}
SWIFT

swiftc -parse-as-library \
  "$ROOT"/Sources/Shared/*.swift \
  "$ROOT/Sources/GUI/ViewModels/ProfileClient.swift" \
  "$ROOT/Sources/GUI/App/DemoMode.swift" \
  "$TMP/verify.swift" \
  -lsqlite3 -o "$TMP/verify" 2>"$TMP/build.log" || { cat "$TMP/build.log" >&2; fail "the harness did not compile"; }
"$TMP/verify"
