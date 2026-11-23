#!/usr/bin/env bash
# Harness for how the helper makes /etc/pf.conf attach its anchor (issue #206).
#
# The harness is compiled from the real helper and shared sources, never from a
# copy. It checks that only active pf.conf directives count: a comment or a
# half reference that names the anchor no longer stops FreeSnitch from adding
# the `anchor` and `load anchor` lines pf needs, and lines that are already
# active are never added twice.
#
# Nothing here touches the real pf or /etc: PFManager is pointed at a scratch
# pf.conf, a scratch anchor file and a stub pfctl that only logs its arguments.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-pf-conf.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

SDK="$(xcrun --show-sdk-path)"
TARGET="arm64-apple-macos13.0"

cat > "$TMP/pfctl" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$PF_STUB_LOG"
exit 0
STUB
chmod +x "$TMP/pfctl"

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

final class Checks {
    private var failures: [String] = []
    private var passed = 0

    func expect(_ condition: Bool, _ message: String) {
        if condition { passed += 1 } else { failures.append(message) }
    }

    func finish() {
        guard failures.isEmpty else {
            for failure in failures {
                FileHandle.standardError.write(Data(("pf.conf harness: FAIL: " + failure + "\n").utf8))
            }
            exit(1)
        }
        print("pf.conf harness: real sources: \(passed) assertions PASS")
    }
}

@main
struct Verify {
    static func main() throws {
        let checks = Checks()
        let env = ProcessInfo.processInfo.environment
        let work = env["PF_WORK"]!
        let stub = env["PF_STUB"]!
        let log = env["PF_STUB_LOG"]!
        let anchorPath = "/etc/pf.anchors/puresnitch"
        let attach = "anchor \"puresnitch\""
        let load = "load anchor \"puresnitch\" from \"/etc/pf.anchors/puresnitch\""

        // The pf.conf macOS ships, which names only Apple's anchors.
        let apple = """
        scrub-anchor "com.apple/*"
        nat-anchor "com.apple/*"
        rdr-anchor "com.apple/*"
        dummynet-anchor "com.apple/*"
        anchor "com.apple/*"
        load anchor "com.apple" from "/etc/pf.anchors/com.apple"

        """

        func active(_ text: String) -> [String] {
            PFManager.pfConfDirectives(text).map { $0.joined(separator: " ") }
        }
        func count(_ line: String, in text: String) -> Int {
            let words = PFManager.pfConfDirectives(line)[0].joined(separator: " ")
            return active(text).filter { $0 == words }.count
        }
        /// After the edit, pf must read exactly one active attach and one
        /// active load, and every line the user had must still be there.
        func expectAttached(_ name: String, _ before: String) {
            let after = PFManager.pfConfAttachingAnchor(before, anchorPath: anchorPath) ?? before
            checks.expect(count(attach, in: after) >= 1, "\(name): pf.conf still has no active attach")
            checks.expect(count(load, in: after) >= 1, "\(name): pf.conf still has no active load")
            checks.expect(count(attach, in: after) == max(1, count(attach, in: before)),
                          "\(name): an active attach was added twice")
            checks.expect(count(load, in: after) == max(1, count(load, in: before)),
                          "\(name): an active load was added twice")
            checks.expect(after.hasPrefix(before.hasSuffix("\n") || before.isEmpty ? before : before + "\n"),
                          "\(name): the user's own lines were changed")
            checks.expect(PFManager.pfConfAttachingAnchor(after, anchorPath: anchorPath) == nil,
                          "\(name): a second enable would edit pf.conf again")
        }

        // The case from the issue: only a commented example names the anchor.
        expectAttached("a commented attach", apple + "# \(attach)\n")
        expectAttached("commented attach and load", apple + "#\(attach)\n  # \(load)\n")
        expectAttached("a comment after another directive", apple + "pass all # \(attach)\n")
        // pfctl continues a comment over a trailing backslash.
        expectAttached("a comment continued onto the next line", apple + "# see below \\\n\(attach)\n")
        // A last comment that ends in a backslash would swallow the next line.
        expectAttached("a last comment ending in a backslash", apple + "# trailing \\\n")
        expectAttached("a last comment ending in a backslash, no newline", apple + "# trailing \\")
        // Text inside a quoted macro value is not a directive, even over lines.
        expectAttached("both lines inside a multi-line macro",
                       apple + "notes = \"\n\(attach)\n\(load)\n\"\n")
        // Lines inside another anchor's inline block are not top level.
        expectAttached("an attach nested in another anchor's block",
                       apple + "anchor \"other\" {\n  \(attach)\n}\n" + load + "\n")
        // An attach limited by options leaves the rest of the traffic out.
        expectAttached("an attach limited to one interface", apple + "anchor \"puresnitch\" on lo0\n" + load + "\n")
        // Two backslashes stand for one, so the comment ends at that line
        // and the block after it is still a block.
        expectAttached("a comment ending in an escaped backslash before a block",
                       apple + "# note \\\\\nanchor \"other\" {\n  \(attach)\n}\n" + load + "\n")
        // A quote inside an unquoted word is a plain character to pfctl.
        expectAttached("a quote inside an unquoted name", apple + "anchor pure\"snitch\"\n" + load + "\n")
        expectAttached("a quoted string followed by more letters", apple + "anchor \"pure\"snitch\n" + load + "\n")
        // Half references.
        expectAttached("an attach without its load", apple + attach + "\n")
        expectAttached("a load without its attach", apple + load + "\n")
        expectAttached("a load from another file", apple + attach + "\nload anchor \"puresnitch\" from \"/tmp/x\"\n")
        expectAttached("only sub-anchors attached", apple + "anchor \"puresnitch/*\"\n" + load + "\n")
        expectAttached("another anchor whose name starts the same", apple + "anchor \"puresnitch2\"\n")
        // The plain cases still work.
        expectAttached("the pf.conf macOS ships", apple)
        expectAttached("an empty pf.conf", "")
        expectAttached("no newline at the end", "anchor \"com.apple/*\"")

        let after = PFManager.pfConfAttachingAnchor(apple + "# \(attach)\n", anchorPath: anchorPath) ?? ""
        checks.expect(after == apple + "# \(attach)\n" + attach + "\n" + load + "\n",
                      "the added lines are not the two directives at the end: \(after)")
        checks.expect(PFManager.pfConfAttachingAnchor(apple + attach + "\n", anchorPath: anchorPath)
                        == apple + attach + "\n" + load + "\n",
                      "an existing attach was not kept as the only attach")

        // Already attached and loaded, however it is written: no edit.
        for (name, text) in [
            ("the lines FreeSnitch writes", apple + attach + "\n" + load + "\n"),
            ("unquoted, with tabs and extra options", "anchor\tpuresnitch all\nload  anchor 'puresnitch' from \"/etc/pf.anchors/puresnitch\" # ok\n"),
            ("an escaped backslash inside a comment", "# a \\\\ b\n" + attach + "\n" + load + "\n"),
            ("a load continued over two lines", attach + "\nload anchor \"puresnitch\" \\\n  from \"/etc/pf.anchors/puresnitch\"\n"),
            // pfctl joins a backslash-newline with nothing between, even in quotes.
            ("a quoted name split over two lines", "anchor \"pure\\\nsnitch\"\n" + load + "\n"),
            ("an attach with a list on the same line", "pass proto { tcp udp } all\n" + attach + "\n" + load + "\n"),
        ] {
            checks.expect(PFManager.pfConfAttachingAnchor(text, anchorPath: anchorPath) == nil,
                          "\(name): an already attached anchor was added again")
        }

        // The whole enable path, against a scratch pf.conf.
        let conf = (work as NSString).appendingPathComponent("pf.conf")
        let anchor = (work as NSString).appendingPathComponent("puresnitch")
        let original = apple + "# \(attach)\n"
        try original.write(toFile: conf, atomically: true, encoding: .utf8)
        try "".write(toFile: log, atomically: true, encoding: .utf8)
        let pf = PFManager(anchorPath: anchor, pfctl: stub, pfConfPath: conf)
        try pf.install(rules: [])
        let written = (try? String(contentsOfFile: conf, encoding: .utf8)) ?? ""
        checks.expect(written == original + attach + "\nload anchor \"puresnitch\" from \"\(anchor)\"\n",
                      "enabling enforcement did not attach the anchor in pf.conf: \(written)")
        checks.expect((try? String(contentsOfFile: conf + ".puresnitch.bak", encoding: .utf8)) == original,
                      "enabling enforcement did not back up the original pf.conf")
        checks.expect(pf.isLoaded, "enabling enforcement did not load the anchor")

        // A second enable leaves the file, and the first backup, alone.
        try "changed by hand".write(toFile: conf + ".puresnitch.bak", atomically: true, encoding: .utf8)
        try pf.install(rules: [])
        checks.expect((try? String(contentsOfFile: conf, encoding: .utf8)) == written,
                      "a second enable edited pf.conf again")
        checks.expect((try? String(contentsOfFile: conf + ".puresnitch.bak", encoding: .utf8)) == "changed by hand",
                      "a second enable overwrote the backup")

        // A Mac without a readable pf.conf gets none created.
        let missing = (work as NSString).appendingPathComponent("missing.conf")
        try PFManager(anchorPath: anchor, pfctl: stub, pfConfPath: missing).install(rules: [])
        checks.expect(!FileManager.default.fileExists(atPath: missing), "enabling enforcement created a pf.conf")

        checks.finish()
    }
}
SWIFT

printf 'pf.conf harness: building from the real helper and shared sources\n'
# shellcheck disable=SC2046
xcrun swiftc -O -sdk "$SDK" -target "$TARGET" -parse-as-library \
  -o "$TMP/run" \
  $(ls "$ROOT"/Sources/Helper/*.swift | grep -v '/main.swift$') \
  "$ROOT"/Sources/Shared/*.swift \
  "$TMP/verify.swift"

mkdir -p "$TMP/work"
PF_WORK="$TMP/work" PF_STUB="$TMP/pfctl" PF_STUB_LOG="$TMP/pfctl.log" "$TMP/run"

printf 'pf.conf anchor verification: PASS\n'
