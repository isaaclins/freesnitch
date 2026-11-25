#!/usr/bin/env bash
# Harness for a domain blocklist source that sends too much (issue #208).
#
# Compiled from the real helper and shared sources, and downloads over the
# real network path: URLSession against a small HTTP server on 127.0.0.1, no
# test seam. It replays the issue's steps:
#
#   1. A normal list downloads, so there is something saved to keep.
#   2. Its source then answers 200 with a body that never ends. The refresh
#      must stop at the byte ceiling, name the list as failed, keep its saved
#      names blocking, and the helper must not grow anywhere near what an
#      unbounded read would take.
#   3. A source that announces a body larger than the ceiling is refused
#      without reading it.
#   4. A body under the byte ceiling with more names than the entry ceiling
#      is refused whole, never cut at the ceiling.
#   5. A list right next to the failing ones still downloads.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-blocklist-size.XXXXXX")"
SERVER_PID=""
cleanup() {
  if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT

SDK="$(xcrun --show-sdk-path)"
TARGET="arm64-apple-macos13.0"

cat > "$TMP/server.py" <<'PY'
import http.server, socketserver, sys

MODE = {"good": "small"}

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def body(self, data):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        try:
            if self.path == "/switch-alpha-endless":
                MODE["good"] = "endless"
                return self.body(b"ok\n")
            if self.path == "/alpha.txt" and MODE["good"] == "small":
                return self.body(b"0.0.0.0 alpha-one.example\n0.0.0.0 alpha-two.example\n")
            if self.path in ("/alpha.txt", "/endless.txt"):
                # 200, no length, and it never stops.
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Connection", "close")
                self.end_headers()
                chunk = b"".join(b"0.0.0.0 host%07d.example\n" % i for i in range(20000))
                while True:
                    self.wfile.write(chunk)
            if self.path == "/declared.txt":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(4 * 1024 * 1024 * 1024))
                self.end_headers()
                # Keeps trickling, the way a slow huge download would, so
                # only the announced length can end this early.
                import time
                for _ in range(120):
                    self.wfile.write(b"0.0.0.0 declared.example\n")
                    self.wfile.flush()
                    time.sleep(0.25)
                return
            if self.path == "/many.txt":
                count = int(sys.argv[2])
                return self.body(b"".join(b"n%d.x\n" % i for i in range(count)))
            if self.path == "/neighbour.txt":
                return self.body(b"neighbour.example\n")
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError):
            pass

class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        # The helper hangs up on oversized bodies on purpose.
        pass

with Server(("127.0.0.1", 0), Handler) as httpd:
    with open(sys.argv[1], "w") as f:
        f.write(str(httpd.server_address[1]))
    httpd.serve_forever()
PY

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

@main
struct Verify {
    static var failures: [String] = []
    static var passed = 0

    static func expect(_ condition: Bool, _ message: String) {
        if condition { passed += 1 } else { failures.append(message) }
    }

    static func peakMegabytes() -> Int {
        var usage = rusage()
        getrusage(RUSAGE_SELF, &usage)
        // ru_maxrss is in bytes on macOS.
        return Int(usage.ru_maxrss) / (1024 * 1024)
    }

    static func main() async {
        let port = CommandLine.arguments[1]
        let base = "http://127.0.0.1:\(port)"
        let path = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("freesnitch-blsize-\(UUID().uuidString).sqlite")
        defer { try? FileManager.default.removeItem(atPath: path) }
        guard let store = try? RuleStore(path: path) else {
            fail("could not open a RuleStore")
        }
        let profile = Profile.defaultName
        // The seeded catalog lists are not under test and must not reach the
        // real internet from a test run.
        for list in store.allBlocklists() where list.enabled {
            try? store.setBlocklistEnabled(id: list.id, profileName: profile, enabled: false)
        }
        func add(_ name: String, _ file: String) -> BlocklistInfo {
            guard let list = try? store.addCustomBlocklist(name: name, url: "\(base)/\(file)",
                                                           profileName: profile,
                                                           allowLocalhostHTTPForInjectedTest: true) else {
                fail("could not add \(name)")
            }
            return list
        }

        // 1. A normal download.
        let alpha = add("Alpha", "alpha.txt")
        let manager = BlocklistManager(store: store)
        var result = await manager.refresh()
        expect(result.isComplete, "the first download must succeed, failed: \(result.failedLists)")
        expect(manager.domains.isSuperset(of: ["alpha-one.example", "alpha-two.example"]),
               "the first download must block its names")
        let savedAt = store.blocklist(id: alpha.id)?.lastUpdated

        // 2. The same source now sends forever.
        _ = try? await URLSession.shared.data(from: URL(string: "\(base)/switch-alpha-endless")!)
        let started = Date()
        result = await manager.refresh()
        let seconds = Date().timeIntervalSince(started)
        expect(result.failedLists == ["Alpha"], "an endless body must fail the list, got \(result.failedLists)")
        expect(manager.domains.isSuperset(of: ["alpha-one.example", "alpha-two.example"]),
               "the saved names must keep blocking when the source sends too much")
        expect(store.blocklist(id: alpha.id)?.lastUpdated == savedAt, "a refused list must not look freshly updated")
        expect(store.blocklist(id: alpha.id)?.entryCount == 2, "a refused list must keep its count")
        expect(seconds < 120, "the endless download must stop at the ceiling, took \(Int(seconds)) s")
        let peak = peakMegabytes()
        // The ceiling is 128 MB of body plus its text copy; an unbounded read
        // keeps going until the machine runs out.
        expect(peak < 1024, "the helper must stay bounded while refusing an endless list, peaked at \(peak) MB")

        // 3 to 5. Announced too large, too many names, and a good neighbour.
        try? store.setBlocklistEnabled(id: alpha.id, profileName: profile, enabled: false)
        // Timed on its own, so only this download is measured.
        _ = add("Declared", "declared.txt")
        let declaredStart = Date()
        result = await manager.refresh()
        expect(result.failedLists == ["Declared"], "a list announced too large must fail, got \(result.failedLists)")
        expect(Date().timeIntervalSince(declaredStart) < 10,
               "a body announced larger than the ceiling must be refused without reading it")
        _ = add("Many", "many.txt")
        _ = add("Neighbour", "neighbour.txt")
        result = await manager.refresh()
        expect(Set(result.failedLists) == ["Declared", "Many"],
               "an oversized or overfull list must fail, got \(result.failedLists)")
        expect(manager.domains.contains("neighbour.example"), "a good list next to refused ones must still load")
        expect(!manager.domains.contains("n0.x") && !manager.domains.contains("declared.example"),
               "nothing from a refused list may be blocked, not even its first part")

        guard failures.isEmpty else {
            for f in failures {
                FileHandle.standardError.write(Data(("blocklist size harness: FAIL: " + f + "\n").utf8))
            }
            exit(1)
        }
        print("blocklist size harness: \(passed) assertions PASS (peak \(peakMegabytes()) MB)")
    }

    static func fail(_ message: String) -> Never {
        FileHandle.standardError.write(Data("blocklist size harness: FAIL: \(message)\n".utf8))
        exit(1)
    }
}
SWIFT

printf 'blocklist size harness: building from the real helper and shared sources\n'
# shellcheck disable=SC2046
xcrun swiftc -O -sdk "$SDK" -target "$TARGET" -parse-as-library \
  -o "$TMP/run" \
  $(ls "$ROOT"/Sources/Helper/*.swift | grep -v '/main.swift$') \
  "$ROOT"/Sources/Shared/*.swift \
  "$TMP/verify.swift"

# One name more than the helper's entry ceiling, in a body far under its byte
# ceiling.
MAX_ENTRIES="$(grep -E 'static let maxEntries = ' "$ROOT/Sources/Helper/BlocklistManager.swift" | head -1 | sed -E 's/.*= *([0-9_]+).*/\1/' | tr -d _)"
python3 -I "$TMP/server.py" "$TMP/port" "$((MAX_ENTRIES + 1))" &
SERVER_PID=$!
for _ in $(seq 1 50); do [ -s "$TMP/port" ] && break; sleep 0.1; done
[ -s "$TMP/port" ] || { echo 'blocklist size harness: FAIL: test server did not start' >&2; exit 1; }

"$TMP/run" "$(cat "$TMP/port")"
