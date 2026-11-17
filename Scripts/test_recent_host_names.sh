#!/usr/bin/env bash
# Checks the helper's recent address-to-name memory that labels Network
# Monitor rows (issue #168). Compiled from the real helper and shared sources.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-recent-names.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

@main
struct Verify {
    static var failures = 0

    static func check(_ name: String, _ condition: Bool) {
        print("recent names harness: \(condition ? "PASS" : "FAIL"): \(name)")
        if !condition { failures += 1 }
    }

    static func flow(host: String, ip: String, port: Int, at date: Date) -> FlowObservation {
        FlowObservation(connection: Connection(pid: 1, processName: "Mail", processPath: "/System/Applications/Mail.app",
                                               remoteHost: host, remoteIP: ip, remotePort: port),
                        observedAt: date)
    }

    static func main() {
        let now = Date()
        let names = RecentHostNames(capacity: 8, lifetime: 600)
        names.note(name: "GitHub.com", for: "185.199.110.153", at: now)
        check("a DNS answer names its address, lowercased", names.name(for: "185.199.110.153", now: now) == "github.com")
        check("the name expires", names.name(for: "185.199.110.153", now: now.addingTimeInterval(601)) == nil)

        names.note([flow(host: "api.example.com", ip: "203.0.113.5", port: 443, at: now),
                    flow(host: "lookup.example.com", ip: "46.243.231.30", port: 53, at: now)])
        check("a flow's hostname names its address", names.name(for: "203.0.113.5", now: now) == "api.example.com")
        check("a lookup does not name the resolver (#167)", names.name(for: "46.243.231.30", now: now) == nil)

        names.note(name: "203.0.113.9", for: "203.0.113.9", at: now)
        names.note(name: "not a host", for: "203.0.113.10", at: now)
        names.note(name: "ok.example", for: "not-an-address", at: now)
        check("an address is never stored as its own name", names.name(for: "203.0.113.9", now: now) == nil)
        check("an invalid name is refused", names.name(for: "203.0.113.10", now: now) == nil)
        for junk in ["0.0.0.0", "127.0.0.1", "::", "::1", "224.0.0.251", "ff02::fb", "255.255.255.255"] {
            names.note(name: "blocked.example", for: junk, at: now)
            check("\(junk) never gets a name", names.name(for: junk, now: now) == nil)
        }
        names.note(name: "nas.example", for: "192.168.1.20", at: now)
        check("a device on the local network keeps its name", names.name(for: "192.168.1.20", now: now) == "nas.example")

        let lsof = Connection(pid: 2, processName: "curl", processPath: "/usr/bin/curl",
                              remoteHost: "203.0.113.5", remoteIP: "203.0.113.5", remotePort: 443)
        let asked = Connection(pid: 2, processName: "curl", processPath: "/usr/bin/curl",
                               remoteHost: "asked.example", remoteIP: "203.0.113.5", remotePort: 443)
        let annotated = names.annotate([lsof, asked], now: now)
        check("an address-only connection gets the seen name", annotated[0].resolvedName == "api.example.com")
        check("the seen name never replaces the rule fields",
              annotated[0].remoteHost == "203.0.113.5" && annotated[0].remoteIP == "203.0.113.5")
        check("a connection that asked for a name keeps it and gets no seen name", annotated[1].resolvedName == nil)

        for index in 0..<20 {
            names.note(name: "h\(index).example", for: "198.51.100.\(index)", at: now.addingTimeInterval(Double(index)))
        }
        check("the memory stays bounded", (0..<20).filter { names.name(for: "198.51.100.\($0)", now: now.addingTimeInterval(20)) != nil }.count <= 8)
        check("the newest name survives eviction", names.name(for: "198.51.100.19", now: now.addingTimeInterval(20)) == "h19.example")

        if failures > 0 {
            print("recent names harness: \(failures) FAILURES")
            exit(1)
        }
        print("recent names harness: PASS (all checks)")
    }
}
SWIFT

xcrun swiftc -O -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos13.0 -parse-as-library \
  -o "$TMP/run" "$ROOT/Sources/Helper/RecentHostNames.swift" "$ROOT"/Sources/Shared/*.swift "$TMP/verify.swift"
"$TMP/run"
