#!/usr/bin/env bash
# Connection map refresh verification (issue #230).
#
# The map only asks for a new clustering pass when the input fingerprint
# changes. It used to hash only the connection count and the byte total, so an
# endpoint replaced by another with the same traffic left the old pin and arc
# on screen. The harness is compiled from the shipping
# Sources/GUI/Views/MapClustering.swift, MapGeometry.swift and Sources/Shared, never from a copy.
#
# What is proven here:
#   * the issue's case: one connection to 1.1.1.1 with 100 bytes replaced by
#     one to 8.8.8.8 with 100 bytes changes the fingerprint, and the map
#     built from the new input really is different
#   * every field the clusterer reads changes the fingerprint on its own
#   * the same input gives the same fingerprint, so an idle monitor does not
#     recluster on every redraw
#
# Static checks: the view refreshes on the engine's fingerprint, and every
# Connection field the clusterer reads is part of the fingerprint, so a new
# field read later cannot quietly bring the bug back.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-map-refresh.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

ENGINE="$ROOT/Sources/GUI/Views/MapClustering.swift"
GEOMETRY="$ROOT/Sources/GUI/Views/MapGeometry.swift"
VIEW="$ROOT/Sources/GUI/Views/ConnectionMap.swift"

fail() {
  printf 'connection map refresh verification: FAIL: %s\n' "$*" >&2
  exit 1
}

pass() {
  printf 'connection map refresh verification: PASS: %s\n' "$*"
}

for file in "$ENGINE" "$GEOMETRY" "$VIEW"; do
  [[ -f "$file" ]] || fail "missing $file"
done

# 1. The view must refresh on the engine's fingerprint, not a local shortcut.
grep -q 'MapClusterEngine.inputFingerprint(connections)' "$VIEW" \
  || fail "ConnectionMap.swift no longer refreshes on MapClusterEngine.inputFingerprint"
grep -q '\.onChange(of: inputFingerprint)' "$VIEW" \
  || fail "ConnectionMap.swift no longer refreshes when the input fingerprint changes"
pass "the map view refreshes on the engine's input fingerprint"

# 2. Every Connection field the clusterer reads is in the fingerprint.
fingerprint_body="$(awk '/static func inputFingerprint/{on=1} on{print} on&&/^    }$/{exit}' "$ENGINE")"
[[ -n "$fingerprint_body" ]] || fail "could not find inputFingerprint in MapClustering.swift"
read_fields="$(awk '/static func inputFingerprint/{skip=1} skip&&/^    }$/{skip=0; next} !skip{print}' "$ENGINE" \
  | grep -oE '\b(connection|representative)\??\.[a-zA-Z]+' | sed -E 's/.*\.//' | sort -u)"
[[ -n "$read_fields" ]] || fail "found no Connection fields read by the clusterer"
for field in $read_fields; do
  grep -q "connection\.$field)" <<<"$fingerprint_body" \
    || fail "the clusterer reads Connection.$field but the fingerprint ignores it"
done
pass "every Connection field the clusterer reads is in the fingerprint ($(echo $read_fields | tr '\n' ' '))"

cat > "$TMP/main.swift" <<'SWIFT'
import Foundation

func check(_ condition: Bool, _ message: String) {
    if !condition {
        FileHandle.standardError.write("connection map refresh verification: FAIL: \(message)\n".data(using: .utf8)!)
        exit(1)
    }
}

let seen = Date(timeIntervalSince1970: 1_800_000_000)
func connection(ip: String, country: String, code: String, city: String,
                latitude: Double, longitude: Double) -> Connection {
    Connection(pid: 42, processName: "curl", processPath: "/usr/bin/curl",
               remoteIP: ip, status: .established, bytesIn: 60, bytesOut: 40,
               country: country, countryCode: code, city: city,
               latitude: latitude, longitude: longitude,
               firstSeen: seen, lastSeen: seen)
}

// The issue's steps: same count, same 100 bytes, different endpoint.
let before = [connection(ip: "1.1.1.1", country: "Australia", code: "AU", city: "Sydney",
                         latitude: -33.87, longitude: 151.21)]
let after = [connection(ip: "8.8.8.8", country: "United States", code: "US", city: "Mountain View",
                        latitude: 37.39, longitude: -122.08)]
check(before.count == after.count, "test setup: counts differ")
check(before[0].bytesIn + before[0].bytesOut == after[0].bytesIn + after[0].bytesOut, "test setup: byte totals differ")
check(MapClusterEngine.inputFingerprint(before) != MapClusterEngine.inputFingerprint(after),
      "replacing 1.1.1.1 with 8.8.8.8 at the same count and traffic leaves the fingerprint unchanged, so the map keeps the old endpoint")

let request = MapClusterRequest(tier: MapDetailTier(level: 6), home: MapPoint(latitude: 47.37, longitude: 8.54))
let oldMap = MapClusterEngine.build(connections: before, request: request)
let newMap = MapClusterEngine.build(connections: after, request: request)
check(oldMap.nodes.map(\.title) == ["Sydney"], "the old map should show Sydney, got \(oldMap.nodes.map(\.title))")
check(newMap.nodes.map(\.title) == ["Mountain View"], "the new map should show Mountain View, got \(newMap.nodes.map(\.title))")
print("connection map refresh verification: PASS: swapping 1.1.1.1 for 8.8.8.8 at equal count and traffic changes the fingerprint, and the rebuilt map shows Mountain View instead of Sydney")

// Same input, same fingerprint: no reclustering when nothing changed.
check(MapClusterEngine.inputFingerprint(before) == MapClusterEngine.inputFingerprint(before),
      "the same input gives two fingerprints")
let copy = before.map { $0 }
check(MapClusterEngine.inputFingerprint(copy) == MapClusterEngine.inputFingerprint(before),
      "an equal copy of the input gives a different fingerprint")
print("connection map refresh verification: PASS: unchanged input keeps its fingerprint")

// Each field the clusterer reads changes the fingerprint by itself.
let base = before[0]
let base_print = MapClusterEngine.inputFingerprint([base])
let edits: [(String, (inout Connection) -> Void)] = [
    ("id", { $0.id = UUID() }),
    ("latitude", { $0.latitude = -33.0 }),
    ("longitude", { $0.longitude = 150.0 }),
    ("latitude to nil", { $0.latitude = nil }),
    ("countryCode", { $0.countryCode = "NZ" }),
    ("country", { $0.country = "New Zealand" }),
    ("city", { $0.city = "Melbourne" }),
    ("remoteHost", { $0.remoteHost = "one.one.one.one" }),
    ("remoteIP", { $0.remoteIP = "1.0.0.1" }),
    ("processName", { $0.processName = "Safari" }),
    ("bytes moved from in to out", { $0.bytesIn = 40; $0.bytesOut = 60 }),
    ("lastSeen", { $0.lastSeen = seen.addingTimeInterval(30) }),
]
for (name, edit) in edits {
    var changed = base
    edit(&changed)
    check(MapClusterEngine.inputFingerprint([changed]) != base_print,
          "changing \(name) leaves the fingerprint unchanged")
}
print("connection map refresh verification: PASS: each of \(edits.count) map-relevant edits changes the fingerprint")

// Order of the input matters to ties when input is bounded, so it counts too.
let two = [before[0], after[0]]
check(MapClusterEngine.inputFingerprint(two) != MapClusterEngine.inputFingerprint(two.reversed()),
      "reordering the input leaves the fingerprint unchanged")
print("connection map refresh verification: PASS: reordered input changes the fingerprint")
SWIFT

swiftc -O \
  -sdk "$(xcrun --show-sdk-path)" \
  -target arm64-apple-macos13.0 \
  "$ROOT"/Sources/Shared/*.swift \
  "$ENGINE" \
  "$GEOMETRY" \
  "$TMP/main.swift" \
  -lsqlite3 \
  -o "$TMP/map_refresh_harness"

"$TMP/map_refresh_harness"
