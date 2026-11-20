#!/usr/bin/env bash
# Checks that the menu bar speed text keeps one width whatever the speed (#460).
#
# Compiled from the real MenuBarSpeed source. Every speed from idle to
# gigabytes per second is formatted and measured in the menu bar font; a
# single different width means the icon would slide sideways again.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-menu-speed.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/verify.swift" <<'SWIFT'
import AppKit

@main
struct Verify {
    static var failures = 0

    static func check(_ name: String, _ condition: Bool) {
        print("menu bar speed harness: \(condition ? "PASS" : "FAIL"): \(name)")
        if !condition { failures += 1 }
    }

    static func width(_ s: String) -> CGFloat {
        (s as NSString).size(withAttributes: [.font: MenuBarSpeed.font]).width
    }

    static func main() {
        // Every boundary where a unit or decimal place changes, plus a sweep.
        var speeds: [Int64] = [0, 1, 9, 10, 99, 100, 999, 1000, 1023, 1024, 1025,
                               10_188, 10_189, 10_240, 512_000, 1_023_999, 1_024_000,
                               1_048_576, 10_433_331, 10_433_332, 104_857_600,
                               1_048_575_999, 1_073_741_824, 10_737_418_240,
                               1_099_511_627_776, Int64.max, -5]
        var v: Int64 = 1
        while v < Int64.max / 3 { speeds.append(v); speeds.append(v * 3 / 2); v *= 3 }

        let reference = MenuBarSpeed.title(bytesIn: 0, bytesOut: 0)
        let referenceWidth = width(reference)
        var widths = Set<CGFloat>()
        var lengths = Set<Int>()
        var odd: [String] = []
        for a in speeds {
            for b in [Int64(0), 999, 1_048_576, a] {
                let t = MenuBarSpeed.title(bytesIn: a, bytesOut: b)
                widths.insert(width(t))
                lengths.insert(t.count)
                if width(t) != referenceWidth { odd.append(t) }
            }
        }
        check("every speed is drawn at the same width (odd ones: \(odd.prefix(5)))", widths.count == 1)
        check("every speed has the same number of characters", lengths.count == 1)

        check("idle reads as zero bytes", MenuBarSpeed.compact(0) == "  0 B/s")
        check("bytes stay whole", MenuBarSpeed.compact(999) == "999 B/s")
        check("a thousand bytes becomes kilobytes", MenuBarSpeed.compact(1_000) == "1.0 K/s")
        check("small kilobytes keep one decimal", MenuBarSpeed.compact(4_300) == "4.2 K/s")
        check("larger kilobytes drop the decimal", MenuBarSpeed.compact(512_000) == "500 K/s")
        check("megabytes", MenuBarSpeed.compact(4_404_019) == "4.2 M/s")
        check("gigabytes", MenuBarSpeed.compact(1_073_741_824) == "1.0 G/s")
        check("just under a thousand rounds into the next unit, never four digits",
              MenuBarSpeed.compact(1_023_500) == "1.0 M/s" && MenuBarSpeed.compact(1_022_976) == "999 K/s")
        check("both directions are shown with arrows",
              MenuBarSpeed.title(bytesIn: 0, bytesOut: 1_000) == " ↓  0 B/s ↑1.0 K/s")

        if failures > 0 { print("menu bar speed harness: \(failures) failure(s)"); exit(1) }
        print("menu bar speed harness: all checks passed")
    }
}
SWIFT

xcrun swiftc -O -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos13.0 -parse-as-library \
  -o "$TMP/run" "$ROOT/Sources/GUI/App/MenuBarSpeed.swift" "$TMP/verify.swift"
"$TMP/run"
