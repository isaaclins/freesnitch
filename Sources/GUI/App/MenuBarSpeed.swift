import AppKit

/// The live speed text next to the menu bar icon.
///
/// It must keep the same width whatever the speed, or the icon and everything
/// left of it shift sideways every second as traffic changes (#460). So each
/// number is at most three characters, padded on the left, every unit is three
/// characters, and the text is drawn in a monospaced font where every
/// character has the same width.
enum MenuBarSpeed {
    static let font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)

    static func title(bytesIn: Int64, bytesOut: Int64) -> String {
        " ↓\(compact(bytesIn)) ↑\(compact(bytesOut))"
    }

    /// Three characters of number, a space and a three character unit:
    /// "  0 B/s", "512 K/s", "4.2 M/s".
    static func compact(_ bytesPerSecond: Int64) -> String {
        var value = Double(max(0, bytesPerSecond))
        var unit = 0
        let units = ["B/s", "K/s", "M/s", "G/s"]
        // 999.5 and up would round to four digits, so it moves to the next unit.
        while value >= 999.5, unit < units.count - 1 {
            value /= 1024
            unit += 1
        }
        let number: String
        if unit == 0 {
            number = String(Int(value))
        } else if value < 9.95 {
            number = String(format: "%.1f", value)
        } else {
            number = String(format: "%.0f", min(value, 999))
        }
        let padded = String(repeating: " ", count: max(0, 3 - number.count)) + number
        return "\(padded) \(units[unit])"
    }
}
