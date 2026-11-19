#!/usr/bin/env bash
# Every translation must format without crashing and show every value it is
# given, in every language and for every plural form.
#
# A translated string whose placeholders don't line up with the English one
# reads the wrong argument at run time. With plural substitutions that is not
# just a wrong number: Foundation reads an Int where it expects an object and
# the app crashes (#462 review: "Reached by %lld apps, %lld connections, %@"
# with an unnumbered %@ next to numbered plural arguments). So this compiles
# the String Catalog the way Xcode does and formats every key with sample
# values: counts 0, 1, 2, 5, 21 and 105 (each plural form in English and
# Russian, below where a locale groups digits) and a distinct text for every %@.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CATALOG="$ROOT/Resources/Localizable.xcstrings"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-loc.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

xcrun xcstringstool compile --output-directory "$WORK/compiled" "$CATALOG" >/dev/null

cat > "$WORK/check.swift" <<'SWIFT'
import Foundation

let catalogPath = CommandLine.arguments[1]
let compiled = URL(fileURLWithPath: CommandLine.arguments[2])
let data = try! Data(contentsOf: URL(fileURLWithPath: catalogPath))
let catalog = try! JSONSerialization.jsonObject(with: data) as! [String: Any]
let strings = catalog["strings"] as! [String: [String: Any]]

let spec = try! NSRegularExpression(pattern: "%(?:[0-9]+\\$)?(lld|ld|d|@|u|llu)")
func argumentTypes(_ key: String) -> [String] {
    let range = NSRange(key.startIndex..., in: key)
    return spec.matches(in: key, range: range).map { String(key[Range($0.range(at: 1), in: key)!]) }
}

let languages = (try! FileManager.default.contentsOfDirectory(atPath: compiled.path))
    .filter { $0.hasSuffix(".lproj") }
    .map { String($0.dropLast(".lproj".count)) }
    .sorted()
var failures: [String] = []
var formatted = 0

for language in languages {
    guard let bundle = Bundle(url: compiled.appendingPathComponent("\(language).lproj")) else {
        failures.append("\(language): cannot open the compiled table"); continue
    }
    let locale = Locale(identifier: language)
    for (key, entry) in strings.sorted(by: { $0.key < $1.key }) {
        if entry["shouldTranslate"] as? Bool == false { continue }
        let types = argumentTypes(key)
        let localized = bundle.localizedString(forKey: key, value: "\u{0}missing", table: "Localizable")
        if localized == "\u{0}missing" {
            // English falls back to the key itself; every other language
            // must carry its own text.
            if language != "en" { failures.append("\(language): no translation for \(key.debugDescription)") }
            continue
        }
        guard !types.isEmpty else { continue }
        for count in [0, 1, 2, 5, 21, 105] {
            var texts: [String] = []
            let arguments: [CVarArg] = types.enumerated().map { index, type in
                if type == "@" {
                    let text = "‹text\(index + 1)›"
                    texts.append(text)
                    return text as NSString
                }
                return count
            }
            // Printed first, so a crash names the string that caused it.
            FileHandle.standardError.write(Data("\(language) \(count) \(key.debugDescription)\n".utf8))
            let output = String(format: localized, locale: locale, arguments: arguments)
            formatted += 1
            for text in texts where !output.contains(text) {
                failures.append("\(language): \(key.debugDescription) with \(count) lost \(text): \(output.debugDescription)")
            }
            if types.contains(where: { $0 != "@" }) && !output.contains(String(count)) {
                failures.append("\(language): \(key.debugDescription) with \(count) lost the number: \(output.debugDescription)")
            }
        }
    }
}

if !languages.contains("ru") { failures.append("the catalog compiled no Russian table") }
if failures.isEmpty {
    print("localization formats: PASS (\(languages.joined(separator: ", ")), \(formatted) formatted strings)")
} else {
    failures.forEach { print("FAIL \($0)") }
    exit(1)
}
SWIFT

# The helper and the command line tool run from inside the app bundle, next to
# these tables. Both pin English before anything looks up text, so their logs,
# replies and parsed output stay English on a Mac set to Russian.
PIN='UserDefaults.standard.setVolatileDomain(["AppleLanguages": ["en"]], forName: UserDefaults.argumentDomain)'
first_statement="$(grep -v '^[[:space:]]*\(//.*\)\{0,1\}$' "$ROOT/Sources/Helper/main.swift" | grep -v '^import ' | head -1 | sed 's/^[[:space:]]*//')"
[ "$first_statement" = "$PIN" ] || { echo "FAIL the helper does not pin English first: $first_statement"; exit 1; }
cli_first="$(awk '/static func main\(\)/ {getline; while ($0 ~ /^[[:space:]]*\/\//) getline; sub(/^[[:space:]]*/, ""); print; exit}' "$ROOT/Sources/CLI/CLIEntry.swift")"
[ "$cli_first" = "$PIN" ] || { echo "FAIL the command line tool does not pin English first: $cli_first"; exit 1; }
# And the pin wins over a Russian language preference for a tool inside a
# bundle that carries a Russian table.
mkdir -p "$WORK/Probe.app/Contents/MacOS" "$WORK/Probe.app/Contents/Resources"
cp -R "$WORK/compiled/"*.lproj "$WORK/Probe.app/Contents/Resources/"
cat > "$WORK/Probe.app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>io.isaaclins.freesnitch.localization-probe</string>
<key>CFBundleExecutable</key><string>Probe</string>
<key>CFBundleDevelopmentRegion</key><string>en</string>
<key>CFBundleLocalizations</key><array><string>en</string><string>ru</string></array>
</dict></plist>
PLIST
printf '%s\n' 'import Foundation' "if CommandLine.arguments.contains(\"--pin\") { $PIN }" 'print(String(localized: "Settings"))' > "$WORK/probe.swift"
xcrun swiftc "$WORK/probe.swift" -o "$WORK/Probe.app/Contents/MacOS/Probe"
unpinned="$("$WORK/Probe.app/Contents/MacOS/Probe" -AppleLanguages '(ru)')"
pinned="$("$WORK/Probe.app/Contents/MacOS/Probe" --pin -AppleLanguages '(ru)')"
[ "$unpinned" != "Settings" ] || { echo "FAIL the probe did not pick up the Russian table, so it proves nothing"; exit 1; }
[ "$pinned" = "Settings" ] || { echo "FAIL pinning English did not override Russian: $pinned"; exit 1; }
echo "localization formats: helper and command line tool stay English (probe: $unpinned -> $pinned)"

xcrun swiftc -O "$WORK/check.swift" -o "$WORK/check" 2>&1 | grep -v "^$" >&2 || true
if ! "$WORK/check" "$CATALOG" "$WORK/compiled" 2>"$WORK/progress.log"; then
  echo "localization formats: FAIL; last string formatted before stopping:" >&2
  tail -1 "$WORK/progress.log" >&2
  exit 1
fi
