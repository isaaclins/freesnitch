#!/usr/bin/env bash
# Regression gate for #464.
#
# Settings showed the helper's English reason for a refused DNS over HTTPS
# upstream ("... the URL is empty ...") in an otherwise translated app. The
# app now maps each refusal to its own translated sentence, while the helper
# and the CLI keep logging the English reason.
#
# This checks that every refusal the validator can return has its own
# translated sentence in Settings, in every language the catalog carries, and
# that the helper's English reasons did not change.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-doh-messages.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/main.swift" <<'SWIFT'
var failures: [String] = []
func expect(_ value: String, _ wanted: DoHUpstreamValidator.Rejection?, _ reason: String?) {
    let got = DoHUpstreamValidator.rejection(for: value)
    if got != wanted { failures.append("\(value.debugDescription): \(String(describing: got)), wanted \(String(describing: wanted))") }
    if DoHUpstreamValidator.rejectionReason(for: value) != reason {
        failures.append("\(value.debugDescription): English reason changed to \(String(describing: DoHUpstreamValidator.rejectionReason(for: value)))")
    }
}
expect("", .empty, "the URL is empty")
expect(" https://dns.example/dns-query", .surroundingWhitespace, "the URL has leading or trailing whitespace")
expect("https://dns.example/dns-query\n", .surroundingWhitespace, "the URL has leading or trailing whitespace")
expect("http s://x", .notAURL, "the value is not a URL")
expect("http://dns.example/dns-query", .notHTTPS, "the URL scheme must be https")
expect("cloudflare-dns.com", .notHTTPS, "the URL scheme must be https")
expect("https:///dns-query", .missingHost, "the URL must include a host")
expect("https://cloudflare-dns.com/dns-query", nil, nil)
expect("HTTPS://dns.example/dns-query", nil, nil)
print(DoHUpstreamValidator.Rejection.allCases.count)
if !failures.isEmpty {
    for failure in failures { FileHandle.standardError.write(Data("FAIL \(failure)\n".utf8)) }
    exit(1)
}
SWIFT
printf 'import Foundation\n' | cat - "$TMP/main.swift" > "$TMP/main2.swift" && mv "$TMP/main2.swift" "$TMP/main.swift"

xcrun swiftc -O -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos13.0 \
  -o "$TMP/run" "$ROOT/Sources/Shared/DoHUpstreamValidator.swift" "$TMP/main.swift"
CASES="$("$TMP/run")"

python3 - "$ROOT/Sources/GUI/Views/SettingsView.swift" "$ROOT/Resources/Localizable.xcstrings" "$CASES" <<'PY'
import json, re, sys
source, catalog_path, cases = open(sys.argv[1]).read(), sys.argv[2], int(sys.argv[3])
start = source.index("static func message(for rejection: DoHUpstreamValidator.Rejection)")
body = source[start:source.index("\n    }\n", start)]
case_lines = re.findall(r"case \.(\w+):\s*\n\s*reason = String\(localized: \"([^\"]+)\"\)", body)
keys = [key for _, key in case_lines] + re.findall(r"\+ String\(localized: \"([^\"]+)\"\)", body)
failures = []
if len(case_lines) != cases:
    failures.append(f"Settings maps {len(case_lines)} refusals, the validator has {cases}")
if len(set(k for _, k in case_lines)) != len(case_lines):
    failures.append("two refusals share one sentence")
if "\\(" in body or ".reason" in body or "rejectionReason" in body:
    failures.append("Settings splices the helper's English reason into its message")
catalog = json.load(open(catalog_path))
languages = {lang for entry in catalog["strings"].values() for lang in entry.get("localizations", {})}
for key in keys:
    entry = catalog["strings"].get(key)
    if entry is None:
        failures.append(f"not in the catalog: {key!r}"); continue
    for lang in sorted(languages - {catalog.get("sourceLanguage", "en")}):
        unit = entry.get("localizations", {}).get(lang, {}).get("stringUnit", {})
        if unit.get("state") != "translated" or not unit.get("value"):
            failures.append(f"{lang}: no translation for {key!r}")
# #219: an empty upstream is refused (.empty above) and the proxy has no
# system-resolver mode, so the field's prompt must not offer empty as a choice.
prompt = re.search(r'TextField\("Upstream", text: \$doh,\s*prompt: Text\("([^"]+)"\)\)', source)
if prompt is None:
    failures.append("the DoH upstream field's prompt was not found")
else:
    text = prompt.group(1)
    if re.search(r"empty|system resolver", text, re.I):
        failures.append(f"the prompt offers an empty upstream, which the helper refuses: {text!r}")
    for lang in sorted(languages - {catalog.get("sourceLanguage", "en")}):
        unit = catalog["strings"].get(text, {}).get("localizations", {}).get(lang, {}).get("stringUnit", {})
        if unit.get("state") != "translated" or not unit.get("value"):
            failures.append(f"{lang}: no translation for the prompt {text!r}")
for failure in failures:
    print("FAIL", failure, file=sys.stderr)
sys.exit(1 if failures else 0)
PY
printf 'DoH upstream messages verification: PASS\n'
