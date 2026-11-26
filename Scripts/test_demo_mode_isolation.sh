#!/usr/bin/env bash
# Replays #388 and #389: FREESNITCH_DEMO=1 on a Mac where FreeSnitch is really
# installed, under the same bundle id. The demo must leave that install alone:
# no reads or saves of the content filter configuration, no system extension
# requests, no helper registration, repair or removal, no login item change and
# no files removed.
#
# Those calls need the signed app's entitlements and would change the real
# install, so they are not run here. The filter-off harness proves a closed
# preferences line runs nothing; this script proves the firewall safety audit
# requires every guard, by taking each one out of a copy of the tree in turn
# and checking that the audit then fails.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-demo-mode.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

copy_tree() {
  mkdir -p "$1"
  cp -R "$ROOT/Sources" "$ROOT/Scripts" "$1/"
  cp "$ROOT/project.yml" "$ROOT/project-netext.yml" "$1/"
}

mutate_and_expect_failure() {
  local label="$1" file="$2" old="$3" new="$4"
  local tree="$TMP/$label"
  copy_tree "$tree"
  python3 - "$tree/$file" "$old" "$new" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
if sys.argv[2] not in text:
    raise SystemExit(f"mutation target not found: {path}")
path.write_text(text.replace(sys.argv[2], sys.argv[3], 1))
PY
  if bash "$tree/Scripts/audit_firewall_safety.sh" >/dev/null 2>&1; then
    printf 'demo mode isolation: FAIL: mutation %s was not caught\n' "$label" >&2
    exit 1
  fi
  printf 'demo mode isolation: mutation %s caught\n' "$label"
}

bash "$ROOT/Scripts/audit_firewall_safety.sh" >/dev/null
printf 'demo mode isolation: audit passed on the real tree\n'

SEM=Sources/GUI/App/SystemExtensionManager.swift
HELPER=Sources/GUI/App/HelperClient.swift
PRIV=Sources/GUI/App/PrivilegedUninstall.swift
UNINSTALL=Sources/GUI/Views/UninstallView.swift

# #388: the content filter configuration.
mutate_and_expect_failure filter-line-open "$SEM" \
  'FilterPreferencesLine(closed: demo)' 'FilterPreferencesLine()'
mutate_and_expect_failure closed-line-runs-anyway Sources/Shared/FilterPreferencesLine.swift \
  '        guard !closed else { return }' ''
mutate_and_expect_failure follows-system-settings "$SEM" \
  $'        guard !demo else { return }\n        // The filter can be turned on or off' \
  $'        // The filter can be turned on or off'
mutate_and_expect_failure submits-extension-requests "$SEM" \
  $'    private var hasEmbeddedExtension: Bool {\n        guard !demo else { return false }' \
  $'    private var hasEmbeddedExtension: Bool {'
mutate_and_expect_failure manager-not-told "$SEM" \
  'demo: Bool = DemoMode.isOn' 'demo: Bool = false'
mutate_and_expect_failure flag-not-from-env Sources/GUI/App/DemoMode.swift \
  'environment["FREESNITCH_DEMO"] == "1"' 'environment["FREESNITCH_DEMO"] == "yes"'

# #389: the extension, the helper, the login item and files.
mutate_and_expect_failure uninstall-deactivates-extension "$SEM" \
  $'        guard !demo else {\n            uninstallState = .removed' \
  $'        if false {\n            uninstallState = .removed'
mutate_and_expect_failure unregisters-helper "$HELPER" \
  '        guard !DemoMode.isOn else { return nil }' ''
mutate_and_expect_failure registers-helper "$HELPER" \
  $'    func registerDaemon() {\n        guard !DemoMode.isOn else { return }' \
  $'    func registerDaemon() {'
mutate_and_expect_failure repairs-helper "$HELPER" \
  'guard !DemoMode.isOn, repairGate.begin(state: repairState) else { return }' 'guard repairGate.begin(state: repairState) else { return }'
mutate_and_expect_failure kickstarts-helper "$HELPER" \
  $'    private func performPrivilegedKickstart() {\n        guard !DemoMode.isOn else { return }' \
  $'    private func performPrivilegedKickstart() {'
mutate_and_expect_failure runs-privileged-uninstall "$PRIV" \
  '        guard !DemoMode.isOn else { return .success(()) }' ''
mutate_and_expect_failure removes-user-data "$PRIV" \
  $'    static func removeUserData() -> [String] {\n        // A demo never deletes the real install\'s data (#389).\n        guard !DemoMode.isOn else { return [] }' \
  $'    static func removeUserData() -> [String] {'
mutate_and_expect_failure trashes-app "$PRIV" \
  '        guard !DemoMode.isOn else { completion(nil); return }' ''
mutate_and_expect_failure uninstall-begin-acts "$UNINSTALL" \
  $'    func begin() {\n        guard !DemoMode.isOn else {' \
  $'    func begin() {\n        if false {'
mutate_and_expect_failure uninstall-finish-acts "$UNINSTALL" \
  $'    func finish() {\n        guard !DemoMode.isOn else {' \
  $'    func finish() {\n        if false {'
mutate_and_expect_failure changes-login-item Sources/GUI/Views/SettingsView.swift \
  $'        guard !DemoMode.isOn else { return }\n        do {' \
  $'        do {'

printf 'demo mode isolation: PASS\n'
