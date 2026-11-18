#!/usr/bin/env bash
# Replays #423: Settings > Command Line installs and removes the `freesnitch`
# command link. Compiles the shipping CommandLineTool.swift and reads link
# states from a scratch directory, then runs the exact shell commands of the
# two privileged AppleScript constants with every path moved under that
# directory. Nothing here touches the real /usr/local/bin or /Applications,
# and nothing asks for a password.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOL="$ROOT/Sources/GUI/App/CommandLineTool.swift"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-command-line.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
failures=0
pass() { echo "command line tool: PASS: $*"; }
fail() { echo "command line tool: FAIL: $*" >&2; failures=$((failures + 1)); }

# --- link states, from the shipping code -----------------------------------
cat > "$TMP/main.swift" <<'SWIFT'
import Foundation

var failures = 0
func check(_ ok: Bool, _ what: String) {
    print("command line tool: \(ok ? "PASS" : "FAIL"): \(what)")
    if !ok { failures += 1 }
}
let fm = FileManager.default
let work = CommandLine.arguments[1]
let target = "/Applications/FreeSnitch.app/Contents/Helpers/freesnitch"
let link = work + "/usr/local/bin/freesnitch"
let brew = work + "/opt/homebrew/bin/freesnitch"
try! fm.createDirectory(atPath: work + "/usr/local/bin", withIntermediateDirectories: true)
try! fm.createDirectory(atPath: work + "/opt/homebrew/bin", withIntermediateDirectories: true)
func state() -> CommandLineTool.LinkState {
    CommandLineTool.linkState(linkPath: link, otherLinkPaths: [brew], target: target)
}
func reset() { try? fm.removeItem(atPath: link); try? fm.removeItem(atPath: brew) }

check(state() == .notInstalled, "nothing at the path reads as not installed")

// The target does not exist in the scratch directory, so this is also the
// dangling case: a link to the app counts even while the app is being replaced.
try! fm.createSymbolicLink(atPath: link, withDestinationPath: target)
check(state() == .installed(path: link), "a link to the tool inside the app reads as installed")
reset()

try! fm.createSymbolicLink(atPath: link, withDestinationPath: "/somewhere/else/freesnitch")
if case .occupied = state() { check(true, "a link elsewhere is someone else's") } else { check(false, "a link elsewhere is someone else's") }
reset()

fm.createFile(atPath: link, contents: Data("#!/bin/sh\necho mine\n".utf8))
if case .occupied = state() { check(true, "a plain file is someone else's") } else { check(false, "a plain file is someone else's") }
reset()

try! fm.createSymbolicLink(atPath: brew, withDestinationPath: target)
check(state() == .installed(path: brew), "a Homebrew link to the tool counts as set up")
reset()

check(!CommandLineTool.canInstall(running: URL(fileURLWithPath: work + "/Downloads/FreeSnitch.app")),
      "a copy outside /Applications is never offered the link")

exit(failures == 0 ? 0 : 1)
SWIFT
cat > "$TMP/stubs.swift" <<'SWIFT'
import Foundation
enum DemoMode { static let isOn = false }
enum InstallLocation { static var runningOriginal: URL { Bundle.main.bundleURL } }
SWIFT
swiftc -O -o "$TMP/run" "$TMP/main.swift" "$TMP/stubs.swift" "$TOOL" 2>&1
"$TMP/run" "$TMP/states" || failures=$((failures + 1))

# --- the privileged commands, run for real under a scratch root -------------
shell_of() {
  # The shell command inside `do shell script "..." with administrator privileges`.
  sed -n "/private static let $1 =/{n;p;}" "$TOOL" \
    | sed -E 's/^[[:space:]]*"do shell script \\"//; s/\\" with administrator privileges"$//'
}
install_cmd="$(shell_of installScript)"
remove_cmd="$(shell_of removeScript)"
[[ "$install_cmd" == "/bin/mkdir -p /usr/local/bin && /bin/ln -s /Applications/FreeSnitch.app/Contents/Helpers/freesnitch /usr/local/bin/freesnitch" ]] \
  || fail "could not read the install command: $install_cmd"
[[ "$remove_cmd" == *"/bin/rm -f /usr/local/bin/freesnitch"* ]] || fail "could not read the remove command: $remove_cmd"
[[ "$install_cmd$remove_cmd" == *'\('* ]] \
  && fail "a privileged command interpolates a value; both must be constants"
if [[ "$(grep -c 'guard !DemoMode.isOn else' "$TOOL")" != 2 ]]; then fail "install and remove must both refuse to run in a demo"; fi

R="$TMP/root"
moved() { sed -e "s#/usr/local/bin#$R/usr/local/bin#g" -e "s#/Applications/#$R/Applications/#g" <<<"$1"; }
mkdir -p "$R/Applications/FreeSnitch.app/Contents/Helpers"
printf '#!/bin/sh\necho freesnitch-cli "$@"\n' > "$R/Applications/FreeSnitch.app/Contents/Helpers/freesnitch"
chmod +x "$R/Applications/FreeSnitch.app/Contents/Helpers/freesnitch"
link="$R/usr/local/bin/freesnitch"

# A Mac without /usr/local/bin (fresh Apple silicon): install creates it.
sh -c "$(moved "$install_cmd")" || fail "install failed on a Mac without /usr/local/bin"
[[ -L "$link" && "$(readlink "$link")" == "$R/Applications/FreeSnitch.app/Contents/Helpers/freesnitch" ]] \
  && pass "install makes a link to the tool inside the app" || fail "install did not make the link"
[[ "$("$link" status)" == "freesnitch-cli status" ]] && pass "the link runs the tool" || fail "the link does not run the tool"

# Removing ours.
sh -c "$(moved "$remove_cmd")" || fail "remove failed"
[[ ! -e "$link" && ! -L "$link" ]] && pass "remove deletes FreeSnitch's link" || fail "remove left the link"
sh -c "$(moved "$remove_cmd")" && pass "remove with nothing there succeeds quietly" || fail "remove failed with nothing there"

# Someone else's file: install refuses to replace it, remove leaves it.
printf '#!/bin/sh\necho mine\n' > "$link"
if sh -c "$(moved "$install_cmd")" 2>/dev/null; then fail "install replaced a file it did not make"; fi
[[ "$(cat "$link")" == $'#!/bin/sh\necho mine' ]] && pass "install never replaces someone else's file" || fail "the user's file changed"
sh -c "$(moved "$remove_cmd")" || fail "remove failed next to the user's file"
[[ -f "$link" && ! -L "$link" ]] && pass "remove leaves someone else's file alone" || fail "remove deleted the user's file"
rm -f "$link"
ln -s /somewhere/else "$link"
sh -c "$(moved "$remove_cmd")" || true
[[ "$(readlink "$link")" == /somewhere/else ]] && pass "remove leaves a link elsewhere alone" || fail "remove deleted a link it did not make"

# The uninstall's copy of the removal is the same guarded command.
uninstall_src="$ROOT/Sources/GUI/App/PrivilegedUninstall.swift"
[[ "$(grep -c -F "if /usr/bin/readlink /usr/local/bin/freesnitch | /usr/bin/grep -qx /Applications/FreeSnitch.app/Contents/Helpers/freesnitch; then /bin/rm -f /usr/local/bin/freesnitch; fi;" "$uninstall_src")" == 2 ]] \
  && pass "both uninstall forms remove only FreeSnitch's link" || fail "an uninstall form does not remove the link, or removes it unguarded"

if (( failures > 0 )); then echo "command line tool verification: FAIL ($failures)"; exit 1; fi
echo "command line tool verification: PASS"
