#!/usr/bin/env bash
# The sandboxed extension can read the code signature of an app wherever it
# runs from (#398).
#
# The network extension runs in the app sandbox. To check a process's
# signature, the Security framework reads the process's executable file, and
# the sandbox alone refuses every file outside the system folders: an app in
# ~/Applications, /Users/Shared, /opt or on a mounted disk image got no signed
# bundle id, so every bundle-id allow rule for it turned into an alert.
#
# The harness compiles the real CodeSigningIdentity into a small tool, signs it
# with the extension's own sandbox entitlements (the keys that need a
# provisioning profile left out), and asks it about real running processes,
# started suspended so nothing of theirs runs:
#   - with the sandbox alone, Safari in /Applications resolves but copies of
#     Calculator under the home folder and in the temp folder do not, and the
#     failure is logged: the failure this fixes, replayed
#   - with the extension's entitlements, all three resolve to their signed
#     ids, and the kernel's code hash is readable for each
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-sandbox-sig.XXXXXX")"
HOMECOPY="$(mktemp -d "$HOME/.freesnitch-sandbox-sig.XXXXXX")"
trap 'rm -rf "$TMP" "$HOMECOPY"' EXIT
ENTITLEMENTS="$ROOT/Sources/NetExt/NetExt.entitlements"
PB=/usr/libexec/PlistBuddy
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

cat > "$TMP/main.swift" <<'SWIFT'
import Foundation
import Security

@_silgen_name("csops_audittoken")
func csops_audittoken(_ pid: pid_t, _ ops: UInt32, _ useraddr: UnsafeMutableRawPointer?,
                      _ usersize: Int, _ token: UnsafeMutablePointer<audit_token_t>?) -> Int32

func bytes(_ hex: String) -> Data {
    var data = Data()
    var i = hex.startIndex
    while i < hex.endIndex {
        let j = hex.index(i, offsetBy: 2)
        data.append(UInt8(hex[i..<j], radix: 16)!)
        i = j
    }
    return data
}

// Arguments: pairs of <executable path> <audit token as hex>.
let sandboxed = ProcessInfo.processInfo.environment["APP_SANDBOX_CONTAINER_ID"] != nil
print("sandboxed \(sandboxed)")
var i = 1
while i + 1 < CommandLine.arguments.count {
    let path = CommandLine.arguments[i]
    let token = bytes(CommandLine.arguments[i + 1])
    i += 2
    var audit = audit_token_t()
    _ = withUnsafeMutableBytes(of: &audit) { token.copyBytes(to: $0, count: $0.count) }
    var hash = [UInt8](repeating: 0, count: 20)
    let cs = hash.withUnsafeMutableBytes { csops_audittoken(pid_t(bitPattern: audit.val.5), 5, $0.baseAddress, 20, &audit) }
    let id: String
    switch CodeSigningIdentity.resolve(executablePath: path, auditToken: token, pid: 0, fileFallback: false) {
    case .resolved(let signed?): id = "\(signed.identifier)/\(signed.team)"
    case .resolved(nil): id = "untrusted"
    case .unavailable: id = "unavailable"
    case .noBundle: id = "nobundle"
    }
    print("\(path)\thash=\(cs == 0 ? "ok" : "failed")\tid=\(id)")
}
SWIFT

# Starts each target suspended, reads its audit token, hands both to the tool.
cat > "$TMP/launcher.swift" <<'SWIFT'
import Foundation
var pids: [pid_t] = []
var args: [String] = []
for path in CommandLine.arguments.dropFirst(2) {
    var attr: posix_spawnattr_t?
    posix_spawnattr_init(&attr)
    posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_START_SUSPENDED))
    var pid: pid_t = 0
    let argv: [UnsafeMutablePointer<CChar>?] = [strdup(path), nil]
    guard posix_spawn(&pid, path, nil, &attr, argv, environ) == 0 else { print("spawn failed: \(path)"); exit(2) }
    pids.append(pid)
    var task: mach_port_t = 0
    guard task_name_for_pid(mach_task_self_, pid, &task) == KERN_SUCCESS else { print("no task: \(path)"); exit(2) }
    var token = audit_token_t()
    var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
    _ = withUnsafeMutablePointer(to: &token) {
        $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { task_info(task, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count) }
    }
    args += [path, withUnsafeBytes(of: &token) { Data($0) }.map { String(format: "%02x", $0) }.joined()]
}
let tool = Process()
tool.executableURL = URL(fileURLWithPath: CommandLine.arguments[1])
tool.arguments = args
try tool.run()
tool.waitUntilExit()
for pid in pids { kill(pid, SIGKILL) }
exit(tool.terminationStatus)
SWIFT

xcrun swiftc -O -o "$TMP/tool" "$TMP/main.swift" "$ROOT/Sources/Shared/CodeSigningIdentity.swift" 2>"$TMP/build.log" || { cat "$TMP/build.log"; fail "tool did not build"; }
xcrun swiftc -O -o "$TMP/launcher" "$TMP/launcher.swift" 2>"$TMP/build.log" || { cat "$TMP/build.log"; fail "launcher did not build"; }

# The sandbox needs the tool inside an app bundle with its own identifier.
make_tool() {  # make_tool <name> <entitlements plist>
  local app="$TMP/$1.app"
  mkdir -p "$app/Contents/MacOS"
  cp "$TMP/tool" "$app/Contents/MacOS/tool"
  "$PB" -c "Add :CFBundleIdentifier string io.isaaclins.freesnitch.test-sandbox-sig.$1" \
    -c "Add :CFBundleExecutable string tool" -c "Add :CFBundlePackageType string APPL" \
    "$app/Contents/Info.plist" >/dev/null
  codesign --force -s - --entitlements "$2" "$app" 2>/dev/null
}

# Only the sandbox keys: the Network Extension entitlement and the app group
# need a provisioning profile, and without one the tool would not launch.
"$PB" -c "Add :com.apple.security.app-sandbox bool true" "$TMP/plain.plist" >/dev/null
cp "$TMP/plain.plist" "$TMP/extension.plist"
"$PB" -c "Print :com.apple.security.app-sandbox" "$ENTITLEMENTS" | grep -qx true || fail "the extension is not sandboxed any more"
key=com.apple.security.temporary-exception.files.absolute-path.read-only
if "$PB" -c "Print :$key" "$ENTITLEMENTS" >/dev/null 2>&1; then
  "$PB" -c "Add :$key array" "$TMP/extension.plist"
  n=0
  while value="$("$PB" -c "Print :$key:$n" "$ENTITLEMENTS" 2>/dev/null)"; do
    "$PB" -c "Add :$key:$n string $value" "$TMP/extension.plist"
    n=$((n + 1))
  done
fi
# Nothing else may be loosened: the read-only exception for / is the only
# sandbox exception the extension has.
others="$(grep -oE 'com\.apple\.security\.(temporary-exception|files|network|device|personal-information|automation|assets|print|cs)[a-zA-Z0-9.-]*' "$ENTITLEMENTS" | grep -vx "$key" || true)"
[[ -z "$others" ]] || fail "the extension's sandbox has other exceptions: $others"
[[ "$("$PB" -c "Print :$key" "$ENTITLEMENTS" | grep -c '^ ')" == 1 ]] || fail "the read-only exception names more than one path"

make_tool plain "$TMP/plain.plist"
make_tool extension "$TMP/extension.plist"

SYSTEM=/System/Applications/Calculator.app
mkdir -p "$TMP/apps"
cp -R "$SYSTEM" "$HOMECOPY/Calculator.app"
cp -R "$SYSTEM" "$TMP/apps/Calculator.app"
TARGETS=(/Applications/Safari.app/Contents/MacOS/Safari "$HOMECOPY/Calculator.app/Contents/MacOS/Calculator" "$TMP/apps/Calculator.app/Contents/MacOS/Calculator")

run() {  # run <tool name>: prints the tool's report, its log in $TMP/<name>.err
  "$TMP/launcher" "$TMP/$1.app/Contents/MacOS/tool" "${TARGETS[@]}" 2>"$TMP/$1.err"
}

if ! plain="$(run plain)" || ! grep -qx 'sandboxed true' <<<"$plain"; then
  # A shell without a login session (some agent and launchd contexts) cannot
  # start sandboxed processes at all ("does not match secinitd uid").
  if [[ -n "${CI:-}" ]]; then printf '%s\n' "$plain"; cat "$TMP/plain.err"; fail "could not start a sandboxed process"; fi
  printf 'SKIP: this shell cannot start sandboxed processes; run it from a login session\n'
  exit 0
fi
extension="$(run extension)"
printf 'sandbox alone:\n%s\nwith the extension entitlements:\n%s\n' "$plain" "$extension"

expect() {  # expect <report> <path> <field=value>
  grep -F "$2"$'\t' <<<"$1" | grep -Fq "$3" || fail "$2: expected $3"
}
calc=com.apple.calculator/apple
# The failure this fixes: the sandbox alone refuses the copies, and says so.
expect "$plain" "${TARGETS[0]}" "id=com.apple.Safari/apple"
expect "$plain" "${TARGETS[1]}" "id=unavailable"
expect "$plain" "${TARGETS[2]}" "id=unavailable"
grep -q 'could not read a code signature to verify a bundle id' "$TMP/plain.err" || \
  fail "a refused signature check was not logged"
# With the extension's entitlements every copy resolves.
grep -qx 'sandboxed true' <<<"$extension" || fail "the tool with the extension entitlements did not run sandboxed"
expect "$extension" "${TARGETS[0]}" "id=com.apple.Safari/apple"
for t in "${TARGETS[@]:1}"; do expect "$extension" "$t" "id=$calc"; done
for t in "${TARGETS[@]}"; do expect "$extension" "$t" "hash=ok"; done
if grep -q 'could not read a code signature' "$TMP/extension.err"; then
  cat "$TMP/extension.err"; fail "the extension still logs a refused signature check"
fi
printf 'PASS: the sandboxed extension reads signatures outside the system folders\n'
