#!/usr/bin/env bash
# A bundle id only comes from a valid code signature, never from a plist (#351).
#
# Rules scoped to a bundle id used to trust whatever Info.plist sat next to the
# executable, so any binary in a folder named Something.app whose plist said
# com.apple.Safari got Safari's rules, allow rules included. The harness
# compiles the real CodeSigningIdentity and the extension's real
# BundleIdentifierCache, then checks against real code on this Mac:
#   - a binary in a fake Safari.app with Safari's plist gets no bundle id,
#     ad-hoc signed, unsigned, or signed with its own made-up identifier
#   - a real Safari, an App Store app and a Developer ID app keep theirs
#   - a copy of a signed app whose executable was swapped gets none
#   - a tool inside an app answers its own signed id, never the app's: Apple's
#     curl copied into a copy of Safari.app is not Safari
#   - a Developer ID cannot claim an identifier under com.apple.
#   - a running fake, looked up by pid, gets none
#   - a signed id is tied to the code the kernel says a process runs, so a
#     binary swapped in at a checked path never inherits the earlier id
#   - the extension's cache never takes the plist's bundle id as the signed
#     one, keeps it apart as the claimed one, keeps the version, and checks
#     again soon when no signature could be read
#   - allow and ask rules match only the signed id; deny rules also match the
#     claimed one, so an unsigned binary claiming Safari's id gets Safari's
#     deny but never its allow, and a user's deny for an unsigned app keeps
#     blocking it
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-code-signing.XXXXXX")"
trap 'kill "${FAKE_PID:-}" 2>/dev/null || true; rm -rf "$TMP"' EXIT
FILTER="$ROOT/Sources/NetExt/FilterDataProvider.swift"

{
  printf 'import Foundation\nimport Darwin\nimport os.log\n'
  awk '/^struct AppBundleMetadata/{on=1} on && /^#endif/{exit} on' "$FILTER"
} > "$TMP/cache.swift"
grep -q 'final class BundleIdentifierCache' "$TMP/cache.swift"

# A tiny real executable to dress up as other apps.
mkdir -p "$TMP/src"
cat > "$TMP/src/tool.c" <<'C'
#include <unistd.h>
int main(void) { sleep(900); return 0; }
C
xcrun clang -o "$TMP/tool" "$TMP/src/tool.c"

fake_app() {  # fake_app <dir> <plist bundle id> <signing>
  local app="$1" id="$2" signing="$3"
  mkdir -p "$app/Contents/MacOS"
  cp "$TMP/tool" "$app/Contents/MacOS/$(basename "$app" .app)"
  /usr/libexec/PlistBuddy -c "Add :CFBundleIdentifier string $id" \
    -c "Add :CFBundleExecutable string $(basename "$app" .app)" \
    -c "Add :CFBundleShortVersionString string 9.9" "$app/Contents/Info.plist" >/dev/null
  case "$signing" in
    adhoc) codesign --force -s - "$app" 2>/dev/null ;;
    adhoc-claim) codesign --force -s - -i "$id" "$app" 2>/dev/null ;;
    none) codesign --remove-signature "$app/Contents/MacOS/$(basename "$app" .app)" ;;
  esac
}

FAKES="$TMP/fakes"
fake_app "$FAKES/adhoc/Safari.app" com.apple.Safari adhoc
fake_app "$FAKES/claim/Safari.app" com.apple.Safari adhoc-claim
fake_app "$FAKES/unsigned/Safari.app" com.apple.Safari none
fake_app "$FAKES/chrome/Google Chrome.app" com.google.Chrome adhoc-claim

# A real signed app copied elsewhere, then its executable swapped for ours.
SWAPPED="$TMP/swapped/Calculator.app"
mkdir -p "$(dirname "$SWAPPED")"
cp -R /System/Applications/Calculator.app "$SWAPPED"
cp "$TMP/tool" "$SWAPPED/Contents/MacOS/Calculator"
codesign --force -s - "$SWAPPED/Contents/MacOS/Calculator" 2>/dev/null

# A foreign, ad-hoc tool dropped into a copy of a Developer ID app.
CHROME="/Applications/Google Chrome.app"
DROPPED=""
if [[ -d "$CHROME" ]]; then
  DROPPED="$TMP/dropped/Google Chrome.app"
  mkdir -p "$DROPPED/Contents/MacOS"
  cp -R "$CHROME/Contents/Info.plist" "$CHROME/Contents/_CodeSignature" "$DROPPED/Contents/" 2>/dev/null || true
  cp "$TMP/tool" "$DROPPED/Contents/MacOS/dropped-tool"
  codesign --force -s - -i com.google.Chrome "$DROPPED/Contents/MacOS/dropped-tool" 2>/dev/null
fi

# Apple's own, validly signed curl copied into a copy of Safari.app.
CURL_IN_SAFARI=""
if [[ -d /Applications/Safari.app ]]; then
  CURL_IN_SAFARI="$TMP/curl/Safari.app"
  mkdir -p "$CURL_IN_SAFARI/Contents/MacOS"
  cp /Applications/Safari.app/Contents/Info.plist "$CURL_IN_SAFARI/Contents/"
  cp -R /Applications/Safari.app/Contents/_CodeSignature "$CURL_IN_SAFARI/Contents/" 2>/dev/null || true
  cp /usr/bin/curl "$CURL_IN_SAFARI/Contents/MacOS/curl"
fi

# Real signed apps that are already running, to check a running process.
FINDER_PID="$(pgrep -x Finder | head -1 || true)"
# Any running Developer ID app's main process: its path, pid and the
# identifier codesign reports for it.
DEVID_PATH="" DEVID_PID="0" DEVID_ID=""
for app in /Applications/*.app; do
  info="$(codesign -dvv "$app" 2>&1 || true)"
  [[ "$info" == *"Authority=Developer ID Application"* ]] || continue
  exe="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$app/Contents/Info.plist" 2>/dev/null || true)"
  [[ -n "$exe" ]] || continue
  pid="$(pgrep -f "^$app/Contents/MacOS/$exe( |\$)" | head -1 || true)"
  [[ -n "$pid" ]] || continue
  DEVID_PATH="$app/Contents/MacOS/$exe" DEVID_PID="$pid"
  DEVID_ID="$(printf '%s\n' "$info" | sed -n 's/^Identifier=//p')"
  break
done

"$FAKES/adhoc/Safari.app/Contents/MacOS/Safari" &
FAKE_PID=$!

cat > "$TMP/main.swift" <<'SWIFT'
import Foundation
import os.log

var checks = 0
func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else {
        FileHandle.standardError.write(Data(("code signing harness: FAIL: " + message + "\n").utf8))
        exit(1)
    }
    checks += 1
    print("code signing harness: ok: " + message)
}

let args = CommandLine.arguments
let fakes = args[1], swapped = args[2], dropped = args[3]
let fakePID = Int32(args[4])!
let curlInSafari = args[5]
let fm = FileManager.default

func id(_ path: String, pid: Int32 = 0) -> String? {
    CodeSigningIdentity.resolve(executablePath: path, auditToken: nil, pid: pid).bundleIdentifier
}

// Fakes carrying Safari's plist.
expect(id(fakes + "/adhoc/Safari.app/Contents/MacOS/Safari") == nil,
       "an ad-hoc binary with Safari's Info.plist gets no bundle id")
expect(id(fakes + "/claim/Safari.app/Contents/MacOS/Safari") == nil,
       "an ad-hoc binary signed with Safari's identifier gets no bundle id")
expect(id(fakes + "/unsigned/Safari.app/Contents/MacOS/Safari") == nil,
       "an unsigned binary with Safari's Info.plist gets no bundle id")
expect(id(fakes + "/chrome/Google Chrome.app/Contents/MacOS/Google Chrome") == nil,
       "an ad-hoc binary claiming Chrome's id gets no bundle id")
expect(id(fakes + "/adhoc/Safari.app/Contents/MacOS/Safari", pid: fakePID) == nil,
       "a running fake Safari, looked up by its pid, gets no bundle id")
expect(id(swapped + "/Contents/MacOS/Calculator") == nil,
       "a copied Calculator whose executable was swapped gets no bundle id")

// Running processes: the check the extension and the monitor really make,
// by the process (no file fallback).
func runningID(_ path: String, _ pid: Int32) -> CodeSigningIdentity.Resolution {
    CodeSigningIdentity.resolve(executablePath: path, auditToken: nil, pid: pid, fileFallback: false)
}
let finderPID = Int32(args[7]) ?? 0, devIDPID = Int32(args[8]) ?? 0
let devIDPath = args[9], devID = args[10]
if finderPID > 0 {
    expect(runningID("/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder", finderPID) == .resolved("com.apple.finder"),
           "the running Finder, checked as a running process, gets com.apple.finder")
} else {
    print("code signing harness: skip: Finder is not running")
}
let devIDAnswer = devIDPID > 0 ? runningID(devIDPath, devIDPID) : .unavailable
if devIDPID > 0, kill(devIDPID, 0) == 0 {
    expect(devIDAnswer == .resolved(devID),
           "a running Developer ID app (\((devIDPath as NSString).lastPathComponent)), checked as a running process, gets \(devID)")
} else {
    print("code signing harness: skip: no Developer ID app is running")
}
expect(runningID(fakes + "/adhoc/Safari.app/Contents/MacOS/Safari", fakePID) == .resolved(nil),
       "the running fake Safari is checked and found untrusted, not unreadable")

// Real code on this Mac.
let safari = "/Applications/Safari.app/Contents/MacOS/Safari"
if fm.fileExists(atPath: safari) {
    expect(id(safari) == "com.apple.Safari", "the real Safari keeps com.apple.Safari")
}
expect(id("/System/Applications/Calculator.app/Contents/MacOS/Calculator") == "com.apple.calculator",
       "Apple's own Calculator keeps its bundle id")
expect(id("/bin/ls") == nil, "a binary outside any .app still has no bundle id")

let chrome = "/Applications/Google Chrome.app"
if fm.fileExists(atPath: chrome) {
    expect(id(chrome + "/Contents/MacOS/Google Chrome") == "com.google.Chrome",
           "a Developer ID app keeps its bundle id")
    let helpers = chrome + "/Contents/Frameworks/Google Chrome Framework.framework/Helpers"
    expect(id(helpers + "/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper") == "com.google.Chrome.helper",
           "a nested helper app keeps its own bundle id")
    if fm.fileExists(atPath: helpers + "/chrome_crashpad_handler") {
        expect(id(helpers + "/chrome_crashpad_handler") == "chrome_crashpad_handler",
               "a tool inside a Developer ID app answers its own signed id, not the app's")
    }
    expect(id(dropped + "/Contents/MacOS/dropped-tool") == nil,
           "a foreign ad-hoc tool dropped into a copy of Chrome gets no bundle id")
} else {
    print("code signing harness: skip: no Google Chrome on this Mac")
}
if fm.fileExists(atPath: curlInSafari) {
    expect(id(curlInSafari + "/Contents/MacOS/curl") == "com.apple.curl",
           "Apple's curl copied into a copy of Safari.app is curl, not Safari")
}
let appStore = ["/Applications/Xcode.app/Contents/MacOS/Xcode": "com.apple.dt.Xcode",
                "/Applications/Tailscale.app/Contents/MacOS/Tailscale": "io.tailscale.ipn.macsys"]
for (path, expected) in appStore where fm.fileExists(atPath: path) {
    let got = id(path)
    // Tailscale's standalone build is Developer ID, its App Store one is
    // io.tailscale.ipn.macos: either way the id is its own, never nil.
    expect(got == expected || (expected.hasPrefix("io.tailscale") && got?.hasPrefix("io.tailscale") == true),
           "the signed app at \((path as NSString).lastPathComponent) keeps its bundle id (\(got ?? "nil"))")
}

// TestFlight (#402). No TestFlight-signed build exists on this Mac, so this
// checks that both requirements carry Apple's TestFlight (Prod) leaf marker
// and that Security parses and keeps it, plus the decision for such a signer.
func compiledText(_ text: String) -> String? {
    var requirement: SecRequirement?
    guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
          let requirement else { return nil }
    var out: CFString?
    guard SecRequirementCopyString(requirement, [], &out) == errSecSuccess else { return nil }
    return out as String?
}
let testFlightClause = "certificate leaf[field.1.2.840.113635.100.6.1.25.1] /* exists */"
expect(compiledText(CodeSigningIdentity.distributionRequirementText)?.contains(testFlightClause) == true,
       "the accepted signers include TestFlight (Prod), leaf marker 1.2.840.113635.100.6.1.25.1")
expect(compiledText(CodeSigningIdentity.appStoreRequirementText)?.contains(testFlightClause) == true,
       "TestFlight counts as a channel where Apple hands out bundle ids")
expect(CodeSigningIdentity.decide(.trusted(CodeSigningIdentity.Signed(identifier: "com.example.beta",
                                                                     signer: .team("ABCDE12345"), appStore: true)))
       == .resolved("com.example.beta"),
       "a TestFlight-signed app keeps its own signed id")

// Apple's own code comes from the certificate chain, never from a missing
// team id: a non-Apple signature without a team id can't pose as Apple.
expect(CodeSigningIdentity.classify(identifier: "com.apple.Safari", team: nil, apple: false, appStore: false) == .untrusted,
       "a non-Apple signature without a team id is not taken as Apple's (and not trusted)")
expect(CodeSigningIdentity.decide(CodeSigningIdentity.classify(identifier: "com.apple.Safari", team: nil, apple: false, appStore: false)) == .resolved(nil),
       "so it cannot claim com.apple.Safari")
expect(CodeSigningIdentity.classify(identifier: "com.apple.Safari", team: nil, apple: true, appStore: false)
       == .trusted(CodeSigningIdentity.Signed(identifier: "com.apple.Safari", signer: .apple, appStore: false)),
       "a signature that passed anchor apple is Apple's")
expect(CodeSigningIdentity.failure(errSecCSInternalError) == .unavailable,
       "a signing-information read that fails is checked again, not untrusted")

// The decision itself, for signers this Mac may not have.
typealias S = CodeSigningIdentity.Signed
func decideID(_ p: CodeSigningIdentity.Lookup) -> String? { CodeSigningIdentity.decide(p).bundleIdentifier }
expect(decideID(.trusted(S(identifier: "com.apple.Safari", signer: .team("ATTACKER01"), appStore: false))) == nil,
       "a Developer ID cannot claim an identifier under com.apple.")
expect(decideID(.trusted(S(identifier: "com.apple.Pages", signer: .team("K36BKF7T3D"), appStore: true))) == "com.apple.Pages",
       "Apple's own App Store apps keep their com.apple. id")
expect(decideID(.trusted(S(identifier: "com.google.Chrome", signer: .team("EQHXZ8M8AV"), appStore: false))) == "com.google.Chrome",
       "a Developer ID app keeps its own id")
expect(decideID(.untrusted) == nil, "an untrusted signature gives no bundle id")
expect(CodeSigningIdentity.failure(errSecCSReqFailed) == .untrusted && CodeSigningIdentity.failure(errSecCSUnsigned) == .untrusted,
       "an unsigned binary, or a signer rules may not trust, is untrusted")
expect(CodeSigningIdentity.failure(errSecCSStaticCodeChanged) == .unavailable,
       "an app updated on disk while it runs is checked again, not untrusted")
expect(CodeSigningIdentity.failure(errSecCSSignatureNotVerifiable) == .unavailable,
       "a signature the verifier could not read is checked again, not untrusted")
expect(CodeSigningIdentity.failure(errSecCSStaticCodeNotFound) == .unavailable
       && CodeSigningIdentity.failure(errSecCSInternalError) == .unavailable,
       "a signature that could not be read (a sandbox refusal, a missing file) is checked again, not untrusted")
expect(CodeSigningIdentity.decide(.unavailable) == .unavailable,
       "a signature that could not be read is reported as such, not as no bundle id")

// The extension's cache: the plist's bundle id never reaches a rule.
let plistOnly: @Sendable (String) -> AppBundleMetadataRead = { _ in
    .read(AppBundleMetadata(bundleIdentifier: "com.apple.Safari", version: "9.9"))
}
let cache = BundleIdentifierCache(read: plistOnly, identify: { _, _ in .resolved(nil) })
let fakeSafari = fakes + "/adhoc/Safari.app/Contents/MacOS/Safari"
_ = cache.cachedMetadata(forExecutablePath: fakeSafari)
cache.waitForPendingResolves()
expect(cache.cachedBundleId(forExecutablePath: fakeSafari) == nil,
       "the extension's cache never answers the plist's bundle id")
expect(cache.cachedMetadata(forExecutablePath: fakeSafari)?.version == "9.9",
       "the extension's cache still shows the plist's version")

// The cache over the real signature check, with the file standing in for
// the running process (the harness cannot hand out other processes' tokens).
let h1 = CDHash((1, 1, 1)), h2 = CDHash((2, 2, 2))
let fileCheck: @Sendable (String, Data?) -> CodeSigningIdentity.Resolution = { path, _ in
    CodeSigningIdentity.resolve(executablePath: path, auditToken: nil, pid: 0)
}
let real = BundleIdentifierCache(identify: fileCheck, codeHash: { _ in h1 })
_ = real.cachedMetadata(forExecutablePath: fakeSafari)
real.waitForPendingResolves()
expect(real.cachedBundleId(forExecutablePath: fakeSafari) == nil,
       "the extension's cache gives the fake Safari no bundle id")
let calculator = "/System/Applications/Calculator.app/Contents/MacOS/Calculator"
_ = real.cachedMetadata(forExecutablePath: calculator)
real.waitForPendingResolves()
expect(real.cachedBundleId(forExecutablePath: calculator) == "com.apple.calculator",
       "the extension's cache answers Calculator's signed id")

// The kernel's code hash for a real process: this harness's own.
var ownToken = audit_token_t()
var tokenSize = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
let tokenStatus = withUnsafeMutablePointer(to: &ownToken) {
    $0.withMemoryRebound(to: integer_t.self, capacity: Int(tokenSize)) {
        task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), $0, &tokenSize)
    }
}
let ownTokenData = withUnsafeBytes(of: &ownToken) { Data($0) }
let ownHash = tokenStatus == KERN_SUCCESS ? BundleIdentifierCache.kernelCodeHash(auditToken: ownTokenData) : nil
let expectedHash = args[6]
let ownHashText = ownHash.map { hash -> String in
    var bytes = (hash.head, hash.middle, hash.tail)
    return withUnsafeBytes(of: &bytes) { Array($0.prefix(20)) }.map { String(format: "%02x", $0) }.joined()
}
expect(ownHashText == expectedHash,
       "the kernel's code hash for a running process matches codesign's (\(ownHashText ?? "nil"))")
expect(BundleIdentifierCache.kernelCodeHash(auditToken: nil) == nil, "no audit token, no code hash")

// A binary swapped in at a path never inherits the earlier process's id.
final class HashBox: @unchecked Sendable { var hash: CDHash? = h1; var checks: [CDHash?] = [] }
let current = HashBox()
let swapCache = BundleIdentifierCache(read: { _ in .read(AppBundleMetadata(bundleIdentifier: "com.google.Chrome", version: "1")) }, identify: { _, _ in
    current.checks.append(current.hash)
    return current.hash == h1 ? .resolved("com.google.Chrome") : .resolved(nil)
}, codeHash: { _ in current.hash })
let chromePath = "/Users/someone/Copied Chrome.app/Contents/MacOS/Google Chrome"
_ = swapCache.cachedMetadata(forExecutablePath: chromePath)
swapCache.waitForPendingResolves()
expect(swapCache.cachedBundleId(forExecutablePath: chromePath) == "com.google.Chrome",
       "the process whose code was checked gets its signed id")
current.hash = h2
expect(swapCache.cachedBundleId(forExecutablePath: chromePath) == nil,
       "a process running other code at the same path gets no id before its own check")
swapCache.waitForPendingResolves()
expect(swapCache.cachedBundleId(forExecutablePath: chromePath) == nil && current.checks.count == 2,
       "the swapped-in binary is checked itself and gets no id")
current.hash = CDHash((3, 3, 3))
expect(swapCache.cachedMetadata(forExecutablePath: chromePath)?.signatureChecked != true,
       "code that has not been checked yet is reported as unchecked, not as unvouched")
swapCache.waitForPendingResolves()
current.hash = h2
let checkedSwap = swapCache.cachedMetadata(forExecutablePath: chromePath)
expect(checkedSwap?.signatureChecked == true && checkedSwap?.bundleIdentifier == nil
       && checkedSwap?.claimedBundleIdentifier == "com.google.Chrome",
       "checked code without a trusted signature is reported as checked, with the plist id only claimed")
current.hash = h1
expect(swapCache.cachedBundleId(forExecutablePath: chromePath) == "com.google.Chrome" && current.checks.count == 3,
       "the original code keeps its id without another check")
current.hash = nil
expect(swapCache.cachedBundleId(forExecutablePath: chromePath) == nil,
       "a process whose code hash the kernel cannot give gets no signed id")

final class Box: @unchecked Sendable { var calls = 0; var answer: CodeSigningIdentity.Resolution = .unavailable }
let box = Box()
final class Clock: @unchecked Sendable { var nanos: UInt64 = 1_000_000_000 }
let clock = Clock()
let retrying = BundleIdentifierCache(entryLifetime: 300, read: { _ in .read(nil) }, identify: { _, _ in
    box.calls += 1
    return box.answer
}, codeHash: { _ in h1 }, clock: { clock.nanos })
let path = "/Applications/Gone.app/Contents/MacOS/Gone"
_ = retrying.cachedMetadata(forExecutablePath: path)
retrying.waitForPendingResolves()
expect(retrying.cachedBundleId(forExecutablePath: path) == nil, "an unreadable signature gives no bundle id")
retrying.waitForPendingResolves()
expect(box.calls == 1, "an unreadable signature is not checked again on every flow")
clock.nanos += 1_000_000_000
box.answer = .resolved("com.example.gone")
_ = retrying.cachedMetadata(forExecutablePath: path)
retrying.waitForPendingResolves()
expect(box.calls == 2 && retrying.cachedBundleId(forExecutablePath: path) == "com.example.gone",
       "an unreadable signature is checked again after a second, not after the whole lifetime")

// An app updated on disk under a running process can't be checked until it
// is relaunched: checked again with growing gaps, not every second.
let stuck = Box()
let stuckClock = Clock()
let stuckCache = BundleIdentifierCache(entryLifetime: 300, read: { _ in .read(nil) }, identify: { _, _ in
    stuck.calls += 1
    return .unavailable
}, codeHash: { _ in h1 }, clock: { stuckClock.nanos })
let stuckPath = "/Applications/Updated.app/Contents/MacOS/Updated"
// Ten flows a second for a minute.
for _ in 0..<600 {
    _ = stuckCache.cachedMetadata(forExecutablePath: stuckPath)
    stuckCache.waitForPendingResolves()
    stuckClock.nanos += 100_000_000
}
// Checks at 0, 1, 3, 7, 15, 31 s: 6 in 60 s.
expect(stuck.calls == 6, "a signature that stays unreadable is checked with growing gaps (\(stuck.calls) checks for 600 flows)")
// The app is relaunched: new code at the same path is checked at once, not
// after its predecessor's backoff.
let stuckHash = HashBox()
stuckHash.hash = h1
let relaunch = BundleIdentifierCache(entryLifetime: 300, read: { _ in .read(nil) }, identify: { _, _ in
    stuckHash.checks.append(stuckHash.hash)
    return stuckHash.hash == h1 ? .unavailable : .resolved("com.example.updated")
}, codeHash: { _ in stuckHash.hash }, clock: { stuckClock.nanos })
for _ in 0..<5 {
    _ = relaunch.cachedMetadata(forExecutablePath: stuckPath)
    relaunch.waitForPendingResolves()
    stuckClock.nanos += 60_000_000_000
}
stuckHash.hash = h2
_ = relaunch.cachedMetadata(forExecutablePath: stuckPath)
relaunch.waitForPendingResolves()
expect(relaunch.cachedBundleId(forExecutablePath: stuckPath) == "com.example.updated",
       "a relaunched app's new code is checked at once, whatever the old code's backoff")

// The cache keeps the plist's id apart, as the claimed one.
let claiming = BundleIdentifierCache(read: plistOnly, identify: { _, _ in .resolved(nil) })
_ = claiming.cachedMetadata(forExecutablePath: fakeSafari)
claiming.waitForPendingResolves()
expect(claiming.cachedMetadata(forExecutablePath: fakeSafari)?.claimedBundleIdentifier == "com.apple.Safari",
       "the extension's cache keeps the plist's id only as the claimed one")
let signedSafari = BundleIdentifierCache(read: plistOnly, identify: { _, _ in .resolved("com.apple.Safari") }, codeHash: { _ in h1 })
_ = signedSafari.cachedMetadata(forExecutablePath: fakeSafari)
signedSafari.waitForPendingResolves()
expect(signedSafari.cachedMetadata(forExecutablePath: fakeSafari)?.claimedBundleIdentifier == nil,
       "a plist that agrees with the signature adds no claimed id")

// Matching: an unsigned claim can get a binary blocked, never let through.
let matcher = RuleMatcher()
func flow(signed: String?, claimed: String?, path: String = "/tmp/x/Safari.app/Contents/MacOS/Safari") -> Connection {
    Connection(pid: 4242, processName: "Safari", processPath: path,
               processBundleId: signed, claimedBundleId: claimed,
               remoteHost: "example.com", remoteIP: "203.0.113.5", remotePort: 443, direction: .outgoing)
}
let allowSafari = Rule(processBundleId: "com.apple.Safari", action: .allow, priority: 100)
let askSafari = Rule(processBundleId: "com.apple.Safari", action: .ask, priority: 100)
let denySafari = Rule(processBundleId: "com.apple.Safari", action: .deny, priority: 100)
let spoof = flow(signed: nil, claimed: "com.apple.Safari")
let realSafari = flow(signed: "com.apple.Safari", claimed: nil, path: "/Applications/Safari.app/Contents/MacOS/Safari")
func decide(_ c: Connection, _ rules: [Rule], _ mode: AppMode = .alert) -> (RuleAction, Rule?) {
    let r = matcher.explainedDecision(for: c, prepared: PreparedRuleSet(rules: rules), defaultMode: mode)
    return (r.action, r.skippedUnverified)
}

// Allow direction.
expect(decide(realSafari, [allowSafari]).0 == .allow, "the signed app still gets its allow rule")
expect(decide(spoof, [allowSafari]).0 == .ask,
       "an unsigned binary claiming a signed app's id does not get that app's allow rule")
expect(decide(spoof, [allowSafari]).1?.id == allowSafari.id,
       "the skipped allow rule is reported, so the extension can log why the user was asked")
expect(decide(spoof, [allowSafari], .silentDeny).0 == .deny,
       "with no allow, a spoofer falls to the default mode like any unknown app")
expect(!matcher.matches(rule: allowSafari, connection: spoof), "the one-rule matcher agrees on the allow")
// Ask: a claimed id can only make a verdict stricter (allow -> ask).
expect(decide(spoof, [askSafari], .silentAllow).0 == .ask && decide(spoof, [askSafari]).1 == nil,
       "an ask rule for a claimed id still asks in Silent Allow mode, and is not reported as skipped")
let allowSpoofPath = Rule(processPath: "/tmp/x/Safari.app/Contents/MacOS/Safari", action: .allow, priority: 50)
expect(decide(spoof, [askSafari, allowSpoofPath]).0 == .ask,
       "an ask rule for a claimed id raises a lower allow for the same binary to an ask")
let denySpoofPath = Rule(processPath: "/tmp/x/Safari.app/Contents/MacOS/Safari", action: .deny, priority: 50)
expect(decide(spoof, [askSafari, denySpoofPath], .silentAllow).0 == .deny,
       "an ask rule for a claimed id never lowers a deny to an ask")
expect(decide(spoof, [askSafari], .silentDeny).0 == .deny,
       "an ask rule for a claimed id never lowers Silent Deny to an ask")
expect(matcher.matches(rule: askSafari, connection: spoof), "the one-rule matcher counts a claimed id for an ask rule")
let unsignedApp = flow(signed: nil, claimed: "org.example.homebrewed", path: "/Applications/Homebrewed.app/Contents/MacOS/Homebrewed")
let allowUnsigned = Rule(processBundleId: "org.example.homebrewed", action: .allow, priority: 100)
let askUnsigned = Rule(processBundleId: "org.example.homebrewed", action: .ask, priority: 100)
expect(decide(unsignedApp, [askUnsigned], .silentAllow).0 == .ask,
       "a user's ask rule for an unsigned app keeps asking in Silent Allow mode")
expect(decide(unsignedApp, [allowUnsigned]).0 == .ask,
       "an allow rule for an unsigned app's own id now alerts (the one change in behaviour)")

// Allow and ask rules that also name a path (what alerts and the Monitor tree
// write) keep matching an unsigned app at that path: no broader than a
// path-only rule.
let homebrewedPath = "/Applications/Homebrewed.app/Contents/MacOS/Homebrewed"
let allowUnsignedAtPath = Rule(processBundleId: "org.example.homebrewed", processPath: homebrewedPath,
                               action: .allow, priority: 100)
expect(decide(unsignedApp, [allowUnsignedAtPath], .silentDeny).0 == .allow,
       "an unsigned app keeps its allow rule made with its bundle id and path, even in Silent Deny mode")
expect(matcher.matches(rule: allowUnsignedAtPath, connection: unsignedApp),
       "the one-rule matcher agrees on the id+path allow")
let impostor = flow(signed: nil, claimed: "org.example.homebrewed", path: "/Users/someone/Downloads/Homebrewed.app/Contents/MacOS/Homebrewed")
expect(decide(impostor, [allowUnsignedAtPath], .silentDeny).0 == .deny,
       "the same claimed id from another path does not get that allow")
expect(!matcher.matches(rule: allowUnsignedAtPath, connection: impostor),
       "the one-rule matcher agrees the impostor path does not match")
let askUnsignedAtPath = Rule(processBundleId: "org.example.homebrewed", processPath: homebrewedPath,
                             action: .ask, priority: 100)
let allowAll = Rule(processPath: "/Applications/", action: .allow, priority: 50)
expect(decide(unsignedApp, [askUnsignedAtPath, allowAll]).0 == .ask,
       "an id+path ask rule for an unsigned app still asks")
let spoofSafariAtRealPath = flow(signed: nil, claimed: "com.apple.Safari", path: "/tmp/x/Safari.app/Contents/MacOS/Safari")
let allowSafariAtRealPath = Rule(processBundleId: "com.apple.Safari", processPath: "/Applications/Safari.app/Contents/MacOS/Safari",
                                 action: .allow, priority: 100)
expect(decide(spoofSafariAtRealPath, [allowSafariAtRealPath], .silentDeny).0 == .deny,
       "a fake Safari elsewhere does not get Safari's id+path allow")

// Deny direction.
expect(decide(realSafari, [denySafari]).0 == .deny, "the signed app still gets its deny rule")
expect(decide(spoof, [denySafari]).0 == .deny,
       "an unsigned binary claiming a signed app's id gets any deny rule for that id")
expect(decide(spoof, [denySafari]).1 == nil, "a deny that matched reports no skipped rule")
expect(matcher.matches(rule: denySafari, connection: spoof), "the one-rule matcher agrees on the deny")
let denyUnsigned = Rule(processBundleId: "org.example.homebrewed", action: .deny, priority: 100)
expect(decide(unsignedApp, [denyUnsigned], .silentAllow).0 == .deny,
       "a user's existing deny for an unsigned app keeps blocking it")
let devSigned = flow(signed: "org.example.devbuild-signed", claimed: "org.example.devbuild")
expect(decide(devSigned, [Rule(processBundleId: "org.example.devbuild", action: .deny)], .silentAllow).0 == .deny,
       "a deny also matches a plist id that differs from the signed one")

// Both at once: the spoofer gets the deny, never the allow.
let allowHigh = Rule(processBundleId: "com.apple.Safari", remoteHost: "example.com", action: .allow, priority: 200)
let denyLow = Rule(processBundleId: "com.apple.Safari", action: .deny, priority: 50)
expect(decide(spoof, [allowHigh, denyLow], .silentAllow).0 == .deny,
       "an unsigned binary claiming Safari's id skips Safari's allow and lands on Safari's deny")
expect(decide(realSafari, [allowHigh, denyLow], .silentAllow).0 == .allow,
       "the real Safari still gets its higher-priority allow")
expect(decide(flow(signed: nil, claimed: nil), [denySafari], .silentAllow).0 == .allow,
       "a binary with no claim at all is not caught by a bundle-id deny")

print("code signing harness: all \(checks) checks passed")
SWIFT

SHARED=()
while IFS= read -r file; do SHARED+=("$file"); done < <(find "$ROOT/Sources/Shared" -name '*.swift' | sort)
xcrun swiftc -swift-version 5 -O -o "$TMP/harness" "${SHARED[@]}" "$TMP/cache.swift" "$TMP/main.swift" -lsqlite3
OWN_CDHASH="$(codesign -dvvv "$TMP/harness" 2>&1 | sed -n 's/^CDHash=//p' | head -1)"
"$TMP/harness" "$FAKES" "$SWAPPED" "${DROPPED:-$TMP/none}" "$FAKE_PID" "${CURL_IN_SAFARI:-$TMP/none}" "$OWN_CDHASH" \
  "${FINDER_PID:-0}" "$DEVID_PID" "$DEVID_PATH" "$DEVID_ID"
