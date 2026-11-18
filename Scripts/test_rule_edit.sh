#!/usr/bin/env bash
# Editing a rule from the Rules page (#433): the edited rule replaces the old
# one in place, keeps what the sheet doesn't show, and the matcher then
# follows the new action.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-rule-edit.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/main.swift" <<'SWIFT'
import Foundation

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data(("rule edit: FAIL: " + message + "\n").utf8))
    exit(1)
}
func pass(_ message: String) { print("rule edit: PASS: \(message)") }

/// The helper's addRule write: replace by id, keep a learned team.
func store(_ rule: Rule, into rules: [Rule]) -> [Rule] {
    var updated = rules
    if let index = updated.firstIndex(where: { $0.id == rule.id }) {
        updated[index] = RuleSigningTeam.keepingLearnedTeam(rule, over: updated[index])
    } else {
        updated.append(rule)
    }
    return updated
}

func edit(_ r: Rule, process: RuleEdit.Process = .unchanged, bundleId: String?? = .none,
          action: RuleAction? = nil, port: Int?? = .none) -> RuleEdit {
    RuleEdit(process: process,
             bundleId: bundleId ?? r.processBundleId,
             remoteHost: r.remoteHost, remoteIP: r.remoteIP,
             remotePort: port ?? r.remotePort,
             direction: r.direction, action: action ?? r.action, scope: r.scope,
             profile: r.profile, notes: r.notes, enabled: r.enabled)
}

// The report: a deny rule made from an alert, which the user wants to allow.
let created = Date(timeIntervalSince1970: 1_700_000_000)
let expires = Date(timeIntervalSince1970: 1_900_000_000)
let original = Rule(processBundleId: "com.example.tool", processTeamId: "ABCDE12345",
                    processPath: "/Applications/Tool.app/Contents/MacOS/Tool", processName: "Tool",
                    remoteHost: "example.com", remotePort: 443, action: .deny, scope: .domain,
                    priority: 250, profile: "Home", groupName: "Work", notes: "from alert",
                    temporary: true, createdAt: created, expiresAt: expires,
                    lastUsedAt: created, hitCount: 42)
let other = Rule(remoteHost: "other.example", action: .allow)
var rules = [other, original]

let connection = Connection(pid: 1, processName: "Tool",
                            processPath: "/Applications/Tool.app/Contents/MacOS/Tool",
                            processBundleId: "com.example.tool", processTeamId: "ABCDE12345",
                            remoteHost: "example.com", remoteIP: "93.184.216.34", remotePort: 443)
let matcher = RuleMatcher()
guard matcher.decision(for: connection, rules: rules, defaultMode: .alert) == .deny else {
    fail("the original deny rule does not deny its own connection")
}

let allowed = edit(original, action: .allow).applied(to: original)
rules = store(allowed, into: rules)
guard rules.count == 2 else { fail("editing added a rule instead of replacing it (\(rules.count) rules)") }
guard let saved = rules.first(where: { $0.id == original.id }) else { fail("the edited rule lost its id") }
guard saved.action == .allow else { fail("the new action was not saved") }
guard saved.priority == 250, saved.groupName == "Work", saved.hitCount == 42,
      saved.createdAt == created, saved.lastUsedAt == created,
      saved.temporary, saved.expiresAt == expires, saved.profile == "Home" else {
    fail("fields the sheet doesn't show changed: \(saved)")
}
guard saved.processPath == original.processPath, saved.processName == "Tool" else {
    fail("an unchanged process was rewritten: \(saved.processPath ?? "nil") \(saved.processName ?? "nil")")
}
guard saved.processTeamId == "ABCDE12345" else { fail("the same bundle id lost its signing team") }
guard rules.first(where: { $0.id == other.id }) == other else { fail("another rule changed") }
guard matcher.decision(for: connection, rules: rules, defaultMode: .alert) == .allow else {
    fail("the matcher still follows the old action after the edit")
}
pass("deny -> allow replaces the rule in place, keeps its stats and expiry, and the matcher follows it")

// A new bundle id never inherits the old app's signing team, neither from the
// sheet nor from the helper's keep-the-learned-team step.
let moved = edit(saved, bundleId: "com.example.other").applied(to: saved)
guard moved.processTeamId == nil else { fail("a new bundle id kept the old team in the sheet") }
let movedStored = store(moved, into: rules).first(where: { $0.id == original.id })!
guard movedStored.processTeamId == nil else { fail("the helper gave the old team to a new bundle id") }
pass("a changed bundle id drops the old signing team")

// Choosing another app: the sheet clears the old app's bundle id (pick()), so
// the rule matches the new app by its path, helpers inside it included.
let rechosen = edit(saved, process: .app(path: "/Applications/Other.app/", name: "Other"),
                    bundleId: .some(nil), port: .some(nil)).applied(to: saved)
guard rechosen.processPath == "/Applications/Other.app/", rechosen.processName == "Other",
      rechosen.processBundleId == nil, rechosen.processTeamId == nil,
      rechosen.remotePort == nil else { fail("a chosen app or cleared port was not saved: \(rechosen)") }
let rechosenRules = store(rechosen, into: rules)
let otherAppHelper = Connection(pid: 2, processName: "Other Helper",
                                processPath: "/Applications/Other.app/Contents/Frameworks/Other Helper.app/Contents/MacOS/Other Helper",
                                processBundleId: "com.other.helper", processTeamId: "ZZZZZ99999",
                                remoteHost: "example.com", remoteIP: "93.184.216.34", remotePort: 8443)
guard matcher.decision(for: otherAppHelper, rules: rechosenRules, defaultMode: .alert) == .allow else {
    fail("a rule moved to another app does not match that app")
}
guard matcher.decision(for: connection, rules: rechosenRules, defaultMode: .alert) == .ask else {
    fail("a rule moved to another app still matches the old one")
}
let anyApp = edit(saved, process: .anyApp).applied(to: saved)
guard anyApp.processPath == nil, anyApp.processName == nil else { fail("removing the app kept it") }
pass("a new app, no app and a cleared port are saved, and the moved rule matches the new app")

// Only what the user changed is written, over the rule as it is at save time:
// a team learned, a toggle or a profile move made elsewhere (the CLI) while
// the sheet was open stays. A field the user did change wins.
var meanwhile = original
meanwhile.processTeamId = "FGHIJ67890"
meanwhile.enabled = false
meanwhile.profile = "Work"
let late = edit(original, action: .allow).applied(to: meanwhile, openedWith: original)
guard late.processTeamId == "FGHIJ67890", !late.enabled, late.profile == "Work", late.action == .allow else {
    fail("a change made while the sheet was open was undone: \(late)")
}
var reEnabled = edit(original, action: .allow)
reEnabled.profile = "Cafe"
let both = reEnabled.applied(to: meanwhile, openedWith: original)
guard both.profile == "Cafe", !both.enabled else { fail("the user's own profile change lost, or an untouched toggle was reverted") }
pass("an edit writes only the fields the user changed, over the current rule")

// The edit is still a valid rule for the transport the helper checks.
do { try RuleTransportBoundary.validate(rule: saved) } catch { fail("the edited rule is refused: \(error)") }
pass("the edited rule passes the helper's rule checks")
SWIFT

SHARED=()
while IFS= read -r file; do SHARED+=("$file"); done < <(find "$ROOT/Sources/Shared" -name '*.swift' | sort)

xcrun swiftc -O \
    -sdk "$(xcrun --show-sdk-path)" \
    -target arm64-apple-macos13.0 \
    -o "$WORK/harness" \
    "$WORK/main.swift" "${SHARED[@]}" \
    -lsqlite3

"$WORK/harness"

# The sheet uses this merge, and every way into it is wired.
SRC="$ROOT/Sources/GUI/Views/RulesManager.swift"
grep -Fq 'edit.applied(to: current, openedWith: original)' "$SRC" || { echo 'rule edit: FAIL: the sheet does not use RuleEdit' >&2; exit 1; }
grep -Fq 'Button("Edit Rule\u{2026}")' "$SRC" || { echo 'rule edit: FAIL: no Edit Rule item in the context menu' >&2; exit 1; }
grep -Fq 'if let existingRule, processBundleID == (existingRule.processBundleId ?? "")' "$SRC" || { echo 'rule edit: FAIL: choosing another app keeps the old bundle id' >&2; exit 1; }
grep -Fq 'primaryAction:' "$SRC" || { echo 'rule edit: FAIL: double-click does not open the editor' >&2; exit 1; }
echo 'rule edit: PASS: the sheet, the menu item and double-click are wired'
