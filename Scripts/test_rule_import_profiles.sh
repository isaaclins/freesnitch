#!/usr/bin/env bash
# Replays issue #247: a rule backup made while one profile is active, then
# imported, must not lose the other profiles' rules.
#
# The harness compiles the shipping Sources/Shared code, never a copy. It runs
# the real RuleStore against a temporary database and the same RuleImportPlan
# the helper applies inside its import transaction. Static checks pin the two
# call sites that cannot be compiled on their own: the app's export reads
# every profile from the helper, and the helper's import goes through the plan.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-rule-import-profiles.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() { printf 'rule import profiles: FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'rule import profiles: PASS: %s\n' "$*"; }

RULES_MANAGER="$ROOT/Sources/GUI/Views/RulesManager.swift"
HELPER="$ROOT/Sources/Helper/HelperService.swift"

# The app's export must not be built from state.rules, which holds only the
# active profile's layers.
if grep -Fq 'RuleJSONDocument(rules: state.rules)' "$RULES_MANAGER"; then
  fail "the app still exports state.rules, the active profile only"
fi
grep -Fq 'allRulesInEveryProfile' "$RULES_MANAGER" \
  || fail "the app's export and import do not read every profile's rules"
pass "the app's export and import read every profile's rules from the helper"

# The helper's import must go through the plan, never assign the file wholesale.
if grep -Eq 'draft\.rules[[:space:]]*=[[:space:]]*rules[[:space:]]*\}' "$HELPER"; then
  fail "the helper import still replaces the whole rule table with the file"
fi
grep -Fq 'plan = try RuleImportPlan.apply(imported: rules,' "$HELPER" \
  || fail "the helper import does not apply RuleImportPlan"
grep -Fq 'confirmedIDs: Set(expectedRemovedIDs),' "$HELPER" \
  || fail "the helper import does not check the deletions the user confirmed"
grep -Fq 'expectedRemovedIDs: plan?.confirmedIDs ?? []' "$RULES_MANAGER" \
  || fail "the app does not send the deletions it showed in the dialog"
grep -Fq 'plan?.logLines.forEach { PSLog.notice(PSLog.helper, $0) }' "$HELPER" \
  || fail "the helper import does not log what it removed, at a level the log store keeps"
# An older helper drops the new import request without answering. The app
# must give up on its own instead of waiting forever.
awk '/func replaceRules\(_ rules: \[Rule\]/,/^    }$/' "$ROOT/Sources/GUI/App/HelperClient.swift" > "$TMP/replace.swift"
grep -Fq 'asyncAfter(deadline: .now() + 30, execute: work)' "$TMP/replace.swift" \
  || fail "the app's import request has no timeout"
grep -Fq 'finish(ok, message)' "$TMP/replace.swift" \
  || fail "the import reply does not go through the once-only finish"
pass "the app's import request times out instead of waiting on an older helper"
pass "the helper import applies RuleImportPlan and logs it"

cat > "$TMP/main.swift" <<'SWIFT'
import Foundation

var failures = 0
func check(_ name: String, _ condition: Bool) {
    if condition { print("rule import profiles: PASS: \(name)") }
    else { failures += 1; print("rule import profiles: FAIL: \(name)") }
}

func rule(_ host: String, _ profile: String) -> Rule {
    Rule(processPath: "/usr/bin/curl", processName: "curl", remoteHost: host,
         action: .deny, scope: .domain, profile: profile)
}
func labels(_ rules: [Rule]) -> [String] {
    rules.map { "\($0.profile):\($0.remoteHost ?? "")" }.sorted()
}
/// The app's side: build the plan the dialog shows from every stored rule.
func dialogPlan(_ store: RuleStore, _ fileRules: [Rule]) -> RuleImportPlan {
    RuleImportPlan(current: (try! store.allRules(profile: nil)), imported: fileRules)
}
/// The helper's side: the same call replaceRules makes inside its transaction,
/// with the deletions the dialog showed.
@discardableResult
func helperImport(_ store: RuleStore, _ fileRules: [Rule], confirmed: RuleImportPlan) throws -> RuleImportPlan {
    var plan: RuleImportPlan?
    _ = try store.mutatePolicy { draft in
        plan = try RuleImportPlan.apply(imported: fileRules,
                                        confirmedIDs: Set(confirmed.confirmedIDs),
                                        to: &draft)
    }
    return plan!
}
func importConfirmed(_ store: RuleStore, _ fileRules: [Rule]) throws -> RuleImportPlan {
    try helperImport(store, fileRules, confirmed: dialogPlan(store, fileRules))
}

let path = CommandLine.arguments[1]
let store = try RuleStore(path: path)
_ = try store.createProfile(name: "Office")
let always = rule("always.example", Profile.alwaysName)
let office = rule("office.example", "Office")
let home = rule("home.example", "home")
_ = try store.mutatePolicy { $0.rules = [always, office, home] }
_ = try store.setActiveProfile(name: "home")
let everything = labels((try! store.allRules(profile: nil)))
check("setup: rules in Always, Office and home, home active",
      everything == ["Office:office.example", "always:always.example", "home:home.example"])

// 1. The fixed export: every profile, through the shared file format.
let fullFile = try RuleExportCodec.encode((try! store.allRules(profile: nil)))
let fullImport = try RuleExportCodec.decode(fullFile).rules
check("export carries the inactive profile's rule", labels(fullImport).contains("Office:office.example"))
let roundTrip = try importConfirmed(store, fullImport)
check("export then import keeps every rule", labels((try! store.allRules(profile: nil))) == everything)
check("a full round trip deletes nothing", roundTrip.removed.isEmpty)

// 2. A backup from an older build: only Always plus the active profile.
//    Importing it must keep Office, which the file says nothing about.
let oldFile = try RuleExportCodec.encode((try! store.activePolicyState()).rules)
let oldImport = try RuleExportCodec.decode(oldFile).rules
check("an older backup lacks Office (the #247 file)", !labels(oldImport).contains("Office:office.example"))
let oldPlan = try importConfirmed(store, oldImport)
check("importing an older backup keeps the Office rule",
      labels((try! store.allRules(profile: nil))).contains("Office:office.example"))
check("the plan reports the Office rule as kept",
      oldPlan.kept.map(\.id) == [office.id] && oldPlan.keptByProfile.map(\.profile) == ["Office"])
check("the plan reports nothing removed", oldPlan.removed.isEmpty)

// 3. A rule in a replaced profile that the file lacks is deleted, and the
//    plan names it, so the dialog and the log can say so.
let extraHome = rule("extra-home.example", "home")
_ = try store.mutatePolicy { $0.rules.append(extraHome) }
let lossPlan = try importConfirmed(store, oldImport)
check("a home rule missing from the file is removed",
      !labels((try! store.allRules(profile: nil))).contains("home:extra-home.example"))
check("the plan names exactly the removed rule", lossPlan.removed.map(\.id) == [extraHome.id])
check("the log line names the removed rule's ID", lossPlan.logLines.joined().contains(extraHome.id.uuidString))
check("the log line names the removed rule the way a person reads it",
      lossPlan.logLines.joined().contains("deny curl to extra-home.example in home"))
check("the log keeps one line per removed rule",
      lossPlan.logLines.contains { $0.hasPrefix("rule import removed: deny curl to extra-home.example in home") })
check("Always is listed first among replaced profiles",
      RuleImportPlan(current: [], imported: [office, always, home]).replacedProfiles == [Profile.alwaysName, "Office", "home"])
check("Office still survives", labels((try! store.allRules(profile: nil))).contains("Office:office.example"))

// 4. The stored rules change while the dialog is open: a rule allowed from an
//    alert lands in home. The helper's deletions no longer match what the
//    user confirmed, so it refuses and nothing changes.
let shown = dialogPlan(store, oldImport)
let allowedMeanwhile = rule("allowed-meanwhile.example", "home")
_ = try store.mutatePolicy { $0.rules.append(allowedMeanwhile) }
let beforeStale = labels((try! store.allRules(profile: nil)))
var refused = false
do { try helperImport(store, oldImport, confirmed: shown) } catch is RuleImportConflict { refused = true }
check("an import confirmed against older rules is refused", refused)
check("the refused import changed nothing", labels((try! store.allRules(profile: nil))) == beforeStale)
let reviewed = try importConfirmed(store, oldImport)
check("reviewing again shows the new rule as deleted, and then imports",
      reviewed.removed.map(\.id) == [allowedMeanwhile.id])

// 4b. Same count, different rule: one rule added and the one the user saw
//     deleted removed meanwhile. A count check would pass; the ID check refuses.
let extraA = rule("a.example", "home")
_ = try store.mutatePolicy { $0.rules.append(extraA) }
let shownA = dialogPlan(store, oldImport)
let extraB = rule("b.example", "home")
_ = try store.mutatePolicy { draft in
    draft.rules.removeAll { $0.id == extraA.id }
    draft.rules.append(extraB)
}
var refusedSwap = false
do { try helperImport(store, oldImport, confirmed: shownA) } catch is RuleImportConflict { refusedSwap = true }
check("a different rule to delete, same count, is refused", refusedSwap)
_ = try importConfirmed(store, oldImport)

// 5. A file whose rule moved profile, by ID, replaces the stored copy once.
var moved = office
moved.profile = "home"
let movePlan = RuleImportPlan(current: (try! store.allRules(profile: nil)), imported: [moved])
check("a rule moved to another profile is not kept twice",
      movePlan.resulting.filter { $0.id == office.id }.count == 1
      && movePlan.resulting.first { $0.id == office.id }?.profile == "home")
// A move the user did not see is refused like a deletion.
let staleMove = RuleImportPlan(current: [always, home], imported: [moved])
var refusedMove = false
_ = try store.mutatePolicy { $0.rules = [always, office, home] }
do {
    _ = try store.mutatePolicy { draft in
        _ = try RuleImportPlan.apply(imported: [moved], confirmedIDs: Set(staleMove.confirmedIDs), to: &draft)
    }
} catch is RuleImportConflict { refusedMove = true }
check("a move the user was not shown is refused", refusedMove)
var refusedDuplicate = false
do {
    _ = try store.mutatePolicy { draft in
        _ = try RuleImportPlan.apply(imported: [home, home], confirmedIDs: [], to: &draft)
    }
} catch is RuleExportError { refusedDuplicate = true }
check("duplicate IDs in an import are refused", refusedDuplicate)
check("a rule moved out of a profile the file does not mention is reported",
      movePlan.moved.map(\.id) == [office.id] && movePlan.logLines.contains { $0.contains("from Office to home") }
      && movePlan.confirmedIDs.contains(office.id))

// 6. A file with no rules changes nothing.
let emptyPlan = RuleImportPlan(current: (try! store.allRules(profile: nil)), imported: [])
check("an empty file deletes nothing", emptyPlan.removed.isEmpty
      && emptyPlan.resulting.count == (try! store.allRules(profile: nil)).count)

if failures > 0 { print("rule import profiles: \(failures) failure(s)"); exit(1) }
SWIFT

swiftc -suppress-warnings "$ROOT"/Sources/Shared/*.swift "$TMP/main.swift" -lsqlite3 -o "$TMP/verify"
"$TMP/verify" "$TMP/rules.sqlite"
