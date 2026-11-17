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
if grep -Fq 'draft.rules = rules }' "$HELPER"; then
  fail "the helper import still replaces the whole rule table with the file"
fi
grep -Fq 'RuleImportPlan(current: draft.rules, imported: rules)' "$HELPER" \
  || fail "the helper import does not apply RuleImportPlan"
grep -Fq 'PSLog.info(PSLog.helper, plan.logSummary)' "$HELPER" \
  || fail "the helper import does not log what it removed and kept"
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
/// What the helper's replaceRules does inside its transaction.
func helperImport(_ store: RuleStore, _ fileRules: [Rule]) throws -> RuleImportPlan {
    var plan: RuleImportPlan?
    _ = try store.mutatePolicy { draft in
        let p = RuleImportPlan(current: draft.rules, imported: fileRules)
        draft.rules = p.resulting
        plan = p
    }
    return plan!
}

let path = CommandLine.arguments[1]
let store = try RuleStore(path: path)
_ = try store.createProfile(name: "Office")
let always = rule("always.example", Profile.alwaysName)
let office = rule("office.example", "Office")
let home = rule("home.example", "home")
_ = try store.mutatePolicy { $0.rules = [always, office, home] }
_ = try store.setActiveProfile(name: "home")
let everything = labels(store.allRules(profile: nil))
check("setup: rules in Always, Office and home, home active",
      everything == ["Office:office.example", "always:always.example", "home:home.example"])

// 1. The fixed export: every profile, through the shared file format.
let fullFile = try RuleExportCodec.encode(store.allRules(profile: nil))
let fullImport = try RuleExportCodec.decode(fullFile).rules
check("export carries the inactive profile's rule", labels(fullImport).contains("Office:office.example"))
let roundTrip = try helperImport(store, fullImport)
check("export then import keeps every rule", labels(store.allRules(profile: nil)) == everything)
check("a full round trip deletes nothing", roundTrip.removed.isEmpty)

// 2. A backup from an older build: only Always plus the active profile.
//    Importing it must keep Office, which the file says nothing about.
let oldFile = try RuleExportCodec.encode(store.activePolicyState().rules)
let oldImport = try RuleExportCodec.decode(oldFile).rules
check("an older backup lacks Office (the #247 file)", !labels(oldImport).contains("Office:office.example"))
let oldPlan = try helperImport(store, oldImport)
check("importing an older backup keeps the Office rule",
      labels(store.allRules(profile: nil)).contains("Office:office.example"))
check("the plan reports the Office rule as kept",
      oldPlan.kept.map(\.id) == [office.id] && oldPlan.keptByProfile.map(\.profile) == ["Office"])
check("the plan reports nothing removed", oldPlan.removed.isEmpty)

// 3. A rule in a replaced profile that the file lacks is deleted, and the
//    plan names it, so the dialog and the log can say so.
let extraHome = rule("extra-home.example", "home")
_ = try store.mutatePolicy { $0.rules.append(extraHome) }
let lossPlan = try helperImport(store, oldImport)
check("a home rule missing from the file is removed",
      !labels(store.allRules(profile: nil)).contains("home:extra-home.example"))
check("the plan names exactly the removed rule", lossPlan.removed.map(\.id) == [extraHome.id])
check("the log line names the removed rule's ID", lossPlan.logSummary.contains(extraHome.id.uuidString))
check("Office still survives", labels(store.allRules(profile: nil)).contains("Office:office.example"))

// 4. A file whose rule moved profile, by ID, replaces the stored copy once.
var moved = office
moved.profile = "home"
let movePlan = RuleImportPlan(current: store.allRules(profile: nil), imported: [moved])
check("a rule moved to another profile is not kept twice",
      movePlan.resulting.filter { $0.id == office.id }.count == 1
      && movePlan.resulting.first { $0.id == office.id }?.profile == "home")

// 5. A file with no rules changes nothing.
let emptyPlan = RuleImportPlan(current: store.allRules(profile: nil), imported: [])
check("an empty file deletes nothing", emptyPlan.removed.isEmpty
      && emptyPlan.resulting.count == store.allRules(profile: nil).count)

if failures > 0 { print("rule import profiles: \(failures) failure(s)"); exit(1) }
SWIFT

swiftc -suppress-warnings "$ROOT"/Sources/Shared/*.swift "$TMP/main.swift" -lsqlite3 -o "$TMP/verify"
"$TMP/verify" "$TMP/rules.sqlite"
