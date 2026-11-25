#!/usr/bin/env bash
# Regression gate for #236.
#
# The firewall safety audit required the helper initializer to contain the
# line that restores the user's DNS over HTTPS resolver, but it searched raw
# source lines. With the live line deleted and the same text left in a comment
# inside the initializer, the audit still passed, so a helper that drops the
# user's resolver after every restart could ship.
#
# The audit now reads every Swift file with its comments blanked out. This
# replays the issue on a copy of the sources: the untouched copy passes, and
# every way of leaving the line only as a comment fails with the resolver
# message. One check that reads a file directly instead of through a helper
# is covered the same way. It also checks that reading code without comments
# keeps string literals whole, so text after a URL in a string is still seen.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-audit-comments.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
  echo "AUDIT COMMENT TEST FAILED: $*" >&2
  exit 1
}

AUDIT="$ROOT/Scripts/audit_firewall_safety.sh"
RESTORE='dns.dohURL = Self.restoredDoHUpstream(from: store.getSetting("doh_url"))'
VALIDATE='DoHUpstreamValidator.rejectionReason(for: storedValue)'
RESTORE_MESSAGE='restores mode without also restoring and validating the persisted DoH upstream'
VALIDATE_MESSAGE='restores a persisted DoH upstream without validating it'
OWN_TRAFFIC='if isOwnTraffic(conn) || isLoopback(conn.remoteIP) { observe(.unfiltered); return .allow() }'
OWN_TRAFFIC_MESSAGE='own-traffic and loopback exemption is missing'
HELPER_FILE=Sources/Helper/HelperService.swift
FILTER_FILE=Sources/NetExt/FilterDataProvider.swift

grep -Fq -- "$RESTORE" "$ROOT/$HELPER_FILE" \
  || fail "the helper no longer has the restore line this test edits"
grep -Fq -- "$VALIDATE" "$ROOT/$HELPER_FILE" \
  || fail "the helper no longer has the validation call this test edits"
grep -Fq -- "$OWN_TRAFFIC" "$ROOT/$FILTER_FILE" \
  || fail "the extension no longer has the own-traffic line this test edits"

# A fresh copy of what the audit reads, with one piece of text replaced.
# $1 names the case, $2 is the file, $3 the text to replace, $4 what replaces it.
make_copy() {
  local dir="$TMP/$1"
  mkdir -p "$dir"
  cp -R "$ROOT/Scripts" "$ROOT/Sources" "$ROOT/project.yml" "$ROOT/project-netext.yml" "$dir/"
  if [ "$#" -eq 4 ]; then
    FIND="$3" REPLACE="$4" perl -0pi -e 's/\Q$ENV{FIND}\E/$ENV{REPLACE}/ or die "text not found\n"' \
      "$dir/$2"
  fi
  printf '%s\n' "$dir"
}

# Runs the copied audit; prints its output and returns its status.
run_audit() {
  bash "$1/Scripts/audit_firewall_safety.sh" 2>&1
}

expect_failure() {
  local name="$1" file="$2" find="$3" replace="$4" message="$5"
  local dir output
  dir="$(make_copy "$name" "$file" "$find" "$replace")"
  if output="$(run_audit "$dir")"; then
    fail "$name: the audit passed although the line is only left in a comment"
  fi
  grep -Fq -- "$message" <<<"$output" \
    || fail "$name: the audit failed for another reason: $output"
  echo "ok - $name fails the audit"
}

# The untouched sources pass, so the failures below come from the edit.
output="$(run_audit "$(make_copy untouched)")" || fail "the untouched sources fail the audit: $output"
echo "ok - untouched sources pass"

# The steps in #236: the live line removed, its text left in a // comment
# inside the initializer.
expect_failure "line comment" "$HELPER_FILE" "$RESTORE" "// $RESTORE" "$RESTORE_MESSAGE"
# The same text after other code on the line.
expect_failure "trailing comment" "$HELPER_FILE" "$RESTORE" "_ = 0 // $RESTORE" "$RESTORE_MESSAGE"
# The same text in a block comment, on one line and across lines.
expect_failure "block comment" "$HELPER_FILE" "$RESTORE" "/* $RESTORE */" "$RESTORE_MESSAGE"
expect_failure "multi-line block comment" "$HELPER_FILE" "$RESTORE" "/*
        $RESTORE
        */" "$RESTORE_MESSAGE"
# The validator check had the same gap.
expect_failure "validator in a comment" "$HELPER_FILE" "guard let reason = $VALIDATE else {" \
  "// guard let reason = $VALIDATE else {
        guard let reason = Optional<String>.none else {" "$VALIDATE_MESSAGE"
# A check that greps the file itself rather than going through a helper.
expect_failure "own-traffic exemption in a comment" "$FILTER_FILE" "$OWN_TRAFFIC" \
  "// $OWN_TRAFFIC" "$OWN_TRAFFIC_MESSAGE"

# Reading code without comments must not cut a line at the // of a URL in a
# string, or drop code after a string that holds one.
helper="$(awk '/^swift_code\(\) \{$/ {a=1} a {print} a && /^\}$/ {exit}' "$AUDIT")"
[ -n "$helper" ] || fail "the audit no longer defines swift_code"
eval "$helper"
cat > "$TMP/sample.swift" <<'SWIFT'
let a = "https://example.com/dns-query"; keptAfterURL()
let b = "\(name ?? "http://fallback")"; keptAfterInterpolation()
let c = "a \"quoted\" // not a comment"; keptAfterEscapes()
/* opened /* nested */ still a comment droppedNested() */ keptAfterNested()
let d = """
  // inside a multi-line string
  """; keptAfterMultiLine()
code() // droppedLineComment()
SWIFT
stripped="$(swift_code "$TMP/sample.swift")"
for kept in keptAfterURL keptAfterInterpolation keptAfterEscapes keptAfterNested keptAfterMultiLine \
            '"https://example.com/dns-query"' '// not a comment' '// inside a multi-line string'; do
  grep -Fq -- "$kept" <<<"$stripped" || fail "reading code without comments dropped $kept"
done
for dropped in droppedNested droppedLineComment; do
  if grep -Fq -- "$dropped" <<<"$stripped"; then
    fail "reading code without comments kept $dropped, which is in a comment"
  fi
done
[ "$(wc -l <"$TMP/sample.swift")" -eq "$(printf '%s\n' "$stripped" | wc -l)" ] \
  || fail "reading code without comments changed the number of lines"
echo "ok - comments removed, strings kept"

echo "audit comment test passed"
