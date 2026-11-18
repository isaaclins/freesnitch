#!/usr/bin/env bash
# The firewall safety audit must not fail because grep -q stopped reading early.
#
# grep -q exits at its first match. When its input comes through a pipe whose
# writer is still sending, that writer dies of SIGPIPE, and under pipefail the
# check fails although the text it looks for is there. On a loaded CI runner
# this failed the audit at random (#411). This replays that failure with a body
# big enough to make it certain, checks the audit's way of matching survives
# it, and keeps the audit free of checks that read a pipe with grep -q.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AUDIT="$ROOT/Scripts/audit_firewall_safety.sh"

fail() {
  echo "AUDIT PIPE SAFETY TEST FAILED: $*" >&2
  exit 1
}

# The audit's own helper, taken from the script so this tests what it runs.
helper="$(awk '/^grep_all_q\(\) \{$/ {a=1} a {print} a && /^\}$/ {exit}' "$AUDIT")"
[ -n "$helper" ] || fail "the audit no longer defines grep_all_q"
eval "$helper"

# Several megabytes with the needle on the first line: grep finds it in its
# first read and quits while the writer still has almost everything left.
body="needle"$'\n'"$(awk 'BEGIN { for (i = 0; i < 200000; i++) print "filler line " i " of a long Swift function body" }')"

# The old form: this is the failure the audit hit, made certain by the size.
if (printf '%s\n' "$body" | grep -Fq 'needle') 2>/dev/null; then
  fail "the replay did not reproduce the broken pipe, so it proves nothing"
fi

# Matching captured text with a here-string reads nothing through a pipe.
grep -Fq 'needle' <<<"$body" || fail "a here-string match missed text that is there"

# Checks that must read a pipe drain it first, so the writer finishes cleanly.
printf '%s\n' "$body" | grep_all_q -F 'needle' \
  || fail "grep_all_q missed text that is there, or its writer died of a broken pipe"
printf '%s\n' "$body" | grep_all_q -E '^filler line 199999 ' \
  || fail "grep_all_q missed a match on the last line"
if printf '%s\n' "$body" | grep_all_q -F 'not in the body'; then
  fail "grep_all_q matched text that is not there"
fi
if ! printf '%s\n' "$body" | grep_all_q -Fv 'needle'; then
  fail "grep_all_q -v did not see the lines without the text"
fi

# No check in the audit may read a pipe with grep -q or stop a pipe early with
# head or grep -m, unless its result is thrown away with || true.
offenders="$(grep -nE '(^|[^|])\|[[:space:]]*grep[[:space:]]+-[A-Za-z]*q|(^|[^|])\|[[:space:]]*(head|grep[[:space:]]+-[A-Za-z]*m)\b' "$AUDIT" \
  | grep -v '|| true' || true)"
if [ -n "$offenders" ]; then
  printf '%s\n' "$offenders" >&2
  fail "these audit checks can still fail when a reader stops early; use a here-string or grep_all_q"
fi

echo "Audit pipe safety test passed."
