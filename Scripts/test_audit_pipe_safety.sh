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
helper="$(awk '/^read_all_then\(\) \{$/ {a=1} a {print} a && /^\}$/ {exit}' "$AUDIT")"
[ -n "$helper" ] || fail "the audit no longer defines read_all_then"
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

# Readers that must read a pipe get it drained first, so the writer finishes.
printf '%s\n' "$body" | read_all_then grep -Fq 'needle' \
  || fail "read_all_then grep missed text that is there, or its writer died of a broken pipe"
printf '%s\n' "$body" | read_all_then grep -Eq '^filler line 199999 ' \
  || fail "read_all_then grep missed a match on the last line"
if printf '%s\n' "$body" | read_all_then grep -Fq 'not in the body'; then
  fail "read_all_then grep matched text that is not there"
fi
printf '%s\n' "$body" | read_all_then grep -Fvq 'needle' \
  || fail "read_all_then grep -v did not see the lines without the text"
printf '%s\n' "$body" | read_all_then rg -q 'needle' \
  || fail "read_all_then rg missed text that is there, or its writer died of a broken pipe"
printf '%s\n' "$body" | read_all_then awk '/needle/ { found = 1; exit } END { exit !found }' \
  || fail "an awk program that exits early still breaks its writer's pipe"

# Empty input stays empty: no made-up empty line for -v to find, and rg reads
# the empty pipe instead of searching the current directory.
if printf '' | read_all_then grep -vq 'anything'; then
  fail "read_all_then turned empty input into a line"
fi
if (cd "$ROOT" && printf '' | read_all_then rg -q 'read_all_then'); then
  fail "read_all_then made rg search the current directory on empty input"
fi

# No check in the audit may read a pipe with a reader that can stop early
# (grep -q, grep -m, rg -q, head, an awk program that exits before END), unless
# read_all_then drains the pipe for it or the result is thrown away with || true.
offenders="$(perl -ne '
  next if /\|\|\s*true/;
  my $line = $_;
  $line =~ s/END\s*\{[^}]*\}//g;
  my $pipe = qr/(?:^|[^|])\|\s*/;
  if ($line =~ /$pipe(?:grep|rg)(?:\s+-[A-Za-z0-9]+)*\s+-[A-Za-z]*[qm]/
      || $line =~ /$pipe(?:head|tail\s+-[A-Za-z]*q)\b/
      || $line =~ /$pipe(?:grep|rg)(?:\s+-[A-Za-z0-9]+)*\s+--(?:quiet|max-count)/
      || $line =~ /$pipe(?:awk)\b[^|]*\bexit\b/) {
    print "$.: $_";
  }
' "$AUDIT")"
if [ -n "$offenders" ]; then
  printf '%s\n' "$offenders" >&2
  fail "these audit checks can still fail when a reader stops early; use a here-string or read_all_then"
fi

echo "Audit pipe safety test passed."
