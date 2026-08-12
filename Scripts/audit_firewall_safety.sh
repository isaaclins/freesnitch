#!/usr/bin/env bash
# Static release gate for the Network System Extension's safety invariants.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FILTER="$ROOT/Sources/NetExt/FilterDataProvider.swift"

fail() {
  printf 'FIREWALL SAFETY AUDIT FAILED: %s\n' "$*" >&2
  exit 1
}

require_text() {
  local file="$1"
  local text="$2"
  local message="$3"
  grep -Fq -- "$text" "$file" || fail "$message"
}

[[ -f "$FILTER" ]] || fail "missing $FILTER"

# A missing GUI must never leave a socket flow paused forever or turn a GUI
# outage into a network outage. Keep this check tied to the actual branch that
# handles the false result from promptUser, not only to a comment.
require_text "$FILTER" "let asked = IPCConnection.shared.promptUser" \
  "the extension no longer asks the GUI through IPCConnection"
require_text "$FILTER" "if !asked {" \
  "the no-GUI path is missing"

# Each fail-open check is scoped to its own brace block. A window of N lines
# would let one block borrow another block's allow verdict and hide a
# fail-closed regression, so the block is delimited by brace depth instead.
allow_within_block() {
  local file="$1"
  local start_regex="$2"
  awk -v start="$start_regex" '
    !active && $0 ~ start {
      active = 1
      depth = 0
    }
    active {
      if ($0 ~ /resumeOnce\(NEFilterNewFlowVerdict\.allow\(\)\)/) {
        found = 1
        exit 0
      }
      n = gsub(/\{/, "{")
      m = gsub(/\}/, "}")
      depth += n - m
      if (depth <= 0) active = 0
    }
    END { exit(found ? 0 : 1) }
  ' "$file"
}

if ! allow_within_block "$FILTER" 'if !asked[[:space:]]*\{'; then
  fail "the no-GUI path does not fail open with an allow verdict"
fi

# FreeSnitch, its helper, and loopback are safety-critical exemptions. They
# must be decided before the general matcher can pause or drop the flow.
own_line="$(grep -nF 'if isOwnTraffic(conn) || isLoopback(conn.remoteIP) { return .allow() }' "$FILTER" | head -1 | cut -d: -f1 || true)"
matcher_line="$(grep -nF 'matcher.decision(for: conn' "$FILTER" | head -1 | cut -d: -f1 || true)"
[[ -n "$own_line" ]] || fail "own-traffic and loopback exemption is missing"
[[ -n "$matcher_line" ]] || fail "the extension no longer invokes the shared matcher"
if (( own_line >= matcher_line )); then
  fail "own-traffic and loopback must be allowed before matcher.decision"
fi

require_text "$FILTER" "if isOwnCode(pid: conn.pid)" \
  "own-traffic detection no longer checks the process code signature"
require_text "$FILTER" "SecCodeCheckValidity" \
  "own-traffic detection no longer validates a code signature"
require_text "$FILTER" "AppConstants.bundleIdGUI" \
  "the GUI bundle identifier is missing from the own-code requirement"
require_text "$FILTER" "AppConstants.bundleIdHelper" \
  "the helper bundle identifier is missing from the own-code requirement"
require_text "$FILTER" "AppConstants.bundleIdNetExt" \
  "the system extension bundle identifier is missing from the own-code requirement"
require_text "$FILTER" 'ip.hasPrefix("127.")' \
  "IPv4 loopback is no longer exempted"
require_text "$FILTER" 'ip == "::1"' \
  "IPv6 loopback is no longer exempted"
require_text "$FILTER" 'ip == "localhost"' \
  "localhost is no longer exempted"

# A path prefix of / is an exemption for every process. Reject the known bad
# shape even if a future refactor moves it into a helper in this source file.
active_code="$(grep -vE '^[[:space:]]*//' "$FILTER" || true)"
if printf '%s\n' "$active_code" | grep -Eq 'hasPrefix\([[:space:]]*"/|==[[:space:]]*"/"|"/[[:space:]]*==|Bundle\.main|URL\(fileURLWithPath:[[:space:]]*"/' ; then
  fail "found a broad root-path or Bundle.main exemption that could whitelist every process"
fi

# The interactive path also needs a timeout. This prevents a connected but
# unresponsive GUI from wedging a flow indefinitely.
require_text "$FILTER" "workQueue.asyncAfter" \
  "interactive flow handling has no timeout"
# The allow verdict may sit on the same line as the asyncAfter call, so the
# matching line itself counts as evidence, not only the lines after it.
if ! allow_within_block "$FILTER" 'workQueue\.asyncAfter'; then
  fail "the interactive timeout does not fail open with an allow verdict"
fi

printf 'Firewall safety audit passed: fail-open GUI handling, code-signature self exemption, loopback ordering, and timeout are present.\n'
