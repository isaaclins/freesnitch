#!/usr/bin/env bash
# Regression gate for #58: the uninstall script's own guards, exercised against
# a FAKE root directory.
#
# Nothing here may touch the real /Applications, /Library, launchd, pf, or the
# real system extension database. Every privileged tool is a stub in a scratch
# directory, every path lives under a temporary root, and the script's
# run_privileged never escalates while a test root is set.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UNINSTALL="$ROOT/Scripts/uninstall_freesnitch.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-uninstall-safety.XXXXXX")"
trap '[[ -n "${FREESNITCH_KEEP_WORK:-}" ]] || rm -rf "$WORK"' EXIT

failures=0

fail() {
  printf 'UNINSTALL SAFETY TEST FAILED: %s\n' "$*" >&2
  failures=$((failures + 1))
}

expect_contains() {
  local haystack="$1" needle="$2" what="$3"
  [[ "$haystack" == *"$needle"* ]] || fail "$what (missing: $needle)"
}

expect_absent() {
  local haystack="$1" needle="$2" what="$3"
  [[ "$haystack" != *"$needle"* ]] || fail "$what (unexpectedly present: $needle)"
}

# --- fake system ------------------------------------------------------------

make_fake_root() {
  local name="$1"
  local root="$WORK/$name/root"
  local stubs="$WORK/$name/stubs"
  mkdir -p "$root/Applications/FreeSnitch.app/Contents/Library/LaunchDaemons"
  mkdir -p "$root/Applications/FreeSnitch.app/Contents/Helpers"
  mkdir -p "$root/Library/Application Support/FreeSnitch/Insights"
  mkdir -p "$root/etc/pf.anchors"
  : >"$root/Applications/FreeSnitch.app/Contents/Library/LaunchDaemons/io.isaaclins.freesnitch.helper.plist"
  : >"$root/Applications/FreeSnitch.app/Contents/Helpers/freesnitch-helper"
  : >"$root/Library/Application Support/FreeSnitch/Insights/insights.sqlite"
  printf 'fake policy database\n' >"$root/Library/Application Support/FreeSnitch/freesnitch.sqlite"
  : >"$root/etc/pf.anchors/puresnitch"
  mkdir -p "$stubs"
  write_stubs "$stubs"
  printf '%s\n' "$root"
}

write_stubs() {
  local stubs="$1"

  cat >"$stubs/pfctl" <<'STUB'
#!/usr/bin/env bash
printf 'pfctl %s\n' "$*" >>"$STUB_LOG"
exit 0
STUB

  cat >"$stubs/systemextensionsctl" <<'STUB'
#!/usr/bin/env bash
printf 'systemextensionsctl %s\n' "$*" >>"$STUB_LOG"
case "${1:-}" in
  list)
    printf '1 extension(s)\n'
    if [[ "${FAKE_EXT_PRESENT:-0}" == "1" ]]; then
      printf -- '--- com.apple.system_extension.network_extension\nenabled\tactive\tteamID\tBHAF4L4726\tio.isaaclins.freesnitch.netext (0.3.1/26)\t[activated enabled]\n'
    fi
    exit 0
    ;;
  uninstall)
    if [[ "${FAKE_SIP:-enabled}" == "enabled" || "${FAKE_SYSEXT_REFUSAL:-0}" == "1" ]]; then
      printf 'At this time, this tool cannot be used if System Integrity Protection is enabled.\n'
      exit 1
    fi
    printf 'Sent uninstall request\n'
    exit 0
    ;;
esac
exit 0
STUB

  cat >"$stubs/launchctl" <<'STUB'
#!/usr/bin/env bash
printf 'launchctl %s\n' "$*" >>"$STUB_LOG"
case "${1:-}" in
  bootout)
    [[ "${FAKE_HELPER_RUNNING:-0}" == "1" ]] && exit 1
    exit 0
    ;;
  print)
    if [[ "${FAKE_HELPER_RUNNING:-0}" == "1" ]]; then
      printf 'system/io.isaaclins.freesnitch.helper = {\n\tactive count = 1\n\tprogram = %s/Applications/FreeSnitch.app/Contents/Helpers/freesnitch-helper\n}\n' \
        "$FREESNITCH_UNINSTALL_TEST_ROOT"
      exit 0
    fi
    printf 'Could not find service "io.isaaclins.freesnitch.helper" in domain for system\n' >&2
    exit 113
    ;;
esac
exit 0
STUB

  cat >"$stubs/csrutil" <<'STUB'
#!/usr/bin/env bash
printf 'csrutil %s\n' "$*" >>"$STUB_LOG"
if [[ "${FAKE_SIP:-enabled}" == "enabled" ]]; then
  printf 'System Integrity Protection status: enabled.\n'
else
  printf 'System Integrity Protection status: disabled.\n'
fi
exit 0
STUB

  chmod +x "$stubs/pfctl" "$stubs/systemextensionsctl" "$stubs/launchctl" "$stubs/csrutil"
}

# Runs the uninstall script against one fake root and publishes its combined
# output in RUN_OUTPUT and its exit status in RUN_STATUS. Never inherits a PATH
# entry that could reach a real privileged tool: every tool is passed by
# absolute stub path.
RUN_OUTPUT=""
RUN_STATUS=0
run_uninstall() {
  local name="$1"; shift
  local root="$WORK/$name/root"
  local stubs="$WORK/$name/stubs"
  local out_file="$WORK/$name/output.txt"
  export STUB_LOG="$WORK/$name/stub.log"
  : >"$STUB_LOG"
  set +e
  env \
    FREESNITCH_UNINSTALL_TEST_ROOT="$root" \
    FREESNITCH_PFCTL="$stubs/pfctl" \
    FREESNITCH_SYSTEMEXTENSIONSCTL="$stubs/systemextensionsctl" \
    FREESNITCH_LAUNCHCTL="$stubs/launchctl" \
    FREESNITCH_CSRUTIL="$stubs/csrutil" \
    STUB_LOG="$STUB_LOG" \
    FAKE_SIP="${FAKE_SIP:-enabled}" \
    FAKE_EXT_PRESENT="${FAKE_EXT_PRESENT:-0}" \
    FAKE_HELPER_RUNNING="${FAKE_HELPER_RUNNING:-0}" \
    FAKE_SYSEXT_REFUSAL="${FAKE_SYSEXT_REFUSAL:-0}" \
    bash "$UNINSTALL" "$@" >"$out_file" 2>&1
  RUN_STATUS=$?
  set -e
  RUN_OUTPUT="$(cat "$out_file")"
}

# --- 1. it refuses to remove an unexpected path -----------------------------

test_refuses_unexpected_path() {
  local root; root="$(make_fake_root refuse-path)"
  local output status

  set +e
  output="$(FREESNITCH_UNINSTALL_TEST_ROOT="$root" bash -c '
    source "$1"
    safe_remove_directory "/tmp/definitely-not-freesnitch"
  ' _ "$UNINSTALL" 2>&1)"
  status=$?
  set -e
  (( status != 0 )) || fail "an unexpected path was accepted for removal"
  expect_contains "$output" "refusing an unexpected uninstall path" "unexpected path guard message"
  [[ -d /tmp/definitely-not-freesnitch ]] && fail "the guard test created a real path"

  # An allowlisted path that is still not a removal target must be refused too.
  set +e
  output="$(FREESNITCH_UNINSTALL_TEST_ROOT="$root" bash -c '
    source "$1"
    safe_remove_directory "$SUPPORT"
  ' _ "$UNINSTALL" 2>&1)"
  status=$?
  set -e
  (( status != 0 )) || fail "the shared support directory was accepted for removal"
  expect_contains "$output" "refusing to remove a non-removable path" "non-removable path guard message"
  [[ -d "$root/Library/Application Support/FreeSnitch" ]] || fail "the support directory was removed anyway"

  # A relative path must never reach the case statement.
  set +e
  output="$(FREESNITCH_UNINSTALL_TEST_ROOT="$root" bash -c '
    source "$1"
    assert_exact_path "Applications/FreeSnitch.app"
  ' _ "$UNINSTALL" 2>&1)"
  status=$?
  set -e
  (( status != 0 )) || fail "a relative path was accepted"
  expect_contains "$output" "refusing a non-absolute path" "non-absolute path guard message"

  # The fake-root seam itself must fail closed on a system path.
  set +e
  output="$(FREESNITCH_UNINSTALL_TEST_ROOT="/Library" bash -c 'source "$1"' _ "$UNINSTALL" 2>&1)"
  status=$?
  set -e
  (( status != 0 )) || fail "a system path was accepted as the test root"
  expect_contains "$output" "refusing a system path as the test root" "test root guard message"
}

# --- 2. it refuses to remove the app while the helper still runs ------------

test_refuses_while_helper_runs() {
  local root; root="$(make_fake_root helper-running)"
  local output status

  export FAKE_SIP=enabled FAKE_EXT_PRESENT=0 FAKE_HELPER_RUNNING=1
  run_uninstall helper-running --yes
  output="$RUN_OUTPUT"
  status=$RUN_STATUS
  unset FAKE_HELPER_RUNNING FAKE_EXT_PRESENT FAKE_SIP

  (( status != 0 )) || fail "the app was removed while the helper was still running from the bundle"
  expect_contains "$output" "still running from" "live-helper guard message"
  expect_absent "$output" "Removed $root/Applications/FreeSnitch.app" "the app must not be removed under a live helper"
  [[ -d "$root/Applications/FreeSnitch.app" ]] || fail "the app bundle was removed under a live helper"
  [[ -d "$root/Library/Application Support/FreeSnitch/Insights" ]] || fail "Insights was removed under a live helper"
}

# --- 3. it handles the SIP refusal without claiming removal -----------------

test_sip_refusal_is_honest() {
  local root; root="$(make_fake_root sip-refusal)"
  local output status

  # SIP on and a record still present: the script must say what to do and must
  # not remove anything.
  export FAKE_SIP=enabled FAKE_EXT_PRESENT=1 FAKE_HELPER_RUNNING=0
  run_uninstall sip-refusal --yes
  output="$RUN_OUTPUT"
  status=$RUN_STATUS
  (( status != 0 )) || fail "the uninstall continued while the extension was still registered"
  expect_contains "$output" "System Integrity Protection is enabled" "SIP explanation"
  expect_contains "$output" "Settings > Uninstall" "pointer to the in-app uninstall"
  expect_contains "$output" "still holds a record" "registered-extension guard message"
  expect_absent "$output" "Requested deactivation" "no deactivation may be claimed"
  expect_absent "$output" "Removed " "nothing may be removed while the extension is registered"
  [[ -d "$root/Applications/FreeSnitch.app" ]] || fail "the app was removed with the extension still registered"

  # SIP reported off, but the tool still answers with the SIP refusal. The
  # answer, not the csrutil reading, decides what is claimed.
  export FAKE_SIP=disabled FAKE_SYSEXT_REFUSAL=1 FAKE_EXT_PRESENT=1 FAKE_HELPER_RUNNING=0
  run_uninstall sip-refusal --yes
  output="$RUN_OUTPUT"
  status=$RUN_STATUS
  unset FAKE_SIP FAKE_SYSEXT_REFUSAL FAKE_EXT_PRESENT FAKE_HELPER_RUNNING
  (( status != 0 )) || fail "the uninstall continued after a systemextensionsctl SIP refusal"
  expect_contains "$output" "Nothing was deactivated" "honest report of the tool refusal"
  expect_absent "$output" "Removed " "nothing may be removed after a refused deactivation"
  [[ -d "$root/Applications/FreeSnitch.app" ]] || fail "the app was removed after a refused deactivation"
}

# --- 4. it flushes only the named anchor, and honours the database choice ----

test_flushes_only_named_anchor() {
  local root; root="$(make_fake_root happy-path)"
  local output status

  export FAKE_SIP=enabled FAKE_EXT_PRESENT=0 FAKE_HELPER_RUNNING=0
  run_uninstall happy-path --yes
  output="$RUN_OUTPUT"
  status=$RUN_STATUS
  (( status == 0 )) || fail "a clean uninstall failed: $output"
  [[ -d "$root/Applications/FreeSnitch.app" ]] && fail "the app bundle was not removed on the clean path"
  [[ -d "$root/Library/Application Support/FreeSnitch/Insights" ]] && fail "Insights was not removed on the clean path"
  [[ -f "$root/Library/Application Support/FreeSnitch/freesnitch.sqlite" ]] || fail "the policy database was deleted without --remove-database"
  expect_contains "$output" "Kept $root/Library/Application Support/FreeSnitch/freesnitch.sqlite" "kept-database message"
  [[ -f "$root/etc/pf.anchors/puresnitch" ]] || fail "the shared anchor file was deleted"

  local pf_calls
  pf_calls="$(grep '^pfctl ' "$WORK/happy-path/stub.log" || true)"
  expect_contains "$pf_calls" "pfctl -a puresnitch -F all" "anchor flush call"
  expect_contains "$pf_calls" "pfctl -a puresnitch -f /dev/null" "anchor reload call"
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    [[ "$line" == "pfctl -a puresnitch "* ]] || fail "pfctl was called outside the puresnitch anchor: $line"
  done <<<"$pf_calls"
  expect_absent "$pf_calls" "pfctl -d" "pf must never be disabled globally"
  expect_absent "$pf_calls" "-F rules" "no global rule flush"

  # The database is only deleted when explicitly asked for.
  local root2; root2="$(make_fake_root purge-db)"
  run_uninstall purge-db --yes --remove-database
  output="$RUN_OUTPUT"
  status=$RUN_STATUS
  unset FAKE_SIP FAKE_EXT_PRESENT FAKE_HELPER_RUNNING
  (( status == 0 )) || fail "the uninstall with --remove-database failed: $output"
  [[ -f "$root2/Library/Application Support/FreeSnitch/freesnitch.sqlite" ]] && fail "--remove-database did not delete the policy database"
  expect_contains "$output" "Removed $root2/Library/Application Support/FreeSnitch/freesnitch.sqlite" "database removal message"
}

# --- 5. no real system path may appear in any privileged call ---------------

test_never_touched_the_real_system() {
  local log
  for log in "$WORK"/*/stub.log; do
    [[ -f "$log" ]] || continue
    while IFS= read -r line; do
      case "$line" in
        *" /Applications/"*|*" /Library/"*)
          [[ "$line" == *"$WORK"* ]] || fail "a privileged call referenced a real system path: $line"
          ;;
      esac
    done <"$log"
  done
}

test_refuses_unexpected_path
test_refuses_while_helper_runs
test_sip_refusal_is_honest
test_flushes_only_named_anchor
test_never_touched_the_real_system

if (( failures > 0 )); then
  printf 'uninstall safety verification: FAIL (%d)\n' "$failures"
  exit 1
fi
printf 'uninstall safety verification: PASS\n'
