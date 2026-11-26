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
  # What SQLite leaves beside it when the helper stopped mid-write (#237): the
  # WAL with recent policy records, its index, and a rollback journal.
  local companion
  for companion in wal shm journal; do
    printf 'fake %s\n' "$companion" >"$root/Library/Application Support/FreeSnitch/freesnitch.sqlite-$companion"
  done
  # The anchor file holds the last rules, as it does when the helper was not
  # reachable to turn enforcement off before the uninstall (issue #192).
  printf 'table <freesnitch_feed> persist { 203.0.113.7 }\nblock drop out quick proto tcp to 198.51.100.4 port 443\n' \
    >"$root/etc/pf.anchors/puresnitch"
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
    if [[ "${FAKE_LIST_FAILS:-0}" == "1" ]]; then
      printf 'Error Domain=OSSystemExtensionErrorDomain Code=1 "unknown error"\n' >&2
      exit 1
    fi
    # Exit 0 but no listing: an answer that says nothing about the extension.
    [[ "${FAKE_LIST_EMPTY:-0}" == "1" ]] && exit 0
    if [[ "${FAKE_LIST_GARBLED:-0}" == "1" ]]; then
      printf 'XPC connection interrupted\n'
      exit 0
    fi
    if [[ "${FAKE_LIST_NONE:-0}" == "1" ]]; then
      # What a Mac with no system extensions prints, byte for byte.
      printf '0 extension(s)\n'
      exit 0
    fi
    printf '1 extension(s)\n'
    if [[ "${FAKE_EXT_PRESENT:-0}" == "1" ]]; then
      printf -- '--- com.apple.system_extension.network_extension\nenabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n*\t*\tBHAF4L4726\tio.isaaclins.freesnitch.netext (0.3.1/26)\tFreeSnitch\t[activated enabled]\n'
    fi
    if [[ "${FAKE_EXT_STOPPED:-0}" == "1" ]]; then
      printf -- '--- com.apple.system_extension.network_extension\n\t\tBHAF4L4726\tio.isaaclins.freesnitch.netext (0.3.1/26)\tFreeSnitch\t[terminated waiting to uninstall on reboot]\n'
    fi
    if [[ "${FAKE_EXT_VALIDATING:-0}" == "1" ]]; then
      printf -- '--- com.apple.system_extension.network_extension\n*\t*\tBHAF4L4726\tio.isaaclins.freesnitch.netext (0.3.1/26)\t[validating by category]\n'
    fi
    if [[ "${FAKE_EXT_DISABLED:-0}" == "1" ]]; then
      printf -- '--- com.apple.system_extension.network_extension\n\t\tBHAF4L4726\tio.isaaclins.freesnitch.netext (0.3.1/26)\tFreeSnitch\t[activated disabled]\n'
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
    FAKE_EXT_STOPPED="${FAKE_EXT_STOPPED:-0}" \
    FAKE_LIST_FAILS="${FAKE_LIST_FAILS:-0}" \
    FAKE_LIST_EMPTY="${FAKE_LIST_EMPTY:-0}" \
    FAKE_LIST_NONE="${FAKE_LIST_NONE:-0}" \
    FAKE_LIST_GARBLED="${FAKE_LIST_GARBLED:-0}" \
    FAKE_EXT_VALIDATING="${FAKE_EXT_VALIDATING:-0}" \
    FAKE_EXT_DISABLED="${FAKE_EXT_DISABLED:-0}" \
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

# An extension FreeSnitch already removed stays listed as "terminated waiting
# to uninstall on reboot" until the next restart. It no longer runs, so it must
# not hold the uninstall up; a listing that fails still must (#391).
test_stopped_extension_record() {
  local root; root="$(make_fake_root stopped-record)"
  export FAKE_SIP=enabled FAKE_EXT_STOPPED=1 FAKE_HELPER_RUNNING=0
  run_uninstall stopped-record --yes
  unset FAKE_EXT_STOPPED
  (( RUN_STATUS == 0 )) || fail "a stopped extension record held the uninstall up: $RUN_OUTPUT"
  [[ -d "$root/Applications/FreeSnitch.app" ]] && fail "the app was kept although the extension no longer runs"

  root="$(make_fake_root disabled-record)"
  export FAKE_EXT_DISABLED=1
  run_uninstall disabled-record --yes
  unset FAKE_EXT_DISABLED
  (( RUN_STATUS == 0 )) || fail "a disabled extension record held the uninstall up: $RUN_OUTPUT"

  root="$(make_fake_root validating)"
  export FAKE_EXT_VALIDATING=1
  run_uninstall validating --yes
  unset FAKE_EXT_VALIDATING
  (( RUN_STATUS != 0 )) || fail "the uninstall went on while the extension was in another state"
  [[ -d "$root/Applications/FreeSnitch.app" ]] || fail "the app was removed while the extension was in another state"

  unset FAKE_SIP FAKE_HELPER_RUNNING
}

# A query that fails, or answers without a listing, is "unknown", never
# "absent": the script prints what came back and stops before touching pf or
# removing anything (#260).
expect_unknown_state_stops() {
  local name="$1" detail="$2" root="$WORK/$1/root"
  (( RUN_STATUS != 0 )) || fail "$name: the uninstall went on although the extension state could not be read"
  expect_contains "$RUN_OUTPUT" "could not read the system extension state" "$name: unknown-state message"
  expect_contains "$RUN_OUTPUT" "$detail" "$name: the query failure is shown"
  expect_absent "$RUN_OUTPUT" "still holds a record" "$name: an unknown state must not be reported as a record"
  expect_absent "$RUN_OUTPUT" "is not running any more" "$name: an unknown state must not be reported as gone"
  expect_absent "$RUN_OUTPUT" "Removed " "$name: nothing may be removed"
  [[ -d "$root/Applications/FreeSnitch.app" ]] || fail "$name: the app was removed"
  [[ -d "$root/Library/Application Support/FreeSnitch/Insights" ]] || fail "$name: Insights was removed"
  grep -q '^pfctl ' "$WORK/$name/stub.log" && fail "$name: pf was flushed before the extension state was known"
  grep -q 'block drop' "$root/etc/pf.anchors/puresnitch" || fail "$name: the anchor file was changed"
  return 0
}

test_unknown_extension_state() {
  export FAKE_SIP=enabled FAKE_HELPER_RUNNING=0

  make_fake_root list-fails >/dev/null
  export FAKE_LIST_FAILS=1
  run_uninstall list-fails --yes
  unset FAKE_LIST_FAILS
  expect_unknown_state_stops list-fails "failed with exit status 1"
  expect_contains "$RUN_OUTPUT" "OSSystemExtensionErrorDomain" "list-fails: the tool's own error text is shown"

  make_fake_root list-empty >/dev/null
  export FAKE_LIST_EMPTY=1
  run_uninstall list-empty --yes
  unset FAKE_LIST_EMPTY
  expect_unknown_state_stops list-empty "did not return an extension listing (no output)"

  make_fake_root list-garbled >/dev/null
  export FAKE_LIST_GARBLED=1
  run_uninstall list-garbled --yes
  unset FAKE_LIST_GARBLED
  expect_unknown_state_stops list-garbled "did not return an extension listing"

  # A real listing with no extensions at all is a clear "absent".
  local root; root="$(make_fake_root list-none)"
  export FAKE_LIST_NONE=1
  run_uninstall list-none --yes
  unset FAKE_LIST_NONE FAKE_SIP FAKE_HELPER_RUNNING
  (( RUN_STATUS == 0 )) || fail "a real listing without the extension held the uninstall up: $RUN_OUTPUT"
  expect_contains "$RUN_OUTPUT" "is not running any more" "absent-state message"
}

# pf.conf loads the anchor file at boot, so after an uninstall it must hold no
# rules: only comments or blank lines (issue #192).
expect_anchor_file_empty() {
  local root="$1" what="$2" rules
  rules="$(grep -Ev '^[[:space:]]*(#|$)' "$root/etc/pf.anchors/puresnitch" || true)"
  [[ -z "$rules" ]] || fail "$what left rules in the anchor file pf.conf loads at boot: $rules"
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
  local companion
  for companion in wal shm journal; do
    [[ -f "$root/Library/Application Support/FreeSnitch/freesnitch.sqlite-$companion" ]] \
      || fail "freesnitch.sqlite-$companion was deleted without --remove-database"
  done
  [[ -f "$root/etc/pf.anchors/puresnitch" ]] || fail "the shared anchor file was deleted"
  expect_anchor_file_empty "$root" "a clean uninstall"

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
  for companion in wal shm journal; do
    [[ -e "$root2/Library/Application Support/FreeSnitch/freesnitch.sqlite-$companion" ]] \
      && fail "--remove-database left freesnitch.sqlite-$companion behind (#237)"
    expect_contains "$output" "Removed $root2/Library/Application Support/FreeSnitch/freesnitch.sqlite-$companion" \
      "removal message for freesnitch.sqlite-$companion"
  done
  # Nothing of the policy store may remain, whatever SQLite named it.
  local leftover
  leftover="$(find "$root2/Library/Application Support/FreeSnitch" -maxdepth 1 -name 'freesnitch.sqlite*' -print)"
  [[ -z "$leftover" ]] || fail "--remove-database left policy store files: $leftover"

  # A database whose files are already gone (or only partly there) is fine.
  local root3; root3="$(make_fake_root purge-db-partial)"
  rm -f "$root3/Library/Application Support/FreeSnitch/freesnitch.sqlite" \
        "$root3/Library/Application Support/FreeSnitch/freesnitch.sqlite-shm"
  export FAKE_SIP=enabled FAKE_EXT_PRESENT=0 FAKE_HELPER_RUNNING=0
  run_uninstall purge-db-partial --yes --remove-database
  unset FAKE_SIP FAKE_EXT_PRESENT FAKE_HELPER_RUNNING
  (( RUN_STATUS == 0 )) || fail "--remove-database failed with only a WAL left: $RUN_OUTPUT"
  leftover="$(find "$root3/Library/Application Support/FreeSnitch" -maxdepth 1 -name 'freesnitch.sqlite*' -print)"
  [[ -z "$leftover" ]] || fail "--remove-database left an orphaned WAL behind: $leftover"
  expect_anchor_file_empty "$root2" "the uninstall with --remove-database"
}

# --- 4b. it never writes through a symlinked anchor file ---------------------

test_refuses_symlinked_anchor() {
  local root; root="$(make_fake_root symlinked-anchor)"
  local target="$WORK/symlinked-anchor/elsewhere"
  printf 'not FreeSnitch\n' >"$target"
  rm "$root/etc/pf.anchors/puresnitch"
  ln -s "$target" "$root/etc/pf.anchors/puresnitch"

  export FAKE_SIP=enabled FAKE_EXT_PRESENT=0 FAKE_HELPER_RUNNING=0
  run_uninstall symlinked-anchor --yes
  unset FAKE_SIP FAKE_EXT_PRESENT FAKE_HELPER_RUNNING
  (( RUN_STATUS != 0 )) || fail "the uninstall wrote through a symlinked anchor file"
  [[ "$(cat "$target")" == "not FreeSnitch" ]] || fail "the symlink target was overwritten"
  [[ -d "$root/Applications/FreeSnitch.app" ]] || fail "the app was removed although the anchor could not be emptied"
}

# --- 4c. the command link goes only when it is FreeSnitch's (#423) ----------

test_command_link() {
  local root; root="$(make_fake_root command-link)"
  mkdir -p "$root/usr/local/bin"
  ln -s /Applications/FreeSnitch.app/Contents/Helpers/freesnitch "$root/usr/local/bin/freesnitch"
  export FAKE_SIP=enabled FAKE_EXT_PRESENT=0 FAKE_HELPER_RUNNING=0
  run_uninstall command-link --yes
  (( RUN_STATUS == 0 )) || fail "the uninstall with a command link failed: $RUN_OUTPUT"
  [[ -L "$root/usr/local/bin/freesnitch" ]] && fail "the uninstall left FreeSnitch's command link"
  expect_contains "$RUN_OUTPUT" "Removed $root/usr/local/bin/freesnitch" "command link removal message"

  local root2; root2="$(make_fake_root someone-elses-command)"
  mkdir -p "$root2/usr/local/bin"
  printf '#!/bin/sh\necho mine\n' >"$root2/usr/local/bin/freesnitch"
  run_uninstall someone-elses-command --yes
  unset FAKE_SIP FAKE_EXT_PRESENT FAKE_HELPER_RUNNING
  (( RUN_STATUS == 0 )) || fail "the uninstall next to a user's freesnitch file failed: $RUN_OUTPUT"
  [[ -f "$root2/usr/local/bin/freesnitch" ]] || fail "the uninstall deleted a freesnitch file it did not make"
  expect_contains "$RUN_OUTPUT" "Left $root2/usr/local/bin/freesnitch alone" "kept user file message"
}

# --- 4d. a symlinked database companion is refused before anything goes ----

test_refuses_symlinked_database_companion() {
  local root; root="$(make_fake_root symlinked-wal)"
  local target="$WORK/symlinked-wal/elsewhere"
  printf 'not FreeSnitch\n' >"$target"
  rm -f "$root/Library/Application Support/FreeSnitch/freesnitch.sqlite-wal"
  ln -s "$target" "$root/Library/Application Support/FreeSnitch/freesnitch.sqlite-wal"
  export FAKE_SIP=enabled FAKE_EXT_PRESENT=0 FAKE_HELPER_RUNNING=0
  run_uninstall symlinked-wal --yes --remove-database
  unset FAKE_SIP FAKE_EXT_PRESENT FAKE_HELPER_RUNNING
  (( RUN_STATUS != 0 )) || fail "the uninstall removed through a symlinked database companion"
  [[ "$(cat "$target")" == "not FreeSnitch" ]] || fail "the symlink target was changed"
  [[ -f "$root/Library/Application Support/FreeSnitch/freesnitch.sqlite" ]] \
    || fail "the database was deleted before the symlinked companion was refused"
}

# --- 4e. the app's own uninstall removes the same files ---------------------
#
# The Uninstall screen runs a fixed AppleScript, not this script. Its
# remove-database form must delete the same set of files (#237).

test_app_uninstall_removes_database_companions() {
  local src="$ROOT/Sources/GUI/App/PrivilegedUninstall.swift"
  local remove_form keep_form suffix
  remove_form="$(awk '/private static let removeDatabase = """/,/^    """$/' "$src")"
  keep_form="$(awk '/private static let keepDatabase = """/,/^    """$/' "$src")"
  [[ -n "$remove_form" && -n "$keep_form" ]] || { fail "could not read the app's uninstall scripts"; return; }
  for suffix in "" -wal -shm -journal; do
    expect_contains "$remove_form" "'/Library/Application Support/FreeSnitch/freesnitch.sqlite$suffix'" \
      "the app's remove-database uninstall does not delete freesnitch.sqlite$suffix"
  done
  expect_absent "$keep_form" "freesnitch.sqlite" "the app's keep-database uninstall touches the policy database"
  # A history folder that could not be deleted must fail the step, not be
  # dropped by a following command whose success becomes the result (#272).
  expect_contains "$remove_form" "/bin/rm -rf '/Library/Application Support/FreeSnitch/Insights' && " \
    "the app's remove-database uninstall goes on silently when the history could not be deleted"
}

# --- 4f. a failed step stops the app's uninstall ---------------------------
#
# The app's two forms used to join their steps with bare semicolons, so the
# script's exit status was the last command's: a pf flush that failed was
# hidden by a removal that worked, the uninstall reported success and the app
# went to the Trash with rules still loaded (#271). Each form runs here, as
# /bin/sh would run it, against a fake root with a pfctl stub that fails.

# The shell command inside one form, with every absolute path moved under a
# fake root and pfctl replaced by a stub.
app_uninstall_command() {
  local form="$1" root="$2" pfctl="$3"
  awk "/private static let $form = \"\"\"/,/^    \"\"\"\$/" "$ROOT/Sources/GUI/App/PrivilegedUninstall.swift" \
    | sed -e '1d' -e '$d' -e 's/^    //' -e 's/ \\$//' | tr -d '\n' \
    | sed -e 's/^do shell script "//' -e 's/" with administrator privileges$//' \
          -e "s#/sbin/pfctl#$pfctl#g" \
          -e "s#/etc/pf.anchors#$root/etc/pf.anchors#g" \
          -e "s#/Library/Application Support#$root/Library/Application Support#g" \
          -e "s#/usr/local/bin#$root/usr/local/bin#g" \
          -e "s#/Applications/FreeSnitch.app#$root/Applications/FreeSnitch.app#g"
}

test_app_uninstall_stops_at_failed_step() {
  local form failing root stubs cmd status expected
  for form in keepDatabase removeDatabase; do
    for failing in "-F all:82" "-f /dev/null:83"; do
      root="$WORK/app-$form-${failing%%:*}/root"; root="${root// /_}"
      stubs="$(dirname "$root")/stubs"
      expected="${failing##*:}"
      mkdir -p "$root/etc/pf.anchors" "$root/Library/Application Support/FreeSnitch/Insights" "$stubs"
      printf 'pass out all\n' >"$root/etc/pf.anchors/puresnitch"
      : >"$root/Library/Application Support/FreeSnitch/Insights/insights.sqlite"
      printf 'fake policy database\n' >"$root/Library/Application Support/FreeSnitch/freesnitch.sqlite"
      cat >"$stubs/pfctl" <<STUB
#!/bin/sh
printf 'pfctl %s\n' "\$*" >>"$stubs/stub.log"
case "\$*" in *"${failing%%:*}"*) echo "pfctl: DIOCXBEGIN: Operation not permitted" >&2; exit 1 ;; esac
exit 0
STUB
      chmod +x "$stubs/pfctl"
      cmd="$(app_uninstall_command "$form" "$root" "$stubs/pfctl")"
      [[ "$cmd" == *"$root/etc/pf.anchors/puresnitch"* && "$cmd" != *" /Library/"* && "$cmd" != *"/sbin/pfctl"* ]] \
        || { fail "could not move the app's $form uninstall onto a fake root"; continue; }
      status=0
      /bin/sh -c "$cmd" 2>/dev/null || status=$?
      [[ "$status" == "$expected" ]] \
        || fail "the app's $form uninstall exited $status, not $expected, when 'pfctl ${failing%%:*}' failed"
      [[ -f "$root/Library/Application Support/FreeSnitch/Insights/insights.sqlite" ]] \
        || fail "the app's $form uninstall went on to delete Insights after the pf step failed"
      [[ -f "$root/Library/Application Support/FreeSnitch/freesnitch.sqlite" ]] \
        || fail "the app's $form uninstall went on to delete the database after the pf step failed"
      grep -q 'uninstalled, so it holds no rules' "$root/etc/pf.anchors/puresnitch" \
        || fail "the app's $form uninstall did not empty the anchor file before flushing"
    done
    # And with every step working, the run succeeds and removes what it should.
    root="$WORK/app-$form-ok/root"; stubs="$(dirname "$root")/stubs"
    mkdir -p "$root/etc/pf.anchors" "$root/Library/Application Support/FreeSnitch/Insights" "$stubs"
    : >"$root/Library/Application Support/FreeSnitch/Insights/insights.sqlite"
    printf 'fake policy database\n' >"$root/Library/Application Support/FreeSnitch/freesnitch.sqlite"
    printf '#!/bin/sh\nexit 0\n' >"$stubs/pfctl"; chmod +x "$stubs/pfctl"
    cmd="$(app_uninstall_command "$form" "$root" "$stubs/pfctl")"
    status=0
    /bin/sh -c "$cmd" 2>/dev/null || status=$?
    [[ "$status" == 0 ]] || fail "the app's $form uninstall failed ($status) with every step working"
    [[ ! -e "$root/Library/Application Support/FreeSnitch/Insights" ]] \
      || fail "the app's $form uninstall left Insights behind"
    if [[ "$form" == removeDatabase ]]; then
      [[ ! -e "$root/Library/Application Support/FreeSnitch/freesnitch.sqlite" ]] \
        || fail "the app's removeDatabase uninstall left the database behind"
    else
      [[ -f "$root/Library/Application Support/FreeSnitch/freesnitch.sqlite" ]] \
        || fail "the app's keepDatabase uninstall deleted the database"
    fi
  done
  # A database that can't be deleted fails the run too, as the last step.
  root="$WORK/app-db-fail/root"; stubs="$(dirname "$root")/stubs"
  mkdir -p "$root/etc/pf.anchors" "$root/Library/Application Support/FreeSnitch" "$stubs"
  printf '#!/bin/sh\nexit 0\n' >"$stubs/pfctl"; chmod +x "$stubs/pfctl"
  printf 'fake policy database\n' >"$root/Library/Application Support/FreeSnitch/freesnitch.sqlite"
  chmod 555 "$root/Library/Application Support/FreeSnitch"
  cmd="$(app_uninstall_command removeDatabase "$root" "$stubs/pfctl")"
  status=0
  /bin/sh -c "$cmd" 2>/dev/null || status=$?
  chmod 755 "$root/Library/Application Support/FreeSnitch"
  [[ "$status" == 86 ]] || fail "the app's removeDatabase uninstall exited $status, not 86, when the database could not be deleted"
  # Every exit code the scripts use names a step the Uninstall screen can show.
  local code
  for code in $(grep -o 'exit [0-9][0-9]*' "$ROOT/Sources/GUI/App/PrivilegedUninstall.swift" | awk '{print $2}' | sort -u); do
    grep -Eq "case [a-zA-Z]+ = $code\$" "$ROOT/Sources/GUI/App/PrivilegedUninstall.swift" \
      || fail "exit $code in the app's uninstall has no Step the screen can name"
  done
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
test_stopped_extension_record
test_unknown_extension_state
test_flushes_only_named_anchor
test_refuses_symlinked_anchor
test_command_link
test_refuses_symlinked_database_companion
test_app_uninstall_removes_database_companions
test_app_uninstall_stops_at_failed_step
test_never_touched_the_real_system

if (( failures > 0 )); then
  printf 'uninstall safety verification: FAIL (%d)\n' "$failures"
  exit 1
fi
printf 'uninstall safety verification: PASS\n'
