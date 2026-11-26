#!/usr/bin/env bash
# Regression gate for #262: Scripts/uninstall_puresnitch.sh must not delete the
# old helper's LaunchDaemon plist or PureSnitch.app unless launchd confirms the
# helper is gone. A helper that would not stop, or a launchd answer that says
# nothing, aborts the teardown with a recovery instruction and leaves both.
#
# Everything runs against a FAKE root with stub tools. Nothing here touches the
# real /Applications, /Library, launchd or system extensions.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UNINSTALL="$ROOT/Scripts/uninstall_puresnitch.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/puresnitch-uninstall-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

failures=0
fail() {
  printf 'PURESNITCH UNINSTALL TEST FAILED: %s\n' "$*" >&2
  failures=$((failures + 1))
}

LABEL="io.isaaclins.puresnitch.helper"

# One case: a fake root with the old plist and app, a stub launchctl whose
# bootout and print answers come from FAKE_* variables, and the script's exit
# status and output.
RUN_STATUS=0
RUN_OUTPUT=""
CASE_ROOT=""
run_case() {
  local name="$1"; shift
  local dir="$WORK/$name"
  CASE_ROOT="$dir/root"
  mkdir -p "$CASE_ROOT/Applications/PureSnitch.app/Contents" "$CASE_ROOT/Library/LaunchDaemons" "$dir/home" "$dir/stubs"
  : >"$CASE_ROOT/Library/LaunchDaemons/$LABEL.plist"
  : >"$CASE_ROOT/Applications/PureSnitch.app/Contents/Info.plist"

  cat >"$dir/stubs/launchctl" <<'STUB'
#!/usr/bin/env bash
printf 'launchctl %s\n' "$*" >>"$STUB_LOG"
case "${1:-}" in
  bootout)
    exit "${FAKE_BOOTOUT_STATUS:-0}"
    ;;
  print)
    # FAKE_PRINT is a space-separated list of answers, one per call; the last
    # one repeats. loaded = exit 0, absent = exit 113 like launchd, other =
    # an error that says nothing about the service.
    count_file="$STUB_LOG.print"
    n=$(( $(cat "$count_file" 2>/dev/null || echo 0) + 1 ))
    printf '%s\n' "$n" >"$count_file"
    read -r -a answers <<<"${FAKE_PRINT:-absent}"
    i=$(( n <= ${#answers[@]} ? n - 1 : ${#answers[@]} - 1 ))
    case "${answers[$i]}" in
      loaded)
        printf 'system/io.isaaclins.puresnitch.helper = {\n\tstate = running\n}\n'
        exit 0
        ;;
      absent)
        printf 'Could not find service "io.isaaclins.puresnitch.helper" in domain for system\n' >&2
        exit 113
        ;;
      *)
        printf 'Unrecognized target specifier.\n' >&2
        exit 1
        ;;
    esac
    ;;
esac
exit 0
STUB
  cat >"$dir/stubs/systemextensionsctl" <<'STUB'
#!/usr/bin/env bash
printf 'At this time, this tool cannot be used if System Integrity Protection is enabled.\n'
exit 1
STUB
  chmod +x "$dir/stubs/launchctl" "$dir/stubs/systemextensionsctl"

  export STUB_LOG="$dir/stub.log"
  : >"$STUB_LOG"
  set +e
  RUN_OUTPUT="$(env "$@" \
    HOME="$dir/home" \
    STUB_LOG="$STUB_LOG" \
    PURESNITCH_UNINSTALL_TEST_ROOT="$CASE_ROOT" \
    PURESNITCH_LAUNCHCTL="$dir/stubs/launchctl" \
    PURESNITCH_SYSTEMEXTENSIONSCTL="$dir/stubs/systemextensionsctl" \
    bash "$UNINSTALL" 2>&1)"
  RUN_STATUS=$?
  set -e
}

plist_present() { [[ -e "$CASE_ROOT/Library/LaunchDaemons/$LABEL.plist" ]]; }
app_present() { [[ -e "$CASE_ROOT/Applications/PureSnitch.app" ]]; }

expect_kept() {
  local name="$1"
  (( RUN_STATUS != 0 )) || fail "$name: the script exited 0"
  plist_present || fail "$name: the LaunchDaemon plist was deleted"
  app_present || fail "$name: PureSnitch.app was deleted"
  [[ "$RUN_OUTPUT" == *"launchctl bootout system/$LABEL"* ]] \
    || fail "$name: no recovery instruction in: $RUN_OUTPUT"
  [[ "$RUN_OUTPUT" == *"left in place"* ]] || fail "$name: it did not say what was kept"
}

expect_removed() {
  local name="$1"
  (( RUN_STATUS == 0 )) || fail "$name: exited $RUN_STATUS: $RUN_OUTPUT"
  plist_present && fail "$name: the LaunchDaemon plist was kept"
  app_present && fail "$name: PureSnitch.app was kept"
  [[ "$RUN_OUTPUT" == *"Confirmed LaunchDaemon $LABEL is not loaded."* ]] \
    || fail "$name: no confirmation in: $RUN_OUTPUT"
}

# 1. The issue's case: both bootout forms fail and the helper is still loaded.
run_case bootout-fails-still-loaded FAKE_BOOTOUT_STATUS=5 FAKE_PRINT=loaded
expect_kept "both bootouts fail, helper still loaded"
grep -q '^launchctl bootout system .*\.plist$' "$STUB_LOG" || fail "the plist form of bootout was not tried"
grep -q "^launchctl bootout system/$LABEL$" "$STUB_LOG" || fail "the label form of bootout was not tried"

# 2. bootout says it worked but launchd still has the service after every retry.
run_case bootout-ok-still-loaded FAKE_BOOTOUT_STATUS=0 FAKE_PRINT=loaded
expect_kept "bootout succeeds but the helper stays loaded"
[[ "$(grep -c '^launchctl print' "$STUB_LOG")" -ge 2 ]] || fail "a loaded answer was not asked again"

# 3. launchctl print gives an answer that says neither loaded nor absent.
run_case state-unknown FAKE_BOOTOUT_STATUS=5 FAKE_PRINT=error
expect_kept "the helper's state cannot be read"
[[ "$RUN_OUTPUT" == *"could not confirm"* ]] || fail "unknown state: it did not say it could not confirm"

# 4. Both bootouts fail because the helper was never loaded: nothing to stop,
#    so the leftovers are removed.
run_case not-loaded FAKE_BOOTOUT_STATUS=5 FAKE_PRINT=absent
expect_removed "the helper was not loaded"

# 5. The normal path: bootout works and launchd confirms the helper is gone.
run_case normal FAKE_BOOTOUT_STATUS=0 FAKE_PRINT=absent
expect_removed "normal uninstall"

# 6. launchd still finishes the bootout on the first check, then lets go.
run_case slow-bootout FAKE_BOOTOUT_STATUS=0 "FAKE_PRINT=loaded loaded absent"
expect_removed "bootout that takes a moment"

if (( failures > 0 )); then
  printf 'uninstall_puresnitch: %d check(s) failed\n' "$failures" >&2
  exit 1
fi
printf 'uninstall_puresnitch: PASS: the plist and app are only removed once launchd confirms the old helper is gone\n'
