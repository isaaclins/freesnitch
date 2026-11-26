#!/usr/bin/env bash
# Remove the pre-FreeSnitch installation without touching FreeSnitch state.
set -euo pipefail

readonly TEAM_ID="BHAF4L4726"
readonly OLD_APP_BUNDLE_ID="io.isaaclins.puresnitch"
readonly OLD_NETEXT_BUNDLE_ID="io.isaaclins.puresnitch.netext"
readonly OLD_HELPER_LABEL="io.isaaclins.puresnitch.helper"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

# Scripts/test_uninstall_puresnitch.sh runs this script against a fake root
# with stub tools. Outside a test root every path and tool is the real one.
TEST_ROOT="${PURESNITCH_UNINSTALL_TEST_ROOT:-}"
if [[ -n "$TEST_ROOT" ]]; then
  [[ "$TEST_ROOT" == /* && "$TEST_ROOT" != */ && -d "$TEST_ROOT" ]] \
    || die "the test root must be an existing absolute directory without a trailing slash: $TEST_ROOT"
  case "$TEST_ROOT" in
    /|/Applications|/Library|/System|/usr|/bin|/sbin|/etc|/var|/Users|/opt|/private)
      die "refusing a system path as the test root: $TEST_ROOT"
      ;;
  esac
  LAUNCHCTL="${PURESNITCH_LAUNCHCTL:-launchctl}"
  SYSTEMEXTENSIONSCTL="${PURESNITCH_SYSTEMEXTENSIONSCTL:-systemextensionsctl}"
  CONFIRM_DELAY=0
else
  LAUNCHCTL="launchctl"
  SYSTEMEXTENSIONSCTL="systemextensionsctl"
  CONFIRM_DELAY=1
fi
readonly TEST_ROOT LAUNCHCTL SYSTEMEXTENSIONSCTL CONFIRM_DELAY

readonly OLD_APP="${TEST_ROOT}/Applications/PureSnitch.app"
readonly OLD_DAEMON_PLIST="${TEST_ROOT}/Library/LaunchDaemons/${OLD_HELPER_LABEL}.plist"

if [[ -z "${HOME:-}" || "${HOME:-}" != /* ]]; then
  printf 'ERROR: HOME must be a non-empty absolute path.\n' >&2
  exit 1
fi

readonly OLD_USER_SUPPORT="${HOME}/Library/Application Support/PureSnitch"
readonly OLD_APP_GROUP="BHAF4L4726.io.isaaclins.puresnitch"
readonly OLD_APP_GROUP_PATH="${HOME}/Library/Group Containers/${OLD_APP_GROUP}"

remove_user_data=0

usage() {
  cat <<'EOF'
Usage: Scripts/uninstall_puresnitch.sh [--remove-user-data]

Deactivates the old PureSnitch system extension, unloads its helper daemon,
and removes /Applications/PureSnitch.app. Legacy user data and the old app
 group are reported but retained unless --remove-user-data is supplied.

The script never modifies FreeSnitch bundles, identifiers, app-group data,
or Application Support directories.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --remove-user-data)
      remove_user_data=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

if [[ -n "$TEST_ROOT" ]] || (( EUID == 0 )); then
  run_privileged() {
    "$@"
  }
else
  run_privileged() {
    sudo "$@"
  }
fi

assert_old_path() {
  local path="$1"
  [[ -n "$path" ]] || die "refusing to operate on an empty path"
  case "$path" in
    *io.isaaclins.freesnitch*|*FreeSnitch*)
      die "refusing to touch a FreeSnitch path: $path"
      ;;
  esac
  case "$path" in
    "$OLD_APP"|"$OLD_DAEMON_PLIST"|"$OLD_USER_SUPPORT"|"$OLD_APP_GROUP_PATH")
      ;;
    *)
      die "refusing to operate on an unexpected path: $path"
      ;;
  esac
}

report_path() {
  local path="$1"
  assert_old_path "$path"
  if [[ -e "$path" || -L "$path" ]]; then
    printf 'Legacy data found at %s\n' "$path"
    du -sh -- "$path" 2>/dev/null || true
  else
    printf 'Legacy path is not present: %s\n' "$path"
  fi
}

remove_directory() {
  local path="$1"
  assert_old_path "$path"
  if [[ -e "$path" || -L "$path" ]]; then
    printf 'Removing legacy directory %s\n' "$path"
    run_privileged rm -rf -- "$path"
  else
    printf 'Legacy directory already absent: %s\n' "$path"
  fi
}

printf 'Removing the pre-FreeSnitch installation only.\n'
printf 'FreeSnitch paths are never modified by this script.\n'

if command -v "$SYSTEMEXTENSIONSCTL" >/dev/null 2>&1; then
  printf 'Requesting uninstall of system extension %s.\n' "$OLD_NETEXT_BUNDLE_ID"
  if run_privileged "$SYSTEMEXTENSIONSCTL" uninstall "$TEAM_ID" "$OLD_NETEXT_BUNDLE_ID" >/dev/null 2>&1; then
    printf 'Uninstall request accepted for %s; removal is not complete yet.\n' "$OLD_NETEXT_BUNDLE_ID"
  else
    printf 'systemextensionsctl cannot remove a system extension while System Integrity Protection is enabled; this is expected on a normal macOS installation.\n'
    printf 'After the containing app is deleted, macOS removes the orphaned system extension, typically completing on reboot.\n'
    printf 'You can also remove it under System Settings > General > Login Items and Extensions > Network Extensions.\n'
  fi
  printf 'A reboot is required to finish system extension removal; this script does not reboot.\n'
else
  printf 'systemextensionsctl is unavailable; no system extension was changed.\n'
fi

# What launchd says about the old helper right now: loaded, absent, or unknown
# when launchctl could not be asked or gave an answer that says neither.
HELPER_STATE=""
read_helper_state() {
  HELPER_STATE="unknown"
  command -v "$LAUNCHCTL" >/dev/null 2>&1 || return 0
  local output status
  set +e
  output="$(run_privileged "$LAUNCHCTL" print "system/${OLD_HELPER_LABEL}" 2>&1)"
  status=$?
  set -e
  if (( status == 0 )); then
    HELPER_STATE="loaded"
  elif (( status == 113 )) || [[ "$output" == *"Could not find service"* ]]; then
    HELPER_STATE="absent"
  fi
}

# The plist and the app are what a user needs to find and stop a running root
# daemon, so neither is removed until launchd confirms the helper is gone
# (#262). A bootout can take a moment to finish, so a loaded answer is asked
# again a few times; an unknown answer is never taken as stopped.
require_helper_stopped() {
  local attempt
  for attempt in 1 2 3 4 5; do
    read_helper_state
    [[ "$HELPER_STATE" == "loaded" ]] || break
    if (( attempt < 5 )); then
      sleep "$CONFIRM_DELAY"
    fi
  done
  case "$HELPER_STATE" in
    absent)
      printf 'Confirmed LaunchDaemon %s is not loaded.\n' "$OLD_HELPER_LABEL"
      ;;
    loaded)
      die "LaunchDaemon ${OLD_HELPER_LABEL} is still loaded, so ${OLD_DAEMON_PLIST} and ${OLD_APP} were left in place. Stop it with 'sudo launchctl bootout system/${OLD_HELPER_LABEL}', check that 'sudo launchctl print system/${OLD_HELPER_LABEL}' says it could not find the service, then run this script again."
      ;;
    *)
      die "could not confirm that LaunchDaemon ${OLD_HELPER_LABEL} is stopped, so ${OLD_DAEMON_PLIST} and ${OLD_APP} were left in place. Check with 'sudo launchctl print system/${OLD_HELPER_LABEL}'. If it is still listed, stop it with 'sudo launchctl bootout system/${OLD_HELPER_LABEL}'. Once print says it could not find the service, run this script again."
      ;;
  esac
}

assert_old_path "$OLD_DAEMON_PLIST"
printf 'Unloading LaunchDaemon %s.\n' "$OLD_HELPER_LABEL"
if run_privileged "$LAUNCHCTL" bootout system "$OLD_DAEMON_PLIST"; then
  printf 'launchctl accepted the unload from the plist.\n'
elif run_privileged "$LAUNCHCTL" bootout "system/${OLD_HELPER_LABEL}"; then
  printf 'launchctl accepted the unload by label.\n'
else
  printf 'launchctl did not unload the LaunchDaemon; checking whether it is loaded at all.\n'
fi
require_helper_stopped
if [[ -e "$OLD_DAEMON_PLIST" || -L "$OLD_DAEMON_PLIST" ]]; then
  run_privileged rm -f -- "$OLD_DAEMON_PLIST"
  printf 'Removed %s.\n' "$OLD_DAEMON_PLIST"
else
  printf 'Legacy LaunchDaemon plist is already absent: %s\n' "$OLD_DAEMON_PLIST"
fi

assert_old_path "$OLD_APP"
if [[ -e "$OLD_APP" || -L "$OLD_APP" ]]; then
  printf 'Removing %s.\n' "$OLD_APP"
  run_privileged rm -rf -- "$OLD_APP"
else
  printf 'Legacy application is already absent: %s\n' "$OLD_APP"
fi

report_path "$OLD_USER_SUPPORT"
report_path "$OLD_APP_GROUP_PATH"
if (( remove_user_data == 1 )); then
  remove_directory "$OLD_USER_SUPPORT"
  remove_directory "$OLD_APP_GROUP_PATH"
else
  printf 'Leaving legacy user data untouched. Pass --remove-user-data to remove only the two reported paths.\n'
fi

printf 'The legacy PF anchor name puresnitch is intentionally not modified; FreeSnitch reuses it so active firewall rules are not stranded.\n'
printf 'Migration complete. Reboot if macOS reports that system extension removal is pending.\n'
