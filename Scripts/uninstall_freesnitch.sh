#!/usr/bin/env bash
# Remove the current FreeSnitch installation without touching legacy PureSnitch data.
#
# This script finishes an uninstall; it cannot start one. Under System
# Integrity Protection, which is the default, `systemextensionsctl uninstall`
# refuses to run even as root, so the app itself is the only component macOS
# lets deactivate the system extension. Do that first in FreeSnitch under
# Settings > Uninstall, then run this.
#
# Everything here is a deliberate, user-initiated teardown. Nothing in this
# script is a repair path: it is never correct to run any of it to fix a
# misbehaving helper (see #24, where unregistering the helper as a repair
# removed the service).
set -euo pipefail

# Test seam. Scripts/test_uninstall_safety.sh sources this file with a fake
# root so the guards can be exercised without ever touching the real
# /Applications, /Library, launchd, or pf. The overrides below are honoured
# only when that fake root is set, so a stray environment variable cannot
# redirect pfctl or launchctl during a real uninstall.
readonly TEST_ROOT="${FREESNITCH_UNINSTALL_TEST_ROOT:-}"

readonly TEAM_ID="BHAF4L4726"
readonly APP_BUNDLE_ID="io.isaaclins.freesnitch"
readonly NETEXT_BUNDLE_ID="io.isaaclins.freesnitch.netext"
readonly HELPER_LABEL="io.isaaclins.freesnitch.helper"
readonly APP="${TEST_ROOT}/Applications/FreeSnitch.app"
readonly SUPPORT="${TEST_ROOT}/Library/Application Support/FreeSnitch"
readonly INSIGHTS="${SUPPORT}/Insights"
readonly DATABASE="${SUPPORT}/freesnitch.sqlite"
readonly HELPER_PLIST="${APP}/Contents/Library/LaunchDaemons/${HELPER_LABEL}.plist"
readonly PF_ANCHOR="${TEST_ROOT}/etc/pf.anchors/puresnitch"

assume_yes=0
remove_database=0

usage() {
  cat <<'EOF'
Usage: Scripts/uninstall_freesnitch.sh [--yes] [--remove-database]

Finishes a FreeSnitch uninstall: flushes the reused puresnitch PF anchor,
removes the FreeSnitch app and the root Insights data, and leaves the legacy
PureSnitch user data untouched.

Deactivate the system extension FIRST, in FreeSnitch under Settings >
Uninstall. `systemextensionsctl uninstall` cannot do it while System Integrity
Protection is enabled, which is the default, so this script refuses to remove
the app while macOS still holds a record for the extension. Deactivation
usually completes only after a restart.

  --yes                Do not prompt for confirmation.
  --remove-database    Also delete freesnitch.sqlite, which holds your rules,
                       profiles and blocklists. It can exceed 300 MB. Without
                       this flag the database is kept and a later reinstall
                       picks it up again.

The puresnitch anchor file is intentionally retained empty because pf.conf
still references that established anchor. This avoids stranding a live PF
configuration. Refuse the uninstall if the anchor cannot be flushed safely.
EOF
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '%s\n' "$*"
}

# A fake root must be an obviously disposable absolute directory. Anything that
# could resolve to a real system location is refused before a single path is
# derived from it.
assert_test_root() {
  local root="$1"
  [[ "$root" == /* ]] || die "the test root must be an absolute path: $root"
  [[ "$root" != */ ]] || die "the test root must not end in a slash: $root"
  [[ -d "$root" ]] || die "the test root does not exist: $root"
  case "$root" in
    /|/Applications|/Library|/System|/usr|/bin|/sbin|/etc|/var|/Users|/opt|/private)
      die "refusing a system path as the test root: $root"
      ;;
  esac
  [[ "$root" == */* && "${root#/}" == */* ]] || die "refusing a top-level test root: $root"
}

if [[ -n "$TEST_ROOT" ]]; then
  assert_test_root "$TEST_ROOT"
  PFCTL="${FREESNITCH_PFCTL:-/sbin/pfctl}"
  SYSTEMEXTENSIONSCTL="${FREESNITCH_SYSTEMEXTENSIONSCTL:-systemextensionsctl}"
  LAUNCHCTL="${FREESNITCH_LAUNCHCTL:-launchctl}"
  CSRUTIL="${FREESNITCH_CSRUTIL:-csrutil}"
else
  PFCTL="/sbin/pfctl"
  SYSTEMEXTENSIONSCTL="systemextensionsctl"
  LAUNCHCTL="launchctl"
  CSRUTIL="csrutil"
fi
readonly PFCTL SYSTEMEXTENSIONSCTL LAUNCHCTL CSRUTIL

parse_arguments() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --yes)
        assume_yes=1
        shift
        ;;
      --remove-database)
        remove_database=1
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
}

confirm() {
  (( assume_yes == 0 )) || return 0
  if (( remove_database == 1 )); then
    printf 'This removes the FreeSnitch app, the root Insights data, AND %s with all your rules. Continue? [y/N] ' "$DATABASE"
  else
    printf 'This removes the FreeSnitch app and root Insights data. %s is kept. Continue? [y/N] ' "$DATABASE"
  fi
  read -r answer
  [[ "$answer" == "y" || "$answer" == "Y" ]] || { log 'Uninstall cancelled.'; exit 0; }
}

if (( EUID == 0 )); then
  run_privileged() { "$@"; }
else
  run_privileged() { sudo "$@"; }
fi

# In a test root nothing may escalate: a guard test must never be able to ask
# the real system for privileges.
if [[ -n "$TEST_ROOT" ]]; then
  run_privileged() { "$@"; }
fi

assert_exact_path() {
  local path="$1"
  [[ -n "$path" && "$path" == /* ]] || die "refusing a non-absolute path: $path"
  case "$path" in
    "$APP"|"$SUPPORT"|"$INSIGHTS"|"$DATABASE"|"$HELPER_PLIST"|"$PF_ANCHOR") ;;
    *) die "refusing an unexpected uninstall path: $path" ;;
  esac
}

# Keep the guard literal and separate from the variable names. This makes a
# future path edit fail closed rather than broadening rm -rf accidentally. Each
# path is compared with the test root stripped, so with no test root these are
# the same literal assertions as before.
assert_fixed_paths() {
  [[ "${APP#"$TEST_ROOT"}" == "/Applications/FreeSnitch.app" ]] || die "FreeSnitch app guard changed"
  [[ "${SUPPORT#"$TEST_ROOT"}" == "/Library/Application Support/FreeSnitch" ]] || die "FreeSnitch support guard changed"
  [[ "${INSIGHTS#"$TEST_ROOT"}" == "/Library/Application Support/FreeSnitch/Insights" ]] || die "Insights guard changed"
  [[ "${DATABASE#"$TEST_ROOT"}" == "/Library/Application Support/FreeSnitch/freesnitch.sqlite" ]] || die "policy database guard changed"
  [[ "${HELPER_PLIST#"$TEST_ROOT"}" == "/Applications/FreeSnitch.app/Contents/Library/LaunchDaemons/io.isaaclins.freesnitch.helper.plist" ]] || die "helper plist guard changed"
  [[ "${PF_ANCHOR#"$TEST_ROOT"}" == "/etc/pf.anchors/puresnitch" ]] || die "PF anchor guard changed"
  [[ "$APP_BUNDLE_ID" == "io.isaaclins.freesnitch" && "$NETEXT_BUNDLE_ID" == "io.isaaclins.freesnitch.netext" ]] || die "bundle identifier guard changed"
  [[ "$HELPER_LABEL" == "io.isaaclins.freesnitch.helper" ]] || die "helper label guard changed"
  [[ "$TEAM_ID" == "BHAF4L4726" ]] || die "team identifier guard changed"
}

safe_remove_directory() {
  local path="$1"
  assert_exact_path "$path"
  [[ "$path" == "$INSIGHTS" || "$path" == "$APP" ]] || die "refusing to remove a non-removable path: $path"
  [[ -L "$path" ]] && die "refusing to remove a symlink: $path"
  if [[ -e "$path" ]]; then
    run_privileged rm -rf -- "$path"
    log "Removed $path"
  else
    log "Path already absent: $path"
  fi
}

safe_remove_database() {
  local path="$DATABASE"
  assert_exact_path "$path"
  [[ "$path" == "$DATABASE" ]] || die "refusing to remove a non-removable path: $path"
  [[ -L "$path" ]] && die "refusing to remove a symlink: $path"
  if [[ -e "$path" ]]; then
    run_privileged rm -f -- "$path"
    log "Removed $path"
  else
    log "Path already absent: $path"
  fi
}

sip_enabled() {
  command -v "$CSRUTIL" >/dev/null 2>&1 || return 1
  local status
  status="$("$CSRUTIL" status 2>/dev/null || true)"
  [[ "$status" == *"status: enabled"* ]]
}

# Ask macOS, do not infer. An empty answer from a tool that failed is not
# evidence that the record is gone, so the caller treats "cannot tell" as
# "still registered".
extension_record_present() {
  local listing
  listing="$("$SYSTEMEXTENSIONSCTL" list 2>/dev/null || true)"
  [[ "$listing" == *"$NETEXT_BUNDLE_ID"* ]]
}

# Best effort only, and it never claims the extension was removed. Under SIP
# this cannot work at all, which is precisely why the app owns deactivation.
attempt_extension_deactivation() {
  if ! command -v "$SYSTEMEXTENSIONSCTL" >/dev/null 2>&1; then
    log "systemextensionsctl is unavailable, so the system extension state cannot be read here."
    return 0
  fi

  if sip_enabled; then
    log "System Integrity Protection is enabled, so systemextensionsctl cannot uninstall $NETEXT_BUNDLE_ID. Deactivate it in FreeSnitch under Settings > Uninstall; the app is the only component macOS permits to do this."
    return 0
  fi

  local output
  output="$(run_privileged "$SYSTEMEXTENSIONSCTL" uninstall "$TEAM_ID" "$NETEXT_BUNDLE_ID" 2>&1 || true)"
  if [[ "$output" == *"System Integrity Protection"* ]]; then
    log "systemextensionsctl refused: System Integrity Protection is enabled. Nothing was deactivated. Deactivate the extension in FreeSnitch under Settings > Uninstall."
    return 0
  fi
  log "Asked systemextensionsctl to deactivate $NETEXT_BUNDLE_ID. Whether the record is gone is verified below, not assumed."
}

require_extension_unregistered() {
  if ! command -v "$SYSTEMEXTENSIONSCTL" >/dev/null 2>&1; then
    die "cannot verify whether $NETEXT_BUNDLE_ID is still registered, so the app is left in place. Removing it now could strand an extension record whose bundle is gone."
  fi
  if extension_record_present; then
    die "macOS still holds a record for $NETEXT_BUNDLE_ID, so the app is left in place. Removing it now would strand an extension record whose bundle is gone. Deactivate the extension in FreeSnitch under Settings > Uninstall, restart the Mac, then rerun this script."
  fi
  log "No system extension record for $NETEXT_BUNDLE_ID remains."
}

# A deliberate uninstall may stop the service the user asked to remove. This is
# NOT the repair path and must never be reused as one: #24 exists because
# removing the service to fix something removed the service.
deactivate_helper_for_uninstall() {
  command -v "$LAUNCHCTL" >/dev/null 2>&1 || return 0
  [[ -e "$HELPER_PLIST" ]] || return 0
  if run_privileged "$LAUNCHCTL" bootout system "$HELPER_PLIST" >/dev/null 2>&1; then
    log "Stopped helper $HELPER_LABEL as part of this uninstall."
  elif run_privileged "$LAUNCHCTL" bootout "system/${HELPER_LABEL}" >/dev/null 2>&1; then
    log "Stopped helper $HELPER_LABEL by label as part of this uninstall."
  else
    log "Helper was not running, or launchctl could not stop it."
  fi
}

helper_running_from_bundle() {
  command -v "$LAUNCHCTL" >/dev/null 2>&1 || return 1
  local output
  output="$(run_privileged "$LAUNCHCTL" print "system/${HELPER_LABEL}" 2>/dev/null || true)"
  [[ -n "$output" ]] || return 1
  [[ "$output" == *"${APP}/"* ]]
}

require_helper_not_running_from_bundle() {
  if helper_running_from_bundle; then
    die "the privileged helper is still running from ${APP}. Removing the bundle underneath a live root daemon is refused. Switch FreeSnitch off in System Settings > General > Login Items & Extensions, or run 'launchctl bootout system/${HELPER_LABEL}' as root, then rerun this script."
  fi
}

# FreeSnitch intentionally reuses this old anchor name. Flush the exact anchor
# before removing the app and store; never disable PF globally or leave rules
# active with the anchor file gone.
flush_pf_anchor() {
  [[ -x "$PFCTL" ]] || die "$PFCTL is unavailable; refusing to remove FreeSnitch while the reused PF anchor cannot be flushed"
  if ! run_privileged "$PFCTL" -a puresnitch -F all >/dev/null 2>&1 \
     || ! run_privileged "$PFCTL" -a puresnitch -f /dev/null >/dev/null 2>&1; then
    die "could not flush and disable the reused puresnitch PF anchor; run '$PFCTL -a puresnitch -F all' and '$PFCTL -a puresnitch -f /dev/null', then rerun with --yes"
  fi
  log "Flushed the reused puresnitch PF anchor. The empty anchor file is retained because pf.conf still references it."
}

main() {
  parse_arguments "$@"
  confirm
  assert_fixed_paths

  attempt_extension_deactivation
  require_extension_unregistered

  deactivate_helper_for_uninstall
  require_helper_not_running_from_bundle

  flush_pf_anchor

  safe_remove_directory "$INSIGHTS"
  if (( remove_database == 1 )); then
    safe_remove_database
  else
    log "Kept $DATABASE with your rules, profiles and blocklists. Rerun with --remove-database to delete it."
  fi
  safe_remove_directory "$APP"
  log "FreeSnitch uninstall complete. Legacy PureSnitch user data was not touched."
}

# Sourcing this file defines the guards without running them, which is how the
# safety test exercises them against a fake root.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
