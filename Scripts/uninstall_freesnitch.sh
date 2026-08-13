#!/usr/bin/env bash
# Remove the current FreeSnitch installation without touching legacy PureSnitch data.
set -euo pipefail

readonly TEAM_ID="BHAF4L4726"
readonly APP_BUNDLE_ID="io.isaaclins.freesnitch"
readonly NETEXT_BUNDLE_ID="io.isaaclins.freesnitch.netext"
readonly HELPER_LABEL="io.isaaclins.freesnitch.helper"
readonly APP="/Applications/FreeSnitch.app"
readonly SUPPORT="/Library/Application Support/FreeSnitch"
readonly INSIGHTS="${SUPPORT}/Insights"
readonly HELPER_PLIST="${APP}/Contents/Library/LaunchDaemons/${HELPER_LABEL}.plist"
readonly PFCTL="/sbin/pfctl"
readonly PF_ANCHOR="/etc/pf.anchors/puresnitch"

assume_yes=0

usage() {
  cat <<'EOF'
Usage: Scripts/uninstall_freesnitch.sh [--yes]

Deactivates the current FreeSnitch system extension and helper, flushes the
reused puresnitch PF anchor, removes the FreeSnitch app and root Insights data,
and leaves the legacy PureSnitch user data untouched. The shared FreeSnitch
support directory and freesnitch.sqlite are retained.

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

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes)
      assume_yes=1
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

if (( assume_yes == 0 )); then
  printf 'This removes the current FreeSnitch app and root Insights data. Continue? [y/N] '
  read -r answer
  [[ "$answer" == "y" || "$answer" == "Y" ]] || { log 'Uninstall cancelled.'; exit 0; }
fi

if (( EUID == 0 )); then
  run_privileged() { "$@"; }
else
  run_privileged() { sudo "$@"; }
fi

assert_exact_path() {
  local path="$1"
  [[ -n "$path" && "$path" == /* ]] || die "refusing a non-absolute path: $path"
  case "$path" in
    "$APP"|"$SUPPORT"|"$INSIGHTS"|"$HELPER_PLIST"|"$PF_ANCHOR") ;;
    *) die "refusing an unexpected uninstall path: $path" ;;
  esac
}

# Keep the guard literal and separate from the variable names. This makes a
# future path edit fail closed rather than broadening rm -rf accidentally.
assert_fixed_paths() {
  [[ "$APP" == "/Applications/FreeSnitch.app" ]] || die "FreeSnitch app guard changed"
  [[ "$SUPPORT" == "/Library/Application Support/FreeSnitch" ]] || die "FreeSnitch support guard changed"
  [[ "$INSIGHTS" == "/Library/Application Support/FreeSnitch/Insights" ]] || die "Insights guard changed"
  [[ "$HELPER_PLIST" == "/Applications/FreeSnitch.app/Contents/Library/LaunchDaemons/io.isaaclins.freesnitch.helper.plist" ]] || die "helper plist guard changed"
  [[ "$APP_BUNDLE_ID" == "io.isaaclins.freesnitch" && "$NETEXT_BUNDLE_ID" == "io.isaaclins.freesnitch.netext" ]] || die "bundle identifier guard changed"
  [[ "$HELPER_LABEL" == "io.isaaclins.freesnitch.helper" ]] || die "helper label guard changed"
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

assert_fixed_paths

# Never remove the app or its helper while the privileged service is still
# running from that bundle.
if command -v launchctl >/dev/null 2>&1 && [[ -e "$HELPER_PLIST" ]]; then
  if run_privileged launchctl bootout system "$HELPER_PLIST" >/dev/null 2>&1; then
    log "Deactivated helper $HELPER_LABEL."
  elif run_privileged launchctl bootout "system/${HELPER_LABEL}" >/dev/null 2>&1; then
    log "Deactivated helper $HELPER_LABEL by label."
  else
    log "Helper was not running or launchctl could not deactivate it. Continuing with exact-path removal."
  fi
fi

if command -v systemextensionsctl >/dev/null 2>&1; then
  if run_privileged systemextensionsctl uninstall "$TEAM_ID" "$NETEXT_BUNDLE_ID" >/dev/null 2>&1; then
    log "Requested deactivation of system extension $NETEXT_BUNDLE_ID."
  else
    log "System extension deactivation was not accepted. Finish it in System Settings before reinstalling FreeSnitch."
  fi
else
  log "systemextensionsctl is unavailable. No system extension deactivation was attempted."
fi

# FreeSnitch intentionally reuses this old anchor name. Flush the exact anchor
# before removing the app and store; never disable PF globally or leave rules
# active with the anchor file gone.
[[ -x "$PFCTL" ]] || die "$PFCTL is unavailable; refusing to remove FreeSnitch while the reused PF anchor cannot be flushed"
if ! run_privileged "$PFCTL" -a puresnitch -F all >/dev/null 2>&1 \
   || ! run_privileged "$PFCTL" -a puresnitch -f /dev/null >/dev/null 2>&1; then
  die "could not flush and disable the reused puresnitch PF anchor; run '$PFCTL -a puresnitch -F all' and '$PFCTL -a puresnitch -f /dev/null', then rerun with --yes"
fi
log "Flushed the reused puresnitch PF anchor. The empty anchor file is retained because pf.conf still references it."

safe_remove_directory "$INSIGHTS"
safe_remove_directory "$APP"
log "FreeSnitch uninstall complete. Legacy PureSnitch user data was not touched."
