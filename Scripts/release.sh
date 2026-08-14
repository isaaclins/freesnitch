#!/usr/bin/env bash
# Build, sign, notarize, publish, and release the FreeSnitch firewall flavor.
# This is the one authoritative maintainer release command.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

REPOSITORY="isaaclins/freesnitch"
PROJECT_SPEC="$ROOT/project.yml"
NETEXT_SPEC="$ROOT/project-netext.yml"
PROJECT_FILE="$ROOT/FreeSnitch.xcodeproj"
TEAM_ID="BHAF4L4726"
SIGN_ID="Developer ID Application: isaac lins (BHAF4L4726)"
APP_BUNDLE_ID="io.isaaclins.freesnitch"
NETEXT_BUNDLE_ID="io.isaaclins.freesnitch.netext"
NETEXT_BUNDLE_NAME="io.isaaclins.freesnitch.netext.systemextension"
HELPER_LABEL="io.isaaclins.freesnitch.helper"
APP_PROFILE_NAME="FreeSnitch App DeveloperID"
NETEXT_PROFILE_NAME="FreeSnitch NetExt DeveloperID"
NOTARY_PROFILE="${NOTARY_PROFILE:-puresnitch-dev}"
SPARKLE_VERSION="2.7.1"
SPARKLE_ACCOUNT="puresnitch"
FEED_URL="https://isaaclins.com/freesnitch/appcast.xml"

MODE="release"
VERSION=""
BUILD_NUMBER=""
NOTES_INPUT=""
POSITIONALS=()

usage() {
  cat <<'EOF'
Usage:
  Scripts/release.sh [--validate-only|--dry-run] VERSION [BUILD] [NOTES_FILE]

Examples:
  Scripts/release.sh 0.3.0 12 /tmp/freesnitch-v0.3.0.md
  Scripts/release.sh --validate-only 0.3.0 12
  Scripts/release.sh --dry-run 0.3.0 12

A real release only runs from a clean, pushed main branch. The notes file may
live outside the repository so preparing notes does not make main dirty. The
release command commits the version, appcast, and docs/release-notes file,
creates and pushes tag vVERSION, then creates the GitHub Release itself.

--validate-only checks release arguments, source version state, the repository
release gate, and the firewall safety audit without building or publishing.
Release notes are optional in validation-only mode; a supplied notes file is
still checked for existence and content.
--dry-run validates arguments and the safety audit without requiring main or
running any build, signing, notarization, tag, or GitHub operation.

The environment variables SPARKLE_RELEASE_VALIDATE_ONLY=1 and
SPARKLE_RELEASE_DRY_RUN=1 are equivalent to the corresponding options.
EOF
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h)
      usage
      exit 0
      ;;
    --validate-only)
      MODE="validate-only"
      shift
      ;;
    --dry-run)
      MODE="dry-run"
      shift
      ;;
    --notes|-n)
      [[ $# -ge 2 ]] || die "$1 requires a notes file"
      NOTES_INPUT="$2"
      shift 2
      ;;
    --build|-b)
      [[ $# -ge 2 ]] || die "$1 requires a build number"
      BUILD_NUMBER="$2"
      shift 2
      ;;
    --)
      shift
      while [[ $# -gt 0 ]]; do
        POSITIONALS+=("$1")
        shift
      done
      ;;
    --*)
      die "unknown option: $1"
      ;;
    *)
      POSITIONALS+=("$1")
      shift
      ;;
  esac
done

if [[ -n "${SPARKLE_RELEASE_VALIDATE_ONLY:-}" && "${SPARKLE_RELEASE_VALIDATE_ONLY}" == "1" ]]; then
  MODE="validate-only"
fi
if [[ -n "${SPARKLE_RELEASE_DRY_RUN:-}" && "${SPARKLE_RELEASE_DRY_RUN}" == "1" ]]; then
  MODE="dry-run"
fi

if [[ -z "$VERSION" && ${#POSITIONALS[@]} -ge 1 ]]; then
  VERSION="${POSITIONALS[0]}"
fi
if [[ -z "$BUILD_NUMBER" && ${#POSITIONALS[@]} -ge 2 ]]; then
  BUILD_NUMBER="${POSITIONALS[1]}"
fi
if [[ -z "$NOTES_INPUT" && ${#POSITIONALS[@]} -ge 3 ]]; then
  NOTES_INPUT="${POSITIONALS[2]}"
fi
if [[ ${#POSITIONALS[@]} -gt 3 ]]; then
  usage >&2
  exit 1
fi
[[ -n "$VERSION" ]] || { usage >&2; exit 1; }

read_unique_spec_value() {
  local key="$1"
  local values
  values="$(awk -F: -v key="$key" '$1 ~ "^[[:space:]]*" key "[[:space:]]*$" { value = $2; gsub(/[[:space:]\"]/, "", value); print value }' "$PROJECT_SPEC")"
  [[ -n "$values" ]] || die "no $key values found in $PROJECT_SPEC"

  local distinct
  distinct="$(printf '%s\n' "$values" | sort -u | wc -l | tr -d ' ')"
  if [[ "$distinct" != "1" ]]; then
    printf '%s\n' "$values" | sort -u | sed 's/^/  /' >&2
    die "$key values disagree in $PROJECT_SPEC"
  fi
  printf '%s\n' "$values" | head -1
}

CURRENT_VERSION="$(read_unique_spec_value CFBundleShortVersionString)"
CURRENT_BUILD="$(read_unique_spec_value CFBundleVersion)"

if [[ ! "$CURRENT_VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  die "current project version is not MAJOR.MINOR.PATCH: $CURRENT_VERSION"
fi
if [[ ! "$CURRENT_BUILD" =~ ^[1-9][0-9]*$ ]]; then
  die "current project build is not a positive integer: $CURRENT_BUILD"
fi

if [[ -z "$BUILD_NUMBER" ]]; then
  BUILD_NUMBER="$((CURRENT_BUILD + 1))"
  printf 'No build supplied, using current project build plus one: %s\n' "$BUILD_NUMBER"
fi

validate_semver_and_build() {
  if [[ ! "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    die "release version must be MAJOR.MINOR.PATCH without leading zeroes: $VERSION"
  fi
  if [[ ! "$BUILD_NUMBER" =~ ^[1-9][0-9]*$ ]]; then
    die "release build must be a positive integer without leading zeroes: $BUILD_NUMBER"
  fi
  if (( BUILD_NUMBER <= CURRENT_BUILD )); then
    die "release build $BUILD_NUMBER must be greater than project build $CURRENT_BUILD"
  fi

  local requested_major requested_minor requested_patch
  local current_major current_minor current_patch
  IFS=. read -r requested_major requested_minor requested_patch <<< "$VERSION"
  IFS=. read -r current_major current_minor current_patch <<< "$CURRENT_VERSION"
  if (( requested_major < current_major )) || \
     (( requested_major == current_major && requested_minor < current_minor )) || \
     (( requested_major == current_major && requested_minor == current_minor && requested_patch < current_patch )); then
    die "release version $VERSION is lower than project version $CURRENT_VERSION"
  fi

  printf 'Validated FreeSnitch %s, build %s, against project version %s, build %s.\n' \
    "$VERSION" "$BUILD_NUMBER" "$CURRENT_VERSION" "$CURRENT_BUILD"
}

validate_notes_file() {
  [[ -n "$NOTES_INPUT" ]] || NOTES_INPUT="$ROOT/docs/release-notes/v${VERSION}.md"
  [[ -f "$NOTES_INPUT" ]] || die "release notes file not found: $NOTES_INPUT"
  [[ -s "$NOTES_INPUT" ]] || die "release notes file is empty: $NOTES_INPUT"
}

validate_notes_file_if_present() {
  if [[ -z "$NOTES_INPUT" ]]; then
    local default_notes="$ROOT/docs/release-notes/v${VERSION}.md"
    if [[ -f "$default_notes" ]]; then
      NOTES_INPUT="$default_notes"
    else
      printf 'No release notes file supplied; skipping notes validation in validate-only mode.\n'
      return 0
    fi
  fi
  [[ -f "$NOTES_INPUT" ]] || die "release notes file not found: $NOTES_INPUT"
  [[ -s "$NOTES_INPUT" ]] || die "release notes file is empty: $NOTES_INPUT"
}

run_firewall_safety_audit() {
  [[ -x "$ROOT/Scripts/audit_firewall_safety.sh" ]] || die "firewall safety audit is not executable"
  bash "$ROOT/Scripts/audit_firewall_safety.sh"
}

require_clean_main_and_pushed() {
  local branch
  branch="$(git symbolic-ref --short -q HEAD || true)"
  [[ "$branch" == "main" ]] || die "real releases must run on branch main, not $branch"

  local status
  status="$(git status --porcelain=v1 --untracked-files=all)"
  [[ -z "$status" ]] || die "working tree is not clean"

  local upstream
  upstream="$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null || true)"
  [[ -n "$upstream" ]] || die "main has no upstream branch; push main before releasing"

  local counts ahead behind
  # git separates the two counters with a tab, so split on whitespace rather
  # than assuming a single space. Stripping on a space kept the whole string
  # in both variables and made this gate reject every possible state.
  counts="$(git rev-list --left-right --count "HEAD...$upstream")"
  read -r ahead behind <<<"$counts"
  [[ "$ahead" == "0" && "$behind" == "0" ]] || \
    die "main is not synchronized with $upstream (ahead $ahead, behind $behind)"

  local remote_url
  remote_url="$(git remote get-url origin 2>/dev/null || true)"
  [[ "$remote_url" == *github.com*isaaclins/freesnitch* ]] || \
    die "origin is not the canonical repository: $remote_url"

  local tag="v${VERSION}"
  if git rev-parse --verify --quiet "refs/tags/$tag" >/dev/null; then
    die "tag already exists locally: $tag"
  fi
  if git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1; then
    die "tag already exists on origin: $tag"
  fi
}

find_profile_by_name() {
  local wanted="$1"
  local profile_dir="$HOME/Library/MobileDevice/Provisioning Profiles"
  local profile profile_name
  [[ -d "$profile_dir" ]] || return 1

  for profile in "$profile_dir"/*.mobileprovision "$profile_dir"/*.provisionprofile; do
    [[ -f "$profile" ]] || continue
    profile_name="$(security cms -D -i "$profile" 2>/dev/null | plutil -extract Name raw -o - - 2>/dev/null || true)"
    if [[ "$profile_name" == "$wanted" ]]; then
      printf '%s\n' "$profile"
      return 0
    fi
  done
  return 1
}

require_release_tooling() {
  local command_name
  for command_name in xcodegen xcodebuild codesign xcrun hdiutil spctl lipo ditto security plutil curl tar file gh; do
    require_command "$command_name"
  done
  [[ -x /usr/libexec/PlistBuddy ]] || die "required command not found: /usr/libexec/PlistBuddy"

  local codesigning_identities
  codesigning_identities="$(security find-identity -v -p codesigning 2>/dev/null || true)"
  grep -Fq "\"$SIGN_ID\"" <<<"$codesigning_identities" || \
    die "Developer ID identity is not installed: $SIGN_ID"
  xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null 2>&1 || \
    die "notarytool keychain profile is unavailable: $NOTARY_PROFILE"

  local app_profile netext_profile
  app_profile="$(find_profile_by_name "$APP_PROFILE_NAME" || true)"
  netext_profile="$(find_profile_by_name "$NETEXT_PROFILE_NAME" || true)"
  [[ -n "$app_profile" ]] || die "installed provisioning profile not found: $APP_PROFILE_NAME"
  [[ -n "$netext_profile" ]] || die "installed provisioning profile not found: $NETEXT_PROFILE_NAME"
  printf 'Found provisioning profiles:\n  %s\n  %s\n' "$app_profile" "$netext_profile"

  gh auth status >/dev/null 2>&1 || die "gh is not authenticated for GitHub"
  gh repo view "$REPOSITORY" --json nameWithOwner --jq .nameWithOwner 2>/dev/null | \
    grep -Fxq "$REPOSITORY" || die "gh cannot access $REPOSITORY"
  if gh release view "v${VERSION}" --repo "$REPOSITORY" >/dev/null 2>&1; then
    die "a GitHub Release already exists for v${VERSION}"
  fi
}

BUILD_ROOT="$ROOT/build/release"
DERIVED_DATA="$BUILD_ROOT/DerivedData"
APP_BUNDLE="$DERIVED_DATA/Build/Products/Release/FreeSnitch.app"
NETEXT_BUNDLE="$APP_BUNDLE/Contents/Library/SystemExtensions/$NETEXT_BUNDLE_NAME"
APP_BINARY="$APP_BUNDLE/Contents/MacOS/FreeSnitch"
HELPER_BINARY="$APP_BUNDLE/Contents/MacOS/FreeSnitchHelper"
CLI_BINARY="$APP_BUNDLE/Contents/Helpers/freesnitch"
NETEXT_BINARY="$NETEXT_BUNDLE/Contents/MacOS/$NETEXT_BUNDLE_ID"
APPCAST_ARCHIVES="$ROOT/docs/sparkle-archives"
ZIP_NAME="FreeSnitch-${VERSION}.zip"
DMG_NAME="FreeSnitch-${VERSION}.dmg"
DOWNLOAD_PREFIX="https://github.com/${REPOSITORY}/releases/download/v${VERSION}/"
ZIP_PATH="$APPCAST_ARCHIVES/$ZIP_NAME"
DMG_PATH="$BUILD_ROOT/$DMG_NAME"
NOTARIZE_APP_ZIP="$BUILD_ROOT/FreeSnitch-${VERSION}-app-notary.zip"

assert_file() {
  [[ -e "$1" ]] || die "release bundle is missing: $1"
}

assert_plist_value() {
  local plist="$1"
  local key="$2"
  local expected="$3"
  local actual
  actual="$(plutil -extract "$key" raw -o - "$plist" 2>/dev/null || true)"
  [[ "$actual" == "$expected" ]] || die "$plist $key is '$actual', expected '$expected'"
}

assert_universal() {
  local binary="$1"
  local arches
  arches="$(lipo -archs "$binary" 2>/dev/null || true)"
  [[ "$arches" == *arm64* ]] || die "$binary has no arm64 slice"
  [[ "$arches" == *x86_64* ]] || die "$binary has no x86_64 slice"
}

write_entitlements_dump() {
  local target="$1"
  local output="$2"
  codesign -d --entitlements :- --xml "$target" 2>/dev/null > "$output" || \
    die "could not read signed entitlements from $target"
  [[ -s "$output" ]] || die "signed entitlements are empty for $target"
  plutil -lint "$output" >/dev/null || die "signed entitlements are not valid plist XML for $target"
}

assert_no_get_task_allow() {
  local entitlements="$1"
  local value
  value="$(/usr/libexec/PlistBuddy -c 'Print :com.apple.get-task-allow' "$entitlements" 2>/dev/null || true)"
  [[ "$value" != "true" ]] || die "get-task-allow is true in $entitlements"
}

assert_signed_by_team() {
  local target="$1"
  local details
  details="$(codesign -dv --verbose=4 "$target" 2>&1 || true)"
  printf '%s\n' "$details" | grep -Fq "TeamIdentifier=$TEAM_ID" || \
    die "$target is not signed by team $TEAM_ID"
  printf '%s\n' "$details" | grep -Fq "Authority=$SIGN_ID" || \
    die "$target is not signed with $SIGN_ID"
}

assert_profile_name() {
  local profile="$1"
  local expected="$2"
  local name
  name="$(security cms -D -i "$profile" 2>/dev/null | plutil -extract Name raw -o - - 2>/dev/null || true)"
  [[ "$name" == "$expected" ]] || die "$profile is '$name', expected provisioning profile '$expected'"
}

assert_framework_code_signatures() {
  local frameworks_dir="$APP_BUNDLE/Contents/Frameworks"
  local candidate details
  local macho_count=0
  assert_file "$frameworks_dir"

  while IFS= read -r -d '' candidate; do
    if ! file -b "$candidate" | grep -Fq 'Mach-O'; then
      continue
    fi

    macho_count=$((macho_count + 1))
    details="$(codesign -dvvv "$candidate" 2>&1 || true)"
    printf '%s\n' "$details" | grep -Fq "TeamIdentifier=$TEAM_ID" || \
      die "$candidate is not signed by team $TEAM_ID"
    printf '%s\n' "$details" | grep -Fq "Authority=$SIGN_ID" || \
      die "$candidate is not signed with $SIGN_ID"
    printf '%s\n' "$details" | grep -Eq '^Timestamp=' || \
      die "$candidate signature has no secure timestamp"
  done < <(find "$frameworks_dir" -type f -print0)

  [[ "$macho_count" -gt 0 ]] || die "no Mach-O code found under $frameworks_dir"
  printf 'Verified %s Mach-O files under Contents/Frameworks with the Developer ID identity and secure timestamps.\n' \
    "$macho_count"
}

verify_app_bundle() {
  printf 'Verifying the signed firewall bundle...\n'
  assert_file "$APP_BUNDLE"
  assert_file "$APP_BINARY"
  assert_file "$HELPER_BINARY"
  assert_file "$CLI_BINARY"
  assert_file "$APP_BUNDLE/Contents/Library/LaunchDaemons/$HELPER_LABEL.plist"
  assert_file "$NETEXT_BUNDLE"
  assert_file "$NETEXT_BINARY"
  assert_file "$APP_BUNDLE/Contents/embedded.provisionprofile"
  assert_file "$NETEXT_BUNDLE/Contents/embedded.provisionprofile"
  assert_file "$APP_BUNDLE/Contents/Resources/Assets.car"
  assert_file "$APP_BUNDLE/Contents/Resources/AppIcon.icns"
  [[ ! -e "$APP_BUNDLE/Contents/Library/SystemExtensions/FreeSnitchNetExt.systemextension" ]] || \
    die "system extension has the stale filename FreeSnitchNetExt.systemextension"

  assert_plist_value "$APP_BUNDLE/Contents/Info.plist" CFBundleIdentifier "$APP_BUNDLE_ID"
  assert_plist_value "$NETEXT_BUNDLE/Contents/Info.plist" CFBundleIdentifier "$NETEXT_BUNDLE_ID"

  # Sparkle compares the installed CFBundleVersion against the appcast. If the
  # shipped bundle is older than what the feed advertises, every launch offers
  # an update that never appears to install.
  assert_plist_value "$APP_BUNDLE/Contents/Info.plist" CFBundleShortVersionString "$VERSION"
  assert_plist_value "$APP_BUNDLE/Contents/Info.plist" CFBundleVersion "$BUILD_NUMBER"
  assert_plist_value "$NETEXT_BUNDLE/Contents/Info.plist" CFBundleShortVersionString "$VERSION"
  assert_plist_value "$NETEXT_BUNDLE/Contents/Info.plist" CFBundleVersion "$BUILD_NUMBER"
  plutil -lint "$APP_BUNDLE/Contents/Library/LaunchDaemons/$HELPER_LABEL.plist" >/dev/null || \
    die "launchd plist is invalid"
  assert_plist_value "$APP_BUNDLE/Contents/Library/LaunchDaemons/$HELPER_LABEL.plist" Label "$HELPER_LABEL"

  assert_universal "$APP_BINARY"
  assert_universal "$HELPER_BINARY"
  assert_universal "$CLI_BINARY"
  assert_universal "$NETEXT_BINARY"

  assert_profile_name "$APP_BUNDLE/Contents/embedded.provisionprofile" "$APP_PROFILE_NAME"
  assert_profile_name "$NETEXT_BUNDLE/Contents/embedded.provisionprofile" "$NETEXT_PROFILE_NAME"

  local entitlements_dir="$BUILD_ROOT/entitlements"
  rm -rf "$entitlements_dir"
  mkdir -p "$entitlements_dir"
  local app_entitlements="$entitlements_dir/app.plist"
  local helper_entitlements="$entitlements_dir/helper.plist"
  local netext_entitlements="$entitlements_dir/netext.plist"
  write_entitlements_dump "$APP_BUNDLE" "$app_entitlements"
  write_entitlements_dump "$HELPER_BINARY" "$helper_entitlements"
  write_entitlements_dump "$NETEXT_BUNDLE" "$netext_entitlements"
  assert_no_get_task_allow "$app_entitlements"
  assert_no_get_task_allow "$helper_entitlements"
  assert_no_get_task_allow "$netext_entitlements"
  grep -Fq '<key>com.apple.developer.networking.networkextension</key>' "$app_entitlements" || \
    die "app is missing the Network Extension entitlement"
  grep -Fq 'content-filter-provider-systemextension' "$app_entitlements" || \
    die "app is missing content-filter-provider-systemextension"
  grep -Fq '<key>com.apple.developer.system-extension.install</key>' "$app_entitlements" || \
    die "app is missing the System Extension install entitlement"
  grep -Fq '<key>com.apple.developer.networking.networkextension</key>' "$netext_entitlements" || \
    die "system extension is missing the Network Extension entitlement"
  grep -Fq 'content-filter-provider-systemextension' "$netext_entitlements" || \
    die "system extension is missing content-filter-provider-systemextension"
  grep -Fq "$TEAM_ID.$APP_BUNDLE_ID" "$helper_entitlements" || \
    die "helper entitlement has the wrong application identifier"

  assert_signed_by_team "$APP_BUNDLE"
  assert_signed_by_team "$HELPER_BINARY"
  assert_signed_by_team "$CLI_BINARY"
  assert_signed_by_team "$NETEXT_BUNDLE"
  # Capture first, then match. Piping a still-running codesign into an
  # early-exiting grep -q kills codesign with SIGPIPE, and under pipefail that
  # 141 failed the release for a bundle that was signed correctly.
  local cli_signature
  cli_signature="$(codesign -dv --verbose=4 "$CLI_BINARY" 2>&1 || true)"
  grep -Fq "Identifier=$APP_BUNDLE_ID.cli" <<<"$cli_signature" || \
    die "$CLI_BINARY has the wrong signing identifier"
  assert_framework_code_signatures
  codesign --verify --strict --verbose=2 "$HELPER_BINARY" >/dev/null || die "helper signature verification failed"
  codesign --verify --strict --verbose=2 "$NETEXT_BUNDLE" >/dev/null || die "system extension signature verification failed"
  codesign --verify --strict --deep --verbose=2 "$APP_BUNDLE" >/dev/null || \
    die "deep app signature verification failed"
  printf 'Signed universal app, helper, and %s system extension verified.\n' "$NETEXT_BUNDLE_NAME"
}

sign_nested_code() {
  local helper_entitlements="$ROOT/Sources/Helper/Helper.entitlements"
  local netext_entitlements="$ROOT/Sources/NetExt/NetExt.entitlements"
  local app_entitlements="$ROOT/Sources/GUI/FreeSnitch-netext.entitlements"
  local sparkle_framework="$APP_BUNDLE/Contents/Frameworks/Sparkle.framework"
  local sparkle_versions_dir sparkle_version_dir
  local downloader_xpc installer_xpc updater_app autoupdate
  assert_file "$app_entitlements"
  assert_file "$sparkle_framework"

  sparkle_versions_dir="$(cd "$sparkle_framework/Versions" 2>/dev/null && pwd -P)" || \
    die "could not resolve Sparkle.framework Versions directory: $sparkle_framework"
  [[ -L "$sparkle_versions_dir/Current" ]] || \
    die "Sparkle.framework is missing its Versions/Current symlink: $sparkle_framework"
  sparkle_version_dir="$(cd "$sparkle_versions_dir/Current" 2>/dev/null && pwd -P)" || \
    die "could not resolve Sparkle.framework Versions/Current: $sparkle_framework"
  case "$sparkle_version_dir" in
    "$sparkle_versions_dir"/*) ;;
    *) die "Sparkle.framework Versions/Current points outside Versions: $sparkle_version_dir" ;;
  esac

  downloader_xpc="$sparkle_version_dir/XPCServices/Downloader.xpc"
  installer_xpc="$sparkle_version_dir/XPCServices/Installer.xpc"
  updater_app="$sparkle_version_dir/Updater.app"
  autoupdate="$sparkle_version_dir/Autoupdate"
  assert_file "$downloader_xpc"
  assert_file "$installer_xpc"
  assert_file "$updater_app"
  assert_file "$autoupdate"

  printf 'Re-signing Sparkle nested code inside-out at %s...\n' "$sparkle_version_dir"
  codesign --force --options runtime --timestamp --sign "$SIGN_ID" "$downloader_xpc"
  codesign --force --options runtime --timestamp --sign "$SIGN_ID" "$installer_xpc"
  codesign --force --options runtime --timestamp --sign "$SIGN_ID" "$updater_app"
  codesign --force --options runtime --timestamp --sign "$SIGN_ID" "$autoupdate"
  codesign --force --options runtime --timestamp --sign "$SIGN_ID" "$sparkle_framework"

  printf 'Re-signing the remaining nested code inside-out with Developer ID...\n'
  codesign --force --options runtime --timestamp --entitlements "$helper_entitlements" \
    --sign "$SIGN_ID" "$HELPER_BINARY"
  codesign --force --options runtime --timestamp --identifier "$APP_BUNDLE_ID.cli" \
    --sign "$SIGN_ID" "$CLI_BINARY"
  codesign --force --options runtime --timestamp --entitlements "$netext_entitlements" \
    --sign "$SIGN_ID" "$NETEXT_BUNDLE"
  codesign --force --options runtime --timestamp --entitlements "$app_entitlements" \
    --sign "$SIGN_ID" "$APP_BUNDLE"
}

notarize_app() {
  printf 'Notarizing the app...\n'
  rm -f "$NOTARIZE_APP_ZIP"
  ditto -c -k --sequesterRsrc --keepParent "$APP_BUNDLE" "$NOTARIZE_APP_ZIP"
  xcrun notarytool submit "$NOTARIZE_APP_ZIP" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$APP_BUNDLE"
  xcrun stapler validate "$APP_BUNDLE"
  spctl --assess --verbose=4 --type execute "$APP_BUNDLE"
}

make_and_notarize_dmg() {
  local stage="$BUILD_ROOT/dmg-stage"
  rm -rf "$stage" "$DMG_PATH"
  mkdir -p "$stage"
  ditto "$APP_BUNDLE" "$stage/FreeSnitch.app"
  ln -s /Applications "$stage/Applications"
  hdiutil create -volname "FreeSnitch $VERSION" -srcfolder "$stage" -ov -format UDZO "$DMG_PATH"
  codesign --force --timestamp --sign "$SIGN_ID" "$DMG_PATH"
  xcrun notarytool submit "$DMG_PATH" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$DMG_PATH"
  xcrun stapler validate "$DMG_PATH"
  spctl --assess --verbose=4 --type open --context context:primary-signature "$DMG_PATH"
  printf 'Signed, notarized, stapled, and Gatekeeper-assessed %s.\n' "$DMG_NAME"
}

sparkle_tool() {
  local candidate
  if [[ -n "${SPARKLE_GENERATE_APPCAST:-}" ]]; then
    candidate="$SPARKLE_GENERATE_APPCAST"
    [[ -x "$candidate" ]] || die "SPARKLE_GENERATE_APPCAST is not executable: $candidate"
    printf '%s\n' "$candidate"
    return 0
  fi

  for candidate in \
    "$BUILD_ROOT/sparkle/Sparkle-${SPARKLE_VERSION}/bin/generate_appcast" \
    "$BUILD_ROOT/sparkle/bin/generate_appcast"; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  local sparkle_dir="$BUILD_ROOT/sparkle"
  local tarball="$sparkle_dir/Sparkle-${SPARKLE_VERSION}.tar.xz"
  mkdir -p "$sparkle_dir"
  # This function returns the tool path on stdout, so progress must go to
  # stderr. Printing it to stdout made the caller capture the message and the
  # path together and then try to execute the whole string.
  printf 'Downloading Sparkle %s tools...\n' "$SPARKLE_VERSION" >&2
  curl -fsSL -o "$tarball" \
    "https://github.com/sparkle-project/Sparkle/releases/download/${SPARKLE_VERSION}/Sparkle-${SPARKLE_VERSION}.tar.xz"
  tar -xf "$tarball" -C "$sparkle_dir"
  for candidate in \
    "$sparkle_dir/Sparkle-${SPARKLE_VERSION}/bin/generate_appcast" \
    "$sparkle_dir/bin/generate_appcast"; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  die "Sparkle ${SPARKLE_VERSION} generate_appcast tool was not found"
}

rewrite_appcast_download_urls() {
  local appcast="$1"
  local tmp="$appcast.tmp"
  local full_pattern='<enclosure url="[^"]*/download/[^"/]+/FreeSnitch-[0-9]+\.[0-9]+\.[0-9]+\.zip"'
  local delta_pattern='<enclosure url="[^"]*/download/[^"/]+/FreeSnitch[0-9]+\.[0-9]+\.[0-9]+-[^"/]+\.delta"'
  local full_count delta_count
  full_count="$(grep -Eoc "$full_pattern" "$appcast" || true)"
  [[ "$full_count" != "0" ]] || die "Sparkle appcast has no FreeSnitch full-zip enclosure"

  sed -E \
    -e 's#(<enclosure url="[^"]*/download/)[^"/]+(/FreeSnitch-([0-9]+\.[0-9]+\.[0-9]+)\.zip")#\1v\3\2#g' \
    -e 's#(<enclosure url="[^"]*/download/)[^"/]+(/FreeSnitch([0-9]+\.[0-9]+\.[0-9]+)-[^"/]+\.delta")#\1v\3\2#g' \
    "$appcast" > "$tmp"
  mv "$tmp" "$appcast"

  local mismatch
  # Emit the BARE version here. The awk comparison builds the expected tag by
  # prefixing "v", so prefixing it in sed as well compared v0.3.0 against
  # vv0.3.0 and reported every correct URL as a mismatch.
  mismatch="$(grep -Eo "$full_pattern" "$appcast" | \
    sed -E 's#.*download/([^"/]+)/FreeSnitch-([0-9]+\.[0-9]+\.[0-9]+)\.zip.*#\1 \2#' | \
    awk '$1 != "v" $2 { print }' || true)"
  [[ -z "$mismatch" ]] || die "full-zip appcast URLs do not point to their matching release tags: $mismatch"

  delta_count="$(grep -Eoc "$delta_pattern" "$appcast" || true)"
  printf 'Pinned %s full-zip and %s delta appcast URLs to their release tags.\n' "$full_count" "$delta_count"
}

generate_appcast() {
  local generator="$1"
  local appcast_tmp_dir="$BUILD_ROOT/appcast-tmp"
  local appcast_tmp="$appcast_tmp_dir/appcast.xml"
  local notes_txt="$APPCAST_ARCHIVES/FreeSnitch-${VERSION}.txt"
  local key_args=(--account "$SPARKLE_ACCOUNT")
  rm -rf "$appcast_tmp_dir"
  mkdir -p "$appcast_tmp_dir" "$APPCAST_ARCHIVES"

  # Keep the prior feed beside the archives so Sparkle preserves its history.
  # The output path does not exist yet because generate_appcast parses an
  # existing output path as an input appcast.
  if [[ -f "$ROOT/docs/appcast.xml" ]]; then
    cp "$ROOT/docs/appcast.xml" "$APPCAST_ARCHIVES/appcast.xml"
  fi
  # The archive is normally built straight into the archive directory, so this
  # would be a copy onto itself, which cp refuses and pipefail turns fatal.
  if [[ "$ZIP_PATH" -ef "$APPCAST_ARCHIVES/$ZIP_NAME" ]]; then
    printf 'Sparkle archive is already at %s; no copy needed.\n' "$APPCAST_ARCHIVES/$ZIP_NAME"
  else
    cp "$ZIP_PATH" "$APPCAST_ARCHIVES/$ZIP_NAME"
  fi
  cp "$NOTES_INPUT" "$notes_txt"

  if [[ -n "${SPARKLE_EDDSA_PRIVATE_KEY_FILE:-}" ]]; then
    [[ -f "$SPARKLE_EDDSA_PRIVATE_KEY_FILE" ]] || \
      die "SPARKLE_EDDSA_PRIVATE_KEY_FILE is not a file"
    key_args+=(--ed-key-file "$SPARKLE_EDDSA_PRIVATE_KEY_FILE")
  elif [[ -f "$ROOT/Scripts/sparkle_eddsa_private.key" ]]; then
    key_args+=(--ed-key-file "$ROOT/Scripts/sparkle_eddsa_private.key")
  fi

  printf 'Generating signed Sparkle appcast with account %s...\n' "$SPARKLE_ACCOUNT"
  "$generator" \
    "${key_args[@]}" \
    --download-url-prefix "$DOWNLOAD_PREFIX" \
    --embed-release-notes \
    -o "$appcast_tmp" \
    "$APPCAST_ARCHIVES"
  rewrite_appcast_download_urls "$appcast_tmp"
  grep -Fq "$DOWNLOAD_PREFIX$ZIP_NAME" "$appcast_tmp" || \
    die "generated appcast does not contain the current release URL"
  grep -Fq 'sparkle:edSignature' "$appcast_tmp" || \
    die "generated appcast has no Sparkle EdDSA signature"
  # Sparkle writes the element with attributes, for example
  # <description sparkle:format="plain-text">, so match the tag rather than a
  # bare <description>, which never appears and failed every release.
  grep -Eq '<description[ >]' "$appcast_tmp" || \
    die "generated appcast does not embed release notes"
  grep -Fq 'CDATA' "$appcast_tmp" || \
    die "generated appcast has an empty release notes description"
  cp "$appcast_tmp" "$BUILD_ROOT/appcast.xml"
  printf 'Generated appcast staged at %s (published feed: %s).\n' "$BUILD_ROOT/appcast.xml" "$FEED_URL"
}

# Tracked files that carry the release version. project-netext.yml includes
# project.yml, so bumping the shared spec covers the firewall flavor too.
VERSIONED_TRACKED_PATHS=(
  "project.yml"
  "Sources/GUI/Info.plist"
  "Sources/NetExt/Info.plist"
)
RELEASE_VERSIONS_APPLIED=0
RELEASE_PUBLISHED=0

# A failed release must not leave a bumped version behind, otherwise the next
# attempt starts from a dirty tree and the clean-main gate blocks it.
restore_versioned_paths_on_failure() {
  local status=$?
  if (( status != 0 )) && (( RELEASE_VERSIONS_APPLIED == 1 )) && (( RELEASE_PUBLISHED == 0 )); then
    printf 'Release failed, restoring tracked version files...\n' >&2
    git checkout -- "${VERSIONED_TRACKED_PATHS[@]}" 2>/dev/null || true
  fi
  return $status
}

update_project_versions() {
  local temp="$PROJECT_SPEC.tmp.$$"
  local version_count build_count updated_version_count updated_build_count
  version_count="$(grep -Ec '^[[:space:]]*CFBundleShortVersionString:' "$PROJECT_SPEC" || true)"
  build_count="$(grep -Ec '^[[:space:]]*CFBundleVersion:' "$PROJECT_SPEC" || true)"
  [[ "$version_count" != "0" ]] || die "no CFBundleShortVersionString entries found in $PROJECT_SPEC"
  [[ "$build_count" != "0" ]] || die "no CFBundleVersion entries found in $PROJECT_SPEC"

  sed -E \
    -e "s#^([[:space:]]*CFBundleShortVersionString:)[[:space:]]*\"[^\"]*\"#\1 \"$VERSION\"#" \
    -e "s#^([[:space:]]*CFBundleVersion:)[[:space:]]*\"[^\"]*\"#\1 \"$BUILD_NUMBER\"#" \
    "$PROJECT_SPEC" > "$temp"
  mv "$temp" "$PROJECT_SPEC"

  updated_version_count="$(grep -Ec "^[[:space:]]*CFBundleShortVersionString:[[:space:]]*\"$VERSION\"$" "$PROJECT_SPEC" || true)"
  updated_build_count="$(grep -Ec "^[[:space:]]*CFBundleVersion:[[:space:]]*\"$BUILD_NUMBER\"$" "$PROJECT_SPEC" || true)"
  [[ "$updated_version_count" == "$version_count" ]] || die "not all project version entries were updated"
  [[ "$updated_build_count" == "$build_count" ]] || die "not all project build entries were updated"
}

# The generated Info.plist files hold literal values copied from project.yml,
# not $(MARKETING_VERSION), so the version has to be applied before xcodegen
# runs. Bumping after the build would ship a bundle whose CFBundleVersion is
# older than the appcast advertises, and Sparkle would offer the same update
# forever because the installed build never reaches the advertised version.
apply_release_versions() {
  # Mark the transaction before writing so a validation failure after the
  # first write still restores the clean release tree.
  RELEASE_VERSIONS_APPLIED=1
  update_project_versions
  printf 'Applied version %s, build %s to %s before generating the project.\n' \
    "$VERSION" "$BUILD_NUMBER" "$(basename "$PROJECT_SPEC")"
}

assert_only_version_files_changed() {
  local changed unexpected
  changed="$(git status --porcelain=v1 --untracked-files=all | awk '{ print $2 }')"
  unexpected="$(printf '%s\n' "$changed" | \
    grep -Ev '^(project\.yml|Sources/GUI/Info\.plist|Sources/NetExt/Info\.plist)$' || true)"
  [[ -z "$unexpected" ]] || \
    die "xcodegen changed tracked files beyond the release version bump:"$'\n'"$unexpected"
}

commit_and_publish() {
  local notes_destination="$ROOT/docs/release-notes/v${VERSION}.md"
  local tag="v${VERSION}"
  mkdir -p "$(dirname "$notes_destination")"
  cp "$NOTES_INPUT" "$notes_destination"
  cp "$BUILD_ROOT/appcast.xml" "$ROOT/docs/appcast.xml"

  local staged_files unexpected
  git add -- "${VERSIONED_TRACKED_PATHS[@]}" "$ROOT/docs/appcast.xml" "$notes_destination"
  git diff --cached --check
  staged_files="$(git diff --cached --name-only)"
  unexpected="$(printf '%s\n' "$staged_files" | grep -Ev '^(project\.yml|Sources/GUI/Info\.plist|Sources/NetExt/Info\.plist|docs/appcast\.xml|docs/release-notes/v[0-9]+\.[0-9]+\.[0-9]+\.md)$' || true)"
  [[ -z "$unexpected" ]] || die "release staged unexpected files:\n$unexpected"
  git diff --cached --quiet && die "release has no staged version, appcast, or notes changes"

  git commit -m "chore(release): FreeSnitch ${VERSION}"
  git tag -a "$tag" -m "FreeSnitch $VERSION"
  git push origin main
  git push origin "$tag"

  # Sparkle names deltas by BUILD number, not marketing version:
  # FreeSnitch32-31.delta patches build 31 up to build 32. Globbing these
  # with "$VERSION" silently matched nothing, so every release published
  # signed delta enclosures whose files were never uploaded and 404'd.
  local assets=("$DMG_PATH" "$ZIP_PATH")
  local delta
  for delta in "$APPCAST_ARCHIVES"/FreeSnitch"${BUILD_NUMBER}"-*.delta; do
    [[ -f "$delta" ]] || continue
    assets+=("$delta")
  done

  # Every enclosure the new appcast item advertises must be in the upload set.
  # A feed that points at a file we never attached is indistinguishable from a
  # tampered feed, so refuse to publish rather than ship one.
  local advertised missing=() asset found
  while IFS= read -r advertised; do
    [[ -n "$advertised" ]] || continue
    found=0
    for asset in "${assets[@]}"; do
      [[ "$(basename "$asset")" == "$advertised" ]] && { found=1; break; }
    done
    (( found )) || missing+=("$advertised")
  done < <(grep -o "releases/download/${tag}/[^\"]*" "$BUILD_ROOT/appcast.xml" | sed 's#.*/##' | sort -u)
  (( ${#missing[@]} == 0 )) || \
    die "appcast advertises files that are not being uploaded: ${missing[*]}"

  gh release create "$tag" "${assets[@]}" \
    --repo "$REPOSITORY" \
    --verify-tag \
    --title "FreeSnitch $VERSION" \
    --notes-file "$notes_destination"
  RELEASE_PUBLISHED=1

  printf 'Published FreeSnitch %s.\n' "$VERSION"
  printf '  GitHub Release: https://github.com/%s/releases/tag/%s\n' "$REPOSITORY" "$tag"
  printf '  Sparkle feed: %s\n' "$FEED_URL"
}

validate_semver_and_build
run_firewall_safety_audit

if [[ "$MODE" == "validate-only" ]]; then
  validate_notes_file_if_present
  require_clean_main_and_pushed
  printf 'Validation-only mode passed. No build, tracked-file mutation, tag, push, or GitHub Release was performed.\n'
  exit 0
fi

if [[ "$MODE" == "dry-run" ]]; then
  printf 'Dry run passed. Would generate %s, build the firewall flavor, notarize it, update the appcast, commit, tag, push, and publish.\n' "$NETEXT_SPEC"
  exit 0
fi

validate_notes_file
require_clean_main_and_pushed
require_release_tooling

# Validation-only and dry-run return above, before this transaction trap or any
# release mutation is installed. The trap restores version inputs on failures
# until GitHub confirms that the release exists.
trap restore_versioned_paths_on_failure EXIT
apply_release_versions

rm -rf "$BUILD_ROOT"
mkdir -p "$BUILD_ROOT"
printf 'Generating the firewall Xcode project from %s...\n' "$NETEXT_SPEC"
xcodegen generate --spec "$NETEXT_SPEC"

# xcodegen writes the generated project and netext entitlements, both ignored.
# It may update the tracked Info.plist files from project.yml, but no other
# tracked source or release input may change before artifacts pass.
assert_only_version_files_changed

XCODEBUILD_LOG="$BUILD_ROOT/xcodebuild.log"
printf 'Building universal Release FreeSnitch with Developer ID and both profiles...\n'
if ! xcodebuild \
  -project "$PROJECT_FILE" \
  -scheme FreeSnitch \
  -configuration Release \
  -destination 'generic/platform=macOS' \
  -derivedDataPath "$DERIVED_DATA" \
  ARCHS='arm64 x86_64' \
  ONLY_ACTIVE_ARCH=NO \
  MARKETING_VERSION="$VERSION" \
  CURRENT_PROJECT_VERSION="$BUILD_NUMBER" \
  CODE_SIGN_STYLE=Manual \
  CODE_SIGN_IDENTITY="$SIGN_ID" \
  DEVELOPMENT_TEAM="$TEAM_ID" \
  CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO \
  OTHER_CODE_SIGN_FLAGS='--timestamp --options=runtime' \
  clean build > "$XCODEBUILD_LOG" 2>&1; then
  tail -100 "$XCODEBUILD_LOG" >&2 || true
  die "xcodebuild failed; tracked versions are still unchanged"
fi

assert_file "$APP_BUNDLE"
sign_nested_code
verify_app_bundle
notarize_app

mkdir -p "$APPCAST_ARCHIVES"
rm -f "$ZIP_PATH"
ditto -c -k --sequesterRsrc --keepParent "$APP_BUNDLE" "$ZIP_PATH"
make_and_notarize_dmg

generator="$(sparkle_tool)"
generate_appcast "$generator"
commit_and_publish
