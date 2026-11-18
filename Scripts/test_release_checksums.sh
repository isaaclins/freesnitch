#!/usr/bin/env bash
# Regression gate for #376: SHA256SUMS.txt is written and checked before the
# release commit, and a checksum failure stops the release before anything is
# committed, tagged or pushed.
#
# Runs the real release tail (write_checksums; commit_and_publish) from
# Scripts/release.sh against scratch files. git and gh are stubs that only log
# their arguments; nothing touches the repository or GitHub.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RELEASE="$ROOT/Scripts/release.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-release-checksums.XXXXXX")"
trap '[[ -n "${FREESNITCH_KEEP_WORK:-}" ]] || rm -rf "$WORK"' EXIT

failures=0
fail() {
  printf 'RELEASE CHECKSUM TEST FAILED: %s\n' "$*" >&2
  failures=$((failures + 1))
}

# Pull the functions the release tail uses out of the real script.
extract() {
  awk -v name="$1" '
    index($0, name "() {") == 1 { p = 1 }
    p { print }
    p && /^}/ { exit }
  ' "$RELEASE"
}
for fn in die assert_file write_checksums commit_and_publish; do
  extract "$fn" >>"$WORK/functions.sh"
  grep -q "^$fn() {" "$WORK/functions.sh" || { printf 'missing function %s in release.sh\n' "$fn" >&2; exit 1; }
done

# The main flow must checksum before it commits.
tail_order="$(grep -nE '^(write_checksums|commit_and_publish)$' "$RELEASE" | cut -d: -f2 | tr '\n' ' ')"
[[ "$tail_order" == "write_checksums commit_and_publish " ]] || \
  fail "release.sh must call write_checksums right before commit_and_publish (got: $tail_order)"

# Run the tail in a fresh shell. $1 = case name, $2 = extra stub setup.
run_tail() {
  local case_dir="$WORK/$1"
  mkdir -p "$case_dir/bin" "$case_dir/build/release" "$case_dir/archives" "$case_dir/repo/docs"
  for tool in git gh; do
    printf '#!/usr/bin/env bash\nprintf "%s %%s\\n" "$*" >>"%s/calls.log"\n' "$tool" "$case_dir" >"$case_dir/bin/$tool"
    chmod +x "$case_dir/bin/$tool"
  done
  # "git diff --cached --quiet" has to report staged changes.
  printf '[[ "$*" == "diff --cached --quiet" ]] && exit 1\nexit 0\n' >>"$case_dir/bin/git"
  printf 'disk image\n' >"$case_dir/build/release/FreeSnitch-9.9.9.dmg"
  printf 'zip archive\n' >"$case_dir/archives/FreeSnitch-9.9.9.zip"
  printf '<rss></rss>\n' >"$case_dir/build/release/appcast.xml"
  printf 'notes\n' >"$case_dir/notes.md"
  ${2:-true} "$case_dir"
  : >"$case_dir/calls.log"
  # A separate bash process, so its set -e holds even though the caller tests
  # the result with `if`.
  cat >"$case_dir/tail.sh" <<TAIL
set -euo pipefail
export PATH="$case_dir/bin:\$PATH"
ROOT="$case_dir/repo" BUILD_ROOT="$case_dir/build/release" APPCAST_ARCHIVES="$case_dir/archives"
VERSION=9.9.9 BUILD_NUMBER=99 REPOSITORY=example/freesnitch FEED_URL=https://example.invalid/appcast.xml
NOTES_INPUT="$case_dir/notes.md" VERSIONED_TRACKED_PATHS=(project.yml)
DMG_PATH="\$BUILD_ROOT/FreeSnitch-9.9.9.dmg" ZIP_PATH="\$APPCAST_ARCHIVES/FreeSnitch-9.9.9.zip"
SUMS_PATH="\$BUILD_ROOT/SHA256SUMS.txt"
source "$WORK/functions.sh"
write_checksums
commit_and_publish
TAIL
  bash "$case_dir/tail.sh" >"$case_dir/out.log" 2>&1
}

# 1. Normal release: both files listed, sums verify, and the file is uploaded.
if run_tail ok; then
  sums="$WORK/ok/build/release/SHA256SUMS.txt"
  [[ "$(wc -l <"$sums" | tr -d ' ')" == 2 ]] || fail "SHA256SUMS.txt should list two files"
  grep -q '  FreeSnitch-9.9.9.dmg$' "$sums" || fail "SHA256SUMS.txt is missing the disk image"
  grep -q '  FreeSnitch-9.9.9.zip$' "$sums" || fail "SHA256SUMS.txt is missing the zip"
  (cd "$WORK/ok/build/release" && shasum -a 256 -c --ignore-missing "$sums" >/dev/null) || fail "disk image sum does not verify"
  (cd "$WORK/ok/archives" && shasum -a 256 -c --ignore-missing "$sums" >/dev/null) || fail "zip sum does not verify"
  grep -q "^gh release create .*SHA256SUMS.txt" "$WORK/ok/calls.log" || fail "SHA256SUMS.txt was not uploaded"
else
  fail "normal release tail failed: $(cat "$WORK/ok/out.log")"
fi

# 2. shasum fails (e.g. unreadable image): nothing may be committed or pushed.
broken_shasum() { printf '#!/usr/bin/env bash\nexit 1\n' >"$1/bin/shasum"; chmod +x "$1/bin/shasum"; }
if run_tail shasum-fails broken_shasum; then
  fail "release continued although shasum failed"
fi
grep -q 'could not compute the SHA-256' "$WORK/shasum-fails/out.log" || \
  fail "a failing shasum did not say why the release stopped: $(cat "$WORK/shasum-fails/out.log")"
grep -Eq '^git (commit|tag|push)|^gh release' "$WORK/shasum-fails/calls.log" && \
  fail "release committed, tagged or pushed after a checksum failure: $(cat "$WORK/shasum-fails/calls.log")"

# 3. The zip is missing: same, stop before anything is pushed.
missing_zip() { rm -f "$1/archives/FreeSnitch-9.9.9.zip"; }
if run_tail missing-zip missing_zip; then
  fail "release continued without the zip"
fi
grep -Eq '^git (commit|tag|push)|^gh release' "$WORK/missing-zip/calls.log" && \
  fail "release committed, tagged or pushed without the zip: $(cat "$WORK/missing-zip/calls.log")"

# 4. The appcast advertises a delta that isn't being uploaded: stop before the
#    appcast or notes are copied into the tree and before any git or gh call.
ghost_delta() {
  printf '<rss><enclosure url="https://github.com/example/freesnitch/releases/download/v9.9.9/FreeSnitch99-98.delta"/></rss>\n' \
    >"$1/build/release/appcast.xml"
}
if run_tail ghost-delta ghost_delta; then
  fail "release continued although the appcast advertises a file that isn't uploaded"
fi
grep -q 'appcast advertises files that are not being uploaded: FreeSnitch99-98.delta' "$WORK/ghost-delta/out.log" || \
  fail "appcast mismatch was not the reason the release stopped: $(cat "$WORK/ghost-delta/out.log")"
[[ -s "$WORK/ghost-delta/calls.log" ]] && \
  fail "release ran git or gh before the appcast check: $(cat "$WORK/ghost-delta/calls.log")"
[[ -e "$WORK/ghost-delta/repo/docs/appcast.xml" ]] && fail "appcast was copied into the tree before the check"

if (( failures > 0 )); then
  printf '%d release checksum check(s) failed.\n' "$failures" >&2
  exit 1
fi
printf 'Release checksum checks passed.\n'
