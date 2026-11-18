#!/usr/bin/env bash
# Regression gate for #373: `release.sh --update-tap VERSION` must never move
# the Homebrew cask back to an older version, and never write a checksum it
# could not read from the release.
#
# Runs the real release.sh against a stub `gh` and a local bare git repository
# that stands in for isaaclins/homebrew-tap. Nothing here talks to GitHub.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RELEASE="$ROOT/Scripts/release.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-update-tap.XXXXXX")"
trap '[[ -n "${FREESNITCH_KEEP_WORK:-}" ]] || rm -rf "$WORK"' EXIT

failures=0
fail() {
  printf 'UPDATE TAP TEST FAILED: %s\n' "$*" >&2
  failures=$((failures + 1))
}

OLD_SHA="$(printf '1%.0s' {1..64})"
NEW_SHA="$(printf 'a%.0s' {1..64})"

mkdir -p "$WORK/bin"
cat >"$WORK/bin/gh" <<EOF
#!/usr/bin/env bash
case "\$1 \$2" in
  "repo view") echo WRITE ;;
  "release view") [[ -f "$WORK/digest" ]] && cat "$WORK/digest" || echo "sha256:$NEW_SHA" ;;
  "repo clone") git clone --quiet "$WORK/tap.git" "\$4" ;;
  *) echo "unexpected gh call: \$*" >&2; exit 1 ;;
esac
EOF
chmod +x "$WORK/bin/gh"

# Resets the fake tap to a cask that points at version $1 (checksum $2).
reset_tap() {
  rm -rf "$WORK/tap.git" "$WORK/seed"
  git init --quiet --bare "$WORK/tap.git"
  git init --quiet "$WORK/seed"
  mkdir -p "$WORK/seed/Casks"
  cat >"$WORK/seed/Casks/freesnitch.rb" <<CASK
cask "freesnitch" do
  version "$1"
  sha256 "${2:-$OLD_SHA}"
end
CASK
  git -C "$WORK/seed" add Casks/freesnitch.rb
  git -C "$WORK/seed" -c user.name=t -c user.email=t@t commit --quiet -m seed
  git -C "$WORK/seed" push --quiet "$WORK/tap.git" HEAD:main
  git -C "$WORK/tap.git" symbolic-ref HEAD refs/heads/main
}

tap_version() {
  git -C "$WORK/tap.git" show main:Casks/freesnitch.rb | sed -nE 's/^  version "(.*)"$/\1/p'
}

run_update() {
  PATH="$WORK/bin:$PATH" GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t \
    GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t \
    bash "$RELEASE" --update-tap "$1" >"$WORK/out" 2>&1
}

# A lower version is refused, names the cask's version, and leaves the tap alone.
for case in "1.1.0 1.0.0" "1.1.0 1.0.9" "2.0.0 1.9.9" "1.10.0 1.9.0" "1.0.10 1.0.9"; do
  read -r current requested <<<"$case"
  reset_tap "$current"
  if run_update "$requested"; then
    fail "--update-tap $requested succeeded while the cask was at $current"
  fi
  grep -Fq "already points at FreeSnitch $current, which is newer than $requested" "$WORK/out" || \
    fail "refusing $requested over $current did not name $current: $(cat "$WORK/out")"
  [[ "$(tap_version)" == "$current" ]] || fail "the cask moved from $current to $(tap_version)"
done

# A newer version still bumps the cask.
for case in "1.0.0 1.1.0" "1.9.0 1.10.0" "1.0.9 1.0.10" "0.9.9 1.0.0"; do
  read -r current requested <<<"$case"
  reset_tap "$current"
  run_update "$requested" || fail "--update-tap $requested over $current failed: $(cat "$WORK/out")"
  [[ "$(tap_version)" == "$requested" ]] || fail "the cask did not move from $current to $requested"
done

# The same version is accepted and, with the same checksum, changes nothing.
reset_tap "1.1.0" "$NEW_SHA"
before="$(git -C "$WORK/tap.git" rev-parse main)"
run_update "1.1.0" || fail "--update-tap 1.1.0 at 1.1.0 failed: $(cat "$WORK/out")"
grep -Fq "already points at FreeSnitch 1.1.0." "$WORK/out" || fail "same version was not reported as a no-op: $(cat "$WORK/out")"
[[ "$(git -C "$WORK/tap.git" rev-parse main)" == "$before" ]] || fail "same version pushed a commit"

# A digest GitHub didn't report, or one that isn't a SHA-256, is refused and
# leaves the tap alone.
for digest in "" "sha256:not-a-checksum" "sha512:$NEW_SHA$NEW_SHA" "sha256:${NEW_SHA:0:63}"; do
  reset_tap "1.0.0"
  before="$(git -C "$WORK/tap.git" rev-parse main)"
  printf '%s\n' "$digest" > "$WORK/digest"
  if run_update "1.1.0"; then
    fail "--update-tap succeeded with digest '$digest'"
  fi
  grep -Fq "Could not read the SHA-256" "$WORK/out" || fail "digest '$digest' was not reported: $(cat "$WORK/out")"
  [[ "$(git -C "$WORK/tap.git" rev-parse main)" == "$before" ]] || fail "digest '$digest' changed the tap"
done
rm -f "$WORK/digest"

if (( failures > 0 )); then
  printf '%d update-tap check(s) failed.\n' "$failures" >&2
  exit 1
fi
printf 'update-tap checks passed.\n'
