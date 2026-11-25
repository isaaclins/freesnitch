#!/usr/bin/env bash
# CI only: switch the runner to the newest released Xcode it has and stop if
# that is older than Xcode 26. The runner image defaults to an older Xcode,
# but the Icon Composer app icon (Resources/AppIcon.icon) only compiles with
# Xcode 26, and the harnesses should use the same compiler as the release.
set -euo pipefail

minimum_major=26

# Only plain Xcode_<version>.app folders: no betas, release candidates or
# the image's version symlinks.
xcode=$(find /Applications -maxdepth 1 -type d -name 'Xcode_*.app' \
  | grep -E '/Xcode_[0-9]+(\.[0-9]+)*\.app$' | sort -V | tail -n 1 || true)
if [ -z "$xcode" ]; then
  echo '::error::No released Xcode found on this runner.'
  exit 1
fi

sudo xcode-select -s "$xcode/Contents/Developer"
xcodebuild -version
swiftc --version

major=$(xcodebuild -version | awk 'NR == 1 { split($2, v, "."); print v[1] }')
if ! [[ "$major" =~ ^[0-9]+$ ]] || [ "$major" -lt "$minimum_major" ]; then
  echo "::error::Newest Xcode on this runner is $xcode; FreeSnitch needs Xcode $minimum_major or newer."
  exit 1
fi
