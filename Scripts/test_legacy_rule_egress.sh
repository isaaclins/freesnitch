#!/usr/bin/env bash
# Regression gate for #57.
#
# Rules created by earlier builds can contain values that a later content rule
# rejects, for example reverse-DNS names refused since #15. Reading our own
# store back out must still work, or one legacy row hides every rule from the
# user and can stop policy reaching the extension, which fails open.
#
# Bounds stay enforced on transport, and ingest must still refuse those rules.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-legacy-egress.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cp "$ROOT/Scripts/legacy_rule_egress_check.swift" "$TMP/main.swift"

xcrun swiftc -O -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos13.0 \
  -o "$TMP/run" "$ROOT"/Sources/Shared/*.swift "$TMP/main.swift"

"$TMP/run"
bash "$ROOT/Scripts/audit_firewall_safety.sh" >/dev/null
printf 'legacy rule egress verification: PASS\n'
