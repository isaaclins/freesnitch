#!/usr/bin/env bash
# Static release gate for the Network System Extension's safety invariants.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FILTER="$ROOT/Sources/NetExt/FilterDataProvider.swift"
BRIDGE="$ROOT/Sources/Shared/SharedRuleBridge.swift"
IPC="$ROOT/Sources/Shared/IPCConnection.swift"
PEER_VALIDATOR="$ROOT/Sources/Shared/XPCPeerValidator.swift"
CLI_HELPER="$ROOT/Sources/CLI/CLIHelperClient.swift"
CLI_EXTENSION="$ROOT/Sources/CLI/CLIExtensionClient.swift"
PROJECT_SPEC="$ROOT/project.yml"
HELPER="$ROOT/Sources/Helper/HelperService.swift"
APP_STATE="$ROOT/Sources/GUI/ViewModels/AppState.swift"
SYSTEM_EXTENSION_MANAGER="$ROOT/Sources/GUI/App/SystemExtensionManager.swift"
LAUNCHD_PLIST="$ROOT/Sources/Helper/Launchd.plist"
MODELS="$ROOT/Sources/Shared/Models.swift"
WIRE_CODEC="$ROOT/Sources/Shared/WireCodec.swift"
CLI_CONTRACT="$ROOT/Sources/CLI/CLIContract.swift"
INSIGHTS_STORE="$ROOT/Sources/Helper/InsightsStore.swift"
INSIGHTS_MODELS="$ROOT/Sources/Shared/InsightsModels.swift"
OBSERVATION_QUEUE="$ROOT/Sources/NetExt/ObservationQueue.swift"
UNINSTALL="$ROOT/Scripts/uninstall_freesnitch.sh"

fail() {
  printf 'FIREWALL SAFETY AUDIT FAILED: %s\n' "$*" >&2
  exit 1
}

require_text() {
  local file="$1"
  local text="$2"
  local message="$3"
  grep -Fq -- "$text" "$file" || fail "$message"
}

[[ -f "$FILTER" ]] || fail "missing $FILTER"
[[ -f "$BRIDGE" ]] || fail "missing $BRIDGE"
[[ -f "$IPC" ]] || fail "missing $IPC"
[[ -f "$PEER_VALIDATOR" ]] || fail "missing $PEER_VALIDATOR"
[[ -f "$CLI_HELPER" ]] || fail "missing $CLI_HELPER"
[[ -f "$CLI_EXTENSION" ]] || fail "missing $CLI_EXTENSION"
[[ -f "$PROJECT_SPEC" ]] || fail "missing $PROJECT_SPEC"
[[ -f "$HELPER" ]] || fail "missing $HELPER"
[[ -f "$APP_STATE" ]] || fail "missing $APP_STATE"
[[ -f "$SYSTEM_EXTENSION_MANAGER" ]] || fail "missing $SYSTEM_EXTENSION_MANAGER"
[[ -f "$LAUNCHD_PLIST" ]] || fail "missing $LAUNCHD_PLIST"
[[ -f "$MODELS" ]] || fail "missing $MODELS"
[[ -f "$WIRE_CODEC" ]] || fail "missing $WIRE_CODEC"
[[ -f "$CLI_CONTRACT" ]] || fail "missing $CLI_CONTRACT"
[[ -f "$INSIGHTS_STORE" ]] || fail "missing $INSIGHTS_STORE"
[[ -f "$INSIGHTS_MODELS" ]] || fail "missing $INSIGHTS_MODELS"
[[ -f "$OBSERVATION_QUEUE" ]] || fail "missing $OBSERVATION_QUEUE"
[[ -f "$UNINSTALL" ]] || fail "missing $UNINSTALL"

# Date boundaries are explicit: XPC and snapshots retain Apple's reference
# epoch, SQLite remains Unix seconds, and the CLI contract stays ISO 8601 text.
require_text "$WIRE_CODEC" "date.timeIntervalSinceReferenceDate" \
  "the wire codec does not encode dates with the reference epoch"
require_text "$WIRE_CODEC" "Date(timeIntervalSinceReferenceDate: seconds)" \
  "the wire codec does not decode dates with the reference epoch"
require_text "$CLI_CONTRACT" "encoder.dateEncodingStrategy = .iso8601" \
  "CLI JSON output is no longer ISO 8601"
if grep -Fq "Date(timeIntervalSince1970" "$CLI_CONTRACT"; then
  fail "CLI JSON dates interpret numeric values as Unix seconds"
fi
require_text "$CLI_HELPER" "FreeSnitchWireCodec.decode" \
  "CLI helper responses do not use the explicit wire date codec"
require_text "$CLI_EXTENSION" "SharedRuleBridge.decodeStatus(response)" \
  "CLI snapshot acknowledgements do not use the extension wire codec"
if grep -Fq "CLIJSON.decode(SharedRuleBridge.SnapshotStatus" "$CLI_EXTENSION"; then
  fail "CLI snapshot acknowledgements use the public CLI JSON codec"
fi
require_text "$HELPER" "FreeSnitchWireCodec.decode" \
  "helper rule requests do not use the explicit wire date codec"

# Slice 1 evidence transport and store invariants.
require_text "$INSIGHTS_STORE" "static let defaultPath = \"/Library/Application Support/FreeSnitch/Insights/insights.sqlite\"" \
  "InsightsStore does not isolate evidence below the shared support directory"
require_text "$INSIGHTS_STORE" "expectedUID: uid_t = 0" \
  "InsightsStore has no production root-owner default and test UID seam"
require_text "$INSIGHTS_STORE" "(info.st_mode & 0o022) == 0" \
  "the shared support directory writable-mode check is missing"
require_text "$INSIGHTS_STORE" "mode: 0o700" \
  "the private Insights directory is not strict 0700"
require_text "$INSIGHTS_STORE" "mode: 0o600" \
  "the Insights database companions are not strict 0600"
require_text "$INSIGHTS_STORE" "CREATE TABLE IF NOT EXISTS dns_mappings" \
  "the DNS evidence table is missing"
require_text "$INSIGHTS_STORE" "func recordDNSMappings" \
  "the helper has no direct DNS mapping store method"
require_text "$INSIGHTS_STORE" "func purge()" \
  "the Insights purge seam is missing"
require_text "$INSIGHTS_MODELS" "maxBatchBytes" \
  "bounded Insights payload limits are missing"
require_text "$OBSERVATION_QUEUE" "os_unfair_lock_trylock" \
  "the extension queue enqueue path is not trylock-only"
require_text "$OBSERVATION_QUEUE" "capacity: Int = 1024" \
  "the extension queue capacity is not explicit and modest"
require_text "$FILTER" "FlowObservation(connection: conn)" \
  "the extension does not enqueue a compact observation before verdict handling"
require_text "$FILTER" "observationQueue.drain(maximum: InsightsLimits.maxBatchCount)" \
  "the extension drain is not bounded by the model batch count"
require_text "$IPC" "sendObservationBatch" \
  "the GUI XPC batch sender is missing"
require_text "$SYSTEM_EXTENSION_MANAGER" "observationBatch.count <= InsightsLimits.maxBatchBytes" \
  "the GUI bridge does not enforce the basic observation byte cap"
require_text "$HELPER" "ingestObservationBatch" \
  "the helper observation boundary is missing"
require_text "$HELPER" "batch.validate(payloadBytes: observationBatch.count)" \
  "the helper does not validate the decoded observation batch"
require_text "$HELPER" "recordDNSMappings" \
  "DNSProxy answers are not written directly by the helper"
require_text "$UNINSTALL" "readonly INSIGHTS=\"\${SUPPORT}/Insights\"" \
  "the FreeSnitch uninstall guard does not target the private Insights directory"
require_text "$UNINSTALL" "puresnitch -F all" \
  "the uninstall does not flush the intentionally reused PF anchor"
require_text "$SYSTEM_EXTENSION_MANAGER" \
  "vendorConfiguration[SharedRuleBridge.bootSnapshotVendorConfigurationKey] = snapshotData" \
  "the GUI does not write the persisted boot snapshot to vendorConfiguration"
require_text "$FILTER" "filterConfiguration.vendorConfiguration" \
  "the extension does not read filterConfiguration.vendorConfiguration"
require_text "$BRIDGE" "applyingBootPolicySafety" \
  "stale silent-deny boot policy downgrade is missing"
require_text "$BRIDGE" "NewestWriteWinsQueue" \
  "persisted snapshot coalescing seam is missing"
require_text "$SYSTEM_EXTENSION_MANAGER" "persistenceQueue.takeNewest()" \
  "the GUI does not take the newest persisted snapshot"
require_text "$SYSTEM_EXTENSION_MANAGER" "self.state?.clearFilterPersistenceFailure()" \
  "persistence degradation is not cleared after a successful save"
require_text "$SYSTEM_EXTENSION_MANAGER" "if snapshotData != nil" \
  "a successful save does not prove that a boot snapshot was persisted"
if grep -R -E -q 'io\.isaaclins\.freesnitch\.boot(["<]|$)|BHAF4L4726\.io\.isaaclins\.freesnitch\.boot(["<]|$)|boot-snapshot\.json' \
  "$ROOT/Sources" "$ROOT/project.yml" "$ROOT/project-netext.yml"; then
  fail "an old or experimental boot transport name or cache path is still present"
fi
if ! grep -Fq '<key>io.isaaclins.freesnitch.helper</key>' "$LAUNCHD_PLIST" \
  || grep -Fq 'BHAF4L4726.io.isaaclins.freesnitch.boot' "$LAUNCHD_PLIST"; then
  fail "helper launchd plist does not contain only the main helper MachService"
fi

# A missing GUI must never leave a socket flow paused forever or turn a GUI
# outage into a network outage. Keep this check tied to the actual branch that
# handles the false result from promptUser, not only to a comment.
require_text "$FILTER" "let asked = IPCConnection.shared.promptUser" \
  "the extension no longer asks the GUI through IPCConnection"
require_text "$FILTER" "if !asked {" \
  "the no-GUI path is missing"
require_text "$FILTER" "guard let snapshot = policy.snapshot else" \
  "the no-snapshot path is missing"
require_text "$FILTER" "persisted provider boot policy is missing; filtering will fail open" \
  "the extension does not log its missing persisted-policy state loudly"
require_text "$FILTER" "filter snapshot received over XPC" \
  "the extension does not log received snapshots"
require_text "$IPC" "func updateSnapshot(snapshotJSON: Data, completionHandler: @escaping (Data) -> Void)" \
  "the XPC provider interface has no snapshot update acknowledgement"
require_text "$IPC" "guard XPCPeerValidator.isTrustedGUI(newConnection) else" \
  "the network extension accepts XPC peers without validating the GUI identity"
require_text "$HELPER" "guard XPCPeerValidator.isTrustedGUI(newConnection) else" \
  "the privileged helper no longer shares the GUI peer validator"
require_text "$PEER_VALIDATOR" "kSecGuestAttributeAudit" \
  "the shared XPC peer validator does not prefer audit-token identity"
require_text "$PEER_VALIDATOR" "kSecGuestAttributePid" \
  "the shared XPC peer validator has no pid fallback"
require_text "$PEER_VALIDATOR" "SecCodeCheckValidity" \
  "the shared XPC peer validator does not check the code requirement"
require_text "$PEER_VALIDATOR" "AppConstants.bundleIdCLI" \
  "the shared XPC peer validator does not explicitly allow the bundled CLI"
require_text "$PEER_VALIDATOR" "permittedPeerIdentifiers" \
  "the GUI and CLI peer identities are not held in one validator allowlist"
require_text "$CLI_HELPER" "options: [.privileged]" \
  "the CLI helper client is not using the privileged launchd lookup"
require_text "$CLI_HELPER" "HelperBridge.remoteInterface()" \
  "the CLI helper client is not using the shared HelperProtocol interface"
require_text "$CLI_EXTENSION" "options: [.privileged]" \
  "the CLI extension client is not using the privileged launchd lookup"
require_text "$CLI_HELPER" "proxy.setEnforcementEnabled" \
  "the CLI enforcement path does not go through HelperProtocol"
require_text "$CLI_HELPER" "proxy.flushAll" \
  "the CLI flush path does not go through HelperProtocol"
require_text "$PROJECT_SPEC" "Contents/Helpers/freesnitch" \
  "the CLI is not embedded inside the app bundle"
if grep -R -E -q "SecRequirementCreateWithString|SecCodeCheckValidity" "$ROOT/Sources/CLI" --include='*.swift'; then
  fail "the CLI contains a second peer-validation or code-signature bypass"
fi
requirement_count="$(grep -RohF 'let requirementText = "anchor apple generic"' "$ROOT/Sources" --include='*.swift' | wc -l | tr -d ' ')"
[[ "$requirement_count" == "1" ]] || fail "the GUI XPC requirement is duplicated or missing"
accept_body="$(awk '
  /shouldAcceptNewConnection newConnection: NSXPCConnection/ {
    active = 1
    depth = 0
  }
  active {
    print
    opens = gsub(/\{/, "{")
    closes = gsub(/\}/, "}")
    depth += opens - closes
    if (depth == 0) exit
  }
' "$IPC")"
validation_line="$(printf '%s\n' "$accept_body" | grep -nF 'XPCPeerValidator.isTrustedGUI(newConnection)' | head -1 | cut -d: -f1 || true)"
resume_line="$(printf '%s\n' "$accept_body" | grep -nF 'newConnection.resume()' | head -1 | cut -d: -f1 || true)"
accept_line="$(printf '%s\n' "$accept_body" | grep -nF 'return true' | head -1 | cut -d: -f1 || true)"
reject_line="$(printf '%s\n' "$accept_body" | grep -nF 'return false' | head -1 | cut -d: -f1 || true)"
[[ -n "$validation_line" && -n "$resume_line" && -n "$accept_line" && -n "$reject_line" ]] \
  || fail "the XPC accept path is missing a rejecting validation guard"
(( validation_line < resume_line && validation_line < accept_line && reject_line < resume_line )) \
  || fail "the XPC accept path can resume or accept before peer validation"
if printf '%s\n' "$accept_body" | grep -Fq 'newConnection.resume(); return true'; then
  fail "the XPC accept path is unconditionally accepting peers"
fi
require_text "$APP_STATE" "IPCConnection.shared.sendSnapshot(data)" \
  "the GUI does not push snapshots over XPC"
if grep -Fq "SharedRuleBridge.read" "$FILTER" \
   || grep -Fq "containerURL(forSecurityApplicationGroupIdentifier" "$FILTER" \
   || grep -Fq "containerURL(forSecurityApplicationGroupIdentifier" "$BRIDGE"; then
  fail "the extension still reads policy from a process-local app-group file"
fi

# Each fail-open check is scoped to its own brace block. A window of N lines
# would let one block borrow another block's allow verdict and hide a
# fail-closed regression, so the block is delimited by brace depth instead.
allow_within_block() {
  local file="$1"
  local start_regex="$2"
  awk -v start="$start_regex" '
    !active && $0 ~ start {
      active = 1
      depth = 0
    }
    active {
      if ($0 ~ /resumeOnce\(NEFilterNewFlowVerdict\.allow\(\)\)/) {
        found = 1
        exit 0
      }
      n = gsub(/\{/, "{")
      m = gsub(/\}/, "}")
      depth += n - m
      if (depth <= 0) active = 0
    }
    END { exit(found ? 0 : 1) }
  ' "$file"
}

if ! allow_within_block "$FILTER" 'if !asked[[:space:]]*\{'; then
  fail "the no-GUI path does not fail open with an allow verdict"
fi

# FreeSnitch, its helper, and loopback are safety-critical exemptions. They
# must be decided before the general matcher can pause or drop the flow.
own_line="$(grep -nF 'if isOwnTraffic(conn) || isLoopback(conn.remoteIP) { return .allow() }' "$FILTER" | head -1 | cut -d: -f1 || true)"
matcher_line="$(grep -nF 'matcher.decision(for: conn' "$FILTER" | head -1 | cut -d: -f1 || true)"
[[ -n "$own_line" ]] || fail "own-traffic and loopback exemption is missing"
[[ -n "$matcher_line" ]] || fail "the extension no longer invokes the shared matcher"
if (( own_line >= matcher_line )); then
  fail "own-traffic and loopback must be allowed before matcher.decision"
fi

require_text "$FILTER" "if isOwnCode(pid: conn.pid)" \
  "own-traffic detection no longer checks the process code signature"
require_text "$FILTER" "SecCodeCheckValidity" \
  "own-traffic detection no longer validates a code signature"
require_text "$FILTER" "AppConstants.bundleIdGUI" \
  "the GUI bundle identifier is missing from the own-code requirement"
require_text "$FILTER" "AppConstants.bundleIdCLI" \
  "the CLI bundle identifier is missing from the own-code requirement"
require_text "$FILTER" "AppConstants.bundleIdHelper" \
  "the helper bundle identifier is missing from the own-code requirement"
require_text "$FILTER" "AppConstants.bundleIdNetExt" \
  "the system extension bundle identifier is missing from the own-code requirement"
require_text "$FILTER" 'ip.hasPrefix("127.")' \
  "IPv4 loopback is no longer exempted"
require_text "$FILTER" 'ip == "::1"' \
  "IPv6 loopback is no longer exempted"
require_text "$FILTER" 'ip == "localhost"' \
  "localhost is no longer exempted"

# A path prefix of / is an exemption for every process. Reject the known bad
# shape even if a future refactor moves it into a helper in this source file.
active_code="$(grep -vE '^[[:space:]]*//' "$FILTER" || true)"
if printf '%s\n' "$active_code" | grep -Eq 'hasPrefix\([[:space:]]*"/|==[[:space:]]*"/"|"/[[:space:]]*==|Bundle\.main|URL\(fileURLWithPath:[[:space:]]*"/' ; then
  fail "found a broad root-path or Bundle.main exemption that could whitelist every process"
fi

# The interactive path also needs a timeout. This prevents a connected but
# unresponsive GUI from wedging a flow indefinitely.
require_text "$FILTER" "workQueue.asyncAfter" \
  "interactive flow handling has no timeout"
# The allow verdict may sit on the same line as the asyncAfter call, so the
# matching line itself counts as evidence, not only the lines after it.
if ! allow_within_block "$FILTER" 'workQueue\.asyncAfter'; then
  fail "the interactive timeout does not fail open with an allow verdict"
fi

require_text "$SYSTEM_EXTENSION_MANAGER" "@Published var status: Status = .idle" \
  "system extension status is not published"
require_text "$SYSTEM_EXTENSION_MANAGER" "self.fail(\"filter save: \\(saveError.localizedDescription)\")" \
  "filter-save failures are not recorded in the published status"
require_text "$SYSTEM_EXTENSION_MANAGER" "guard self.requestKind == .activation else" \
  "system extension request completion is not tied to activation"
require_text "$SYSTEM_EXTENSION_MANAGER" "self.enableFilter()" \
  "filter configuration is not enabled from the completed activation callback"
activation_body="$(awk '
  /^    func activate\(\)/ { active = 1 }
  /^    func deactivate\(\)/ { active = 0 }
  active { print }
' "$SYSTEM_EXTENSION_MANAGER")"
if printf '%s\n' "$activation_body" | grep -Fq "enableFilter"; then
  fail "filter configuration is still enabled optimistically during activate()"
fi

printf 'Firewall safety audit passed: fail-open GUI handling, code-signature self exemption, loopback ordering, timeout, XPC snapshots, peer validation, and activation ordering are present.\n'
