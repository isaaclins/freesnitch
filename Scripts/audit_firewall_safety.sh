#!/usr/bin/env bash
# Static release gate for the Network System Extension's safety invariants.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# grep -q stops reading at its first match. A writer still sending into that pipe
# then dies of SIGPIPE, and pipefail turns that into a failed check for text that
# is there (#411). The same happens with rg -q, grep -m, head and an awk program
# that exits early. Match captured text with a here-string, and when such a reader
# has to read a pipe, put read_all_then in front of it: it reads the pipe to the
# end first. Empty input reaches the reader as an empty pipe, not as an empty line
# (and not as /dev/null, which makes rg search the current directory).
read_all_then() {
  local text
  text="$(cat)"
  if [ -n "$text" ]; then
    "$@" <<<"$text"
  else
    printf '' | "$@"
  fi
}

FILTER="$ROOT/Sources/NetExt/FilterDataProvider.swift"
BRIDGE="$ROOT/Sources/Shared/SharedRuleBridge.swift"
SAVE_CYCLE="$ROOT/Sources/Shared/BootPolicySaveCycle.swift"
RULE_STORE="$ROOT/Sources/Shared/RuleStore.swift"
HELPER_PROTOCOL="$ROOT/Sources/Shared/HelperProtocol.swift"
IPC="$ROOT/Sources/Shared/IPCConnection.swift"
PEER_VALIDATOR="$ROOT/Sources/Shared/XPCPeerValidator.swift"
CLI_HELPER="$ROOT/Sources/CLI/CLIHelperClient.swift"
CLI_RUNNER="$ROOT/Sources/CLI/CLIRunner.swift"
CLI_EXTENSION="$ROOT/Sources/CLI/CLIExtensionClient.swift"
GUI_HELPER="$ROOT/Sources/GUI/App/HelperClient.swift"
PROJECT_SPEC="$ROOT/project.yml"
HELPER="$ROOT/Sources/Helper/HelperService.swift"
DNS_PROXY="$ROOT/Sources/Helper/DNSProxy.swift"
APP_STATE="$ROOT/Sources/GUI/ViewModels/AppState.swift"
SYSTEM_EXTENSION_MANAGER="$ROOT/Sources/GUI/App/SystemExtensionManager.swift"
LAUNCHD_PLIST="$ROOT/Sources/Helper/Launchd.plist"
MODELS="$ROOT/Sources/Shared/Models.swift"
WIRE_CODEC="$ROOT/Sources/Shared/WireCodec.swift"
RULE_TRANSPORT="$ROOT/Sources/Shared/RuleTransport.swift"
INSIGHTS_MODELS="$ROOT/Sources/Shared/InsightsModels.swift"
INSIGHTS_STORE="$ROOT/Sources/Helper/InsightsStore.swift"
INSIGHTS_VIEW="$ROOT/Sources/GUI/Views/InsightsView.swift"
CLI_CONTRACT="$ROOT/Sources/CLI/CLIContract.swift"
INSIGHTS_STORE="$ROOT/Sources/Helper/InsightsStore.swift"
INSIGHTS_MODELS="$ROOT/Sources/Shared/InsightsModels.swift"
OBSERVATION_QUEUE="$ROOT/Sources/NetExt/ObservationQueue.swift"
UNINSTALL="$ROOT/Scripts/uninstall_freesnitch.sh"
RULE_MATCHER="$ROOT/Sources/Shared/RuleMatcher.swift"
CLI_PARSER="$ROOT/Sources/CLI/CLIParser.swift"
POLICY_EPOCH="$ROOT/Sources/Shared/PolicyEpoch.swift"
SNAPSHOT_RECOVERY="$ROOT/Sources/Shared/SnapshotRecovery.swift"
PF_MANAGER="$ROOT/Sources/Helper/PFManager.swift"

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
[[ -f "$RULE_STORE" ]] || fail "missing $RULE_STORE"
[[ -f "$HELPER_PROTOCOL" ]] || fail "missing $HELPER_PROTOCOL"
[[ -f "$IPC" ]] || fail "missing $IPC"
[[ -f "$PEER_VALIDATOR" ]] || fail "missing $PEER_VALIDATOR"
[[ -f "$CLI_HELPER" ]] || fail "missing $CLI_HELPER"
[[ -f "$CLI_RUNNER" ]] || fail "missing $CLI_RUNNER"
[[ -f "$CLI_EXTENSION" ]] || fail "missing $CLI_EXTENSION"
[[ -f "$GUI_HELPER" ]] || fail "missing $GUI_HELPER"
[[ -f "$PROJECT_SPEC" ]] || fail "missing $PROJECT_SPEC"
[[ -f "$HELPER" ]] || fail "missing $HELPER"
[[ -f "$APP_STATE" ]] || fail "missing $APP_STATE"
[[ -f "$SYSTEM_EXTENSION_MANAGER" ]] || fail "missing $SYSTEM_EXTENSION_MANAGER"
[[ -f "$LAUNCHD_PLIST" ]] || fail "missing $LAUNCHD_PLIST"
[[ -f "$MODELS" ]] || fail "missing $MODELS"
[[ -f "$WIRE_CODEC" ]] || fail "missing $WIRE_CODEC"
[[ -f "$RULE_TRANSPORT" ]] || fail "missing $RULE_TRANSPORT"
[[ -f "$CLI_CONTRACT" ]] || fail "missing $CLI_CONTRACT"
[[ -f "$INSIGHTS_STORE" ]] || fail "missing $INSIGHTS_STORE"
[[ -f "$INSIGHTS_MODELS" ]] || fail "missing $INSIGHTS_MODELS"
[[ -f "$OBSERVATION_QUEUE" ]] || fail "missing $OBSERVATION_QUEUE"
[[ -f "$UNINSTALL" ]] || fail "missing $UNINSTALL"
[[ -f "$RULE_MATCHER" ]] || fail "missing $RULE_MATCHER"
[[ -f "$CLI_PARSER" ]] || fail "missing $CLI_PARSER"
[[ -f "$DNS_PROXY" ]] || fail "missing $DNS_PROXY"
[[ -f "$POLICY_EPOCH" ]] || fail "missing $POLICY_EPOCH"
[[ -f "$SNAPSHOT_RECOVERY" ]] || fail "missing $SNAPSHOT_RECOVERY"
[[ -f "$PF_MANAGER" ]] || fail "missing $PF_MANAGER"

# A CIDR prefix outside 0...32 used to produce mask 0 through Swift's
# non-trapping smart shift, and mask 0 matches every IPv4 address. The matcher
# must bound the prefix before the mask exists, and both ingest boundaries must
# refuse to store an address the matcher cannot evaluate.
cidr_body="$(awk '
  /func cidrContains\(/ {
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
' "$RULE_MATCHER")"
[[ -n "$cidr_body" ]] || fail "the shared matcher no longer has a cidrContains function to audit"
cidr_guard_line="$(printf '%s\n' "$cidr_body" | grep -nF '(0...32).contains(bits)' | head -1 | cut -d: -f1 || true)"
cidr_mask_line="$(printf '%s\n' "$cidr_body" | grep -nF 'UInt32.max <<' | head -1 | cut -d: -f1 || true)"
[[ -n "$cidr_guard_line" ]] || fail "cidrContains does not bound the CIDR prefix to 0...32, so an over-large prefix can match every address"
[[ -n "$cidr_mask_line" ]] || fail "cidrContains no longer builds the expected IPv4 mask"
(( cidr_guard_line < cidr_mask_line )) \
  || fail "cidrContains builds the mask before bounding the prefix"
if ! grep -Fq 'parts[1].utf8.allSatisfy({ $0 >= 48 && $0 <= 57 })' <<<"$cidr_body"; then
  fail "cidrContains accepts a non-numeric or signed prefix instead of digits only"
fi
# An IPv6 CIDR was accepted at ingest and could never match, so an enabled rule
# did nothing. The IPv6 path must exist, must bound its prefix to 0...128 before
# any mask is built, and must stay a separate address space from IPv4.
swift_function_body() {
  awk -v start="$2" '
    index($0, start) > 0 && !seen {
      seen = 1
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
  ' "$1"
}

grep -Fq 'if net.contains(":") { return ipv6CidrContains(' <<<"$cidr_body" \
  || fail "cidrContains no longer routes an IPv6 network to the IPv6 matcher, so IPv6 CIDR rules are inert again"
ipv6_body="$(swift_function_body "$RULE_MATCHER" 'func ipv6CidrContains(')"
[[ -n "$ipv6_body" ]] || fail "the shared matcher has no ipv6CidrContains function to audit"
ipv6_guard_line="$(printf '%s\n' "$ipv6_body" | grep -nF '(0...128).contains(bits)' | head -1 | cut -d: -f1 || true)"
ipv6_mask_line="$(printf '%s\n' "$ipv6_body" | grep -nF 'UInt8(0xFF) <<' | head -1 | cut -d: -f1 || true)"
[[ -n "$ipv6_guard_line" ]] || fail "ipv6CidrContains does not bound the CIDR prefix to 0...128, so an over-large prefix can match every address"
[[ -n "$ipv6_mask_line" ]] || fail "ipv6CidrContains no longer builds the expected IPv6 mask"
(( ipv6_guard_line < ipv6_mask_line )) \
  || fail "ipv6CidrContains builds the mask before bounding the prefix"
grep -Fq 'ipv6Bytes(network), let addr = ipv6Bytes(ip)' <<<"$ipv6_body" \
  || fail "ipv6CidrContains no longer parses both sides as IPv6, so an IPv4 address could reach the IPv6 comparison"
require_text "$RULE_MATCHER" "inet_pton(AF_INET6" \
  "the matcher no longer parses IPv6 with inet_pton, so it can disagree with what ingest validated"

# Every new socket flow used to filter and sort the whole rule set before the
# verdict. That ordering belongs to the snapshot, and the verdict path must
# stay a scan over the already ordered array.
require_text "$RULE_MATCHER" "public struct PreparedRuleSet" \
  "the precomputed rule order is missing, so every flow pays a filter and a sort again"
verdict_body="$(swift_function_body "$RULE_MATCHER" 'func explainedDecision(for c: Connection, prepared:')"
[[ -n "$verdict_body" ]] || fail "the shared matcher has no prepared-rule verdict path to audit"
# Every app's name lookups leave through the system resolver. With no rule
# for it, the default mode must not ask about it or drop it, or DNS stops for
# the whole Mac until someone answers (#422).
# Only Apple's resolver at its system path gets that default, never any other
# port-53 flow (#30): the path and the signature check must both hold.
grep -Fq 'if sentBySystemResolver, c.direction == .outgoing { return (askFloor ? .ask : .allow, skipped, nil) }' <<<"$verdict_body" \
  || fail "the system resolver's default allow is missing or no longer needs both its path and its signature"
require_text "$RULE_MATCHER" 'public static let systemResolverPath = "/usr/sbin/mDNSResponder"' \
  "the system resolver is no longer identified by its protected system path"
require_text "$RULE_MATCHER" 'public static let systemResolverRequirement = "anchor apple and identifier \"com.apple.mDNSResponder\""' \
  "the system resolver's signature requirement is no longer Apple's mDNSResponder"
require_text "$RULE_MATCHER" 'passesRequirement && senderPath == systemResolverPath' \
  "the system resolver no longer needs both its path and its signature"
require_text "$FILTER" 'let senderToken = socketFlow.sourceProcessAuditToken ?? socketFlow.sourceAppAuditToken' \
  "the extension no longer identifies the resolver by the process that sent the flow"
require_text "$FILTER" 'systemResolverIdentity.isSystemResolver(processAuditToken: senderToken)' \
  "the extension no longer checks the process that sent the flow against the resolver identity"
RESOLVER_IDENTITY="$ROOT/Sources/NetExt/SystemResolverIdentity.swift"
require_text "$RESOLVER_IDENTITY" 'guard path == RuleMatcher.systemResolverPath else { return false }' \
  "the extension no longer checks the sending process's path before vouching for the resolver"
require_text "$RESOLVER_IDENTITY" 'passes = SecCodeCheckValidity(code, [], requirement) == errSecSuccess' \
  "the system resolver's signature is no longer checked against the running code"
require_text "$RESOLVER_IDENTITY" 'RuleMatcher.isSystemResolver(senderPath: path, passesRequirement: passes)' \
  "the extension no longer combines the resolver's path and signature through the shared rule"
for forbidden in '.sorted' '.filter' '.map('; do
  if grep -Fq -- "$forbidden" <<<"$verdict_body"; then
    fail "the per-flow verdict path uses $forbidden, which reorders or allocates on every flow"
  fi
done
grep -Fq 'for r in prepared.compiled' <<<"$verdict_body" \
  || fail "the per-flow verdict path no longer scans the compiled rule order"
if grep -Eq 'matches\(rule:|ipMatches\(|hostMatches\(' <<<"$verdict_body"; then
  fail "the prepared verdict path reparses rule text instead of using compiled match data"
fi
address_line="$(printf '%s\n' "$verdict_body" | grep -nF 'PreparedConnectionAddress(' | head -1 | cut -d: -f1 || true)"
scan_line="$(printf '%s\n' "$verdict_body" | grep -nF 'for r in prepared.compiled' | head -1 | cut -d: -f1 || true)"
[[ -n "$address_line" && -n "$scan_line" ]] \
  || fail "the prepared verdict path does not parse the connection address once before scanning rules"
(( address_line < scan_line )) \
  || fail "the prepared verdict path starts scanning before parsing the connection address"
prepared_body="$(swift_function_body "$RULE_MATCHER" 'public init(rules: [Rule])')"
[[ -n "$prepared_body" ]] || fail "PreparedRuleSet has no initializer to audit"
grep -Fq 'lhs.offset < rhs.offset' <<<"$prepared_body" \
  || fail "PreparedRuleSet no longer breaks equal priorities by snapshot order, so which rule wins becomes undefined"
grep -Fq 'compiled = ordered.map(PreparedRule.init)' <<<"$prepared_body" \
  || fail "PreparedRuleSet does not compile each ordered rule when the snapshot is applied"
prepared_ip_body="$(swift_function_body "$RULE_MATCHER" 'fileprivate struct PreparedIPPattern')"
[[ -n "$prepared_ip_body" ]] || fail "the prepared matcher has no compiled IP pattern representation"
prepared_v4_guard_line="$(printf '%s\n' "$prepared_ip_body" | grep -nF '(0...32).contains(bits)' | head -1 | cut -d: -f1 || true)"
prepared_v4_mask_line="$(printf '%s\n' "$prepared_ip_body" | grep -nF 'let mask: UInt32' | head -1 | cut -d: -f1 || true)"
[[ -n "$prepared_v4_guard_line" ]] \
  || fail "compiled IPv4 CIDR patterns do not reject prefixes above 32"
[[ -n "$prepared_v4_mask_line" ]] \
  || fail "compiled IPv4 CIDR patterns no longer build the expected mask"
(( prepared_v4_guard_line < prepared_v4_mask_line )) \
  || fail "compiled IPv4 CIDR patterns build a mask before bounding the prefix"
prepared_v6_guard_line="$(printf '%s\n' "$prepared_ip_body" | grep -nF '(0...128).contains(bits)' | head -1 | cut -d: -f1 || true)"
prepared_v6_network_line="$(printf '%s\n' "$prepared_ip_body" | grep -nF 'PreparedIPv6Network(address: address, prefix: bits)' | head -1 | cut -d: -f1 || true)"
[[ -n "$prepared_v6_guard_line" ]] \
  || fail "compiled IPv6 CIDR patterns do not reject prefixes above 128"
[[ -n "$prepared_v6_network_line" ]] \
  || fail "compiled IPv6 CIDR patterns no longer retain their bounded prefix"
(( prepared_v6_guard_line < prepared_v6_network_line )) \
  || fail "compiled IPv6 CIDR patterns build a network before bounding the prefix"
grep -Fq 'parts[1].utf8.allSatisfy({ $0 >= 48 && $0 <= 57 })' <<<"$prepared_ip_body" \
  || fail "compiled CIDR patterns accept a non-numeric or signed prefix"
grep -Fq 'if network.contains(":")' <<<"$prepared_ip_body" \
  || fail "compiled rules no longer keep IPv4 and IPv6 CIDRs in separate address spaces"
grep -Fq 'parsePreparedIPv4Address(network)' <<<"$prepared_ip_body" \
  || fail "PreparedRuleSet does not parse IPv4 CIDR networks when the snapshot is applied"
grep -Fq 'parsePreparedIPv6Address(network)' <<<"$prepared_ip_body" \
  || fail "PreparedRuleSet does not parse IPv6 CIDR networks when the snapshot is applied"
grep -Fq 'if raw == rawIP { return true }' <<<"$prepared_ip_body" \
  || fail "compiled IP rules no longer preserve exact-text matches for malformed stored values"
require_text "$RULE_MATCHER" 'octet.count == 1 || octet.first != "0"' \
  "compiled IPv4 parsing accepts ambiguous leading-zero octets"

require_text "$RULE_MATCHER" "public enum RuleAddressValidator" \
  "the shared rule address validator is missing"
require_text "$RULE_MATCHER" "PFHostValidator.kind(for: value)" \
  "the rule address validator does not reuse PFHostValidator"
require_text "$CLI_PARSER" "RuleAddressValidator.rejectionReason(forRemoteIP: value)" \
  "the CLI stores --ip without validating it"
require_text "$HELPER" "RuleAddressValidator.rejectionReason(forRemoteIP: rule.remoteIP)" \
  "the helper trusts its callers to have validated rule addresses"
for ingest_func in 'func addRule[(]' 'func reloadRules[(]'; do
  ingest_body="$(awk -v start="$ingest_func" '
    $0 ~ start {
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
  ' "$HELPER")"
  reason_line="$(printf '%s\n' "$ingest_body" | grep -nF 'rejectionReason(for:' | head -1 | cut -d: -f1 || true)"
  persist_line="$(printf '%s\n' "$ingest_body" | grep -nF 'mutatePolicy' | head -1 | cut -d: -f1 || true)"
  [[ -n "$reason_line" && -n "$persist_line" ]] \
    || fail "a helper rule ingest path stores rules without an address rejection check"
  (( reason_line < persist_line )) \
    || fail "a helper rule ingest path stores the rule before validating its address"
done

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
require_text "$RULE_TRANSPORT" "maximumEncodedSnapshotBytes" \
  "shared rule snapshot byte limit is missing"
require_text "$RULE_TRANSPORT" "maximumEncodedRuleBatchBytes" \
  "shared rule batch byte limit is missing"
require_text "$RULE_TRANSPORT" "maximumEncodedSingleRuleBytes" \
  "shared single-rule byte limit is missing"
require_text "$RULE_TRANSPORT" "maximumDecodedRuleCount" \
  "shared decoded rule count limit is missing"
require_text "$RULE_TRANSPORT" "fieldTooLong" \
  "shared bounded rule field failure is missing"
rule_transport_gate() {
  local file="$1"
  local function_start="$2"
  local byte_check="$3"
  local decode_call="$4"
  local label="$5"
  local body
  body="$(swift_function_body "$file" "$function_start")"
  [[ -n "$body" ]] || fail "$label receiver is missing"
  local byte_line decode_line
  byte_line="$(printf '%s\n' "$body" | grep -nF "$byte_check" | head -1 | cut -d: -f1 || true)"
  decode_line="$(printf '%s\n' "$body" | grep -nF "$decode_call" | head -1 | cut -d: -f1 || true)"
  [[ -n "$byte_line" ]] || fail "$label receiver does not validate bytes"
  [[ -n "$decode_line" ]] || fail "$label receiver no longer has its rule decode"
  (( byte_line < decode_line )) || fail "$label receiver decodes before validating bytes"
}

rule_transport_gate "$FILTER" \
  'private func receiveSnapshot(_ data: Data)' \
  'try RuleTransportBoundary.validateSnapshotBytes(data)' \
  'SharedRuleBridge.decode(data)' \
  'network extension live snapshot'
rule_transport_gate "$HELPER" \
  'func reloadRules(rulesJSON: Data' \
  'try RuleTransportBoundary.validateRuleBatchBytes(rulesJSON)' \
  'FreeSnitchWireCodec.decode([Rule].self' \
  'helper reload-rules'
rule_transport_gate "$HELPER" \
  'func replaceRules(rulesJSON: Data' \
  'try RuleTransportBoundary.validateRuleBatchBytes(rulesJSON)' \
  'FreeSnitchWireCodec.decode([Rule].self' \
  'helper replace-rules'
rule_transport_gate "$HELPER" \
  'func addRule(ruleJSON: Data' \
  'try RuleTransportBoundary.validateSingleRuleBytes(ruleJSON)' \
  'FreeSnitchWireCodec.decode(Rule.self' \
  'helper add-rule'

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
require_text "$FILTER" "FlowObservation(connection: conn, observedAt: observedAt," \
  "the extension does not enqueue a compact observation for each flow"
require_text "$FILTER" "processVersion: version, decision: decision))" \
  "the extension does not record the decision each flow got (#447)"
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
require_text "$HELPER" "insightsObservationQueue.async" \
  "observation writes are not handed to a background helper queue"
require_text "$HELPER" "insightsDNSQueue.async" \
  "DNS mapping writes are not handed to a background helper queue"
require_text "$HELPER" "insightsMaintenanceQueue.async" \
  "startup prune is not asynchronous"
if awk '
  /func ingestObservationBatch\(/ { active = 1 }
  active { print }
  active && /^    func getInsightsRecordingEnabled/ { exit }
' "$HELPER" | read_all_then grep -Fq 'insights.record'; then
  fail "recordObservationBatch performs SQLite recording on the XPC reply path"
fi
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
# The save cycle's decisions live in BootPolicySaveCycle, which
# Scripts/test_boot_policy_save_failure.sh runs branch by branch (#310). These
# gates keep the app wired to it.
require_text "$SAVE_CYCLE" "let pending = queue.takeNewest()" \
  "the save cycle does not take the newest persisted snapshot"
require_text "$SYSTEM_EXTENSION_MANAGER" "self.persistenceCycle.afterLoad(" \
  "the GUI does not let the save cycle decide what happens after loading the preferences"
require_text "$SYSTEM_EXTENSION_MANAGER" "self.persistenceCycle.afterSave(save, saveFailed: saveError != nil," \
  "the GUI does not let the save cycle decide what happens after a save"
require_text "$SYSTEM_EXTENSION_MANAGER" "if result.clearWarning {" \
  "persistence degradation is not cleared after a successful save"
require_text "$SYSTEM_EXTENSION_MANAGER" "self.state?.clearFilterPersistenceFailure()" \
  "persistence degradation is not cleared after a successful save"
require_text "$SYSTEM_EXTENSION_MANAGER" "if let snapshotData = save.pending?.data" \
  "a successful save does not prove that a boot snapshot was persisted"
# A failed boot-policy save must not leave an older saved policy as the last
# word (#213): the app keeps the failed snapshot and retries, and the
# extension refuses a saved policy older than the last live one it enforced.
require_text "$SAVE_CYCLE" "queue.requeueFailed(pending)" \
  "a failed boot-policy save is dropped instead of retried"
require_text "$SYSTEM_EXTENSION_MANAGER" "self.carryOut(result.next, removal: removesBootSnapshot)" \
  "the GUI does not schedule the retry of a failed boot-policy save"
# A failed save while turning the filter on puts the loaded state back on the
# shared manager before the next preferences operation may start (#345).
save_turn_block="$(awk '/mgr.saveToPreferences [{] saveError in/ && !n++ {a=1} a {print} a && /self.endPersistenceTurn[(][)]/ {exit}' "$SYSTEM_EXTENSION_MANAGER")"
grep -Fq 'if saveError != nil && shouldEnable {' <<<"$save_turn_block" \
  || fail "a failed save while turning the filter on does not put the loaded filter state back before the next preferences operation"
for restore in 'mgr.isEnabled = loadedEnabled' 'mgr.providerConfiguration = loadedConfiguration' \
               'mgr.localizedDescription = loadedDescription'; do
  grep -Fq "$restore" <<<"$save_turn_block" \
    || fail "a failed save while turning the filter on leaves the enable in memory, where the retry could save it"
done
require_text "$FILTER" "watermark.supersedes(decoded)" \
  "the extension can load a saved boot policy older than the last live policy it enforced"
require_text "$FILTER" "if decision == .accepted { recordLiveWatermark(accepted) }" \
  "the extension does not remember which live policy it last enforced"
enable_body="$(awk '/private func enableFilter\(/ {a=1} a {print} a && /^    }$/ {exit}' "$SYSTEM_EXTENSION_MANAGER")"
grep -Fq 'persistenceCycle.requestEnable()' <<<"$enable_body" \
  || fail "turning the filter on can save a snapshot kept for a retry instead of the helper's fresh answer"
disable_body="$(awk '/private func disableFilter\(\)/ {a=1} a {print} a && /^    }$/ {exit}' "$SYSTEM_EXTENSION_MANAGER")"
grep -Fq 'cancelPendingPersistence()' <<<"$disable_body" \
  || fail "a boot-policy retry can still run after the filter is turned off"
remove_body="$(awk '/private func removeFilterConfiguration\(/ {a=1} a {print} a && /^    }$/ {exit}' "$SYSTEM_EXTENSION_MANAGER")"
grep -Fq 'cancelPendingPersistence()' <<<"$remove_body" \
  || fail "a boot-policy retry can recreate the filter configuration after uninstall removed it"
cancel_body="$(awk '/private func cancelPendingPersistence\(\)/ {a=1} a {print} a && /^    }$/ {exit}' "$SYSTEM_EXTENSION_MANAGER")"
grep -Fq 'persistenceCycle.cancel()' <<<"$cancel_body" \
  || fail "cancelling a boot-policy save does not invalidate a save already in flight"
request_body="$(awk '/private func requestPersistedSnapshot\(/ {a=1} a {print} a && /^    }$/ {exit}' "$SYSTEM_EXTENSION_MANAGER")"
require_text "$SAVE_CYCLE" "queue.hasNewerWork(since: attempted)" \
  "a boot-policy save put back for a retry also starts an extra immediate cycle, which repeats the give-up message"
# Rules too big for the boot policy are still enforced live, so turning the
# filter on goes ahead; the older saved policy is removed so the next start
# fails open instead of enforcing rules the user has since changed (#320).
grep -Fq 'persistenceCycle.queueRemoval()' <<<"$request_body" \
  || fail "a policy too big for the boot policy leaves an older saved policy in place for the next start"
require_text "$SAVE_CYCLE" "queue.enqueue(SharedRuleBridge.bootSnapshotRemoval)" \
  "a policy too big for the boot policy leaves an older saved policy in place for the next start"
if grep -Eq 'dropEnableRequest|abandonEnableIfIdle|fail\(' <<<"$request_body"; then
  fail "a policy too big for the boot policy stops the filter from being turned on"
fi
require_text "$SYSTEM_EXTENSION_MANAGER" \
  "vendorConfiguration.removeValue(forKey: SharedRuleBridge.bootSnapshotVendorConfigurationKey)" \
  "the boot-policy removal does not take the saved policy out of vendorConfiguration"
removal_block="$(awk '/if result.removedSavedPolicy [{]/ {a=1} a {print} a && /[}] else if result.savedPolicy/ {exit}' "$SYSTEM_EXTENSION_MANAGER")"
[[ -n "$removal_block" ]] || fail "the boot-policy save cycle no longer handles a removal on its own"
if grep -Fq 'clearFilterPersistenceFailure()' <<<"$removal_block"; then
  fail "removing the saved policy clears the could-not-keep-for-restart banner"
fi
# Over the limit, every rule edit fails to encode again; the error is logged
# once per change of state, also when no filter is configured (#342).
grep -Fq 'recordPersistenceFailure("encode", error: error, unsavable: reason, writeLog: firstTime)' <<<"$request_body" \
  || fail "every rule edit over the boot policy limit logs the same error again"
grep -Fq 'let firstTime = !unsavableLogged' <<<"$request_body" \
  || fail "the over-limit log-once check is no longer keyed on the state, so a changed rule count logs again"
grep -Fq 'if filterConfigurationActive || persistenceCycle.enableRequested {' <<<"$request_body" \
  || fail "with no per-process filter, every rule edit over the limit flashes the won't-survive-a-restart banner"
no_config_block="$(awk '/case .stop\(.noConfiguration\):/ {a=1} a {print} a && /return$/ {exit}' "$SYSTEM_EXTENSION_MANAGER")"
[[ -n "$no_config_block" ]] || fail "the save cycle no longer handles a missing filter configuration on its own"
if grep -Fq 'unsavableLogged' <<<"$no_config_block"; then
  fail "a save cycle with no filter configured forgets the over-limit error was logged, so the next edit logs it again"
fi
# A removal that gives up never suggests Send Rules Again, and one while the
# filter isn't in use (no banner shown) leaves the activity log alone (#349).
giveup_body="$(awk '/private func carryOut\(/ {a=1} a {print} a && /^    }$/ {exit}' "$SYSTEM_EXTENSION_MANAGER")"
grep -Fq 'let message = removal' <<<"$giveup_body" \
  || fail "a boot-policy removal that gives up logs the generic Send Rules Again error"
grep -Fq 'if removal && state?.filterPersistenceUnsavable == nil {' <<<"$giveup_body" \
  || fail "a boot-policy removal while the filter isn't in use writes an error to the activity log when it gives up"
if grep -F 'self.carryOut(' "$SYSTEM_EXTENSION_MANAGER" | read_all_then grep -Fvq 'removal: '; then
  fail "a boot-policy retry no longer says whether the failed save was a removal"
fi
require_text "$SYSTEM_EXTENSION_MANAGER" "let removalQueued = self.persistenceCycle.queue.peekNewest == SharedRuleBridge.bootSnapshotRemoval" \
  "a failed load before a removal while the filter isn't in use raises a banner"
require_text "$SYSTEM_EXTENSION_MANAGER" "unsavable: self.unsavableLogged ? self.state?.filterPersistenceUnsavable : nil" \
  "a failed preferences load while the removal is queued swaps the over-limit banner for the Send Rules Again one"
require_text "$SYSTEM_EXTENSION_MANAGER" "unsavable: removesBootSnapshot ? self.state?.filterPersistenceUnsavable : nil" \
  "a failed save of the boot-policy removal swaps the over-limit banner for the Send Rules Again one"
# Removing rules only helps when the count or size is the cause; a policy
# dated after the clock (or any other failure) must not say so (#341).
if grep -Fq 'Remove some rules' "$ROOT/Sources/GUI/Views/HelperBanner.swift"; then
  fail "the won't-survive-a-restart banner tells the user to remove rules whatever the cause"
fi
grep -Fq 'Self.unsavableReason(SharedRuleBridge.BootSnapshotProblem(error, ruleCount: snapshot.rules.count)' <<<"$request_body" \
  || fail "a boot policy that can't be kept no longer says why"
for problem_case in datedInFuture other; do
  if awk -v c="case .$problem_case" 'index($0, c) {a=1; next} a && /case \.|^        }$/ {exit} a {print}' "$SYSTEM_EXTENSION_MANAGER" | read_all_then grep -Fq 'Remove'; then
    fail "a boot policy that can't be kept because of $problem_case tells the user to remove rules"
  fi
done
require_text "$SYSTEM_EXTENSION_MANAGER" "if result.reportFailure {" \
  "a save the user cancelled by turning the filter on, off or removing it can bring the warning back"
require_text "$ROOT/Sources/GUI/Views/HelperBanner.swift" 'liveRulesReady ? String(localized: "The filter is using them now.") : nil' \
  "the over-limit banner says the filter is using the rules when the extension does not hold them"
grep -Fq 'clearFilterPersistenceFailure()' <<<"$remove_body" \
  || fail "removing the filter configuration leaves the could-not-save banner up"
grep -Fq 'clearFilterPersistenceFailure()' <<<"$no_config_block" \
  || fail "a save cycle that finds no filter configuration leaves the could-not-save banner up"
# With the filter off nothing restarts with the saved rules, so a failed
# boot-policy save is logged without the could-not-save banner, and turning
# the filter on saves the current rules again (#321). FilterOffState holds
# the decisions; test_boot_policy_save_failure.sh runs them.
failure_body="$(awk '/private func recordPersistenceFailure\(/ {a=1} a {print} a && /^    }$/ {exit}' "$SYSTEM_EXTENSION_MANAGER")"
printf '%s\n' "$failure_body" | read_all_then awk '/if !filterOff.saveFailureShowsBanner/ {g=1} g && /return$/ {r=1} /recordFilterPersistenceFailure/ {seen=1; ok=g&&r; exit} END {exit !(seen&&ok)}' \
  || fail "a boot-policy save that fails while the filter is off still raises the could-not-save banner"
require_text "$SYSTEM_EXTENSION_MANAGER" "self.apply(self.filterOff.observed(configured: true, enabled: mgr.isEnabled," \
  "a save cycle does not notice the filter is off, so its failure raises the could-not-save banner"
grep -A2 -F 'if completion == .active {' "$SYSTEM_EXTENSION_MANAGER" | read_all_then grep -Fq 'self.filterOff.turnedOn()' \
  || fail "a turn-off that finishes after a turn-on was asked for leaves the filter treated as off while it is on"
[[ "$(grep -cF 'self.filterOff.turnedOff(turnOnPending: self.persistenceCycle.enableRequested)' "$SYSTEM_EXTENSION_MANAGER")" -eq 2 ]] \
  || fail "turning the filter off or removing it does not record the filter as off, or overrides a turn-on asked for meanwhile"
# Once the configuration is off or removed nothing filters, whatever macOS
# answers about deactivating the extension; usually "after a restart" (#335).
[[ "$(grep -A1 -F 'if self.filterOff.turnedOff(turnOnPending: self.persistenceCycle.enableRequested) {' "$SYSTEM_EXTENSION_MANAGER" | grep -cF 'self.showNotFiltering()')" -eq 2 ]] \
  || fail "turning the filter off or removing it leaves the app saying the firewall is active"
not_filtering_body="$(awk '/private func showNotFiltering\(\)/ {a=1} a {print} a && /^    }$/ {exit}' "$SYSTEM_EXTENSION_MANAGER")"
grep -Fq 'filterConfigurationActive = false' <<<"$not_filtering_body" \
  && grep -Fq 'status = .idle' <<<"$not_filtering_body" \
  || fail "turning the filter off or removing it does not reset the firewall status"
# A save refused because the filter was turned on or off in System Settings
# after the load is loaded and saved again onto that change, never reported
# as a failure or written back from the stale load (#368).
require_text "$SYSTEM_EXTENSION_MANAGER" "NEFilterManagerError.configurationStale.rawValue" \
  "a save refused because the filter changed in System Settings is not recognised (#368)"
require_text "$SYSTEM_EXTENSION_MANAGER" "let changedOutside = Self.changedOutside(saveError)" \
  "a rule save does not tell a save refused after a change in System Settings from other failures (#368)"
require_text "$SYSTEM_EXTENSION_MANAGER" "changedOutside: changedOutside)" \
  "a save refused because the filter changed in System Settings is reported as a failure instead of saved again (#368)"
require_text "$SYSTEM_EXTENSION_MANAGER" "forName: .NEFilterConfigurationDidChange" \
  "turning the filter on or off in System Settings is not noticed, so a failure can be hidden while it is on"
init_body="$(awk '/^    init\(state: AppState[,)]/ {a=1} a {print} a && /^    }$/ {exit}' "$SYSTEM_EXTENSION_MANAGER")"
grep -Fq 'if hasEmbeddedExtension { refreshFilterOffState() }' <<<"$init_body" \
  || fail "the app does not read at launch whether the filter is off, so an early save failure can raise the banner (#348)"
refresh_body="$(awk '/private func refreshFilterOffState\(\)/ {a=1} a {print} a && /^    }$/ {exit}' "$SYSTEM_EXTENSION_MANAGER")"
grep -Fq 'fromOutside: true' <<<"$refresh_body" \
  && grep -Fq 'self.apply(change)' <<<"$refresh_body" \
  || fail "turning the filter on in System Settings does not save the current rules again"
apply_body="$(awk '/private func apply\(_ change: FilterOffState.Change\)/ {a=1} a {print} a && /^    }$/ {exit}' "$SYSTEM_EXTENSION_MANAGER")"
save_current_body="$(printf '%s\n' "$apply_body" | read_all_then awk '/case \.saveCurrentRules:/ {a=1; next} a && /^        (case |})/ {exit} a {print}')"
grep -Fq 'state?.syncSharedRules()' <<<"$save_current_body" \
  || fail "turning the filter on in System Settings does not save the current rules again"
# Turned on there, the app turns it on as its own switch does, so the status
# says active once the current rules are saved (#361).
printf '%s\n' "$save_current_body" | grep -B1 -F 'enableFilter(fromSettings: true)' | read_all_then grep -Fq 'if hasEmbeddedExtension && settingsTurnOnMayRun {' \
  || fail "turning the filter on in System Settings leaves the app saying it is not filtering"
may_run_body="$(awk '/private var settingsTurnOnMayRun: Bool/ {a=1} a {print} a && /^    }$/ {exit}' "$SYSTEM_EXTENSION_MANAGER")"
grep -Fq 'case .idle: return true' <<<"$may_run_body" \
  && grep -Fq 'case .failed: return turnOnFromSettings' <<<"$may_run_body" \
  && grep -Fq 'default: return false' <<<"$may_run_body" \
  && grep -A3 -F 'status = .activating' "$SYSTEM_EXTENSION_MANAGER" | read_all_then grep -Fq 'turnOnFromSettings = false' \
  || fail "a turn-on from System Settings runs during approval or after a failed activation, or a failed one can't be tried again (#383)"
grep -A4 -F 'if loadError == nil && self.persistenceCycle.enableRequested' "$SYSTEM_EXTENSION_MANAGER" \
    | tr -d '\n' | read_all_then grep -Eq '!FilterOffState\.turnOnStands\(fromSettings: self\.turnOnFromSettings, +configured: mgr\.providerConfiguration != nil, +enabled: mgr\.isEnabled\) \{ +self\.persistenceCycle\.dropEnableRequest\(\)' \
  && grep -Fq 'enableFilter(fromSettings: true)' "$SYSTEM_EXTENSION_MANAGER" \
  || fail "a turn-on that follows System Settings turns the filter back on after it was turned off there again (#361)"
clear_banner_body="$(printf '%s\n' "$apply_body" | read_all_then awk '/case \.clearBanner:/ {a=1; next} a && /^        (case |})/ {exit} a {print}')"
printf '%s\n' "$clear_banner_body" | grep -A1 -F 'if (filterConfigurationActive || abandonedTurnOnShown) && !persistenceCycle.enableRequested {' | read_all_then grep -Fq 'showNotFiltering()' \
  || fail "turning the filter off in System Settings leaves the app saying the firewall is active (#361)"
# A turn-on from System Settings that the helper gave no rules for: turned
# off there again meanwhile, that is not a failed turn-on (#382).
snapshot_status_body="$(awk '/private func recordSnapshotStatus\(/ {a=1} a {print} a && /^    }$/ {exit}' "$SYSTEM_EXTENSION_MANAGER")"
printf '%s\n' "$snapshot_status_body" | grep -A1 -F 'if turnOnFromSettings {' | read_all_then grep -Fq 'reportAbandonedSettingsTurnOn(message)' \
  && grep -Fq 'failAbandonedTurnOn(message)' <<<"$snapshot_status_body" \
  && awk '/private func failAbandonedTurnOn\(/ {a=1} a {print} a && /^    }$/ {exit}' "$SYSTEM_EXTENSION_MANAGER" | read_all_then grep -Fq 'abandonedTurnOnShown = true' \
  || fail "a turn-on from System Settings that was turned off there again reports a failed turn-on (#382)"
abandoned_body="$(awk '/private func reportAbandonedSettingsTurnOn\(/ {a=1} a {print} a && /^    }$/ {exit}' "$SYSTEM_EXTENSION_MANAGER")"
grep -Fq 'filterPreferences.run {' <<<"$abandoned_body" \
  && grep -Fq 'guard !self.persistenceCycle.enableRequested else { return }' <<<"$abandoned_body" \
  && printf '%s\n' "$abandoned_body" | tr -d '\n' | read_all_then grep -Eq 'FilterOffState\.abandonedTurnOnFailed\(fromSettings: true, readFailed: error != nil, +configured: configured, enabled: enabled\) \{ +self\.failAbandonedTurnOn\(message\) +return +\}' \
  && grep -Fq 'guard self.status != .needsApproval && self.status != .activating else { return }' <<<"$abandoned_body" \
  && printf '%s\n' "$abandoned_body" | grep -A3 -F 'self.apply(self.filterOff.observed(configured: configured, enabled: enabled, fromOutside: true))' | read_all_then grep -Fq 'self.showNotFiltering()' \
  || fail "a turn-on from System Settings given up for lack of rules does not check whether the filter is still on there (#382)"
grep -A4 -F 'self.filterOff.turnedOff(turnOnPending: false)' "$SYSTEM_EXTENSION_MANAGER" | read_all_then grep -Fq 'if self.filterConfigurationActive && !self.persistenceCycle.enableRequested { self.showNotFiltering() }' \
  || fail "a save cycle that finds the filter removed leaves the app saying the firewall is active (#361)"
printf '%s\n' "$apply_body" | grep -A2 -F 'case .clearBanner:' | read_all_then grep -Fq 'state?.clearFilterPersistenceFailure()' \
  || fail "finding the filter off leaves an earlier could-not-save banner up"
grep -Fq 'filterOff.turnedOn()' <<<"$enable_body" \
  || fail "turning the filter on keeps treating it as off, so a failed save there stays hidden"
stop_body="$(awk '/override func stopFilter\(/ {a=1} a {print} a && /^    }$/ {exit}' "$FILTER")"
grep -Fq 'watermarkQueue.sync {}' <<<"$stop_body" \
  || fail "the extension can stop before its live-policy record is written"
watermark_check_line="$(grep -nF 'watermark.supersedes(decoded)' "$FILTER" | head -1 | cut -d: -f1 || true)"
boot_assign_line="$(grep -nF 'snapshotOrigin = .boot' "$FILTER" | head -1 | cut -d: -f1 || true)"
if [[ -z "$watermark_check_line" || -z "$boot_assign_line" || "$watermark_check_line" -gt "$boot_assign_line" ]]; then
  fail "the boot policy is applied before it is checked against the last live policy"
fi
# Every load-then-save on NEFilterManager.shared() runs one at a time, so a
# boot-policy save cannot write the filter back on after the user turned it
# off (#309).
for writer in 'private func flushPersistence()' 'private func disableFilter()' \
              'private func removeFilterConfiguration(' 'private func restartFilterProvider()' \
              'private func refreshFilterOffState()' 'private func reportAbandonedSettingsTurnOn('; do
  writer_body="$(awk -v w="$writer" 'index($0, w) {a=1} a {print} a && /^    }$/ {exit}' "$SYSTEM_EXTENSION_MANAGER")"
  grep -Fq 'filterPreferences.run {' <<<"$writer_body" \
    || fail "${writer} changes the content filter preferences without waiting for the other writers"
done
outside_writers="$(awk '
  /^    (private )?func / { fn = $0 }
  /NEFilterManager\.shared\(\)/ {
    if (fn !~ /func (disableFilter|removeFilterConfiguration|runPersistenceCycle|runFilterRestart|refreshFilterOffState|reportAbandonedSettingsTurnOn)\(/) print NR
  }' "$SYSTEM_EXTENSION_MANAGER")"
[[ -z "$outside_writers" ]] \
  || fail "NEFilterManager is used outside the serialized writers (line ${outside_writers//$'\n'/, })"
# Demo mode shows sample data and must leave the real content filter alone,
# also on a Mac where FreeSnitch is installed (#388): the preferences line is
# closed, System Settings changes are not followed, and no system extension
# request is submitted.
grep -Fq 'filterPreferences = FilterPreferencesLine(closed: demo)' "$SYSTEM_EXTENSION_MANAGER" \
  || fail "demo mode can read or save the real content filter configuration"
grep -Fq 'guard !closed else { return }' "$ROOT/Sources/Shared/FilterPreferencesLine.swift" \
  || fail "a closed filter preferences line still runs operations"
init_body="$(awk '/^    init\(state: AppState[,)]/ {a=1} a {print} a && /^    }$/ {exit}' "$SYSTEM_EXTENSION_MANAGER")"
printf '%s\n' "$init_body" | read_all_then awk '/guard !demo else [{] return [}]/ { g = 1 } /NEFilterConfigurationDidChange/ { ok = g; exit } END { exit !ok }' \
  || fail "demo mode follows filter changes made in System Settings"
embedded_body="$(awk '/private var hasEmbeddedExtension: Bool/ {a=1} a {print} a && /^    }$/ {exit}' "$SYSTEM_EXTENSION_MANAGER")"
grep -Fq 'guard !demo else { return false }' <<<"$embedded_body" \
  || fail "demo mode can submit system extension requests"
# #389: the same for the helper, the extension, the login item and files.
# Each of these acts on the real install and must check demo mode first.
DEMO_MODE_FILE="$ROOT/Sources/GUI/App/DemoMode.swift"
grep -Fq 'static let isOn = ProcessInfo.processInfo.environment["FREESNITCH_DEMO"] == "1"' "$DEMO_MODE_FILE" \
  || fail "demo mode is not read from FREESNITCH_DEMO in one place"
grep -Fq 'init(state: AppState, demo: Bool = DemoMode.isOn)' "$SYSTEM_EXTENSION_MANAGER" \
  || fail "the content filter manager does not know it runs in demo mode"
demo_guard() {
  local file="$1" entry="$2" guard="$3" what="$4"
  swift_function_body "$ROOT/$file" "$entry" | sed -n '2,5p' | read_all_then grep -Fq "$guard" \
    || fail "demo mode can $what"
}
demo_guard Sources/GUI/App/SystemExtensionManager.swift 'func deactivateForUninstall()' 'guard !demo else {' \
  "deactivate the real network extension or remove the filter configuration"
demo_guard Sources/GUI/App/HelperClient.swift 'func unregisterDaemonForUninstall()' 'guard !DemoMode.isOn else' \
  "unregister the real helper"
demo_guard Sources/GUI/App/HelperClient.swift 'func registerDaemon()' 'guard !DemoMode.isOn else' \
  "register the real helper"
demo_guard Sources/GUI/App/HelperClient.swift 'private func repairHelperInternal()' 'guard !DemoMode.isOn' \
  "re-register or repair the real helper"
demo_guard Sources/GUI/App/HelperClient.swift 'private func performPrivilegedKickstart()' 'guard !DemoMode.isOn else' \
  "restart the real helper"
demo_guard Sources/GUI/App/PrivilegedUninstall.swift 'static func run(removingDatabase:' 'guard !DemoMode.isOn else' \
  "run the privileged uninstall"
demo_guard Sources/GUI/App/PrivilegedUninstall.swift 'static func removeUserData()' 'guard !DemoMode.isOn else' \
  "delete the real install's data"
demo_guard Sources/GUI/App/PrivilegedUninstall.swift 'static func trashApplicationBundle(' 'guard !DemoMode.isOn else' \
  "move the real app to the Trash"
demo_guard Sources/GUI/App/CommandLineTool.swift 'static func install()' 'guard !DemoMode.isOn else' \
  "write the freesnitch command link into the real /usr/local/bin"
demo_guard Sources/GUI/App/CommandLineTool.swift 'static func remove()' 'guard !DemoMode.isOn else' \
  "remove the real freesnitch command link"
demo_guard Sources/GUI/Views/UninstallView.swift 'func begin()' 'guard !DemoMode.isOn else' \
  "turn enforcement off from the uninstall screen"
demo_guard Sources/GUI/Views/UninstallView.swift 'func finish()' 'guard !DemoMode.isOn else' \
  "start removing the helper, the data and the app"
demo_guard Sources/GUI/Views/SettingsView.swift 'private func setLaunchAtLogin(' 'guard !DemoMode.isOn else' \
  "change the real app's login item"
for runner in 'runPersistenceCycle()' 'runFilterRestart(done:'; do
  [[ "$(grep -cF "$runner" "$SYSTEM_EXTENSION_MANAGER")" -eq 2 ]] \
    || fail "${runner%%(*} is called from somewhere other than its turn on the preferences line"
done
disable_body="$(awk '/private func disableFilter\(\)/ {a=1} a {print} a && /^    }$/ {exit}' "$SYSTEM_EXTENSION_MANAGER")"
grep -Fq 'persistenceCycle.dropEnableRequest()' <<<"$disable_body" \
  || fail "turning the filter off leaves an enable request that the helper's answer can still act on"
require_text "$SYSTEM_EXTENSION_MANAGER" "guard mgr.isEnabled else {" \
  "a filter restart can turn the filter back on after the user turned it off"
# An enabling save that the user overtook by turning the filter off must not
# report the firewall as active once it finishes (#318).
grep -Fq 'filterTurnOffs &+= 1' <<<"$disable_body" \
  || fail "an enabling save that finishes after the filter was turned off still reports it active"
grep -Fq 'filterTurnOffs &+= 1' <<<"$remove_body" \
  || fail "an enabling save that finishes after the filter was removed still reports it active"
active_guard="$(grep -B1 -F 'self.filterConfigurationActive = true' "$SYSTEM_EXTENSION_MANAGER" | sed -n 1p)"
grep -Fq 'if completion == .active {' <<<"$active_guard" \
  || fail "an enabling save overtaken by a turn-off still marks the filter active"
require_text "$SYSTEM_EXTENSION_MANAGER" "turnOffsNow: self.filterTurnOffs," \
  "the enabling save's completion does not check whether the filter was turned off meanwhile"
require_text "$SYSTEM_EXTENSION_MANAGER" "if completion == .stayedOff {" \
  "an enabling save overtaken by a turn-off leaves the status as it was"
if grep -R -E -q 'io\.isaaclins\.freesnitch\.boot(["<]|$)|BHAF4L4726\.io\.isaaclins\.freesnitch\.boot(["<]|$)|boot-snapshot\.json' \
  "$ROOT/Sources" "$ROOT/project.yml" "$ROOT/project-netext.yml"; then
  fail "an old or experimental boot transport name or cache path is still present"
fi
if ! grep -Fq '<key>io.isaaclins.freesnitch.helper</key>' "$LAUNCHD_PLIST" \
  || grep -Fq 'BHAF4L4726.io.isaaclins.freesnitch.boot' "$LAUNCHD_PLIST"; then
  fail "helper launchd plist does not contain only the main helper MachService"
fi

# A verdict must never wait on the filesystem. The bundle identifier comes from
# a bounded in-memory cache, and the Info.plist read happens on a background
# queue, so a cold page cache or a slow volume cannot become filter latency.
require_text "$FILTER" "let metadata = bundleIdentifierCache.cachedMetadata(forExecutablePath: path," \
  "the verdict path no longer answers bundle identifiers from the bounded cache"
require_text "$FILTER" "capacity: Int = 512" \
  "the bundle identifier cache capacity is not explicit and bounded"
require_text "$FILTER" "resolveQueue.async" \
  "bundle identifier plist reads are not handed to a background queue"
require_text "$FILTER" "private let lock: UnsafeMutablePointer<os_unfair_lock_s>" \
  "the bundle identifier cache does not hold its lock at a stable address"
connection_body="$(awk '
  /private func connection\(from flow: NEFilterSocketFlow\) -> \(Connection, version: String\?, signatureChecked: Bool\)/ {
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
' "$FILTER")"
[[ -n "$connection_body" ]] || fail "the extension no longer resolves a bundle identifier for the flow"
if grep -Eq 'Data\(contentsOf:|PropertyListSerialization|SecStaticCode|SecCodeCopy' <<<"$connection_body"; then
  fail "the verdict path reads an Info.plist or checks a signature synchronously"
fi

# A rule's bundle id comes from the process's code signature, never from an
# unsigned Info.plist anyone can write next to a binary (#351).
require_text "$FILTER" "CodeSigningIdentity.resolve(executablePath:" \
  "the extension no longer takes bundle identifiers from the code signature"
require_text "$ROOT/Sources/Helper/NetMonitor.swift" "CodeSigningIdentity.resolve(executablePath:" \
  "the monitor no longer takes bundle identifiers from the code signature"
if grep -Fq 'CFBundleIdentifier' "$ROOT/Sources/Helper/NetMonitor.swift"; then
  fail "the monitor reads a bundle identifier from an unsigned Info.plist"
fi

# A flow can reach handleNewFlow with no destination at all: the SDK states
# that remoteFlowEndpoint "may be nil when [NEFilterDataProvider
# handleNewFlow:] is invoked and if so will be populated upon receiving network
# data" (NEFilterFlow.h), and in practice the endpoint carries the socket's
# wildcard address instead. A wildcard is not a destination: recording it as
# one makes an unattributable flow look attributed while IP and CIDR rules
# still cannot match it. It must be refused before it becomes a Connection,
# and the resulting limitation must be logged rather than hidden.
require_text "$FILTER" "static func isUnspecifiedAddress" \
  "the extension no longer classifies the unspecified address"
require_text "$FILTER" "FlowDestination.resolve(endpointHost: host, remoteHostname: flow.remoteHostname)" \
  "the flow to connection mapping no longer goes through the destination classifier"
destination_body="$(awk '
  /static func resolve\(endpointHost/ {
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
' "$FILTER")"
[[ -n "$destination_body" ]] || fail "the destination classifier no longer has a resolve function to audit"
unspecified_line="$(printf '%s\n' "$destination_body" | grep -nF 'isUnspecifiedAddress(endpointHost)' | head -1 | cut -d: -f1 || true)"
construct_line="$(printf '%s\n' "$destination_body" | grep -nF 'return FlowDestination(' | head -1 | cut -d: -f1 || true)"
[[ -n "$unspecified_line" && -n "$construct_line" ]] \
  || fail "the destination classifier does not reject the unspecified endpoint address"
(( unspecified_line < construct_line )) \
  || fail "the destination classifier builds a destination before rejecting the unspecified address"
if grep -Eq 'host: "(::|0\.0\.0\.0)"|ip: "(::|0\.0\.0\.0)"' <<<"$destination_body"; then
  fail "the destination classifier stores a wildcard address as a destination"
fi
require_text "$FILTER" "IP and CIDR rules cannot be evaluated for them" \
  "the extension does not report flows whose destination is unknown at verdict time"

# The destination can arrive after the verdict. Learning it is observation
# only: shouldReport is set on an already-decided verdict, and the report
# callback returns no verdict, so it can neither delay a flow nor revise one.
require_text "$FILTER" "verdict.shouldReport = true" \
  "the extension no longer asks for a report on flows with no destination"
reporting_body="$(awk '
  /private func reportingLateDestination\(/ {
    active = 1
    depth = 0
  }
  active {
    print
    opens = gsub(/\{/, "{")
    closes = gsub(/\}/, "}")
    depth += opens - closes
    if (opens > 0) opened = 1
    if (opened && depth == 0) exit
  }
' "$FILTER")"
[[ -n "$reporting_body" ]] || fail "the late-destination reporting helper is missing"
guard_line="$(printf '%s\n' "$reporting_body" | grep -nF 'guard !destinationKnown else { return verdict }' | head -1 | cut -d: -f1 || true)"
flag_line="$(printf '%s\n' "$reporting_body" | grep -nF 'verdict.shouldReport = true' | head -1 | cut -d: -f1 || true)"
[[ -n "$guard_line" && -n "$flag_line" ]] \
  || fail "late-destination reporting is not restricted to flows whose destination was unknown"
(( guard_line < flag_line )) \
  || fail "late-destination reporting is requested before checking that the destination was unknown"
report_body="$(awk '
  /override func handle\(_ report: NEFilterReport\)/ {
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
' "$FILTER")"
[[ -n "$report_body" ]] || fail "the extension no longer handles flow reports"
if grep -Eq 'resumeFlow|updateFlow|Verdict|pause|sleep|DispatchSemaphore|\.sync' <<<"$report_body"; then
  fail "the flow report path touches a verdict or blocks, so a late destination could delay or change a flow"
fi

# Nothing on the verdict path may wait, for a destination or for anything else.
new_flow_body="$(awk '
  /override func handleNewFlow\(/ {
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
' "$FILTER")"
[[ -n "$new_flow_body" ]] || fail "the extension no longer implements handleNewFlow"
if grep -Eq 'DispatchSemaphore|\.sync|sleep|\.wait\(|filterDataVerdict' <<<"$new_flow_body"; then
  fail "handleNewFlow waits or defers its decision instead of returning a verdict immediately"
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
# grep exits 1 when the requirement has been deleted outright, which is exactly
# the case this gate exists to catch. Without the guard, pipefail would abort
# the script with no message instead of naming the missing requirement.
requirement_count="$( { grep -RohF 'let requirementText = "anchor apple generic"' "$ROOT/Sources" --include='*.swift' || true; } | wc -l | tr -d ' ')"
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
if grep -Fq 'newConnection.resume(); return true' <<<"$accept_body"; then
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
# Same idea, for any literal that has to appear inside one brace block.
text_within_block() {
  local file="$1"
  local start_regex="$2"
  local needle="$3"
  awk -v start="$start_regex" -v needle="$needle" '
    !active && $0 ~ start {
      active = 1
      depth = 0
    }
    active {
      if (index($0, needle) > 0) {
        found = 1
        exit 0
      }
      n = gsub(/\{/, "{")
      m = gsub(/\}/, "}")
      depth += n - m
      # A multi-line signature has no brace on its first line. Without waiting
      # for the block to actually open, depth is 0 there and the scan stops
      # before reading any of the body, so the gate checks nothing at all.
      if (n > 0) opened = 1
      if (opened && depth <= 0) active = 0
    }
    END { exit(found ? 0 : 1) }
  ' "$file"
}

# Persisted helper settings must be restored together. Restoring the mode but
# not the DoH upstream silently changes the user's resolver after every helper
# restart.
if ! text_within_block "$HELPER" 'init[(]listener: NSXPCListener[)]' 'store.activePolicyState()'; then
  fail "the helper no longer restores its persisted mode and policy generation"
fi
if ! text_within_block "$HELPER" 'init[(]listener: NSXPCListener[)]' 'dns.dohURL = Self.restoredDoHUpstream(from: store.getSetting("doh_url"))'; then
  fail "the helper restores mode without also restoring and validating the persisted DoH upstream"
fi
if ! text_within_block "$HELPER" 'static func restoredDoHUpstream[(]' 'DoHUpstreamValidator.rejectionReason(for: storedValue)'; then
  fail "the helper restores a persisted DoH upstream without validating it"
fi

allow_within_block() {
  local file="$1"
  local start_regex="$2"
  awk -v start="$start_regex" '
    !active && $0 ~ start {
      active = 1
      depth = 0
    }
    active {
      if ($0 ~ /resumeOnce\(NEFilterNewFlowVerdict\.allow\(\)(\)|, \.unfiltered\))/) {
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
own_line="$(grep -nF 'if isOwnTraffic(conn) || isLoopback(conn.remoteIP) { observe(.unfiltered); return .allow() }' "$FILTER" | head -1 | cut -d: -f1 || true)"
matcher_line="$(grep -nF 'matcher.explainedDecision(for: conn' "$FILTER" | head -1 | cut -d: -f1 || true)"
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
if grep -Eq 'hasPrefix\([[:space:]]*"/|==[[:space:]]*"/"|"/[[:space:]]*==|Bundle\.main|URL\(fileURLWithPath:[[:space:]]*"/' <<<"$active_code" ; then
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
require_text "$SYSTEM_EXTENSION_MANAGER" "self.fail(String(localized: \"filter save: \\(saveError.localizedDescription)\"))" \
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
if grep -Fq "enableFilter" <<<"$activation_body"; then
  fail "filter configuration is still enabled optimistically during activate()"
fi

# A DNS ask must never outlive its answer path. With no client connected the
# helper resolves the query itself, an unanswered ask resolves at the timeout,
# the pending table is bounded, and no completion runs while the lock is held.
require_text "$HELPER" "static let defaultDecision = true" \
  "the DNS ask default is not an explicit fail-open allow"
# Anchored: "= 600" also contains "= 60", and a ten minute budget is not the
# extension's budget.
grep -Eq 'static let askTimeout: TimeInterval = 60[[:space:]]*$' "$HELPER" \
  || fail "the DNS ask path has no 60 second timeout matching the extension budget"
require_text "$HELPER" "static let capacity = " \
  "the pending DNS ask table is not bounded by an explicit capacity"
require_text "$HELPER" "askTimeoutQueue.asyncAfter" \
  "the DNS ask timeout does not run on its own queue"
if grep -Fq 'let askTimeoutQueue = DispatchQueue(label: "io.isaaclins.freesnitch.dns"' "$HELPER"; then
  fail "the DNS ask timeout shares the DNS handling queue it is supposed to unblock"
fi

coordinator_body="$(awk '
  /^final class DNSAskCoordinator/ {
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
' "$HELPER")"
[[ -n "$coordinator_body" ]] || fail "the helper no longer has a DNSAskCoordinator to audit"

# The bound, the timeout, and the no-client path each have to resolve the ask,
# so every one of them must reach a completion with the fail-open default.
for ask_func in 'func ask[(]domain' 'func admit[(]domain' 'func expire[(]domain'; do
  # A multi-line signature has no brace on its first line, so the block only
  # ends once at least one brace has been seen.
  ask_body="$(printf '%s\n' "$coordinator_body" | read_all_then awk -v start="$ask_func" '
    !active && $0 ~ start {
      active = 1
      depth = 0
      seen = 0
    }
    active {
      print
      opens = gsub(/\{/, "{")
      closes = gsub(/\}/, "}")
      if (opens > 0) seen = 1
      depth += opens - closes
      if (seen && depth == 0) exit
    }
  ')"
  grep -Eq 'Self\.defaultDecision' <<<"$ask_body" \
    || fail "a DNS ask resolution path does not fall back to the documented default"
done

# A completion or an XPC send under the lock is how this path deadlocks. Walk
# the coordinator and refuse any call between lock and unlock.
printf '%s\n' "$coordinator_body" | awk '
  /defer[[:space:]]*\{[[:space:]]*askLock\.unlock\(\)/ { next }
  /askLock\.lock\(\)/ { held = 1; next }
  /askLock\.unlock\(\)/ { held = 0; next }
  held && /completion\(|\.completion\(|sendAlert\(/ {
    print "held: " $0
    bad = 1
  }
  END { exit(bad ? 1 : 0) }
' || fail "the DNS ask coordinator runs a completion or an alert send while holding its lock"

# The no-client branch is the whole point of the fix: it must resolve, not log.
if ! text_within_block "$HELPER" 'if delivered <= 0[[:space:]]*\{' 'resolve(domain: domain, allow: Self.defaultDecision)'; then
  fail "the helper does not resolve a DNS ask that reached no client"
fi

require_text "$DNS_PROXY" "guard let onAsk else" \
  "the DNS proxy leaves the query unanswered when no ask handler is wired up"
if ! text_within_block "$DNS_PROXY" 'guard let onAsk else[[:space:]]*\{' 'settleOnce(true)'; then
  fail "the DNS proxy no-handler path does not fail open"
fi
if ! text_within_block "$DNS_PROXY" 'let settleOnce' 'if answered'; then
  fail "the DNS proxy ask path can reply to the same query twice"
fi

# A report may only be counted for a flow this provider actually flagged.
# Counting every report made the late-destination tally describe ordinary
# traffic and overstate by more than two orders of magnitude.
# No parentheses in this pattern on purpose: awk -v processes escapes in the
# value, so an escaped paren never reaches the regex engine intact and the
# block would silently never be found.
if ! text_within_block "$FILTER" 'override func handle.*NEFilterReport' 'classifyFlaggedReport'; then
  fail "the network extension counts filter reports without checking that it flagged the flow"
fi
if ! text_within_block "$FILTER" 'private func reportingLateDestination' 'rememberFlaggedFlow'; then
  fail "the network extension sets shouldReport without recording the flow it expects a report for"
fi

# The evaluation order is derived from the snapshot. If a future edit assigns
# the snapshot directly, the two can disagree and a flow is judged by one
# snapshot's rules in another snapshot's order. Only the setter may assign it.
# rg exits 1 when it matches nothing, which under `set -euo pipefail` would end
# this script silently and make every gate below look like it passed. The
# no-match case is the good case here, so it must not abort the run.
stray_snapshot_writes=$( { rg -n '^\s*snapshot = ' "$FILTER" || true; } | { rg -v 'snapshot = newValue' || true; } | wc -l | tr -d ' ')
if [ "$stray_snapshot_writes" != "0" ]; then
  fail "the network extension assigns its rule snapshot outside setSnapshotLocked, so the prepared rule order can go stale"
fi

# Both verdict paths must scan a prepared order rather than sorting per flow.
if rg -q 'decision\(for:[^)]*rules:' "$FILTER"; then
  fail "the network extension orders the rule set on the verdict path instead of scanning a prepared set"
fi
if rg -q 'decision\(for:[^)]*rules:' "$DNS_PROXY"; then
  fail "the DNS proxy orders the rule set per query instead of scanning a prepared set"
fi

# Authoritative policy snapshots. The helper is the only source allowed to
# construct a policy payload for the extension; cached GUI rules and client
# clocks must never become policy authority.
require_text "$HELPER_PROTOCOL" "@objc optional func getAuthoritativeSnapshot(reply: @escaping (Data) -> Void)" \
  "the helper protocol has no backward-compatible authoritative snapshot getter"
require_text "$HELPER" "func getAuthoritativeSnapshot(reply: @escaping (Data) -> Void)" \
  "the helper does not vend an authoritative encoded policy snapshot"
require_text "$HELPER" "store.activePolicyState()" \
  "the helper snapshot path does not read persisted mode and rules together"
require_text "$HELPER" "store.mutateActivePolicy" \
  "helper policy mutations do not use the serialized RuleStore transaction"
require_text "$RULE_STORE" "BEGIN IMMEDIATE" \
  "RuleStore policy mutations are not transactionally serialized"
require_text "$RULE_STORE" "policyGenerationSettingKey" \
  "RuleStore does not persist the authoritative policy generation"
require_text "$BRIDGE" "generation: UInt64" \
  "snapshots have no helper-owned generation field"
require_text "$BRIDGE" "decodeIfPresent(UInt64.self, forKey: .generation) ?? 0" \
  "snapshot generation decoding is not backward compatible"
require_text "$BRIDGE" "LiveSnapshotGate" \
  "the production snapshot ordering gate is missing"
require_text "$GUI_HELPER" "getAuthoritativeSnapshot != nil" \
  "the GUI does not refuse an old helper that lacks the authoritative getter"
require_text "$GUI_HELPER" "AppConstants.helperKickstartCommand" \
  "the GUI authoritative snapshot failure does not provide the exact helper kickstart remediation"
require_text "$CLI_HELPER" "authoritative_snapshot_unsupported" \
  "the CLI does not diagnose an old helper without the authoritative getter"
require_text "$CLI_HELPER" "AppConstants.helperKickstartCommand" \
  "the CLI authoritative snapshot failure does not provide the exact helper kickstart remediation"
require_text "$APP_STATE" "helper.authoritativeSnapshot" \
  "the GUI sync path does not fetch the helper authoritative snapshot"
require_text "$APP_STATE" "snapshotRequestSequence" \
  "the GUI has no request sequencing for authoritative snapshot replies"
require_text "$APP_STATE" "filterSnapshotPersistenceHandler?(snapshot)" \
  "the GUI does not persist the exact helper snapshot it accepted"
# A remembered alert decision must carry its destination INTO the rule. Both
# destination tests in PreparedRule.matches are `if let`, so a rule with an
# empty host and no address loses both and silently becomes "this process,
# anywhere", turning an allow into far more than the user approved (#64).
# The alert grew a scope control, so the address now reaches the rule through
# the scoped value rather than directly, and the old single check no longer
# described the code. Both halves are asserted instead: the destination is put
# into the scoped value, and the scoped value is what the rule is built with.
require_text "$APP_STATE" "scopedIP = ruleIP" \
  "the remembered alert rule does not carry the remote address into its scope, so an IP-only decision would match every destination"
require_text "$APP_STATE" "remoteIP: scopedIP" \
  "the remembered alert rule is not built with the scoped remote address, so an IP-only decision would match every destination"
require_text "$APP_STATE" "remoteHost: scopedHost" \
  "the remembered alert rule is not built with the scoped remote host, so a domain decision would match every destination"
# The one privileged action the GUI may take on its own behalf must stay one
# fixed command. If a later change ever assembles this script from a variable,
# a path, or a version string, this stops being "restart my own helper" and
# becomes "run something as root" (#69).
PRIVILEGED_REPAIR="$ROOT/Sources/GUI/App/PrivilegedRepair.swift"
[[ -f "$PRIVILEGED_REPAIR" ]] || fail "missing $PRIVILEGED_REPAIR"
require_text "$PRIVILEGED_REPAIR" "private static let script" \
  "the privileged repair command is not a single constant"
require_text "$PRIVILEGED_REPAIR" "/bin/launchctl kickstart -k system/io.isaaclins.freesnitch.helper" \
  "the privileged repair no longer restarts exactly the helper service"
# Comments are stripped BEFORE looking for destructive verbs: this file's own
# documentation explains why bootout and unregister are not used, and an
# earlier version of this check matched that prose and failed itself.
if rg -v '^[[:space:]]*//' "$PRIVILEGED_REPAIR" | read_all_then rg -q 'bootout|unload|unregister'; then
  fail "the privileged repair uses a destructive launchctl verb; it must only ever kickstart"
fi
if rg -v '^[[:space:]]*//' "$PRIVILEGED_REPAIR" | read_all_then rg -q '\\\('; then
  fail "the privileged repair script interpolates a value; it must be a compile-time constant"
fi
# Check the BRANCH, not merely that the identifier exists somewhere. An
# earlier version of this check passed while the call site had been replaced,
# because the now-dead function definition still contained the name.
if ! rg -A6 'case \.manualKickstart:' "$GUI_HELPER" | read_all_then rg -q 'performPrivilegedKickstart\(\)'; then
  fail "the stale-helper path no longer attempts the repair itself, so it would only print a sudo command"
fi
# The `freesnitch` command link (#423) runs as root, so like the repair it
# stays two fixed commands: ln without -f never replaces a file it did not
# make, and the removal only deletes a link that points into the app.
COMMAND_LINE_TOOL="$ROOT/Sources/GUI/App/CommandLineTool.swift"
[[ -f "$COMMAND_LINE_TOOL" ]] || fail "missing $COMMAND_LINE_TOOL"
require_text "$COMMAND_LINE_TOOL" '/bin/ln -sh /Applications/FreeSnitch.app/Contents/Helpers/freesnitch /usr/local/bin/freesnitch\" with administrator privileges' \
  "the command link install is no longer one fixed ln -s into the installed app"
require_text "$COMMAND_LINE_TOOL" 'if /usr/bin/readlink /usr/local/bin/freesnitch | /usr/bin/grep -qxF /Applications/FreeSnitch.app/Contents/Helpers/freesnitch; then /bin/rm -f /usr/local/bin/freesnitch; fi' \
  "the command link removal no longer checks that the link is FreeSnitch's"
if rg 'do shell script' "$COMMAND_LINE_TOOL" | read_all_then rg -q '\\\(|ln -sf|ln -fs|rm -rf'; then
  fail "a command link script interpolates a value, forces a link over an existing file, or removes recursively"
fi
# The uninstaller must be able to uninstall. It previously told users to run
# `sudo bash Scripts/uninstall_freesnitch.sh`, a file that exists only in a
# source checkout, so anyone who installed from the DMG was given instructions
# they could not follow.
PRIVILEGED_UNINSTALL="$ROOT/Sources/GUI/App/PrivilegedUninstall.swift"
UNINSTALL_VIEW="$ROOT/Sources/GUI/Views/UninstallView.swift"
[[ -f "$PRIVILEGED_UNINSTALL" ]] || fail "missing $PRIVILEGED_UNINSTALL"
# Comments stripped first: the view's own documentation explains why it no
# longer names that script, and checking the raw file matched that prose.
if rg -v '^[[:space:]]*//' "$UNINSTALL_VIEW" | read_all_then rg -q 'Scripts/uninstall_freesnitch.sh'; then
  fail "the uninstall screen points the user at a script that only exists in a source checkout"
fi
require_text "$UNINSTALL_VIEW" "PrivilegedUninstall.run" \
  "the uninstall screen does not perform the removal itself"
if rg -v '^[[:space:]]*//' "$PRIVILEGED_UNINSTALL" | read_all_then rg -q '\\\('; then
  fail "the privileged uninstall interpolates a value; every path it removes must be a constant"
fi
# Flushing the shared anchor is required; deleting it or disabling pf is not,
# because /etc/pf.conf still references it and the user's firewall would be
# stranded. Emptying the anchor file is required too: pf.conf loads it at boot,
# so rules left in it came back after FreeSnitch was gone (issue #192). The one
# mention of the file allowed is that write of a comment-only anchor; it is
# removed before the check, so any other use of the path still fails.
EMPTY_ANCHOR_WRITE="[ -f /etc/pf.anchors/puresnitch ] && /bin/echo '# FreeSnitch pf anchor - FreeSnitch was uninstalled, so it holds no rules.' > /etc/pf.anchors/puresnitch; "
privileged_uninstall_code="$(rg -v '^[[:space:]]*//' "$PRIVILEGED_UNINSTALL")"
if printf '%s\n' "${privileged_uninstall_code//"$EMPTY_ANCHOR_WRITE"/}" | read_all_then rg -q 'pfctl -d|rm -f /etc/pf|rm -rf /etc/pf|pf\.anchors|/private/etc/pf'; then
  fail "the privileged uninstall disables pf globally or removes the shared anchor file"
fi
# Every pfctl call stays inside FreeSnitch's own anchor; a bare `pfctl -F all`
# would flush every rule on the Mac.
if printf '%s\n' "$privileged_uninstall_code" | rg -o 'pfctl[^;"]*' | read_all_then rg -qv '^pfctl -a puresnitch '; then
  fail "the privileged uninstall runs pfctl outside the puresnitch anchor"
fi
require_text "$PRIVILEGED_UNINSTALL" "pfctl -a puresnitch -F all" \
  "the privileged uninstall no longer flushes the FreeSnitch anchor"
# Both scripts (keep or remove the database) must start with that write, so
# it runs before the flush and before anything is removed.
[[ "$(rg -F -c "do shell script \"$EMPTY_ANCHOR_WRITE" "$PRIVILEGED_UNINSTALL" || true)" == 2 ]] \
  || fail "the privileged uninstall leaves the last rules in the anchor file pf.conf loads at boot"
UNINSTALL_SCRIPT="$ROOT/Scripts/uninstall_freesnitch.sh"
uninstall_flush="$(awk '/^flush_pf_anchor\(\) [{]/,/^}/' "$UNINSTALL_SCRIPT")"
printf '%s\n' "$uninstall_flush" | read_all_then awk '/empty_pf_anchor_file/ { seen = 1 } /-F all/ { ok = seen; exit } END { exit !ok }' \
  || fail "the uninstall script flushes the anchor without first emptying the file pf.conf loads at boot"
uninstall_empty="$(awk '/^empty_pf_anchor_file\(\) [{]/,/^}/' "$UNINSTALL_SCRIPT")"
grep -Fq 'run_privileged /usr/bin/tee "$PF_ANCHOR"' <<<"$uninstall_empty" \
  || fail "the uninstall script no longer empties the anchor file"
grep -Eq '\brm\b|pfctl' <<<"$uninstall_empty" \
  && fail "emptying the anchor file deletes it or touches pf"
# The app bundle must go to the Trash through Finder, never be deleted.
# Moving an app that hosts a system extension to the Trash is what makes macOS
# remove the extension; deleting the bundle directly takes the app away and
# leaves the extension installed. Objective Development document this for
# Little Snitch and warn against removing such an app by any other means.
if rg -v '^[[:space:]]*//' "$PRIVILEGED_UNINSTALL" | read_all_then rg -q "rm -rf '/Applications"; then
  fail "the privileged uninstall deletes the app bundle, which strands the system extension"
fi
require_text "$PRIVILEGED_UNINSTALL" "NSWorkspace.shared.recycle" \
  "the uninstall deletes the app bundle instead of moving it to the Trash"
require_text "$UNINSTALL_VIEW" "trashApplicationBundle" \
  "the uninstall screen never moves the app to the Trash"
# Uninstall must REMOVE the content filter configuration, not merely disable
# it. macOS keeps a system extension record alive while a
# NEFilterProviderConfiguration still references it, which is why uninstalling
# always ended in "waiting to uninstall on reboot".
SYSEXT_MANAGER="$ROOT/Sources/GUI/App/SystemExtensionManager.swift"
require_text "$SYSEXT_MANAGER" "removeFromPreferences" \
  "the uninstall path does not remove the content filter configuration"
# Look at the whole function body, and check for the WRONG call rather than
# only for the right one: a six-line window still matched the early-return
# branch's call and let a reverted uninstall path pass.
UNINSTALL_BODY=$(awk '/func deactivateForUninstall/,/^    }$/' "$SYSEXT_MANAGER")
if ! rg -q 'removeFilterConfiguration' <<<"$UNINSTALL_BODY"; then
  fail "uninstall no longer removes the filter configuration before deactivating the extension"
fi
if rg -q 'disableFilter\(' <<<"$UNINSTALL_BODY"; then
  fail "uninstall only disables the filter configuration, so macOS keeps the extension record until a reboot"
fi
# The deactivation must be submitted only after the configuration removal
# answered, inside its completion, never next to it.
if ! printf '%s\n' "$UNINSTALL_BODY" | awk '/removeFilterConfiguration \{ \[weak self\] removed in/ { inside = 1 } inside && /guard removed else/ { gated = 1 } gated && /deactivationRequest/ { found = 1 } END { exit !found }'; then
  fail "uninstall submits the extension deactivation without waiting for the filter configuration removal, or after it failed"
fi
# The uninstall removes the helper and the app only after macOS answered the
# deactivation with the extension stopped (#391): removing them while the
# extension still runs strands it.
UNINSTALL_ANSWER=$(awk '/private func extensionAnswered/,/^    }$/' "$UNINSTALL_VIEW")
if ! printf '%s\n' "$UNINSTALL_ANSWER" | read_all_then rg -q 'case \.failed' \
   || printf '%s\n' "$UNINSTALL_ANSWER" | awk '/case \.failed/,/case \.notInstalled/' | read_all_then rg -q 'finish\(\)'; then
  fail "the uninstall removes the helper and the app although macOS kept the network extension"
fi
# A filter configuration removal that failed must stop the uninstall: the
# filter would keep running with the user's rules and no app left (#391).
if ! awk '/private func removeFilterConfiguration/,/^    }$/' "$SYSEXT_MANAGER" | read_all_then rg -q 'completion\(removeError == nil\)'; then
  fail "the filter configuration removal reports success whether or not it worked"
fi
# The helper is unregistered only after the privileged step flushed the pf
# anchor: if that step is cancelled, the helper is what can still clear pf.
if ! awk '/^    func finish\(\)/,/^    }$/' "$UNINSTALL_VIEW" \
     | read_all_then awk '/case \.success:/ { ok = 1 } /unregisterDaemonForUninstall/ { found = ok; exit } END { exit !found }'; then
  fail "the uninstall unregisters the helper before the pf anchor is flushed"
fi
# The finished uninstall ends the process outright: NSApp.terminate from a
# bundle already in the Trash hung 1.1.0 until it was force quit (#391).
if ! awk '/^    func quit\(\)/,/^    }$/' "$UNINSTALL_VIEW" | read_all_then rg -q '^\s*exit\(0\)'; then
  fail "the uninstall's quit no longer exits the process outright"
fi
# The uninstall screen talks to people, not developers (#391).
if rg -v '^[[:space:]]*//' "$UNINSTALL_VIEW" | read_all_then rg -q 'Text\(.*(systemextensionsctl|System Integrity|sudo |io\.isaaclins|bundleId)'; then
  fail "the uninstall screen shows a terminal command, a bundle id or SIP talk"
fi
# Turning enforcement off is NOT an uninstall: that path must keep the
# configuration installed so it can be switched back on without re-approval.
if rg -A10 'private func disableFilter' "$SYSEXT_MANAGER" | read_all_then rg -q 'removeFromPreferences'; then
  fail "disabling enforcement removes the filter configuration, which would force the user to approve it again"
fi
require_text "$APP_STATE" "hasDestination" \
  "the remembered alert rule is not guarded against an empty destination"
if rg -n "remoteHost: alert\\.connection\\.remoteHost," "$APP_STATE" >/dev/null; then
  fail "the remembered alert rule passes the raw connection host, which is empty for an address-only destination"
fi
if rg -n "SharedRuleBridge\\.Snapshot\\(" "$ROOT/Sources/GUI" >/dev/null; then
  fail "the GUI constructs a sendable SharedRuleBridge.Snapshot instead of using the helper"
fi
if rg -n "SharedRuleBridge\\.Snapshot\\(" "$CLI_RUNNER" "$CLI_HELPER" >/dev/null; then
  fail "the CLI constructs a sendable SharedRuleBridge.Snapshot instead of using the helper"
fi
if grep -Fq 'syncSnapshot(mode:' "$CLI_RUNNER"; then
  fail "the CLI sync path still accepts independently fetched mode and rules"
fi
require_text "$CLI_RUNNER" "private func syncSnapshot(_ snapshot: SharedRuleBridge.Snapshot)" \
  "the CLI does not sync the exact helper-owned snapshot"
require_text "$CLI_RUNNER" "try await helper.authoritativeSnapshot()" \
  "the CLI mutation paths do not fetch an authoritative helper snapshot"
require_text "$FILTER" "received.generation < current.generation" \
  "the extension does not reject a lower-generation live snapshot before assignment"
require_text "$FILTER" "received.generation == current.generation" \
  "the extension does not check equal-generation split-brain content"
# A store method that changes rules outside mutatePolicy keeps the policy
# generation, and republishing under an old generation is refused by the
# extension as split-brain, which stops filtering (#438).
# Sources/Shared is compiled into every target, so an internal method is as
# reachable as a public one; only private ones are left out.
if grep -nE '^[[:space:]]*((public|internal|open|fileprivate)[[:space:]]+)?func (upsertRule|deleteRule|insertRule|replaceRules)\b' "$RULE_STORE"; then
  fail "RuleStore exposes a rule write that does not advance the policy generation; use mutatePolicy"
fi
# Same policy or not is decided by one shared definition that leaves out usage
# counters. Comparing whole rules made a resend after a counted match look like
# split-brain, and filtering stopped (#438).
require_text "$FILTER" "let comparable, !SharedRuleBridge.PolicyContent.same(received, comparable)" \
  "the extension's split-brain check does not use the shared policy content"
require_text "$FILTER" "LiveSnapshotGate(current: legacyBootGeneration ? nil : comparable)" \
  "the extension's gate does not check a live resend against the saved boot policy (#455)"
require_text "$BRIDGE" "guard PolicyContent.same(current, received) else {" \
  "the live snapshot gate does not use the shared policy content"
require_text "$BRIDGE" "let rules = PolicyContent.rules(snapshot.rules)" \
  "the watermark digest does not use the shared policy content"
if grep -nE '\.rules[[:space:]]*(==|!=)' "$FILTER" "$BRIDGE"; then
  fail "a policy comparison uses whole rules, usage counters included; use SharedRuleBridge.PolicyContent"
fi
require_text "$FILTER" "setSnapshotLocked(accepted)" \
  "the extension does not assign only after the generation gate"
generation_check_line="$(grep -nF 'received.generation < current.generation' "$FILTER" | head -1 | cut -d: -f1 || true)"
generation_assignment_line="$(grep -nF 'setSnapshotLocked(accepted)' "$FILTER" | head -1 | cut -d: -f1 || true)"
[[ -n "$generation_check_line" && -n "$generation_assignment_line" && "$generation_check_line" -lt "$generation_assignment_line" ]] \
  || fail "the extension assigns a live snapshot before comparing its generation"

# The generation alone is not durable and does not identify who produced it, so
# comparing it alone locked a restarted helper out of its own extension until a
# reboot (#70). Ordering must be (epoch, generation), the generation comparison
# must be scoped to one helper session, and a restart must never rewind either
# value inside a session.
require_text "$BRIDGE" "public var epoch: UInt64" \
  "snapshots carry no helper session epoch, so a restarted helper is indistinguishable from a stale client"
require_text "$BRIDGE" "decodeIfPresent(UInt64.self, forKey: .epoch) ?? PolicyEpoch.unknown" \
  "snapshot epoch decoding is not backward compatible with pre-epoch builds"
require_text "$BRIDGE" "public enum SnapshotAuthority" \
  "there is no single owner of the (epoch, generation) ordering"
require_text "$BRIDGE" "case newerSession" \
  "snapshot ordering cannot express a newer helper session"
require_text "$BRIDGE" "case rejectedOlderSession(currentEpoch: UInt64)" \
  "the shared ordering gate cannot report an older-session rejection"
if ! text_within_block "$BRIDGE" 'public mutating func apply[(]_ received: Snapshot[)]' 'SnapshotAuthority.compare(received: received, against: current)'; then
  fail "the shared live snapshot gate orders by generation alone, so a restarted helper is rejected forever"
fi
require_text "$POLICY_EPOCH" "public static func next(after stored: UInt64)" \
  "the helper session epoch has no monotonic successor rule"
require_text "$POLICY_EPOCH" "public static let unknown: UInt64 = 0" \
  "a pre-epoch snapshot does not decode to a non-authoritative epoch"
if grep -Eq 'Date\(\)|timeIntervalSince|bootTime|kern.boottime|UUID\(\)' "$POLICY_EPOCH"; then
  fail "the helper session epoch is derived from the clock or a random value instead of a persisted counter"
fi
require_text "$RULE_STORE" "policyEpochSettingKey" \
  "RuleStore does not persist the helper session epoch"
require_text "$RULE_STORE" "func beginPolicySession()" \
  "RuleStore has no helper session that advances the epoch on start"
require_text "$RULE_STORE" "func recordPolicyGeneration(atLeast generation: UInt64)" \
  "the policy generation is durable only inside mutatePolicy, so a restart can rewind it"
if ! text_within_block "$RULE_STORE" 'func beginPolicySession[(][)]' 'persistPolicyGenerationLocked(atLeast: generation)'; then
  fail "opening a helper session does not make the current policy generation durable"
fi
if ! text_within_block "$HELPER" 'init[(]listener: NSXPCListener[)]' 'store.beginPolicySession()'; then
  fail "the helper does not open a new policy session on start, so a restarted helper reuses the previous epoch"
fi
require_text "$HELPER" "epoch: state.epoch" \
  "helper snapshots do not carry the session epoch"
require_text "$HELPER" "store.recordPolicyGeneration(atLeast: state.generation)" \
  "the helper does not persist the generation it publishes"
filter_body="$(swift_function_body "$FILTER" 'private func receiveSnapshot(')"
[[ -n "$filter_body" ]] || fail "the extension has no receiveSnapshot function to audit"
grep -Fq 'SharedRuleBridge.SnapshotAuthority.compare(received: received, against: $0)' <<<"$filter_body" \
  || fail "the extension does not rank a received snapshot by helper session before generation"
grep -Fq 'authority == .olderSession' <<<"$filter_body" \
  || fail "the extension does not reject a snapshot from an older helper session"
lower_generation_block="$(swift_function_body "$FILTER" 'if let current, received.generation < current.generation {')"
[[ -n "$lower_generation_block" ]] || fail "the extension has no lower-generation rejection block to audit"
grep -Fq 'authority == .sameSession' <<<"$lower_generation_block" \
  || fail "the extension's lower-generation rejection is not scoped to one helper session, so a restarted helper is locked out until a reboot"
grep -Fq 'rejection: .conflictingContent' <<<"$filter_body" \
  || fail "the extension no longer reports the equal-generation split-brain rejection"

# No rejection may be a state that only a reboot clears. Every ordering refusal
# carries the remediation, and the app acts on it by restarting the filter
# provider, never by deactivating the extension or touching the helper.
require_text "$BRIDGE" "snapshotRejectionRemediation" \
  "an ordering rejection does not tell the user how to recover"
require_text "$BRIDGE" "public var needsFilterRestart" \
  "the app cannot tell an ordering rejection from a malformed payload without parsing a sentence"
require_text "$SNAPSHOT_RECOVERY" "static let maximumAttempts" \
  "automatic filter restarts have no attempt bound"
require_text "$SNAPSHOT_RECOVERY" "static let cooldown" \
  "automatic filter restarts have no cooldown"
if ! text_within_block "$SNAPSHOT_RECOVERY" 'public mutating func decide[(]' 'attempts < Self.maximumAttempts'; then
  fail "automatic filter restarts are unbounded, so a rejected snapshot can restart the provider forever"
fi
if ! text_within_block "$SNAPSHOT_RECOVERY" 'public mutating func decide[(]' 'now.timeIntervalSince(lastAttempt) < Self.cooldown'; then
  fail "automatic filter restarts are not spaced by the cooldown"
fi
require_text "$SYSTEM_EXTENSION_MANAGER" "private func restartFilterProvider()" \
  "the app cannot restart the filter provider, so a rejected snapshot needs a reboot"
if ! text_within_block "$SYSTEM_EXTENSION_MANAGER" 'private func recordSnapshotStatus[(]' 'recoverFromSnapshotRejection(snapshotStatus)'; then
  fail "the app does not act on an extension that refused the helper policy"
fi
restart_body="$(swift_function_body "$SYSTEM_EXTENSION_MANAGER" 'private func restartFilterProvider()')"
[[ -n "$restart_body" ]] || fail "the filter provider restart has no body to audit"
if grep -Eq 'removeFromPreferences|deactivationRequest|kickstart|bootout|unregister' <<<"$restart_body"; then
  fail "recovering from a rejected snapshot removes the filter configuration, deactivates the extension, or touches the helper"
fi
if grep -Fq 'restart your Mac' "$FILTER" "$BRIDGE" "$SYSTEM_EXTENSION_MANAGER" "$APP_STATE"; then
  fail "a snapshot rejection still tells the user to restart the Mac"
fi

# DNS policy must be one immutable value published under one lock, and a query
# must decide from a single snapshot. Stored mutable policy fields raced across
# the XPC, blocklist and DNS queues, and the paired rules plus prepared set tore
# apart between two stores.
require_text "$DNS_PROXY" "private var storedPolicy" \
  "DNSProxy does not keep its policy in one private stored value"
require_text "$DNS_PROXY" "func policySnapshot() -> DNSPolicy" \
  "DNSProxy does not expose one coherent policy snapshot"
require_text "$DNS_PROXY" "let policy = policySnapshot()" \
  "the DNS query path does not decide from a single policy snapshot"
require_text "$DNS_PROXY" "func applyPolicy(mode" \
  "DNSProxy has no combined mode-and-rules transition"
if grep -Fq 'didSet { preparedRules' "$DNS_PROXY"; then
  fail "DNSProxy still rebuilds its prepared rules in a didSet, which tears the pairing"
fi
if grep -Eq '^[[:space:]]+var (rules: \[Rule\]|blocklist: Set<String>|mode: AppMode) = ' "$DNS_PROXY"; then
  fail "DNSProxy still stores mutable DNS policy fields outside the locked snapshot"
fi

# The helper must publish mode and rules as one transition. Two statements left
# a window where a query saw the new mode against the old rules.
require_text "$HELPER" "dns.applyPolicy(mode:" \
  "the helper does not publish mode and rules as one DNS policy transition"
if grep -Eq '^[[:space:]]+dns\.(mode|rules) = ' "$HELPER"; then
  fail "the helper still assigns DNS mode and rules separately, which publishes a torn policy"
fi

# Insights is always-on recording, but querying it must stay bounded and off the
# flow-verdict path. The UI must also say when Silent Allow blocks nothing.
for required in "$INSIGHTS_MODELS" "$INSIGHTS_STORE" "$INSIGHTS_VIEW"; do
  [[ -f "$required" ]] || fail "missing Insights component: $required"
done
require_text "$INSIGHTS_MODELS" "maxQueryPageSize = 200" \
  "Insights query pages are not bounded"
require_text "$INSIGHTS_MODELS" "maxQueryRequestBytes" \
  "Insights query requests have no byte bound"
require_text "$INSIGHTS_MODELS" "maxReportBytes" \
  "Insights query responses have no byte bound"
require_text "$GUI_HELPER" "payload.count <= InsightsLimits.maxReportBytes" \
  "the GUI decodes Insights data before bounding the response"
require_text "$HELPER" "insightsQueryQueue.async" \
  "the helper runs Insights queries on its XPC connection queue"
require_text "$INSIGHTS_VIEW" "FreeSnitch is in Silent Allow: every connection no rule covers is permitted, and your deny and ask rules still apply" \
  "Insights does not say plainly that Silent Allow only blocks what deny rules name (#434)"
require_text "$RULE_STORE" "?? .silentAllow" \
  "a fresh rules database does not default honestly to Silent Allow"
if grep -Eq 'URLSession|CFHost|GetAddrInfo|gethostby' "$INSIGHTS_STORE"; then
  fail "Insights performs an online or reverse-DNS lookup instead of using local DNS answers"
fi

# Issue #71: a drag to the Trash leaves this root daemon enforcing for an app
# that no longer exists, so the helper stands down when its bundle is gone. That
# check is a loaded gun. An update can make a bundle briefly absent, and #24 is
# the incident where unregistering an enabled helper destroyed the service. The
# invariant that matters most is therefore: the bundle-absence path may only
# stop enforcing, never unregister anything and never delete anything, and it
# may never conclude a removal from a single unlucky read.
BUNDLE_WATCHER="$ROOT/Sources/Helper/BundlePresenceWatcher.swift"
HELPER_MAIN="$ROOT/Sources/Helper/main.swift"
[[ -f "$BUNDLE_WATCHER" ]] || fail "missing $BUNDLE_WATCHER"
[[ -f "$HELPER_MAIN" ]] || fail "missing $HELPER_MAIN"

# Comments in that file describe what it must never do, so the forbidden-verb
# check reads the code with comments stripped.
bundle_watcher_code="$(sed -e 's,//.*,,' "$BUNDLE_WATCHER")"
for forbidden in bootout unregister SMAppService launchctl removeItem trashItem 'unlink(' 'Process(' pfctl freesnitch.sqlite; do
  if grep -Fq -- "$forbidden" <(printf '%s\n' "$bundle_watcher_code"); then
    fail "the bundle-absence path uses \`$forbidden\`; it may only stand enforcement down"
  fi
done
require_text "$BUNDLE_WATCHER" "service.setEnforcementEnabled(false, reply: completion)" \
  "the bundle-absence path does not stand down through the enforcement toggle"
require_text "$HELPER_MAIN" "HelperBundleWatchdog.shared.startWatching(service: service)" \
  "the helper does not start the bundle watchdog"

# One unlucky read may never be enough, and neither may a burst of reads.
required_absences="$(sed -n 's/.*requiredConsecutiveAbsences = \([0-9][0-9]*\).*/\1/p' "$BUNDLE_WATCHER" | sed -n 1p)"
absence_interval="$(sed -n 's/.*minimumObservationInterval: TimeInterval = \([0-9][0-9]*\).*/\1/p' "$BUNDLE_WATCHER" | sed -n 1p)"
absence_span="$(sed -n 's/.*minimumAbsenceSpan: TimeInterval = \([0-9][0-9]*\).*/\1/p' "$BUNDLE_WATCHER" | sed -n 1p)"
[[ -n "$required_absences" && -n "$absence_interval" && -n "$absence_span" ]] \
  || fail "the bundle-absence thresholds are no longer stated as plain constants"
(( required_absences >= 3 )) \
  || fail "a stand-down needs only $required_absences absence observations; a single unlucky read must never be enough"
(( absence_interval >= 60 )) \
  || fail "absence observations only need to be ${absence_interval}s apart, so a burst of reads counts as evidence"
(( absence_span >= 300 )) \
  || fail "the absence only needs to span ${absence_span}s, which an in-place update can produce"

# Anything that is not a proven absence must clear the streak, and the evidence
# must be logged before the stand-down is acted on.
require_text "$BUNDLE_WATCHER" "case .inconclusive" \
  "the bundle-absence path has no inconclusive reading, so an unreadable path counts as a removal"
absence_evidence_line="$(grep -nF 'AUDIT: the containing app bundle is gone' "$BUNDLE_WATCHER" | head -1 | cut -d: -f1 || true)"
absence_action_line="$(grep -nF 'action { ok, message in' "$BUNDLE_WATCHER" | head -1 | cut -d: -f1 || true)"
[[ -n "$absence_evidence_line" && -n "$absence_action_line" && "$absence_evidence_line" -lt "$absence_action_line" ]] \
  || fail "the bundle-absence stand-down acts before it logs its evidence"

# The matcher never reads a rule's name, so an enabled rule that names its app
# only by name matches every app (#157). Every helper ingest path and the
# shared import reader must refuse one.
helper_reject_body="$(swift_function_body "$HELPER" 'private func rejectionReason(for rule: Rule)')"
grep -Fq 'rule.nameOnlyRejectionReason' <<<"$helper_reject_body" \
  || fail "the helper accepts an enabled rule that names its app only by name, which matches every app"
for ingest in 'func addRule(ruleJSON' 'func reloadRules(rulesJSON' 'func replaceRules(rulesJSON'; do
  swift_function_body "$HELPER" "$ingest" | read_all_then grep -Fq 'rejectionReason(for:' \
    || fail "the helper's $ingest path skips rule content validation"
done
swift_function_body "$ROOT/Sources/Shared/RuleExportFormat.swift" 'public static func validate(_ rules: [Rule])' \
  | read_all_then grep -Fq 'rule.nameOnlyRejectionReason' \
  || fail "rule import accepts an enabled rule that names its app only by name"
# A rule remembered from a DNS alert carries the proxy's name and no app, and
# means every app. Refusing it would make "remember" on a DNS alert store
# nothing, so the exception must stay, keyed to the name the proxy uses.
swift_function_body "$RULE_MATCHER" 'public var namesAppOnlyByName: Bool' \
  | read_all_then grep -Fq 'Connection.dnsLookupProcessName' \
  || fail "a rule remembered from a DNS alert counts as name-only and would be refused"
require_text "$HELPER" 'processName: Connection.dnsLookupProcessName' \
  "the DNS proxy's alerts no longer use the name the name-only check exempts"

# pf matches packets, not processes. An app's deny rule used to be rendered
# from its address or port alone, so "Discord, deny, <address>" blocked that
# address for every app (issue #155). Deny rules that name an app must stay
# out of the anchor, and no other loop may render the rule set. Allow rules
# stay in, so an address feed never blocks what the user allowed.
anchor_body="$(sed -n '/func renderAnchor(/,/^    }$/p' "$PF_MANAGER")"
[[ -n "$anchor_body" ]] || fail "PFManager has no renderAnchor function to audit"
# A quick line stops pf at the first match, so the lines must follow the matcher's order
# (PreparedRuleSet: enabled rules, priority first) or a lower-priority deny
# overrides a higher-priority allow (issue #181).
grep -Fq 'let liveRules = PreparedRuleSet(rules: rules).ordered.filter { !PFManager.hasExpired($0, at: now) }' <<<"$anchor_body" \
  || fail "the pf anchor no longer renders the matcher's order of enabled, unexpired rules, so pf and the extension can disagree"
grep -Fq 'let renderedRules = liveRules.filter { PFManager.reachesPF($0) }' <<<"$anchor_body" \
  || fail "the pf anchor no longer filters the rules it renders through reachesPF"
[[ "$(printf '%s\n' "$anchor_body" | grep -c 'pfLines(')" -eq 1 ]] \
  || fail "the pf anchor renders rules in more than one pass, which ignores rule priority"
reaches_body="$(swift_function_body "$PF_MANAGER" 'static func reachesPF(')"
grep -Fq 'case .deny: return !namesAnApp(rule)' <<<"$reaches_body" \
  || fail "the pf anchor no longer drops deny rules that name an app, so one app's deny would block every app"
grep -Fq 'case .allow: return true' <<<"$reaches_body" \
  || fail "the pf anchor no longer renders every live allow rule, so an address feed could block what the user allowed"
grep -Fq 'case .ask: return false' <<<"$reaches_body" \
  || fail "the pf anchor renders ask rules as passes, which turns the address feeds off for their whole address or port"
if grep -Eq 'for [a-z]+ in rules\b' <<<"$anchor_body"; then
  fail "the pf anchor renders the unfiltered rule set somewhere"
fi
# pf only changes when the anchor is rendered, so every render must schedule
# the next one for the earliest expiry, or an expired temporary deny keeps
# blocking until some unrelated rule change (issue #180).
write_body="$(swift_function_body "$PF_MANAGER" 'private func writeAndLoad(')"
grep -Fq 'scheduleExpiryRender(for: rules)' <<<"$write_body" \
  || fail "writing the pf anchor no longer schedules a render for the next rule expiry"
expired_body="$(swift_function_body "$PF_MANAGER" 'static func hasExpired(')"
grep -Fq 'expiresAt < now' <<<"$expired_body" \
  || fail "pf decides expiry differently from the matcher, which drops a rule only once expiresAt < now"
names_body="$(swift_function_body "$PF_MANAGER" 'static func namesAnApp(')"
for field in processBundleId processPath; do
  grep -Fq "rule.$field" <<<"$names_body" \
    || fail "namesAnApp ignores $field, so a deny naming an app that way would reach pf"
done
grep -Fq 'trimming' <<<"$names_body" \
  && fail "namesAnApp trims whitespace, which the matcher does not, so pf and the extension would disagree"

# pf, the DNS proxy and the extension enforce one policy: the active profile's
# mode with the Always rules, then that profile's rules. The store's raw state
# carries every profile's rules, and publishing it made pf and the DNS proxy
# enforce profiles that were not active (issue #184).
for raw in 'store.policyState()' 'store.mutatePolicy('; do
  grep -Fq "$raw" "$HELPER" \
    && fail "the helper reads $raw, which carries every profile's rules, not the active profile's"
done
republish_body="$(swift_function_body "$HELPER" 'private func republishActivePolicy(')"
grep -Fq 'applyRulesIfEnforcing()' <<<"$republish_body" \
  || fail "a profile switch no longer reaches pf, which keeps enforcing the previous profile's rules"
# Turning enforcement on loads the rules in force, and pf records every rule
# change even while enforcement is off, so nothing stale can come back on the
# next feed refresh (issue #185).
install_body="$(swift_function_body "$PF_MANAGER" 'func install(')"
grep -Fq 'writeAndLoad(rules: rules)' <<<"$install_body" \
  || fail "loading the pf anchor no longer renders the rules in force"
grep -Fq 'writeAndLoad(rules: [])' <<<"$install_body" \
  && fail "loading the pf anchor renders no user rules"
apply_body="$(swift_function_body "$PF_MANAGER" 'func applyRules(')"
grep -Fq 'lastRules = rules' <<<"$apply_body" \
  || fail "pf no longer records every rule change, so a feed refresh could render stale rules"
for body_name in install_body apply_body; do
  grep -Fq 'let rules = readRules()' <<<"${!body_name}" \
    || fail "pf reads the rules to load before taking its lock, so an older list can win over a newer one"
done
grep -Fq 'guard loaded else { return false }' <<<"$apply_body" \
  || fail "pf no longer decides under its own lock whether the anchor is loaded"
grep -Eq 'pf\.install\(\)' "$HELPER" \
  && fail "the helper loads the pf anchor without the rules in force"
gate_body="$(swift_function_body "$HELPER" 'private func applyRulesIfEnforcing(')"
grep -Fq 'pf.isLoaded' <<<"$gate_body" \
  && fail "the helper skips recording rules in pf while enforcement is off"

# A new helper starts with enforcement off, so it clears whatever anchor the
# previous helper or pf.conf left in the kernel before any client can reach it
# (issue #189). Turning enforcement off empties the anchor file as well as the
# kernel anchor, so a later load of /etc/pf.conf cannot bring the last rules
# back (issue #190). Scripts/test_pf_leftover_anchor.sh exercises both.
start_body="$(swift_function_body "$HELPER" '    func start() {')"
printf '%s\n' "$start_body" | read_all_then awk '/pf\.clearLeftoverAnchor\(\)/ { seen = 1 } /listener\.resume\(\)/ { resumed = 1; ok = seen; exit } END { exit !(resumed && ok) }' \
  || fail "the helper accepts clients before clearing a pf anchor a previous helper left loaded"
for entry in 'func uninstall(' 'func clearLeftoverAnchor('; do
  swift_function_body "$PF_MANAGER" "$entry" | read_all_then grep -Fq 'unloadLocked()' \
    || fail "pf's $entry no longer empties both the kernel anchor and the anchor file"
done
unload_body="$(swift_function_body "$PF_MANAGER" 'private func unloadLocked(')"
grep -Fq 'PFManager.emptyAnchor.write(toFile: anchorPath' <<<"$unload_body" \
  || fail "turning enforcement off leaves the last rules in the anchor file pf.conf loads at boot"
grep -Fq -- '"-F", "all"' <<<"$unload_body" \
  || fail "turning enforcement off no longer flushes the kernel anchor"
grep -Eq 'removeItem|"-d"' <<<"$unload_body" \
  && fail "turning enforcement off deletes the anchor file pf.conf names or disables pf for the whole Mac"

printf 'Firewall safety audit passed: fail-open GUI handling, code-signature self exemption, loopback ordering, timeout, XPC snapshots, peer validation, bounded CIDR matching with validated rule ingest, bounded DNS asks that always complete, activation ordering, authoritative helper-owned policy snapshots, atomic DNS policy publication, bounded offline Insights queries, a bundle-absence stand-down that can neither unregister nor delete, a pf anchor that never carries a deny naming an app, refusal of rules that name an app only by name, expired temporary rules leaving pf on time, pf lines in matcher priority order, pf and the DNS proxy enforcing exactly the current rules of the active profile, and no FreeSnitch rules left in pf once enforcement is off are present.\n'
