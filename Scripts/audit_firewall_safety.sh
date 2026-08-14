#!/usr/bin/env bash
# Static release gate for the Network System Extension's safety invariants.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FILTER="$ROOT/Sources/NetExt/FilterDataProvider.swift"
BRIDGE="$ROOT/Sources/Shared/SharedRuleBridge.swift"
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
if ! printf '%s\n' "$cidr_body" | grep -Fq 'parts[1].utf8.allSatisfy({ $0 >= 48 && $0 <= 57 })'; then
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

printf '%s\n' "$cidr_body" | grep -Fq 'if net.contains(":") { return ipv6CidrContains(' \
  || fail "cidrContains no longer routes an IPv6 network to the IPv6 matcher, so IPv6 CIDR rules are inert again"
ipv6_body="$(swift_function_body "$RULE_MATCHER" 'func ipv6CidrContains(')"
[[ -n "$ipv6_body" ]] || fail "the shared matcher has no ipv6CidrContains function to audit"
ipv6_guard_line="$(printf '%s\n' "$ipv6_body" | grep -nF '(0...128).contains(bits)' | head -1 | cut -d: -f1 || true)"
ipv6_mask_line="$(printf '%s\n' "$ipv6_body" | grep -nF 'UInt8(0xFF) <<' | head -1 | cut -d: -f1 || true)"
[[ -n "$ipv6_guard_line" ]] || fail "ipv6CidrContains does not bound the CIDR prefix to 0...128, so an over-large prefix can match every address"
[[ -n "$ipv6_mask_line" ]] || fail "ipv6CidrContains no longer builds the expected IPv6 mask"
(( ipv6_guard_line < ipv6_mask_line )) \
  || fail "ipv6CidrContains builds the mask before bounding the prefix"
printf '%s\n' "$ipv6_body" | grep -Fq 'ipv6Bytes(network), let addr = ipv6Bytes(ip)' \
  || fail "ipv6CidrContains no longer parses both sides as IPv6, so an IPv4 address could reach the IPv6 comparison"
require_text "$RULE_MATCHER" "inet_pton(AF_INET6" \
  "the matcher no longer parses IPv6 with inet_pton, so it can disagree with what ingest validated"

# Every new socket flow used to filter and sort the whole rule set before the
# verdict. That ordering belongs to the snapshot, and the verdict path must
# stay a scan over the already ordered array.
require_text "$RULE_MATCHER" "public struct PreparedRuleSet" \
  "the precomputed rule order is missing, so every flow pays a filter and a sort again"
verdict_body="$(swift_function_body "$RULE_MATCHER" 'func decision(for c: Connection, prepared:')"
[[ -n "$verdict_body" ]] || fail "the shared matcher has no prepared-rule verdict path to audit"
for forbidden in '.sorted' '.filter' '.map('; do
  if printf '%s\n' "$verdict_body" | grep -Fq -- "$forbidden"; then
    fail "the per-flow verdict path uses $forbidden, which reorders or allocates on every flow"
  fi
done
printf '%s\n' "$verdict_body" | grep -Fq 'for r in prepared.compiled' \
  || fail "the per-flow verdict path no longer scans the compiled rule order"
if printf '%s\n' "$verdict_body" | grep -Eq 'matches\(rule:|ipMatches\(|hostMatches\('; then
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
printf '%s\n' "$prepared_body" | grep -Fq 'lhs.offset < rhs.offset' \
  || fail "PreparedRuleSet no longer breaks equal priorities by snapshot order, so which rule wins becomes undefined"
printf '%s\n' "$prepared_body" | grep -Fq 'compiled = ordered.map(PreparedRule.init)' \
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
printf '%s\n' "$prepared_ip_body" | grep -Fq 'parts[1].utf8.allSatisfy({ $0 >= 48 && $0 <= 57 })' \
  || fail "compiled CIDR patterns accept a non-numeric or signed prefix"
printf '%s\n' "$prepared_ip_body" | grep -Fq 'if network.contains(":")' \
  || fail "compiled rules no longer keep IPv4 and IPv6 CIDRs in separate address spaces"
printf '%s\n' "$prepared_ip_body" | grep -Fq 'parsePreparedIPv4Address(network)' \
  || fail "PreparedRuleSet does not parse IPv4 CIDR networks when the snapshot is applied"
printf '%s\n' "$prepared_ip_body" | grep -Fq 'parsePreparedIPv6Address(network)' \
  || fail "PreparedRuleSet does not parse IPv6 CIDR networks when the snapshot is applied"
printf '%s\n' "$prepared_ip_body" | grep -Fq 'if raw == rawIP { return true }' \
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
  persist_line="$(printf '%s\n' "$ingest_body" | grep -nE 'store\.upsertRule|mutatePolicy' | head -1 | cut -d: -f1 || true)"
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
' "$HELPER" | grep -Fq 'insights.record'; then
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

# A verdict must never wait on the filesystem. The bundle identifier comes from
# a bounded in-memory cache, and the Info.plist read happens on a background
# queue, so a cold page cache or a slow volume cannot become filter latency.
require_text "$FILTER" "bundleIdentifierCache.cachedBundleId(forExecutablePath: path)" \
  "the verdict path no longer answers bundle identifiers from the bounded cache"
require_text "$FILTER" "capacity: Int = 512" \
  "the bundle identifier cache capacity is not explicit and bounded"
require_text "$FILTER" "resolveQueue.async" \
  "bundle identifier plist reads are not handed to a background queue"
require_text "$FILTER" "private let lock: UnsafeMutablePointer<os_unfair_lock_s>" \
  "the bundle identifier cache does not hold its lock at a stable address"
bundle_id_body="$(awk '
  /private func bundleIdForApp\(atPath path: String\)/ {
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
[[ -n "$bundle_id_body" ]] || fail "the extension no longer resolves a bundle identifier for the flow"
if printf '%s\n' "$bundle_id_body" | grep -Eq 'Data\(contentsOf:|PropertyListSerialization'; then
  fail "the verdict path reads and parses an Info.plist synchronously"
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
if printf '%s\n' "$destination_body" | grep -Eq 'host: "(::|0\.0\.0\.0)"|ip: "(::|0\.0\.0\.0)"'; then
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
if printf '%s\n' "$report_body" | grep -Eq 'resumeFlow|updateFlow|Verdict|pause|sleep|DispatchSemaphore|\.sync'; then
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
if printf '%s\n' "$new_flow_body" | grep -Eq 'DispatchSemaphore|\.sync|sleep|\.wait\(|filterDataVerdict'; then
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
if ! text_within_block "$HELPER" 'init[(]listener: NSXPCListener[)]' 'store.policyState()'; then
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
  ask_body="$(printf '%s\n' "$coordinator_body" | awk -v start="$ask_func" '
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
  printf '%s\n' "$ask_body" | grep -Eq 'Self\.defaultDecision' \
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
require_text "$HELPER" "store.policyState()" \
  "the helper snapshot path does not read persisted mode and rules together"
require_text "$HELPER" "store.mutatePolicy" \
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
require_text "$APP_STATE" "remoteIP: ruleIP" \
  "the remembered alert rule does not carry the remote address, so an IP-only decision would match every destination"
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
if rg -v '^[[:space:]]*//' "$PRIVILEGED_REPAIR" | rg -q 'bootout|unload|unregister'; then
  fail "the privileged repair uses a destructive launchctl verb; it must only ever kickstart"
fi
if rg -v '^[[:space:]]*//' "$PRIVILEGED_REPAIR" | rg -q '\\\('; then
  fail "the privileged repair script interpolates a value; it must be a compile-time constant"
fi
# Check the BRANCH, not merely that the identifier exists somewhere. An
# earlier version of this check passed while the call site had been replaced,
# because the now-dead function definition still contained the name.
if ! rg -A6 'case \.manualKickstart:' "$GUI_HELPER" | rg -q 'performPrivilegedKickstart\(\)'; then
  fail "the stale-helper path no longer attempts the repair itself, so it would only print a sudo command"
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
if rg -v '^[[:space:]]*//' "$UNINSTALL_VIEW" | rg -q 'Scripts/uninstall_freesnitch.sh'; then
  fail "the uninstall screen points the user at a script that only exists in a source checkout"
fi
require_text "$UNINSTALL_VIEW" "PrivilegedUninstall.run" \
  "the uninstall screen does not perform the removal itself"
if rg -v '^[[:space:]]*//' "$PRIVILEGED_UNINSTALL" | rg -q '\\\('; then
  fail "the privileged uninstall interpolates a value; every path it removes must be a constant"
fi
# Flushing the shared anchor is required; deleting it or disabling pf is not,
# because /etc/pf.conf still references it and the user's firewall would be
# stranded.
if rg -v '^[[:space:]]*//' "$PRIVILEGED_UNINSTALL" | rg -q 'pfctl -d|rm -f /etc/pf|rm -rf /etc/pf|anchors/puresnitch'; then
  fail "the privileged uninstall disables pf globally or removes the shared anchor file"
fi
require_text "$PRIVILEGED_UNINSTALL" "pfctl -a puresnitch -F all" \
  "the privileged uninstall no longer flushes the FreeSnitch anchor"
# The app bundle must go to the Trash through Finder, never be deleted.
# Moving an app that hosts a system extension to the Trash is what makes macOS
# remove the extension; deleting the bundle directly takes the app away and
# leaves the extension installed. Objective Development document this for
# Little Snitch and warn against removing such an app by any other means.
if rg -v '^[[:space:]]*//' "$PRIVILEGED_UNINSTALL" | rg -q "rm -rf '/Applications"; then
  fail "the privileged uninstall deletes the app bundle, which strands the system extension"
fi
require_text "$PRIVILEGED_UNINSTALL" "NSWorkspace.shared.recycle" \
  "the uninstall does not hand the app bundle to Finder, so macOS will not remove the system extension"
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
UNINSTALL_BODY=$(rg -A24 'func deactivateForUninstall' "$SYSEXT_MANAGER")
if ! rg -q 'removeFilterConfiguration' <<<"$UNINSTALL_BODY"; then
  fail "uninstall no longer removes the filter configuration before deactivating the extension"
fi
if rg -q 'disableFilter\(' <<<"$UNINSTALL_BODY"; then
  fail "uninstall only disables the filter configuration, so macOS keeps the extension record until a reboot"
fi
# Turning enforcement off is NOT an uninstall: that path must keep the
# configuration installed so it can be switched back on without re-approval.
if rg -A10 'private func disableFilter' "$SYSEXT_MANAGER" | rg -q 'removeFromPreferences'; then
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
printf '%s\n' "$filter_body" | grep -Fq 'SharedRuleBridge.SnapshotAuthority.compare(received: received, against: $0)' \
  || fail "the extension does not rank a received snapshot by helper session before generation"
printf '%s\n' "$filter_body" | grep -Fq 'authority == .olderSession' \
  || fail "the extension does not reject a snapshot from an older helper session"
lower_generation_block="$(swift_function_body "$FILTER" 'if let current, received.generation < current.generation {')"
[[ -n "$lower_generation_block" ]] || fail "the extension has no lower-generation rejection block to audit"
printf '%s\n' "$lower_generation_block" | grep -Fq 'authority == .sameSession' \
  || fail "the extension's lower-generation rejection is not scoped to one helper session, so a restarted helper is locked out until a reboot"
printf '%s\n' "$filter_body" | grep -Fq 'rejection: .conflictingContent' \
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
if printf '%s\n' "$restart_body" | grep -Eq 'removeFromPreferences|deactivationRequest|kickstart|bootout|unregister'; then
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
require_text "$INSIGHTS_VIEW" "FreeSnitch is in Silent Allow: every connection is permitted" \
  "Insights does not say plainly that Silent Allow blocks nothing"
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
required_absences="$(sed -n 's/.*requiredConsecutiveAbsences = \([0-9][0-9]*\).*/\1/p' "$BUNDLE_WATCHER" | head -1)"
absence_interval="$(sed -n 's/.*minimumObservationInterval: TimeInterval = \([0-9][0-9]*\).*/\1/p' "$BUNDLE_WATCHER" | head -1)"
absence_span="$(sed -n 's/.*minimumAbsenceSpan: TimeInterval = \([0-9][0-9]*\).*/\1/p' "$BUNDLE_WATCHER" | head -1)"
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

printf 'Firewall safety audit passed: fail-open GUI handling, code-signature self exemption, loopback ordering, timeout, XPC snapshots, peer validation, bounded CIDR matching with validated rule ingest, bounded DNS asks that always complete, activation ordering, authoritative helper-owned policy snapshots, atomic DNS policy publication, bounded offline Insights queries, and a bundle-absence stand-down that can neither unregister nor delete are present.\n'
