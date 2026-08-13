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
DNS_PROXY="$ROOT/Sources/Helper/DNSProxy.swift"
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
RULE_MATCHER="$ROOT/Sources/Shared/RuleMatcher.swift"
CLI_PARSER="$ROOT/Sources/CLI/CLIParser.swift"

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
[[ -f "$RULE_MATCHER" ]] || fail "missing $RULE_MATCHER"
[[ -f "$CLI_PARSER" ]] || fail "missing $CLI_PARSER"
[[ -f "$DNS_PROXY" ]] || fail "missing $DNS_PROXY"

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
printf '%s\n' "$verdict_body" | grep -Fq 'for r in prepared.ordered' \
  || fail "the per-flow verdict path no longer scans the precomputed rule order"
prepared_body="$(swift_function_body "$RULE_MATCHER" 'public init(rules: [Rule])')"
[[ -n "$prepared_body" ]] || fail "PreparedRuleSet has no initializer to audit"
printf '%s\n' "$prepared_body" | grep -Fq 'lhs.offset < rhs.offset' \
  || fail "PreparedRuleSet no longer breaks equal priorities by snapshot order, so which rule wins becomes undefined"

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
  upsert_line="$(printf '%s\n' "$ingest_body" | grep -nF 'store.upsertRule' | head -1 | cut -d: -f1 || true)"
  [[ -n "$reason_line" && -n "$upsert_line" ]] \
    || fail "a helper rule ingest path stores rules without an address rejection check"
  (( reason_line < upsert_line )) \
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
      if (depth <= 0) active = 0
    }
    END { exit(found ? 0 : 1) }
  ' "$file"
}

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

printf 'Firewall safety audit passed: fail-open GUI handling, code-signature self exemption, loopback ordering, timeout, XPC snapshots, peer validation, bounded CIDR matching with validated rule ingest, bounded DNS asks that always complete, and activation ordering are present.\n'
