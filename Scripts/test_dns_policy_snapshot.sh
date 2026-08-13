#!/usr/bin/env bash
# Concurrency harness for the atomic DNS policy snapshot (issue #47).
#
# The harness is compiled from the real helper and shared sources, never from a
# copy, so it exercises the shipping DNSProxy. Two harnesses exist:
#
#   snapshot (default)  asserts that every observed policy is one complete
#                       publication: rules paired with their own prepared
#                       order, a combined mode-plus-rules transition never seen
#                       half applied, and a captured snapshot that stays
#                       constant while writers keep swapping.
#   legacy (--legacy)   drives only the property surface that existed before
#                       the fix, so the same harness text can be compiled
#                       against an older DNSProxy to show the race it had.
#
# Both are run without and with Thread Sanitizer.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HARNESS="snapshot"
if [[ "${1:-}" == "--legacy" ]]; then
  HARNESS="legacy"
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-dns-policy.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

SDK="$(xcrun --show-sdk-path)"
TARGET="arm64-apple-macos13.0"

write_snapshot_harness() {
  cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

/// Every writer publishes a generation. The rules of generation g are tagged
/// with g, the mode is derived from g, and both are published in one call, so
/// any pairing the reader sees that does not belong to a single generation is
/// a torn policy.
enum Generated {
    static func mode(for generation: Int) -> AppMode {
        generation % 2 == 0 ? .silentAllow : .silentDeny
    }

    static func rules(for generation: Int) -> [Rule] {
        let count = 3 + (generation % 7)
        return (0..<count).map { index in
            Rule(remoteHost: "gen\(generation)-\(index).example",
                 action: .allow,
                 scope: .domain,
                 priority: 100 + index,
                 enabled: index % 3 != 0)
        }
    }

    static func generation(ofHost host: String?) -> Int? {
        guard let host, host.hasPrefix("gen") else { return nil }
        let body = host.dropFirst(3)
        guard let dash = body.firstIndex(of: "-") else { return nil }
        return Int(body[body.startIndex..<dash])
    }

    static func blocklist(for generation: Int) -> Set<String> {
        let count = 2 + (generation % 5)
        return Set((0..<count).map { "bl\(generation)-\($0).example" })
    }

    static func generation(ofBlocklistEntry entry: String) -> Int? {
        guard entry.hasPrefix("bl") else { return nil }
        let body = entry.dropFirst(2)
        guard let dash = body.firstIndex(of: "-") else { return nil }
        return Int(body[body.startIndex..<dash])
    }

    static let resolvers = [
        "https://one.example/dns-query",
        "https://two.example/dns-query",
        "https://three.example/dns-query"
    ]
}

/// Collects failures instead of trapping, so one run reports every invariant
/// that broke rather than only the first.
final class Failures: @unchecked Sendable {
    private let lock = NSLock()
    private var messages: [String] = []

    func record(_ message: String) {
        lock.lock()
        if messages.count < 20 { messages.append(message) }
        lock.unlock()
    }

    var all: [String] {
        lock.lock()
        defer { lock.unlock() }
        return messages
    }
}

/// The whole point of the fix: one prepared set belongs to exactly one rule
/// snapshot, and the mode published with them belongs to the same transition.
func incoherence(in policy: DNSPolicy) -> String? {
    guard let first = policy.rules.first else {
        return policy.preparedRules.ordered.isEmpty
            ? nil
            : "empty rule set published with \(policy.preparedRules.ordered.count) prepared rules"
    }
    guard let generation = Generated.generation(ofHost: first.remoteHost) else {
        return "rule host is not tagged: \(first.remoteHost ?? "nil")"
    }
    for rule in policy.rules where Generated.generation(ofHost: rule.remoteHost) != generation {
        return "rules mix generation \(generation) with \(Generated.generation(ofHost: rule.remoteHost).map(String.init) ?? "nil")"
    }
    for rule in policy.preparedRules.ordered where Generated.generation(ofHost: rule.remoteHost) != generation {
        return "prepared set belongs to generation \(Generated.generation(ofHost: rule.remoteHost).map(String.init) ?? "nil") while rules are generation \(generation)"
    }
    let expected = Generated.rules(for: generation)
    if policy.rules.count != expected.count {
        return "generation \(generation) published \(policy.rules.count) rules, expected \(expected.count)"
    }
    let expectedOrder = expected.filter { $0.enabled }
        .sorted { $0.priority > $1.priority }
        .map { $0.remoteHost ?? "" }
    let observedOrder = policy.preparedRules.ordered.map { $0.remoteHost ?? "" }
    if observedOrder != expectedOrder {
        return "prepared order \(observedOrder) does not match its own rule set \(expectedOrder)"
    }
    if policy.mode != Generated.mode(for: generation) {
        return "generation \(generation) rules published with mode \(policy.mode), expected \(Generated.mode(for: generation))"
    }
    for entry in policy.blocklist {
        guard let blocklistGeneration = Generated.generation(ofBlocklistEntry: entry) else {
            return "blocklist entry is not tagged: \(entry)"
        }
        if policy.blocklist != Generated.blocklist(for: blocklistGeneration) {
            return "blocklist mixes generations around \(blocklistGeneration)"
        }
    }
    if !Generated.resolvers.contains(policy.dohURL) {
        return "resolver is not a published value: \(policy.dohURL)"
    }
    return nil
}

@main
struct DNSPolicySnapshotHarness {
    static func main() {
        let proxy = DNSProxy()
        let failures = Failures()
        proxy.applyPolicy(mode: Generated.mode(for: 0), rules: Generated.rules(for: 0))
        proxy.blocklist = Generated.blocklist(for: 0)
        proxy.dohURL = Generated.resolvers[0]

        let iterations = 4000
        let group = DispatchGroup()

        // Writers. Mode and rules only ever move together, through the one
        // combined setter, so a reader that sees them disagree saw a tear.
        for writer in 0..<4 {
            let queue = DispatchQueue(label: "harness.writer.\(writer)")
            queue.async(group: group) {
                for i in 0..<iterations {
                    proxy.applyPolicy(mode: Generated.mode(for: i + writer),
                                      rules: Generated.rules(for: i + writer))
                }
            }
        }
        // Independent policy fields get their own writers, so the pairing
        // checks above run while unrelated transitions are also in flight.
        DispatchQueue(label: "harness.writer.blocklist").async(group: group) {
            for i in 0..<iterations { proxy.blocklist = Generated.blocklist(for: i) }
        }
        DispatchQueue(label: "harness.writer.resolver").async(group: group) {
            for i in 0..<iterations {
                proxy.dohURL = Generated.resolvers[i % Generated.resolvers.count]
            }
        }

        // Readers stand in for the DNS query path: one snapshot per query,
        // then a decision taken entirely from that copy.
        let matcher = RuleMatcher()
        for reader in 0..<6 {
            let queue = DispatchQueue(label: "harness.reader.\(reader)")
            queue.async(group: group) {
                for i in 0..<iterations {
                    let policy = proxy.policySnapshot()
                    if let problem = incoherence(in: policy) {
                        failures.record("torn policy snapshot: \(problem)")
                    }
                    let stub = Connection(pid: 0, processName: "", processPath: "",
                                          remoteHost: "gen0-1.example",
                                          direction: .outgoing, status: .pending)
                    _ = matcher.decision(for: stub,
                                         prepared: policy.preparedRules,
                                         defaultMode: policy.mode)
                    // A query that has begun must keep its own snapshot: the
                    // same value has to still be self consistent after the
                    // writers have moved on many times.
                    if i % 64 == 0 {
                        let fingerprint = (policy.mode, policy.rules.count,
                                           policy.preparedRules.ordered.count,
                                           policy.blocklist.count, policy.dohURL)
                        for _ in 0..<200 { _ = proxy.policySnapshot() }
                        let after = (policy.mode, policy.rules.count,
                                     policy.preparedRules.ordered.count,
                                     policy.blocklist.count, policy.dohURL)
                        if fingerprint != after {
                            failures.record("captured snapshot changed under the reader")
                        }
                        if let problem = incoherence(in: policy) {
                            failures.record("captured snapshot became incoherent: \(problem)")
                        }
                    }
                }
            }
        }

        group.wait()

        let problems = failures.all
        guard problems.isEmpty else {
            for problem in problems {
                FileHandle.standardError.write(Data(("dns policy harness: FAIL: " + problem + "\n").utf8))
            }
            exit(1)
        }
        let final = proxy.policySnapshot()
        print("dns policy harness: \(iterations) iterations, 6 readers, 6 writers")
        print("dns policy harness: final policy mode \(final.mode), \(final.rules.count) rules, \(final.preparedRules.ordered.count) prepared, \(final.blocklist.count) blocked, resolver \(final.dohURL)")
        print("dns policy harness: PASS")
    }
}
SWIFT
}

write_legacy_harness() {
  cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

/// Uses only the DNS policy property surface that existed before issue #47,
/// so the same source compiles against an older DNSProxy. Every published rule
/// set is internally tagged with one generation and has one known length, and
/// every blocklist is one known set, so an unsynchronised read shows up as a
/// mixed or short collection here even without Thread Sanitizer.
enum Generated {
    static func rules(for generation: Int) -> [Rule] {
        let count = 3 + (generation % 7)
        return (0..<count).map { index in
            Rule(remoteHost: "gen\(generation)-\(index).example",
                 action: .allow,
                 scope: .domain,
                 priority: 100 + index,
                 enabled: index % 3 != 0)
        }
    }

    static func generation(ofHost host: String?) -> Int? {
        guard let host, host.hasPrefix("gen") else { return nil }
        let body = host.dropFirst(3)
        guard let dash = body.firstIndex(of: "-") else { return nil }
        return Int(body[body.startIndex..<dash])
    }

    static func blocklist(for generation: Int) -> Set<String> {
        let count = 2 + (generation % 5)
        return Set((0..<count).map { "bl\(generation)-\($0).example" })
    }

    static func generation(ofBlocklistEntry entry: String) -> Int? {
        guard entry.hasPrefix("bl") else { return nil }
        let body = entry.dropFirst(2)
        guard let dash = body.firstIndex(of: "-") else { return nil }
        return Int(body[body.startIndex..<dash])
    }

    static let resolvers = [
        "https://one.example/dns-query",
        "https://two.example/dns-query",
        "https://three.example/dns-query"
    ]
}

final class Failures: @unchecked Sendable {
    private let lock = NSLock()
    private var messages: [String] = []

    func record(_ message: String) {
        lock.lock()
        if messages.count < 20 { messages.append(message) }
        lock.unlock()
    }

    var all: [String] {
        lock.lock()
        defer { lock.unlock() }
        return messages
    }
}

@main
struct DNSPolicyLegacyHarness {
    static func main() {
        let proxy = DNSProxy()
        let failures = Failures()
        proxy.rules = Generated.rules(for: 0)
        proxy.blocklist = Generated.blocklist(for: 0)
        proxy.dohURL = Generated.resolvers[0]

        let iterations = 4000
        let group = DispatchGroup()

        for writer in 0..<4 {
            DispatchQueue(label: "harness.writer.\(writer)").async(group: group) {
                for i in 0..<iterations { proxy.rules = Generated.rules(for: i + writer) }
            }
        }
        DispatchQueue(label: "harness.writer.blocklist").async(group: group) {
            for i in 0..<iterations { proxy.blocklist = Generated.blocklist(for: i) }
        }
        DispatchQueue(label: "harness.writer.resolver").async(group: group) {
            for i in 0..<iterations {
                proxy.dohURL = Generated.resolvers[i % Generated.resolvers.count]
            }
        }

        for reader in 0..<6 {
            DispatchQueue(label: "harness.reader.\(reader)").async(group: group) {
                for _ in 0..<iterations {
                    let rules = proxy.rules
                    if let first = rules.first,
                       let generation = Generated.generation(ofHost: first.remoteHost) {
                        for rule in rules where Generated.generation(ofHost: rule.remoteHost) != generation {
                            failures.record("rule array mixes generations")
                            break
                        }
                        if rules.count != Generated.rules(for: generation).count {
                            failures.record("rule array of generation \(generation) has \(rules.count) rules, expected \(Generated.rules(for: generation).count)")
                        }
                    } else if !rules.isEmpty {
                        failures.record("rule array holds an untagged rule")
                    }
                    let blocklist = proxy.blocklist
                    if let entry = blocklist.first,
                       let generation = Generated.generation(ofBlocklistEntry: entry) {
                        if blocklist != Generated.blocklist(for: generation) {
                            failures.record("blocklist mixes generations around \(generation)")
                        }
                    } else if !blocklist.isEmpty {
                        failures.record("blocklist holds an untagged entry")
                    }
                    if !Generated.resolvers.contains(proxy.dohURL) {
                        failures.record("resolver is not a published value")
                    }
                }
            }
        }

        group.wait()

        let problems = failures.all
        guard problems.isEmpty else {
            for problem in problems {
                FileHandle.standardError.write(Data(("dns policy legacy harness: FAIL: " + problem + "\n").utf8))
            }
            exit(1)
        }
        print("dns policy legacy harness: \(iterations) iterations, 6 readers, 6 writers")
        print("dns policy legacy harness: PASS")
    }
}
SWIFT
}

build_and_run() {
  local label="$1"
  shift
  local binary="$TMP/run-$label"
  # shellcheck disable=SC2046
  xcrun swiftc -O -sdk "$SDK" -target "$TARGET" -parse-as-library "$@" \
    -o "$binary" \
    $(ls "$ROOT"/Sources/Helper/*.swift | grep -v '/main.swift$') \
    "$ROOT"/Sources/Shared/*.swift \
    "$TMP/verify.swift"
  printf 'dns policy harness (%s): running\n' "$label"
  "$binary"
  printf 'dns policy harness (%s): clean\n' "$label"
}

if [[ "$HARNESS" == "legacy" ]]; then
  write_legacy_harness
else
  write_snapshot_harness
fi

build_and_run "$HARNESS"
build_and_run "$HARNESS-tsan" -sanitize=thread

printf 'dns policy snapshot verification (%s): PASS\n' "$HARNESS"
