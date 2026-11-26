#!/usr/bin/env bash
# Harness for #248: turning enforcement on and off at the same time.
#
# The harness is compiled from the real Sources/Helper/EnforcementSwitch.swift,
# the code the helper's setEnforcementEnabled runs. Only pf and the DNS proxy
# are simulated, as two flags, so nothing here touches the Mac's firewall or
# DNS. It checks that:
#
#   1. The interleaving from the issue cannot happen: an enable paused right
#      after loading pf holds a concurrent disable back until it has finished,
#      so the disable runs last, its success reply means the DNS proxy is
#      stopped, and pf and the proxy end up off.
#   2. Many concurrent enables and disables never overlap, so pf and the
#      proxy always end in the same state.
#   3. A turn-on whose DNS proxy cannot start is rolled back to off and
#      replies failure (fail open).
#   4. A direct pf install waits for a transition in progress the same way.
#
# The waits use explicit signals. The one bounded wait (step 1) only gives a
# disable that is not held back time to finish, so load can make it pass
# late but never fail a correct build.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-enforcement-race.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

SDK="$(xcrun --show-sdk-path)"
TARGET="arm64-apple-macos13.0"

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

final class Checks {
    private var failures: [String] = []
    private var passed = 0

    func expect(_ condition: Bool, _ message: String) {
        if condition { passed += 1 } else { failures.append(message) }
    }

    func finish() {
        guard failures.isEmpty else {
            for failure in failures {
                FileHandle.standardError.write(Data(("enforcement race harness: FAIL: " + failure + "\n").utf8))
            }
            exit(1)
        }
        print("enforcement race harness: real sources: \(passed) assertions PASS")
    }
}

struct DNSStartFailed: Error {}

/// pf and the DNS proxy as two flags, plus a count of transitions inside a
/// step at once, which must never exceed one.
final class FakeFirewall: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var pfLoaded = false
    private(set) var dnsRunning = false
    private(set) var maxConcurrent = 0
    private var concurrent = 0
    var failDNSStart = false
    /// Called inside installPF, after pf is loaded: the point the issue pauses at.
    var afterInstall: (() -> Void)?

    func snapshot() -> (pf: Bool, dns: Bool) {
        lock.lock(); defer { lock.unlock() }
        return (pfLoaded, dnsRunning)
    }

    private func step(_ body: () throws -> Void) rethrows {
        lock.lock()
        concurrent += 1
        maxConcurrent = max(maxConcurrent, concurrent)
        lock.unlock()
        defer { lock.lock(); concurrent -= 1; lock.unlock() }
        try body()
    }

    private func set(pf: Bool? = nil, dns: Bool? = nil) {
        lock.lock(); defer { lock.unlock() }
        if let pf { pfLoaded = pf }
        if let dns { dnsRunning = dns }
    }

    var steps: EnforcementSwitch.Steps {
        EnforcementSwitch.Steps(
            installPF: { self.step { self.set(pf: true); self.afterInstall?() } },
            uninstallPF: { self.step { self.set(pf: false) } },
            startDNS: {
                try self.step {
                    if self.failDNSStart { throw DNSStartFailed() }
                    self.set(dns: true)
                }
            },
            stopDNS: { self.step { self.set(dns: false) } },
            pfSucceeded: {},
            pfFailed: { _ in })
    }
}

@main
struct Verify {
    static func main() {
        let checks = Checks()

        // 1. The issue's interleaving.
        do {
            let fake = FakeFirewall()
            let enforcement = EnforcementSwitch()
            let paused = DispatchSemaphore(value: 0)
            let resume = DispatchSemaphore(value: 0)
            let enableDone = DispatchSemaphore(value: 0)
            let disableDone = DispatchSemaphore(value: 0)
            let order = NSLock()
            var finished: [String] = []
            var disableReply: (Bool, String?) = (false, nil)
            var dnsWhenDisableReplied = true

            fake.afterInstall = {
                fake.afterInstall = nil
                paused.signal()
                resume.wait()
            }
            DispatchQueue.global().async {
                let reply = enforcement.setEnabled(true, steps: fake.steps)
                order.lock(); finished.append("on \(reply.0)"); order.unlock()
                enableDone.signal()
            }
            paused.wait()
            DispatchQueue.global().async {
                let reply = enforcement.setEnabled(false, steps: fake.steps)
                let state = fake.snapshot()
                order.lock()
                disableReply = reply
                dnsWhenDisableReplied = state.dns
                finished.append("off \(reply.0)")
                order.unlock()
                disableDone.signal()
            }
            let disableRanDuringPause = disableDone.wait(timeout: .now() + 2) == .success
            checks.expect(!disableRanDuringPause,
                          "a disable must wait for an enable in progress, but it finished while the enable was paused after loading pf")
            resume.signal()
            enableDone.wait()
            if !disableRanDuringPause { disableDone.wait() }

            order.lock()
            checks.expect(finished == ["on true", "off true"],
                          "the enable must finish first and the disable last, got \(finished)")
            checks.expect(disableReply.0, "the disable must succeed")
            checks.expect(!dnsWhenDisableReplied, "a successful disable reply must mean the DNS proxy is stopped")
            order.unlock()
            let end = fake.snapshot()
            checks.expect(!end.pf && !end.dns,
                          "after enable then disable, pf and the DNS proxy must be off, got pf \(end.pf) dns \(end.dns)")
        }

        // 2. Many concurrent requests: never two transitions at once, and the
        //    end state is the last request's.
        do {
            let fake = FakeFirewall()
            let enforcement = EnforcementSwitch()
            DispatchQueue.concurrentPerform(iterations: 4000) { i in
                _ = enforcement.setEnabled(i % 2 == 0, steps: fake.steps)
            }
            checks.expect(fake.maxConcurrent == 1,
                          "two enforcement transitions ran at once (\(fake.maxConcurrent) steps overlapped)")
            let end = fake.snapshot()
            checks.expect(end.pf == end.dns,
                          "after concurrent requests pf and the DNS proxy disagree: pf \(end.pf) dns \(end.dns)")
            let final = enforcement.setEnabled(false, steps: fake.steps)
            let off = fake.snapshot()
            checks.expect(final.0 && !off.pf && !off.dns,
                          "a disable after concurrent requests must leave pf and the DNS proxy off")
        }

        // 3. Fail open when the DNS proxy cannot start.
        do {
            let fake = FakeFirewall()
            fake.failDNSStart = true
            let reply = EnforcementSwitch().setEnabled(true, steps: fake.steps)
            let end = fake.snapshot()
            checks.expect(!reply.0, "a turn-on whose DNS proxy cannot start must reply failure")
            checks.expect(!end.pf && !end.dns, "a failed turn-on must roll pf and the DNS proxy back to off")
        }

        // 4. A direct pf install waits for a transition in progress.
        do {
            let fake = FakeFirewall()
            let enforcement = EnforcementSwitch()
            let paused = DispatchSemaphore(value: 0)
            let resume = DispatchSemaphore(value: 0)
            let directDone = DispatchSemaphore(value: 0)
            let enableDone = DispatchSemaphore(value: 0)
            fake.afterInstall = {
                fake.afterInstall = nil
                paused.signal()
                resume.wait()
            }
            DispatchQueue.global().async {
                _ = enforcement.setEnabled(true, steps: fake.steps)
                enableDone.signal()
            }
            paused.wait()
            DispatchQueue.global().async {
                enforcement.serialized { try? fake.steps.uninstallPF() }
                directDone.signal()
            }
            let ranDuringPause = directDone.wait(timeout: .now() + 2) == .success
            checks.expect(!ranDuringPause, "a direct pf change must wait for an enforcement transition in progress")
            resume.signal()
            enableDone.wait()
            if !ranDuringPause { directDone.wait() }
        }

        checks.finish()
    }
}
SWIFT

xcrun swiftc -O -sdk "$SDK" -target "$TARGET" -parse-as-library \
  "$ROOT/Sources/Helper/EnforcementSwitch.swift" "$TMP/verify.swift" -o "$TMP/verify"
"$TMP/verify"
