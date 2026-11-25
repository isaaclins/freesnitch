#!/usr/bin/env bash
# Deterministic harness for a domain blocklist download that fails (issue #252).
#
# Compiled from the real helper and shared sources, so it drives the shipping
# BlocklistManager against a real RuleStore, with downloads answered by a test
# seam instead of the network. It replays the issue's steps:
#
#   1. Two enabled lists download, and one gets a hand edit.
#   2. The helper restarts while one source is unreachable. That list's saved
#      names, hand edit included, must stay in the set published to the DNS
#      proxy, and the refresh must name the list as failed instead of reporting
#      success. Its "last updated" and count must not move.
#   3. A refresh during a full outage keeps everything and names every list.
#   4. Once the source answers again, the new download replaces the saved
#      names, so a failure never keeps a name blocked after a good download.
#      Resetting hand edits removes hand-added names from the saved copy, so a
#      failed download after a reset does not keep them blocking. Changing a
#      list's source drops the old source's names the same way.
#   5. A list that never downloaded and fails adds nothing to the set.
#   6. A download is stored only under the address it came from (#529): the
#      address check, the count and time, and the names are one transaction,
#      so an address change racing a finished download can never leave the
#      old source's names saved under the new address.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-blocklist-refresh.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

SDK="$(xcrun --show-sdk-path)"
TARGET="arm64-apple-macos13.0"

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

final class Answers: @unchecked Sendable {
    private let lock = NSLock()
    private var byName: [String: Set<String>?] = [:]
    func set(_ name: String, _ value: Set<String>?) { lock.lock(); byName[name] = .some(value); lock.unlock() }
    func answer(_ list: BlocklistInfo) -> Set<String>? {
        lock.lock(); defer { lock.unlock() }
        // Lists the store seeds on its own are not under test: they download
        // as empty so they never show up as failures.
        guard let value = byName[list.name] else { return [] }
        return value
    }
}

@main
struct Verify {
    static var failures: [String] = []
    static var passed = 0

    static func expect(_ condition: Bool, _ message: String) {
        if condition { passed += 1 } else { failures.append(message) }
    }

    static func manager(_ store: RuleStore, _ answers: Answers, published: @escaping (Set<String>) -> Void) -> BlocklistManager {
        let manager = BlocklistManager(store: store)
        manager.domainListFetcher = { list in answers.answer(list) }
        manager.onUpdate = { [unowned manager] _ in published(manager.domains) }
        return manager
    }

    static func main() async {
        let path = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("freesnitch-blrefresh-\(UUID().uuidString).sqlite")
        defer { try? FileManager.default.removeItem(atPath: path) }
        guard let store = try? RuleStore(path: path) else {
            FileHandle.standardError.write(Data("blocklist refresh harness: FAIL: could not open a RuleStore\n".utf8))
            exit(1)
        }
        let profile = Profile.defaultName
        guard let alpha = try? store.addCustomBlocklist(name: "Alpha", url: "https://example.com/alpha.txt", profileName: profile),
              let beta = try? store.addCustomBlocklist(name: "Beta", url: "https://example.com/beta.txt", profileName: profile) else {
            FileHandle.standardError.write(Data("blocklist refresh harness: FAIL: could not add the test lists\n".utf8))
            exit(1)
        }
        let answers = Answers()
        var published: Set<String> = []

        // 1. Both lists download; Alpha gets a hand edit.
        answers.set("Alpha", ["a.example", "shared.example"])
        answers.set("Beta", ["b.example"])
        var m = manager(store, answers) { published = $0 }
        var result = await m.refresh()
        expect(result.isComplete && result.failureMessage == nil, "a refresh where every list downloads must be complete")
        expect(published.isSuperset(of: ["a.example", "shared.example", "b.example"]), "the first download must publish both lists")
        _ = try? store.addBlocklistEntries(id: alpha.id, domains: ["hand.example"])
        m.rebuildFromStore()
        expect(published.contains("hand.example"), "a hand edit must block at once")
        let alphaBefore = store.blocklist(id: alpha.id)

        // 2. Helper restart while Alpha's source is down.
        answers.set("Alpha", nil)
        answers.set("Beta", ["b.example", "b2.example"])
        published = []
        m = manager(store, answers) { published = $0 }
        result = await m.refresh()
        expect(result.failedLists == ["Alpha"], "the failed list must be named, got \(result.failedLists)")
        expect(!result.isComplete, "a refresh with a failed enabled list must not be reported as complete")
        expect(result.failureMessage?.contains("Alpha") == true, "the failure message must name the list")
        for name in ["a.example", "shared.example", "hand.example"] {
            expect(published.contains(name), "\(name) from the unreachable list must stay blocked after a restart")
        }
        expect(published.isSuperset(of: ["b.example", "b2.example"]), "the list that downloaded must publish its new names")
        let alphaAfter = store.blocklist(id: alpha.id)
        expect(alphaAfter?.lastUpdated == alphaBefore?.lastUpdated, "a failed list must not look freshly updated")
        expect(alphaAfter?.entryCount == alphaBefore?.entryCount, "a failed list must keep its count")
        expect(store.blocklistEntries(blocklistID: alpha.id, search: "", offset: 0, limit: 100).total == 3,
               "a failed list must keep its saved entries")

        // 3. Full outage.
        answers.set("Beta", nil)
        result = await m.refresh()
        expect(Set(result.failedLists) == ["Alpha", "Beta"], "every failed list must be named, got \(result.failedLists)")
        expect(published.isSuperset(of: ["a.example", "shared.example", "hand.example", "b.example", "b2.example"]),
               "an outage of every source must not stop blocking anything that was saved")

        // 4. Alpha's source answers again with a different list.
        answers.set("Alpha", ["a-new.example"])
        answers.set("Beta", ["b.example"])
        result = await m.refresh()
        expect(result.isComplete, "a refresh after the outage must be complete")
        expect(!published.contains("a.example") && !published.contains("shared.example") && !published.contains("b2.example"),
               "a good download must replace the saved names, not add to them")
        expect(published.isSuperset(of: ["a-new.example", "hand.example", "b.example"]),
               "the new download and the hand edit must be blocked")
        expect(store.blocklist(id: alpha.id)?.entryCount == 2, "the recovered list must count its new entries")

        let alphaRecovered = store.blocklist(id: alpha.id)?.lastUpdated
        // 4b. Resetting the hand edits, then a failed download, must not keep
        // the hand-added name blocking.
        try? store.clearBlocklistEdits(id: alpha.id)
        answers.set("Alpha", nil)
        expect(store.blocklist(id: alpha.id)?.lastUpdated == alphaRecovered, "a reset must not make a list look freshly downloaded")
        result = await m.refresh()
        expect(result.failedLists == ["Alpha"], "the reset list's failed download must be named")
        expect(!published.contains("hand.example"), "a hand-added name must stop blocking once its edits are reset")
        expect(published.contains("a-new.example"), "the reset list's downloaded names must still block when its source is down")
        answers.set("Alpha", ["a-new.example"])
        _ = await m.refresh()

        // 4c. Pointing a list at a new source that fails must not keep the
        // old source's names blocking; its hand edits stay.
        _ = try? store.addBlocklistEntries(id: beta.id, domains: ["beta-hand.example"])
        _ = try? store.updateBlocklistURL(id: beta.id, url: "https://example.com/beta-moved.txt")
        answers.set("Beta", nil)
        result = await m.refresh()
        expect(result.failedLists == ["Beta"], "the moved list's failed download must be named")
        expect(!published.contains("b.example"), "the old source's names must stop blocking once the source changes")
        expect(published.contains("beta-hand.example"), "a hand edit must survive a source change")
        answers.set("Beta", ["b.example"])
        _ = await m.refresh()

        // 5. A list that never downloaded adds nothing when it fails.
        guard (try? store.addCustomBlocklist(name: "Gamma", url: "https://example.com/gamma.txt", profileName: profile)) != nil else {
            failures.append("could not add Gamma"); return finish()
        }
        answers.set("Gamma", nil)
        let before = published
        result = await m.refresh()
        expect(result.failedLists == ["Gamma"], "a never-downloaded failing list must be named, got \(result.failedLists)")
        expect(published == before, "a never-downloaded failing list must not change what is blocked")

        // 6. A download is stored only under the address it came from (#529).
        guard let delta = try? store.addCustomBlocklist(name: "Delta", url: "https://example.com/delta-old.txt", profileName: profile) else {
            failures.append("could not add Delta"); return finish()
        }
        let oldURL = "https://example.com/delta-old.txt", newURL = "https://example.com/delta-new.txt"
        let deltaBefore = store.blocklist(id: delta.id)
        let refused = try? store.storeBlocklistDownload(id: delta.id, fromURL: newURL,
                                                        domains: ["wrong.example"], at: Date())
        expect(refused == false, "a download of an address the list does not have must be refused")
        expect(store.blocklistEntries(blocklistID: delta.id, search: "", offset: 0, limit: 10).total == 0,
               "a refused download must store no names")
        expect(store.blocklist(id: delta.id)?.lastUpdated == deltaBefore?.lastUpdated,
               "a refused download must not look like an update")
        let stamp = Date(timeIntervalSince1970: 1_800_000_000)
        let accepted = try? store.storeBlocklistDownload(id: delta.id, fromURL: oldURL,
                                                         domains: ["d1.example", "d2.example"], at: stamp)
        expect(accepted == true, "a download of the list's own address must be stored")
        expect(store.blocklist(id: delta.id)?.entryCount == 2, "a stored download must record its count")
        expect(store.blocklist(id: delta.id)?.lastUpdated == stamp, "a stored download must record its time")
        expect(Set(store.blocklistEntries(blocklistID: delta.id, search: "", offset: 0, limit: 10).entries)
                   == ["d1.example", "d2.example"], "a stored download must store its names")

        // The race itself: a download of the old address finishing while the
        // user changes the address, many times over. Whatever order they land
        // in, a list that ends on the new address must not hold the old names.
        let trials = 3000
        let leaked = raceLeaks(store, id: delta.id, oldURL: oldURL, newURL: newURL, trials: trials)
        expect(leaked == 0, "the old address's names were saved under the new address in \(leaked) of \(trials) races")
        finish()
    }

    /// Synchronous on purpose: the two sides race on plain threads.
    static func raceLeaks(_ store: RuleStore, id: UUID, oldURL: String, newURL: String, trials: Int) -> Int {
        var leaked = 0
        for _ in 0..<trials {
            _ = try? store.updateBlocklistURL(id: id, url: oldURL)
            _ = try? store.replaceBlocklistEntries(blocklistID: id, domains: [])
            let start = DispatchSemaphore(value: 0)
            let group = DispatchGroup()
            DispatchQueue.global().async(group: group) {
                start.wait()
                _ = try? store.storeBlocklistDownload(id: id, fromURL: oldURL,
                                                      domains: ["old-source.example"], at: Date())
            }
            DispatchQueue.global().async(group: group) {
                start.wait()
                _ = try? store.updateBlocklistURL(id: id, url: newURL)
            }
            start.signal(); start.signal()
            group.wait()
            let page = store.blocklistEntries(blocklistID: id, search: "", offset: 0, limit: 10)
            if store.blocklist(id: id)?.url == newURL, page.entries.contains("old-source.example") { leaked += 1 }
        }
        return leaked
    }

    static func finish() {
        guard failures.isEmpty else {
            for f in failures {
                FileHandle.standardError.write(Data(("blocklist refresh harness: FAIL: " + f + "\n").utf8))
            }
            exit(1)
        }
        print("blocklist refresh harness: \(passed) assertions PASS")
    }
}
SWIFT

printf 'blocklist refresh harness: building from the real helper and shared sources\n'
# shellcheck disable=SC2046
xcrun swiftc -O -sdk "$SDK" -target "$TARGET" -parse-as-library \
  -o "$TMP/run" \
  $(ls "$ROOT"/Sources/Helper/*.swift | grep -v '/main.swift$') \
  "$ROOT"/Sources/Shared/*.swift \
  "$TMP/verify.swift"

"$TMP/run"
