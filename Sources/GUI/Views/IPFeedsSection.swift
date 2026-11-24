import SwiftUI

/// The IP and CIDR feeds, in Settings > General next to Enforcement (#209).
///
/// They are their own kind of list, apart from the domain blocklists in the
/// Rules sidebar (#51): those are names the DNS proxy refuses, these are
/// addresses pf blocks for every app. Every feed ships off, so this is where a
/// user turns one on, and where they see whether it is blocking anything.
struct IPFeedsSection: View {
    @EnvironmentObject var state: AppState
    @State private var report: IPFeedsReport?
    @State private var failure: String?
    /// Feeds whose switch was flipped and whose download has not answered yet.
    @State private var pending: Set<UUID> = []

    var body: some View {
        Section("IP address blocklists") {
            if let report {
                ForEach(report.feeds) { feed in
                    Toggle(isOn: Binding(
                        get: { feed.enabled },
                        set: { setFeed(feed, enabled: $0) }
                    )) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(feed.name)
                            Text(detail(for: feed))
                                .font(.caption)
                                .foregroundStyle(isFailing(feed) ? Color.orange : Color.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .disabled(!state.helperConnected || pending.contains(feed.id))
                    .help(URL(string: feed.url)?.host ?? feed.url)
                }
                if report.addressTableRefused {
                    Label("The firewall refused the address table, so the feeds are blocking nothing. Your own rules still apply.",
                          systemImage: "exclamationmark.triangle.fill")
                        .font(.caption).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    Text(report.status.summary)
                        .font(.caption).foregroundColor(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else if !state.helperConnected {
                Text("The feeds live in the privileged helper, so they can be changed once the helper is connected.")
                    .font(.caption).foregroundColor(.secondary)
            } else if failure == nil {
                Text("Loading…").font(.caption).foregroundColor(.secondary)
            }
            if let failure {
                Label(failure, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text("Blocks connections to the addresses and ranges a feed lists, for every app, while enforcement is on. A feed that can't be downloaded blocks nothing. Loopback, DHCP, private and shared ranges and your DNS servers are never blocked.")
                .font(.caption).foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .onAppear { load() }
        .onChange(of: state.helperConnected) { connected in
            if connected { load() }
        }
        // Whether the feeds block anything depends on pf being loaded, which
        // is only true once the helper has answered the enforcement switch.
        .onChange(of: state.enforcementChangePending) { isPending in
            if !isPending { load() }
        }
    }

    private func isFailing(_ feed: IPBlocklistFeed) -> Bool {
        feed.enabled && feed.lastError != nil && !pending.contains(feed.id)
    }

    private func detail(for feed: IPBlocklistFeed) -> String {
        if pending.contains(feed.id) {
            return feed.enabled ? String(localized: "Downloading…") : String(localized: "Turning off…")
        }
        guard feed.enabled else {
            return URL(string: feed.url)?.host ?? feed.url
        }
        if feed.isPartlyLoaded, let loaded = feed.loadedEntryCount {
            return String(localized: "Only \(loaded) of \(feed.entryCount) entries fit under the address limit and block.")
        }
        if let error = feed.lastError {
            return String(localized: "Not loaded, so it blocks nothing: \(error)")
        }
        guard let updated = feed.lastUpdated else {
            return String(localized: "Not downloaded yet.")
        }
        let when = updated.formatted(.relative(presentation: .named))
        if feed.rejectedCount > 0 {
            return String(localized: "\(feed.entryCount) entries, \(feed.rejectedCount) refused, updated \(when)")
        }
        return String(localized: "\(feed.entryCount) entries, updated \(when)")
    }

    /// `keepingFailure` is for the reload after a failed toggle: the reload
    /// puts the switch back where the helper has it, and the reason the
    /// toggle failed has to stay on screen beside it.
    private func load(keepingFailure: Bool = false) {
        guard state.helperConnected else { return }
        if DemoMode.isOn {
            report = report.map { Self.demoReport(from: $0, enforcing: state.enforcementEnabled) }
                ?? Self.demoReport(enforcing: state.enforcementEnabled)
            return
        }
        state.helper.listIPFeeds { value, error in
            if let value { report = value }
            if let error {
                failure = error
            } else if !keepingFailure {
                failure = nil
            }
        }
    }

    private func setFeed(_ feed: IPBlocklistFeed, enabled: Bool) {
        guard var current = report,
              let index = current.feeds.firstIndex(where: { $0.id == feed.id }) else { return }
        // The switch shows what was asked at once; the line under it says the
        // download is still running, and the helper's answer replaces both.
        current.feeds[index].enabled = enabled
        report = current
        pending.insert(feed.id)
        failure = nil
        if DemoMode.isOn {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
                pending.remove(feed.id)
                report = Self.demoReport(from: report, enforcing: state.enforcementEnabled)
            }
            return
        }
        state.helper.setIPFeedEnabled(feed.id, enabled: enabled) { value, error in
            pending.remove(feed.id)
            if let value {
                report = value
            } else {
                failure = error
                load(keepingFailure: true)
            }
        }
    }

    // MARK: - Demo

    private static let demoCounts: [UUID: Int] = [
        IPBlocklistCatalog.defaults[0].id: 4_517,
        IPBlocklistCatalog.defaults[1].id: 1_192,
        IPBlocklistCatalog.defaults[2].id: 642
    ]

    private static func demoReport(enforcing: Bool) -> IPFeedsReport {
        var feeds = IPBlocklistCatalog.defaults
        feeds[0].enabled = true
        return demoReport(from: IPFeedsReport(feeds: feeds, status: IPBlocklistPolicy.disabled.status),
                          enforcing: enforcing)
    }

    private static func demoReport(from report: IPFeedsReport?, enforcing: Bool) -> IPFeedsReport {
        var feeds = report?.feeds ?? IPBlocklistCatalog.defaults
        for index in feeds.indices {
            if feeds[index].enabled {
                feeds[index].entryCount = demoCounts[feeds[index].id] ?? 0
                feeds[index].lastUpdated = feeds[index].lastUpdated ?? Date().addingTimeInterval(-2 * 3600)
                feeds[index].lastError = nil
            }
        }
        let loaded = feeds.filter(\.enabled).reduce(0) { $0 + $1.entryCount }
        let status = IPBlocklistStatus(enforcementEnabled: enforcing,
                                       loadedEntryCount: loaded,
                                       loadedRangeCount: loaded,
                                       rejectedEntryCount: 0,
                                       truncated: false,
                                       enabledFeedCount: feeds.filter(\.enabled).count,
                                       failedFeedCount: 0)
        return IPFeedsReport(feeds: feeds, status: status)
    }
}
