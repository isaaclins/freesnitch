import SwiftUI
import AppKit

/// The rows of the live monitor tree.
///
/// Every view here is a pure function of one already-grouped node. No view in
/// this file groups, sorts, filters by traffic, or decides anything: a
/// decision only happens when the user presses one of the two labelled
/// controls on a row, and it is sent straight to the helper.

// MARK: - List

struct MonitorTreeList: View {
    @EnvironmentObject var state: AppState
    @ObservedObject var controller: MonitorTreeController
    let searchText: String
    @Binding var selectedAppID: String?

    var body: some View {
        let visible = MonitorTreeFilter.apply(query: searchText, to: controller.snapshot)
        ScrollView {
            LazyVStack(spacing: 0) {
                if visible.apps.isEmpty {
                    emptyRow
                }
                ForEach(visible.apps) { app in
                    MonitorAppRow(app: app,
                                  expanded: controller.isExpanded(app),
                                  selected: selectedAppID == app.id,
                                  peakTraffic: controller.snapshot.peakAppTraffic,
                                  decision: controller.decision(for: MonitorRuleTarget.app(app)),
                                  pending: controller.isPending(MonitorRuleTarget.app(app)),
                                  onToggleExpand: { controller.toggleExpansion(app) },
                                  onDecide: { action in decide(action, app: app) },
                                  onClear: { clear(app: app) })
                        .contentShape(Rectangle())
                        .onTapGesture { selectedAppID = (selectedAppID == app.id ? nil : app.id) }
                    if controller.isExpanded(app) {
                        ForEach(app.destinations) { destination in
                            MonitorDestinationRow(destination: destination,
                                                  peakTraffic: app.peakDestinationTraffic,
                                                  decision: controller.decision(for: MonitorRuleTarget.destination(destination, in: app)),
                                                  pending: controller.isPending(MonitorRuleTarget.destination(destination, in: app)),
                                                  onDecide: { action in decide(action, destination: destination, app: app) },
                                                  onClear: { clear(destination: destination, app: app) })
                        }
                        if let note = boundsNote(for: app) {
                            Text(note)
                                .font(.system(size: 10))
                                .foregroundColor(PSTheme.textMuted)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(.leading, 34).padding(.trailing, 8).padding(.vertical, 4)
                        }
                    }
                }
                if visible.hiddenAppCount > 0 {
                    Text("\(visible.hiddenAppCount) more apps are not shown, the list is bounded at \(MonitorTreeLimits.maxApps).")
                        .font(.system(size: 10))
                        .foregroundColor(PSTheme.textMuted)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                }
            }
        }
    }

    private var emptyRow: some View {
        Text(state.helperConnected
             ? (searchText.isEmpty ? "No connections yet." : "Nothing matches this search.")
             : "Waiting for the FreeSnitch helper.")
            .font(.system(size: 11))
            .foregroundColor(PSTheme.textMuted)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(10)
    }

    private func boundsNote(for app: MonitorAppNode) -> String? {
        var parts: [String] = []
        if app.hiddenDestinationCount > 0 {
            parts.append("\(app.hiddenDestinationCount) more destinations")
        }
        if app.ungroupedConnectionCount > 0 {
            parts.append("\(app.ungroupedConnectionCount) connections past the grouping bound, counted in the totals above")
        }
        guard !parts.isEmpty else { return nil }
        return parts.joined(separator: ", ") + "."
    }

    private func decide(_ action: RuleAction, app: MonitorAppNode) {
        guard let target = MonitorRuleTarget.app(app) else { return }
        controller.apply(action, to: target, processName: app.name, state: state)
    }

    private func decide(_ action: RuleAction, destination: MonitorDestinationNode, app: MonitorAppNode) {
        guard let target = MonitorRuleTarget.destination(destination, in: app) else { return }
        controller.apply(action, to: target, processName: app.name, state: state)
    }

    private func clear(app: MonitorAppNode) {
        guard let target = MonitorRuleTarget.app(app) else { return }
        controller.clearDecision(for: target, state: state)
    }

    private func clear(destination: MonitorDestinationNode, app: MonitorAppNode) {
        guard let target = MonitorRuleTarget.destination(destination, in: app) else { return }
        controller.clearDecision(for: target, state: state)
    }
}

// MARK: - App row

struct MonitorAppRow: View {
    let app: MonitorAppNode
    let expanded: Bool
    let selected: Bool
    let peakTraffic: Int64
    let decision: Rule?
    let pending: Bool
    let onToggleExpand: () -> Void
    let onDecide: (RuleAction) -> Void
    let onClear: () -> Void

    var body: some View {
        HStack(spacing: 6) {
            Button(action: onToggleExpand) {
                Image(systemName: expanded ? "chevron.down" : "chevron.right")
                    .font(.system(size: 9, weight: .bold))
                    .foregroundColor(app.destinations.isEmpty ? PSTheme.textMuted.opacity(0.4) : PSTheme.textSecondary)
                    .frame(width: 12, height: 12)
            }
            .buttonStyle(.plain)
            .disabled(app.destinations.isEmpty)
            .help(expanded ? "Collapse this app" : "Show the destinations this app contacted")

            if let icon = MonitorAppIconCache.icon(for: app) {
                Image(nsImage: icon).resizable().frame(width: 16, height: 16)
            } else {
                Image(systemName: "app.dashed")
                    .foregroundColor(PSTheme.textSecondary)
                    .frame(width: 16, height: 16)
            }

            VStack(alignment: .leading, spacing: 1) {
                Text(app.name)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundColor(PSTheme.textPrimary)
                    .lineLimit(1)
                Text("\(app.destinationCount) destination\(app.destinationCount == 1 ? "" : "s") · \(PSFormat.bytes(app.traffic.total))")
                    .font(.system(size: 10))
                    .foregroundColor(PSTheme.textMuted)
                    .lineLimit(1)
            }
            Spacer(minLength: 4)
            MonitorTrafficBars(traffic: app.traffic, peak: peakTraffic)
            MonitorDecisionControls(decision: decision,
                                    pending: pending,
                                    addressable: MonitorRuleTarget.app(app)?.isAddressable ?? false,
                                    subject: "every connection from \(app.name)",
                                    onDecide: onDecide,
                                    onClear: onClear)
        }
        .padding(.horizontal, 8).padding(.vertical, 5)
        .background(selected ? PSTheme.accent.opacity(0.18) : Color.clear)
    }
}

// MARK: - Destination row

struct MonitorDestinationRow: View {
    let destination: MonitorDestinationNode
    let peakTraffic: Int64
    let decision: Rule?
    let pending: Bool
    let onDecide: (RuleAction) -> Void
    let onClear: () -> Void

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: destination.remoteHost == nil ? "number" : "globe")
                .font(.system(size: 9))
                .foregroundColor(PSTheme.textMuted)
                .frame(width: 12, height: 12)
                .padding(.leading, 18)
            VStack(alignment: .leading, spacing: 1) {
                Text(destination.label)
                    .font(.system(size: 11))
                    .foregroundColor(PSTheme.textPrimary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(subtitle)
                    .font(.system(size: 9))
                    .foregroundColor(PSTheme.textMuted)
                    .lineLimit(1)
            }
            Spacer(minLength: 4)
            MonitorTrafficBars(traffic: destination.traffic, peak: peakTraffic)
            MonitorDecisionControls(decision: decision,
                                    pending: pending,
                                    addressable: isAddressable,
                                    subject: destination.label,
                                    onDecide: onDecide,
                                    onClear: onClear)
        }
        .padding(.horizontal, 8).padding(.vertical, 4)
        .background(PSTheme.bgRow.opacity(0.45))
    }

    private var isAddressable: Bool {
        if let host = destination.remoteHost { return PFHostValidator.kind(for: host) != nil }
        if let ip = destination.remoteIP { return PFHostValidator.kind(for: ip) != nil }
        return false
    }

    private var subtitle: String {
        var parts = ["\(destination.connectionCount) connection\(destination.connectionCount == 1 ? "" : "s")"]
        parts.append(PSFormat.bytes(destination.traffic.total))
        if let code = destination.countryCode, !code.isEmpty { parts.append(code) }
        return parts.joined(separator: " · ")
    }
}

// MARK: - Traffic bars

/// Sent and received for one row, on the same scale as its siblings so two
/// rows can be compared by eye. Empty traffic draws nothing rather than a
/// hairline that suggests activity that did not happen.
struct MonitorTrafficBars: View {
    let traffic: MonitorTrafficTotals
    let peak: Int64
    private static let width: CGFloat = 42

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            bar(value: traffic.bytesOut, color: PSTheme.trafficOut)
            bar(value: traffic.bytesIn, color: PSTheme.trafficIn)
        }
        .frame(width: Self.width, alignment: .leading)
        .help("Sent \(PSFormat.bytes(traffic.bytesOut)), received \(PSFormat.bytes(traffic.bytesIn))")
        .accessibilityLabel("Sent \(PSFormat.bytes(traffic.bytesOut)), received \(PSFormat.bytes(traffic.bytesIn))")
    }

    private func bar(value: Int64, color: Color) -> some View {
        ZStack(alignment: .leading) {
            Capsule().fill(PSTheme.bgTertiary).frame(height: 3)
            Capsule().fill(color).frame(width: filledWidth(value), height: 3)
        }
        .frame(width: Self.width, height: 3)
    }

    private func filledWidth(_ value: Int64) -> CGFloat {
        guard value > 0, peak > 0 else { return 0 }
        let fraction = min(1, Double(value) / Double(peak))
        return max(2, Self.width * CGFloat(fraction))
    }
}

// MARK: - Decision controls

/// The inline allow and deny for one row.
///
/// Pressing one of these is the only way a decision is made in the monitor.
/// Selecting a row, expanding it, or clicking anywhere else on it changes
/// nothing about policy. When a rule already exists for exactly this row it is
/// shown as the active choice and can be taken back with the clear control,
/// which removes that rule.
struct MonitorDecisionControls: View {
    let decision: Rule?
    let pending: Bool
    let addressable: Bool
    let subject: String
    let onDecide: (RuleAction) -> Void
    let onClear: () -> Void

    var body: some View {
        HStack(spacing: 3) {
            button(action: .allow,
                   symbol: "checkmark",
                   color: PSTheme.accentGreen,
                   help: "Allow \(subject). Writes a rule you can see and change in Rules.")
            button(action: .deny,
                   symbol: "xmark",
                   color: PSTheme.accentRed,
                   help: "Deny \(subject). Writes a rule you can see and change in Rules.")
            if decision != nil {
                Button(action: onClear) {
                    Image(systemName: "arrow.uturn.backward")
                        .font(.system(size: 8, weight: .bold))
                        .foregroundColor(PSTheme.textSecondary)
                        .frame(width: 16, height: 16)
                        .background(PSTheme.bgTertiary)
                        .clipShape(RoundedRectangle(cornerRadius: 4))
                }
                .buttonStyle(.plain)
                .disabled(pending)
                .help("Remove the rule this row created and go back to no decision.")
            }
        }
        .opacity(addressable ? 1 : 0.35)
        .allowsHitTesting(addressable && !pending)
        .help(addressable ? "" : "This row has no destination a rule can name.")
    }

    private func button(action: RuleAction, symbol: String, color: Color, help: String) -> some View {
        let isActive = decision?.action == action
        return Button {
            onDecide(action)
        } label: {
            Image(systemName: symbol)
                .font(.system(size: 8, weight: .bold))
                .foregroundColor(isActive ? .white : color)
                .frame(width: 16, height: 16)
                .background(isActive ? color : color.opacity(0.16))
                .clipShape(RoundedRectangle(cornerRadius: 4))
                .overlay(
                    RoundedRectangle(cornerRadius: 4)
                        .stroke(isActive && decision?.enabled == false ? PSTheme.accentYellow : Color.clear,
                                lineWidth: 1)
                )
        }
        .buttonStyle(.plain)
        .disabled(pending)
        .help(isActive && decision?.enabled == false ? "\(help) A disabled rule for this row exists; pressing this enables it." : help)
    }
}

// MARK: - Filtering

/// Search over an already-built snapshot. Bounded by the snapshot's own caps,
/// and never changes the order rows are in.
enum MonitorTreeFilter {
    struct Result {
        let apps: [MonitorAppNode]
        let hiddenAppCount: Int
    }

    static func apply(query: String, to snapshot: MonitorTreeSnapshot) -> Result {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return Result(apps: snapshot.apps, hiddenAppCount: snapshot.hiddenAppCount)
        }
        let needle = trimmed.lowercased()
        let apps: [MonitorAppNode] = snapshot.apps.compactMap { app in
            if app.name.lowercased().contains(needle) { return app }
            let matches = app.destinations.filter { $0.label.lowercased().contains(needle) }
            guard !matches.isEmpty else { return nil }
            return MonitorAppNode(id: app.id,
                                  name: app.name,
                                  bundleID: app.bundleID,
                                  path: app.path,
                                  connectionCount: app.connectionCount,
                                  destinationCount: app.destinationCount,
                                  traffic: app.traffic,
                                  destinations: matches,
                                  hiddenDestinationCount: app.hiddenDestinationCount,
                                  ungroupedConnectionCount: app.ungroupedConnectionCount,
                                  peakDestinationTraffic: app.peakDestinationTraffic,
                                  order: app.order)
        }
        return Result(apps: apps, hiddenAppCount: 0)
    }
}

// MARK: - Icons

/// Resolving an app icon touches the file system, so a row must not do it on
/// every redraw. Bounded, main-actor only, and cheap to miss.
@MainActor
enum MonitorAppIconCache {
    private static var cache: [String: NSImage?] = [:]
    private static let capacity = 256

    static func icon(for app: MonitorAppNode) -> NSImage? {
        if let cached = cache[app.id] { return cached }
        if cache.count >= capacity { cache.removeAll(keepingCapacity: true) }
        let resolved = AppIcon.resolve(bundleId: app.bundleID, path: app.path, name: app.name)
        cache[app.id] = resolved
        return resolved
    }
}
