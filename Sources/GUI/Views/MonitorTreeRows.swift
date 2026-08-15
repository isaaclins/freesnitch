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
    /// Removing a rule is removing stored policy, so it is confirmed and the
    /// confirmation names what goes (#115).
    @State private var pendingClear: PendingClear?

    private struct PendingClear: Identifiable {
        let id = UUID()
        let subject: String
        let target: MonitorRuleTarget
    }

    var body: some View {
        let visible = MonitorTreeFilter.apply(query: searchText, to: controller.snapshot)
        // A real outline: system disclosure triangles, system selection and
        // arrow-key navigation. The hand-drawn chevron button and the painted
        // selection tint are gone, but the controller still owns expansion, so
        // an app stays open across every refresh of the live data.
        List(selection: $selectedAppID) {
            if visible.apps.isEmpty {
                emptyRow
            }
            ForEach(visible.apps) { app in
                DisclosureGroup(isExpanded: expansion(of: app)) {
                    ForEach(app.destinations) { destination in
                        // Selecting a disclosure group highlights its children
                        // as well, so a destination row can be sitting on the
                        // accent colour without being selected itself. It has
                        // to know, or its blue bar vanishes the same way the
                        // app row's did (#76).
                        MonitorDestinationRow(destination: destination,
                                              selected: selectedAppID == app.id || selectedAppID == destination.id,
                                              peakTraffic: app.peakDestinationTraffic,
                                              decision: controller.decision(for: MonitorRuleTarget.destination(destination, in: app)),
                                              pending: controller.isPending(MonitorRuleTarget.destination(destination, in: app)),
                                              onDecide: { action in decide(action, destination: destination, app: app) },
                                              onClear: { clear(destination: destination, app: app) })
                        // Tagged so the row can be selected and so the list's
                        // context menu can tell which row was clicked.
                        .tag(destination.id)
                    }
                    if let note = boundsNote(for: app) {
                        Text(note)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                } label: {
                    MonitorAppRow(app: app,
                                  selected: selectedAppID == app.id,
                                  peakTraffic: controller.snapshot.peakAppTraffic,
                                  decision: controller.decision(for: MonitorRuleTarget.app(app)),
                                  pending: controller.isPending(MonitorRuleTarget.app(app)),
                                  onDecide: { action in decide(action, app: app) },
                                  onClear: { clear(app: app) })
                }
                .tag(app.id)
            }
            if visible.hiddenAppCount > 0 {
                Text("\(visible.hiddenAppCount) more apps are not shown, the list is bounded at \(MonitorTreeLimits.maxApps).")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        // Content, not a sidebar: the window's own sidebar is the only place
        // that carries a translucent material.
        .listStyle(.inset)
        // A per-row .contextMenu inside a List never sees the right click here:
        // the NSTableView underneath takes the event first. The selection-aware
        // form is installed on the table itself, so it works, and it selects
        // the row that was clicked before opening (#78).
        .contextMenu(forSelectionType: String.self) { ids in
            rowContextMenu(for: ids, in: visible)
        }
        .confirmationDialog("Remove the rule for \(pendingClear?.subject ?? "this row")?",
                            isPresented: Binding(get: { pendingClear != nil },
                                                 set: { if !$0 { pendingClear = nil } }),
                            titleVisibility: .visible) {
            Button("Remove Rule", role: .destructive) {
                if let target = pendingClear?.target {
                    controller.clearDecision(for: target, state: state)
                }
                pendingClear = nil
            }
            Button("Cancel", role: .cancel) { pendingClear = nil }
        } message: {
            Text("The rule is deleted from FreeSnitch. This row goes back to no decision, and the next connection follows the current mode.")
        }
    }

    /// One menu for both kinds of row: the id identifies either an app or one
    /// of its destinations.
    @ViewBuilder
    private func rowContextMenu(for ids: Set<String>, in visible: MonitorTreeFilter.Result) -> some View {
        if let id = ids.first {
            if let app = visible.apps.first(where: { $0.id == id }) {
                decisionMenu(target: MonitorRuleTarget.app(app),
                             onDecide: { decide($0, app: app) },
                             onClear: { clear(app: app) })
                Divider()
                CopyMenuItem(title: "Copy App Name", value: app.name)
                CopyMenuItem(title: "Copy Path", value: app.path)
                if RowActions.canReveal(path: app.path) {
                    Button("Reveal in Finder") { RowActions.revealInFinder(path: app.path) }
                }
            } else if let (app, destination) = visible.destinationRow(withID: id) {
                decisionMenu(target: MonitorRuleTarget.destination(destination, in: app),
                             onDecide: { decide($0, destination: destination, app: app) },
                             onClear: { clear(destination: destination, app: app) })
                Divider()
                CopyMenuItem(title: "Copy Host", value: destination.remoteHost)
                CopyMenuItem(title: "Copy IP Address", value: destination.remoteIP)
            }
        }
    }

    /// Expansion still belongs to the controller; the disclosure triangle just
    /// drives it.
    private func expansion(of app: MonitorAppNode) -> Binding<Bool> {
        Binding(get: { controller.isExpanded(app) },
                set: { _ in controller.toggleExpansion(app) })
    }

    private var emptyRow: some View {
        Text(state.helperConnected
             ? (searchText.isEmpty ? "No connections yet." : "Nothing matches this search.")
             : "Waiting for the FreeSnitch helper.")
            .font(.callout)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
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

    /// Allow, Deny and Remove for one row, driving exactly the closures the
    /// row's own two controls drive (#78). A row that cannot be addressed by a
    /// rule gets no decision items rather than items that quietly do nothing.
    @ViewBuilder
    private func decisionMenu(target: MonitorRuleTarget?,
                              onDecide: @escaping (RuleAction) -> Void,
                              onClear: @escaping () -> Void) -> some View {
        if let target {
            let decision = controller.decision(for: target)
            let pending = controller.isPending(target)
            Button("Allow") { onDecide(.allow) }
                .disabled(pending || decision?.action == .allow)
            Button("Deny") { onDecide(.deny) }
                .disabled(pending || decision?.action == .deny)
            if decision != nil {
                Button("Remove This Rule", role: .destructive) { onClear() }
                    .disabled(pending)
            }
        }
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
        pendingClear = PendingClear(subject: "every connection from \(app.name)", target: target)
    }

    private func clear(destination: MonitorDestinationNode, app: MonitorAppNode) {
        guard let target = MonitorRuleTarget.destination(destination, in: app) else { return }
        pendingClear = PendingClear(subject: "\(app.name) to \(destination.label)", target: target)
    }
}

// MARK: - App row

struct MonitorAppRow: View {
    let app: MonitorAppNode
    /// A selected row is drawn on the accent colour, which swallows anything
    /// else drawn in a saturated colour, so every coloured element on the row
    /// needs to know (#75, #76).
    let selected: Bool
    let peakTraffic: Int64
    let decision: Rule?
    let pending: Bool
    let onDecide: (RuleAction) -> Void
    let onClear: () -> Void

    var body: some View {
        HStack(spacing: 6) {
            if let icon = MonitorAppIconCache.icon(for: app) {
                Image(nsImage: icon).resizable().frame(width: 16, height: 16)
            } else {
                Image(systemName: "app.dashed")
                    .foregroundStyle(.secondary)
                    .frame(width: 16, height: 16)
            }

            VStack(alignment: .leading, spacing: 1) {
                Text(app.name)
                    .font(.body)
                    .lineLimit(1)
                Text("\(app.destinationCount) destination\(app.destinationCount == 1 ? "" : "s") · \(PSFormat.bytes(app.traffic.total))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 4)
            MonitorTrafficBars(traffic: app.traffic, peak: peakTraffic, onSelection: selected)
            MonitorDecisionControls(decision: decision,
                                    pending: pending,
                                    addressable: MonitorRuleTarget.app(app)?.isAddressable ?? false,
                                    subject: "every connection from \(app.name)",
                                    onSelection: selected,
                                    onDecide: onDecide,
                                    onClear: onClear)
        }
        .padding(.vertical, 2)
    }
}

// MARK: - Destination row

struct MonitorDestinationRow: View {
    let destination: MonitorDestinationNode
    /// True while the parent app row is selected, because the selection fill
    /// extends over the children too.
    var selected: Bool = false
    let peakTraffic: Int64
    let decision: Rule?
    let pending: Bool
    let onDecide: (RuleAction) -> Void
    let onClear: () -> Void

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: destination.remoteHost == nil ? "number" : "globe")
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 14)
            VStack(alignment: .leading, spacing: 1) {
                Text(destination.label)
                    .font(.callout)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 4)
            MonitorTrafficBars(traffic: destination.traffic, peak: peakTraffic, onSelection: selected)
            MonitorDecisionControls(decision: decision,
                                    pending: pending,
                                    addressable: isAddressable,
                                    subject: destination.label,
                                    onSelection: selected,
                                    onDecide: onDecide,
                                    onClear: onClear)
        }
        .padding(.vertical, 1)
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
    /// On a selected row the accent fill is behind these, and the sent bar was
    /// drawn in system blue, so it disappeared into the selection entirely
    /// (#76). On selection both bars switch to the selected-content colour and
    /// separate by weight instead of by hue.
    var onSelection: Bool = false
    static let width: CGFloat = 42

    static let sentColor = PSTheme.trafficOut
    static let receivedColor = PSTheme.trafficIn

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            bar(value: traffic.bytesOut, color: Self.sentColor)
            bar(value: traffic.bytesIn, color: Self.receivedColor)
        }
        .frame(width: Self.width, alignment: .leading)
        .help("Sent \(PSFormat.bytes(traffic.bytesOut)), received \(PSFormat.bytes(traffic.bytesIn))")
        .accessibilityLabel("Sent \(PSFormat.bytes(traffic.bytesOut)), received \(PSFormat.bytes(traffic.bytesIn))")
    }

    private func bar(value: Int64, color: Color) -> some View {
        ZStack(alignment: .leading) {
            Capsule()
                .fill(onSelection ? AnyShapeStyle(Color.white.opacity(0.25)) : AnyShapeStyle(.quaternary))
                .frame(height: 3)
            Capsule()
                .fill(onSelection ? selectedFill(for: color) : color)
                .frame(width: filledWidth(value), height: 3)
        }
        .frame(width: Self.width, height: 3)
    }

    /// Sent stays solid, received goes translucent, so the pair is still two
    /// distinguishable values on top of the accent colour.
    private func selectedFill(for color: Color) -> Color {
        color == Self.sentColor ? .white : .white.opacity(0.55)
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
    @EnvironmentObject var state: AppState
    let decision: Rule?
    let pending: Bool
    let addressable: Bool
    let subject: String
    var onSelection: Bool = false
    let onDecide: (RuleAction) -> Void
    let onClear: () -> Void

    /// Rules live in the helper, so a decision cannot be made without it.
    /// Saying so on the control beats letting the click through and answering
    /// with an alert afterwards (#98).
    private var canDecide: Bool { state.helperConnected }

    var body: some View {
        HStack(spacing: 2) {
            button(action: .allow,
                   symbol: "checkmark.circle.fill",
                   color: .green,
                   help: "Allow \(subject). Writes a rule you can see and change in Rules.")
            button(action: .deny,
                   symbol: "xmark.circle.fill",
                   color: .red,
                   help: "Deny \(subject). Writes a rule you can see and change in Rules.")
            if decision != nil {
                Button(action: onClear) {
                    Image(systemName: "arrow.uturn.backward.circle.fill")
                }
                .buttonStyle(.borderless)
                .foregroundStyle(onSelection ? AnyShapeStyle(Color.white.opacity(0.8)) : AnyShapeStyle(.secondary))
                .disabled(pending || !canDecide)
                .help(unavailableReason ?? "Remove the rule this row created and go back to no decision.")
            }
        }
        .imageScale(.large)
        .opacity(addressable && canDecide ? 1 : 0.35)
        .allowsHitTesting(addressable && !pending && canDecide)
        .help(unavailableReason ?? "")
    }

    private var unavailableReason: String? {
        if !addressable { return "This row has no destination a rule can name." }
        if !canDecide { return "Approve the FreeSnitch helper before deciding anything here." }
        return nil
    }

    /// Filled symbol buttons, drawn in two layers.
    ///
    /// Outlined symbols read as decoration rather than as controls (#75), so
    /// the glyph is always filled. What the rule state changes is the pair of
    /// colours: at rest a tinted glyph on a faint disc, in force a white glyph
    /// on a solid disc, which stays obvious on a selected row too.
    private func button(action: RuleAction, symbol: String, color: Color, help: String) -> some View {
        let isActive = decision?.action == action
        let isDisabledRule = isActive && decision?.enabled == false
        return Button {
            onDecide(action)
        } label: {
            Image(systemName: symbol)
                .symbolRenderingMode(.palette)
                .foregroundStyle(glyphColor(isActive: isActive), discColor(color, isActive: isActive))
        }
        .buttonStyle(.borderless)
        .disabled(pending || !canDecide)
        .help(unavailableReason
              ?? (isDisabledRule ? "\(help) A disabled rule for this row exists; pressing this enables it." : help))
    }

    private func glyphColor(isActive: Bool) -> Color {
        if isActive { return .white }
        return onSelection ? .white : .white.opacity(0.9)
    }

    private func discColor(_ color: Color, isActive: Bool) -> Color {
        if isActive { return color }
        return onSelection ? color.opacity(0.55) : color.opacity(0.85)
    }
}

// MARK: - Filtering

/// Search over an already-built snapshot. Bounded by the snapshot's own caps,
/// and never changes the order rows are in.
enum MonitorTreeFilter {
    struct Result {
        let apps: [MonitorAppNode]
        let hiddenAppCount: Int

        /// Finds a destination row and the app it belongs to. Row ids are
        /// unique across the tree, so one id identifies exactly one row.
        func destinationRow(withID id: String) -> (MonitorAppNode, MonitorDestinationNode)? {
            for app in apps {
                if let destination = app.destinations.first(where: { $0.id == id }) {
                    return (app, destination)
                }
            }
            return nil
        }
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
