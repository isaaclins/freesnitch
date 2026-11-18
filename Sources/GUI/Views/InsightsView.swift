import SwiftUI
import AppKit

/// Insights, per issue #23.
///
/// App-first (D6), names only from DNS answers this Mac saw (D5), unresolved
/// addresses as their own section and worded as a signal rather than a verdict
/// (D10), and rules that are proposals a human accepts one at a time (D2, D7).
/// Recording runs in every mode (D3), so this screen has to say plainly when
/// nothing is being blocked (D9).
struct InsightsView: View {
    @EnvironmentObject var state: AppState
    @StateObject private var model = InsightsViewModel()
    /// Only exists so the destination list has a selection for its context
    /// menu to key off. Nothing else reads it.
    @State private var selectedDestinationID: InsightsDestinationSummary.ID?
    /// The selected row in the apps-behind-a-destination list, for its footer
    /// and context menu (#435).
    @State private var selectedReachingAppID: InsightsAppSummary.ID?
    @State private var showingSourceNote = false
    /// Insights was the only page without the recovery banner every other page
    /// carries, so a missing helper showed up here as a red string per query
    /// with nothing to press (#136).
    @ObservedObject var systemExtension: SystemExtensionManager

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            HelperBanner(systemExtension: systemExtension)
            notices
            content
                // An app picked under one address must not stay picked under
                // the next one, in the No Name pane or the Apps-tab sheet.
                .onChange(of: model.reachingKey) { _ in selectedReachingAppID = nil }
        }
        .onAppear { model.attach(state) }
        .alert("Delete all Insights history?", isPresented: $model.confirmingPurge) {
            Button("Cancel", role: .cancel) {}
            Button("Delete History", role: .destructive) { model.purge() }
        } message: {
            Text("This removes every recorded connection, every DNS answer and every daily rollup, including the database write-ahead log. It cannot be undone.")
        }
    }

    // MARK: Toolbar

    /// One bar, the way Activity Monitor does it: the section switcher on the
    /// left, the controls that scope what it shows on the right. It used to be
    /// a title block repeating the window title, over a second strip holding a
    /// full-width segmented control.
    private var toolbar: some View {
        HStack(spacing: 10) {
            Picker("Section", selection: $model.section) {
                ForEach(InsightsSection.allCases) { section in
                    Text(segmentLabel(section)).tag(section)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            .onChange(of: model.section) { _ in model.reload() }

            Spacer(minLength: 12)

            Picker("Range", selection: $model.range) {
                ForEach(InsightsRange.allCases) { range in
                    Text(range.label).tag(range)
                }
            }
            .labelsHidden()
            .pickerStyle(.menu)
            .fixedSize()
            .onChange(of: model.range) { _ in model.reload() }

            // A switch is named for what it does, not for the state it is in,
            // and deleting history is called deleting history. "Recording" and
            // "Purge…" were the developer's words for both (#136).
            Toggle("Record history", isOn: Binding(get: { model.recordingEnabled },
                                                   set: { model.setRecording($0) }))
                .toggleStyle(.switch)
                .controlSize(.small)
                .help("Record connection history. Rules and blocking are unaffected.")

            Button {
                model.reload()
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .help("Reload")
            .accessibilityLabel("Reload")

            // The two lines of fine print that used to be pinned across the
            // bottom of every tab live here, one click away from the controls
            // they describe (#126).
            Button {
                showingSourceNote = true
            } label: {
                Image(systemName: "info.circle")
            }
            .buttonStyle(.borderless)
            .help("About this data")
            .accessibilityLabel("About this data")
            .popover(isPresented: $showingSourceNote, arrowEdge: .bottom) {
                VStack(alignment: .leading, spacing: 8) {
                    Text(model.sourceNote)
                    Text(model.namingNote)
                }
                .font(.callout)
                .frame(width: 320, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
                .padding(14)
            }

            Button("Delete History…", role: .destructive) {
                model.confirmingPurge = true
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background(.bar)
    }

    /// D9's non-negotiable sentence, plus anything else this screen has to
    /// admit before you read a number off it. All three used to be coloured
    /// bands stacked across the top; they are notice cards now, and they only
    /// take space when there is something to say.
    @ViewBuilder private var notices: some View {
        let hasNotice = notBlockingMessage != nil || model.errorMessage != nil
        if hasNotice {
            VStack(spacing: 8) {
                if let message = notBlockingMessage {
                    NoticeCard(title: message, icon: "exclamationmark.shield", tint: .orange)
                }
                if let error = model.errorMessage {
                    NoticeCard(title: error, icon: "exclamationmark.triangle", tint: .red)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
        }
    }

    /// The count of changed apps rides on the segment that shows them, the way
    /// Mail puts a count on the mailbox, instead of a banner that announced the
    /// number without offering a way to go and look (#89). It is not a real
    /// badge because `NSSegmentedControl` has no badge, so it is the count in
    /// the label, which costs no extra row and still disappears at zero.
    /// "1 destination", not "1 destinations". A count that disagrees with its
    /// noun is the sort of thing no Apple app ships (#102).
    static func plural(_ count: Int, _ noun: String) -> String {
        guard count != 1 else { return "1 \(noun)" }
        let needsES = noun.hasSuffix("s") || noun.hasSuffix("x") || noun.hasSuffix("ch") || noun.hasSuffix("sh")
        return "\(count) \(noun)\(needsES ? "es" : "s")"
    }

    private func segmentLabel(_ section: InsightsSection) -> String {
        guard section == .findings, model.changedAppCount > 0 else { return section.shortLabel }
        return "\(section.shortLabel) (\(model.changedAppCount))"
    }

    private var notBlockingMessage: String? {
        if !state.enforcementEnabled {
            return "FreeSnitch is not blocking anything: enforcement is off. Insights still records, and nothing on this screen is in force."
        }
        switch state.mode {
        case .silentAllow:
            return "FreeSnitch is in Silent Allow: every connection no rule covers is permitted, and your deny and ask rules still apply. Insights still records, and nothing on this screen is in force."
        case .alert, .silentDeny:
            return nil
        }
    }

    // MARK: Sections

    @ViewBuilder private var content: some View {
        switch model.section {
        case .apps: appsSection
        case .unresolved: unresolvedSection
        case .proposals: proposalsSection
        case .findings: findingsSection
        }
    }

    // MARK: Apps and their destinations

    private var appsSection: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 0) {
                sectionTitle("Apps", subtitle: "\(model.apps.count) recorded",
                             note: "Every app that went online in this range. Select one to see where it connected.")
                if model.apps.isEmpty && !model.isLoading {
                    emptyState("Nothing recorded in this range yet.")
                } else {
                    // A real List: system selection highlight and arrow keys.
                    // Styled as content, not as a sidebar: the only translucent
                    // band in the window is the window's own sidebar.
                    List(selection: appSelection) {
                        ForEach(model.apps) { app in
                            appRow(app)
                                .tag(app.id)
                        }
                    }
                    .listStyle(.inset)
                    // The selection-aware form is the one that works on a
                    // List: a plain per-row .contextMenu inside one of these
                    // never sees the right click, because the NSTableView
                    // under it takes the event first (#78).
                    .contextMenu(forSelectionType: InsightsAppSummary.ID.self) { ids in
                        if let id = ids.first, let app = model.apps.first(where: { $0.id == id }) {
                            appContextMenu(app)
                        }
                    }
                    listFooter(hasMore: model.hasMoreApps,
                               title: "Load more apps",
                               action: { model.loadMoreApps() })
                }
            }
            .frame(width: 280)

            Divider()

            VStack(alignment: .leading, spacing: 0) {
                if let app = model.selectedApp {
                    sectionTitle(app.displayName,
                                 subtitle: "\(Self.plural(app.destinationCount, "destination")), \(Self.plural(app.connectionCount, "connection"))")
                    if model.destinations.isEmpty && !model.isLoading {
                        emptyState("No destinations recorded for this app in this range.")
                    } else {
                        List(selection: $selectedDestinationID) {
                            ForEach(model.destinations) { destination in
                                destinationRow(destination, app: app)
                                    .tag(destination.id)
                            }
                        }
                        .listStyle(.inset)
                        .contextMenu(forSelectionType: InsightsDestinationSummary.ID.self) { ids in
                            if let id = ids.first,
                               let destination = model.destinations.first(where: { $0.id == id }) {
                                destinationContextMenu(destination, app: app)
                            }
                        }
                        destinationFooter(app: app)
                    }
                } else {
                    emptyState("Select an app to see what it talked to.")
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .sheet(item: $model.sharedDestination) { destination in
            sharedDestinationSheet(destination)
        }
    }

    /// "Also contacted by 2 other apps" said how many and never which (#435).
    private func sharedDestinationSheet(_ destination: InsightsDestinationSummary) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            sectionTitle("Apps that reached \(destination.displayName)",
                         subtitle: "\(Self.plural(destination.otherAppCount + 1, "app")) in this range",
                         note: "Apps that talk to the same server aren't necessarily related.")
            reachingAppsList(proposingFor: nil)
            Divider()
            HStack {
                Spacer()
                Button("Done") { model.sharedDestination = nil }
                    .keyboardShortcut(.defaultAction)
            }
            .padding(12)
        }
        .frame(width: 520, height: 380)
    }

    /// Selection lives in the view model, because picking an app is also what
    /// loads its destinations.
    private var appSelection: Binding<InsightsAppSummary.ID?> {
        Binding(get: { model.selectedApp?.id },
                set: { id in
                    guard let id, let app = model.apps.first(where: { $0.id == id }) else { return }
                    model.select(app)
                })
    }

    @ViewBuilder
    private func appRow(_ app: InsightsAppSummary) -> some View {
        HStack(spacing: 8) {
            if let icon = AppIcon.resolve(bundleId: app.processBundleId, path: app.processPath, name: app.displayName) {
                Image(nsImage: icon).resizable().frame(width: 20, height: 20)
            } else {
                Image(systemName: "app.dashed").foregroundStyle(.secondary)
            }
            VStack(alignment: .leading, spacing: 1) {
                Text(app.displayName).font(.body).lineLimit(1)
                // Short enough to survive the list's width. The long form
                // truncated inside a word ("4.8k connecti..."), which reads as
                // a layout bug rather than as an abbreviation (#102).
                Text("\(Self.plural(app.destinationCount, "destination")), \(PSFormat.compactCount(app.connectionCount)) connections")
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    .help("\(Self.plural(app.destinationCount, "destination")), \(Self.plural(app.connectionCount, "connection"))")
                if app.blockedCount > 0 {
                    Label("\(PSFormat.compactCount(app.blockedCount)) blocked", systemImage: "xmark.octagon.fill")
                        .labelStyle(.titleAndIcon)
                        .font(.caption).foregroundStyle(.red).lineLimit(1)
                        .help("FreeSnitch blocked \(Self.plural(app.blockedCount, "connection")) from this app in this range.")
                }
            }
            Spacer()
            Text(PSFormat.bytes(app.bytesIn + app.bytesOut))
                .font(.caption).foregroundStyle(.secondary).monospacedDigit()
        }
    }

    /// Data only. The action lives under the list, where it works: a button
    /// placed in a `List` row never receives the click in this app, so the one
    /// that used to sit on every row was both noise and inert (#102, #106).
    private func destinationRow(_ destination: InsightsDestinationSummary, app: InsightsAppSummary) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Text(destination.displayName).font(.body)
                if !destination.isNameKnown {
                    PSChip("No DNS name seen", color: .orange, icon: "questionmark.circle")
                }
                Spacer()
                decisionChip(destination)
                Text("\(PSFormat.compactCount(destination.connectionCount)) connections")
                    .font(.caption).foregroundStyle(.secondary).monospacedDigit()
                Text(PSFormat.bytes(destination.bytesIn + destination.bytesOut))
                    .font(.caption).foregroundStyle(.tertiary).monospacedDigit()
            }
            HStack(spacing: 8) {
                if let note = destination.correlationNote {
                    PSChip(note, color: .accentColor, icon: "person.2")
                }
                if destination.isNameKnown, let ip = destination.remoteIP {
                    Text(ip).font(.caption.monospaced()).foregroundStyle(.secondary)
                }
                Spacer()
            }
        }
        .padding(.vertical, 4)
    }

    /// What FreeSnitch did with the connections in this row (#447). Rows with
    /// no recorded decision (from before decisions were kept) show nothing,
    /// rather than a guess.
    @ViewBuilder
    private func decisionChip(_ destination: InsightsDestinationSummary) -> some View {
        if let counts = destination.decisions {
            Group {
                switch counts.status(total: destination.connectionCount) {
                case .allowed:
                    PSChip("Allowed", color: .green, icon: "checkmark.circle.fill")
                case .blocked:
                    PSChip("Blocked", color: .red, icon: "xmark.octagon.fill")
                case .mixed(let blocked, let total):
                    PSChip("\(PSFormat.compactCount(blocked)) of \(PSFormat.compactCount(total)) blocked",
                           color: .orange, icon: "xmark.octagon")
                case .notBlocked:
                    PSChip("Not blocked", color: .green, icon: "checkmark.circle")
                case .unfiltered:
                    PSChip("Not filtered", color: .secondary, icon: "minus.circle")
                case .unknown:
                    EmptyView()
                }
            }
            .help(Self.decisionHelp(counts, total: destination.connectionCount))
        }
    }

    /// The exact split behind the chip, including connections recorded
    /// before decisions were kept.
    static func decisionHelp(_ counts: InsightsDecisionCounts, total: Int) -> String {
        var parts: [String] = []
        if counts.allowed > 0 { parts.append("\(Self.plural(counts.allowed, "connection")) allowed") }
        if counts.blocked > 0 { parts.append("\(Self.plural(counts.blocked, "connection")) blocked") }
        if counts.unfiltered > 0 {
            parts.append("\(Self.plural(counts.unfiltered, "connection")) let through without a filtering decision "
                         + "(name lookups, local traffic, an unanswered alert, or the filter wasn't running)")
        }
        let unknown = total - counts.allowed - counts.blocked - counts.unfiltered
        if unknown > 0 {
            parts.append("\(Self.plural(unknown, "connection")) recorded before FreeSnitch kept decisions")
        }
        return parts.joined(separator: "\n")
    }

    /// Acts on the selected row, the way Mail's toolbar acts on the selected
    /// message. Says what it needs when nothing is selected instead of being
    /// silently inert (#106).
    private func destinationFooter(app: InsightsAppSummary) -> some View {
        HStack(spacing: 8) {
            Button("Suggest a Rule\u{2026}") {
                guard let id = selectedDestinationID,
                      let destination = model.destinations.first(where: { $0.id == id }) else { return }
                model.proposeRule(for: destination, app: app)
            }
            .controlSize(.small)
            .disabled(selectedDestinationID == nil)
            .help(selectedDestinationID == nil
                  ? "Select a destination first."
                  : "Draft a rule for the selected destination. Nothing is enforced until you accept it.")
            if let shared = selectedSharedDestination {
                Button("Show Apps\u{2026}") {
                    selectedReachingAppID = nil
                    model.showApps(reaching: shared)
                }
                .controlSize(.small)
                .help("See every app that reached \(shared.displayName) in this range.")
            }
            Spacer(minLength: 8)
            if model.hasMoreDestinations {
                Button("Load more destinations") { model.loadMoreDestinations() }
                    .controlSize(.small)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(.bar)
    }

    /// The selected destination when other apps reached it too.
    private var selectedSharedDestination: InsightsDestinationSummary? {
        guard let id = selectedDestinationID,
              let destination = model.destinations.first(where: { $0.id == id }),
              destination.otherAppCount > 0 else { return nil }
        return destination
    }

    /// One shape for "there is more where that came from", under the list
    /// rather than as its last row (#106).
    @ViewBuilder
    private func listFooter(hasMore: Bool, title: String, action: @escaping () -> Void) -> some View {
        if hasMore && !model.atPageLimit {
            HStack {
                Button(title, action: action)
                    .controlSize(.small)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(.bar)
        } else if hasMore {
            // Past the page limit the query returns nothing, so the button
            // stayed on screen and did nothing when pressed. A control that
            // cannot act is replaced by the reason it cannot (#136).
            HStack {
                Text("This is as far as one screen goes. Choose a shorter range to see the rest.")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(.bar)
        }
    }

    /// The same call the button on the row makes, plus the two things a reader
    /// wants to take away from this screen (#78).
    @ViewBuilder
    private func destinationContextMenu(_ destination: InsightsDestinationSummary,
                                        app: InsightsAppSummary) -> some View {
        Button("Suggest a Rule\u{2026}") { model.proposeRule(for: destination, app: app) }
        if destination.otherAppCount > 0 {
            Button("Show Apps\u{2026}") {
                selectedReachingAppID = nil
                model.showApps(reaching: destination)
            }
        }
        Divider()
        CopyMenuItem(title: "Copy Destination", value: destination.displayName)
        CopyMenuItem(title: "Copy IP Address", value: destination.remoteIP)
    }

    @ViewBuilder
    private func appContextMenu(_ app: InsightsAppSummary) -> some View {
        CopyMenuItem(title: "Copy App Name", value: app.displayName)
        CopyMenuItem(title: "Copy Bundle ID", value: app.processBundleId)
        if RowActions.canReveal(path: app.processPath) {
            Button("Reveal in Finder") { RowActions.revealInFinder(path: app.processPath) }
        }
    }

    // MARK: Unresolved addresses

    private var unresolvedSection: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 0) {
                sectionTitle("Addresses reached without a name lookup",
                             subtitle: "\(model.unresolved.count) in this range",
                             note: InsightsUnresolvedDestination.signalWording)
                if model.unresolved.isEmpty && !model.isLoading {
                    emptyState("Every recorded address had a DNS answer in this range.")
                } else {
                    // Selectable, copyable and actionable, like the Apps list. It
                    // used to be plain text: the one thing a reader could want to
                    // do with a suspicious address, turn it into a rule, was not
                    // offered anywhere on the tab (#124). Selecting a row shows
                    // every app behind it on the right, because "Reached by 3
                    // apps" named none of them past 14 days (#435).
                    List(selection: unresolvedSelection) {
                        ForEach(model.unresolved) { entry in
                            VStack(alignment: .leading, spacing: 3) {
                                HStack(spacing: 8) {
                                    Text(entry.remoteIP).font(.body.monospaced()).lineLimit(1)
                                    Spacer()
                                    Text("\(PSFormat.compactCount(entry.connectionCount)) connections")
                                        .font(.caption).foregroundStyle(.secondary).monospacedDigit()
                                }
                                Text(Self.reachedBy(entry))
                                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                            }
                            .padding(.vertical, 2)
                            .tag(entry.id)
                        }
                    }
                    .listStyle(.inset)
                    .contextMenu(forSelectionType: String.self) { ids in
                        unresolvedContextMenu(ids)
                    }
                    .onCopyCommand {
                        guard let id = model.selectedUnresolved?.id else { return [] }
                        return [NSItemProvider(object: id as NSString)]
                    }
                    listFooter(hasMore: model.hasMoreUnresolved,
                               title: "Load more addresses",
                               action: { model.loadMoreUnresolved() })
                }
            }
            .frame(width: 320)

            Divider()

            VStack(alignment: .leading, spacing: 0) {
                if let entry = model.selectedUnresolved {
                    sectionTitle(entry.remoteIP,
                                 subtitle: Self.unresolvedSummary(entry))
                    reachingAppsList(proposingFor: entry)
                } else {
                    emptyState("Select an address to see which apps reached it.")
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
    }

    private var unresolvedSelection: Binding<String?> {
        Binding(get: { model.selectedUnresolved?.id },
                set: { id in
                    guard let id, let entry = model.unresolved.first(where: { $0.id == id }) else { return }
                    selectedReachingAppID = nil
                    model.selectUnresolved(entry)
                })
    }

    private static func unresolvedSummary(_ entry: InsightsUnresolvedDestination) -> String {
        var parts = ["Reached by \(plural(entry.appCount, "app"))",
                     plural(entry.connectionCount, "connection"),
                     PSFormat.bytes(entry.bytesIn + entry.bytesOut)]
        if let lastSeen = entry.lastSeen {
            parts.append("last seen \(lastSeen.formatted(.relative(presentation: .named)))")
        }
        return parts.joined(separator: ", ")
    }

    /// Every app behind one destination, each with its own count and the
    /// executable it ran from. Shared by the No Name pane and the Apps tab's
    /// sheet. With `entry`, the footer drafts an address rule for the selected
    /// app, the same proposal the context menu used to offer by name only.
    @ViewBuilder
    private func reachingAppsList(proposingFor entry: InsightsUnresolvedDestination?) -> some View {
        if let error = model.reachingError {
            emptyState(error)
        } else if model.reachingApps.isEmpty && !model.isLoading {
            emptyState("No app recorded for this destination in this range.")
        } else {
            List(selection: $selectedReachingAppID) {
                ForEach(model.reachingApps) { app in
                    reachingAppRow(app).tag(app.id)
                }
            }
            .listStyle(.inset)
            .contextMenu(forSelectionType: InsightsAppSummary.ID.self) { ids in
                if let id = ids.first, let app = model.reachingApps.first(where: { $0.id == id }) {
                    if let entry {
                        Button("Suggest a Rule for \(app.displayName)\u{2026}") {
                            model.proposeRule(forUnresolved: entry, app: app)
                        }
                        Divider()
                    }
                    appContextMenu(app)
                }
            }
            HStack(spacing: 8) {
                if let entry {
                    Button("Suggest a Rule\u{2026}") {
                        guard let id = selectedReachingAppID,
                              let app = model.reachingApps.first(where: { $0.id == id }) else { return }
                        model.proposeRule(forUnresolved: entry, app: app)
                    }
                    .controlSize(.small)
                    .disabled(selectedReachingAppID == nil)
                    .help(selectedReachingAppID == nil
                          ? "Select an app first."
                          : "Draft a rule for the selected app and this address. Nothing is enforced until you accept it.")
                }
                Spacer(minLength: 8)
                if model.hasMoreReachingApps && !model.atPageLimit {
                    Button("Load more apps") { model.loadMoreReachingApps() }
                        .controlSize(.small)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(.bar)
        }
    }

    private func reachingAppRow(_ app: InsightsAppSummary) -> some View {
        HStack(alignment: .top, spacing: 8) {
            if let icon = AppIcon.resolve(bundleId: app.processBundleId, path: app.processPath, name: app.displayName) {
                Image(nsImage: icon).resizable().frame(width: 20, height: 20)
            } else {
                Image(systemName: "app.dashed").foregroundStyle(.secondary).frame(width: 20, height: 20)
            }
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 8) {
                    Text(app.displayName).font(.body).lineLimit(1)
                    Spacer()
                    Text(app.connectionCount == 1 ? "1 connection"
                         : "\(PSFormat.compactCount(app.connectionCount)) connections")
                        .font(.caption).foregroundStyle(.secondary).monospacedDigit()
                }
                if let detail = app.processPath ?? app.processBundleId {
                    Text(detail)
                        .font(.caption.monospaced()).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.middle)
                        .help(detail)
                        .textSelection(.enabled)
                }
            }
        }
        .padding(.vertical, 3)
    }

    /// One way of naming who reached an address. Three rows said "reached by
    /// Telegram" and the fourth said "3 apps" (#124).
    private static func reachedBy(_ entry: InsightsUnresolvedDestination) -> String {
        guard !entry.appNames.isEmpty else {
            return "Reached by \(plural(entry.appCount, "app"))"
        }
        let named = entry.appNames.joined(separator: ", ")
        let remaining = entry.appCount - entry.appNames.count
        guard remaining > 0 else { return "Reached by \(named)" }
        return "Reached by \(named) and \(remaining) more"
    }

    @ViewBuilder
    private func unresolvedContextMenu(_ ids: Set<String>) -> some View {
        // Rules for one app live in the pane on the right, which lists every
        // app behind the address. Matching the five sampled names against the
        // loaded app list offered nothing past 14 days (#435).
        if let id = ids.first, let entry = model.unresolved.first(where: { $0.id == id }) {
            CopyMenuItem(title: "Copy Address", value: entry.remoteIP)
        }
    }

    // MARK: Changed behaviour

    private var findingsSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            sectionTitle("New since an app update",
                         subtitle: "a change, not proof of anything",
                         note: "Places an app started connecting to after it was updated. New versions often add new servers, so this is a pointer, not an alarm. When FreeSnitch can't tell an app's version, it says so instead of guessing.")
            if model.findings.isEmpty && !model.isLoading {
                emptyState("No changed destinations in this range.")
            } else {
                // A scroll view of cards, not a table: each finding carries its
                // own action, and a button inside a `List` row never receives
                // the click here (#106).
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                    ForEach(model.findings) { finding in
                        VStack(alignment: .leading, spacing: 5) {
                            HStack(spacing: 8) {
                                Text(finding.displayName).font(.body.weight(.semibold))
                                // Plain secondary text in the app's own font. An
                                // unknown version is a missing fact, not a
                                // warning, and orange monospace made it look
                                // like a fault (#125).
                                Text(finding.versionLabel)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                Spacer()
                            }
                            HStack(spacing: 8) {
                                Text(finding.destination).font(.body)
                                PSChip(finding.wording, color: .orange, icon: "exclamationmark.magnifyingglass")
                                Text(Self.plural(finding.connectionCount, "connection"))
                                    .font(.caption).foregroundStyle(.secondary)
                                Spacer()
                            }
                            Text(finding.evidence).font(.caption).foregroundStyle(.secondary)
                            if let proposal = finding.proposedRule() {
                                Button("Suggest a Rule\u{2026}") { model.proposeRule(for: proposal) }
                                    .controlSize(.small)
                            }
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        Divider()
                    }
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    // MARK: Proposals

    private var proposalsSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            sectionTitle("Suggested rules",
                         subtitle: "none are active",
                         note: "Rules FreeSnitch suggests from what it recorded, each for one app and one destination. Nothing changes until you accept a suggestion, one at a time.")
            if let message = model.acceptMessage {
                Label(message, systemImage: "checkmark.circle")
                    .font(.callout)
                    .foregroundStyle(.green)
                    .padding(.horizontal, 12).padding(.bottom, 6)
            }
            if model.proposals.isEmpty && !model.isLoading {
                emptyState("No suggestions in this range.")
            } else {
                // Each proposal is a card with its own decision to make, and a
                // decision has to be clickable: inside a `List` row it was not
                // (#106).
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(model.proposals) { proposal in
                            proposalRow(proposal)
                                .padding(.horizontal, 12)
                                .padding(.vertical, 8)
                            Divider()
                        }
                    }
                }
                listFooter(hasMore: model.hasMoreProposals,
                           title: "Load more suggestions",
                           action: { model.loadMoreProposals() })
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private func proposalRow(_ proposal: InsightsProposedRule) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 8) {
                Text("\(proposal.appDisplayName) may not reach \(proposal.destinationLabel)").font(.body)
                if proposal.isDomainScoped {
                    PSChip("Domain rule", color: .green, icon: "globe")
                } else {
                    PSChip("Pinned to an address", color: .orange, icon: "number")
                }
                if proposal.otherAppCount > 0 {
                    PSChip("also contacted by \(proposal.otherAppCount) other app\(proposal.otherAppCount == 1 ? "" : "s")",
                           color: .accentColor, icon: "person.2")
                }
                Spacer()
            }
            Text(proposal.evidence)
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if proposal.requiresExplicitIPChoice {
                Label("No DNS name was ever seen for this address, so this rule can only pin the address itself. Addresses rotate, and a pinned rule silently stops matching when they do. Accept it only if you want that.",
                      systemImage: "exclamationmark.triangle")
                    .font(.caption).foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack(spacing: 10) {
                if model.accepted.contains(proposal.id) {
                    Label("Added to your rules", systemImage: "checkmark.circle")
                        .font(.callout).foregroundStyle(.green)
                } else {
                    // Accepting writes a rule through the helper, so it is
                    // disabled while nothing can answer, and says why (#98).
                    Button(proposal.requiresExplicitIPChoice
                           ? "Block this address for \(proposal.appDisplayName) anyway"
                           : "Block for \(proposal.appDisplayName)") {
                        model.accept(proposal, widened: false)
                    }
                    .controlSize(.small)
                    .disabled(!state.helperConnected)
                    .help(state.helperConnected
                          ? "Adds this rule to \(state.activeProfile)."
                          : "Approve the FreeSnitch helper to add rules.")

                    if proposal.isDomainScoped {
                        Button("Block for every app") { model.accept(proposal, widened: true) }
                            .controlSize(.small)
                            .disabled(!state.helperConnected)
                            .help(state.helperConnected
                                  ? "Adds this rule for every app."
                                  : "Approve the FreeSnitch helper to add rules.")
                    }
                }
                Spacer()
            }
        }
        .padding(.vertical, 4)
    }

    // MARK: Shared pieces

    /// A group header, not a second toolbar: the title, the count that scopes
    /// it, and the policy sentence a section is required to carry.
    private func sectionTitle(_ title: String, subtitle: String, note: String? = nil) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Text(title).font(.headline)
                Text(subtitle).font(.subheadline).foregroundStyle(.secondary)
                Spacer()
                if model.isLoading { ProgressView().controlSize(.small) }
            }
            if let note {
                // Explanatory text is capped at a readable measure instead of
                // running the full width of the window.
                Text(note)
                    .font(.footnote).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: 620, alignment: .leading)
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
    }

    /// Centred and muted, the way macOS shows a list with nothing in it.
    private func emptyState(_ text: String) -> some View {
        VStack {
            Spacer()
            Text(text)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal, 24)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

}

// MARK: - Ranges and sections

enum InsightsRange: String, CaseIterable, Identifiable, Hashable {
    case day
    case week
    case twoWeeks
    case quarter
    case year

    var id: String { rawValue }

    var label: String {
        switch self {
        case .day: return "Last 24 hours"
        case .week: return "Last 7 days"
        case .twoWeeks: return "Last 14 days"
        case .quarter: return "Last 90 days"
        case .year: return "Last 365 days"
        }
    }

    var seconds: TimeInterval {
        switch self {
        case .day: return 24 * 60 * 60
        case .week: return 7 * 24 * 60 * 60
        case .twoWeeks: return 14 * 24 * 60 * 60
        case .quarter: return 90 * 24 * 60 * 60
        case .year: return 365 * 24 * 60 * 60
        }
    }
}

enum InsightsSection: String, CaseIterable, Identifiable, Hashable {
    case apps
    case unresolved
    case proposals
    case findings

    var id: String { rawValue }

    var label: String {
        switch self {
        case .apps: return "Apps"
        case .unresolved: return "Addresses reached without a name lookup"
        case .proposals: return "Suggested rules"
        case .findings: return "New since an app update"
        }
    }

    /// What the segmented control shows. The full label is a sentence and would
    /// force the switcher to the width of the window; the section header below
    /// still spells it out.
    var shortLabel: String {
        switch self {
        case .apps: return "Apps"
        case .unresolved: return "No Name"
        case .proposals: return "Suggestions"
        case .findings: return "New Since Update"
        }
    }
}

// MARK: - View model

@MainActor
final class InsightsViewModel: ObservableObject {
    /// One page per request. The helper refuses anything larger, and a year of
    /// rollups is never pulled across at once.
    private static let pageSize = 50
    /// A bounded screen: past this the answer is "narrow the range", not a
    /// longer list.
    private static let maximumPages = 10

    @Published var range: InsightsRange = .week
    @Published var section: InsightsSection = .apps
    @Published var apps: [InsightsAppSummary] = []
    @Published var destinations: [InsightsDestinationSummary] = []
    @Published var unresolved: [InsightsUnresolvedDestination] = []
    @Published var proposals: [InsightsProposedRule] = []
    @Published var findings: [InsightsBehaviourFinding] = []
    @Published var overview: InsightsOverview?
    @Published var selectedApp: InsightsAppSummary?
    /// The No Name row whose apps fill the right-hand pane (#435).
    @Published var selectedUnresolved: InsightsUnresolvedDestination?
    /// The apps behind one destination, each with its own count: the No Name
    /// pane and the Apps tab's "Show Apps" sheet both read it. `reachingKey`
    /// says which destination they belong to, so a late reply for another
    /// one is dropped instead of shown under the wrong address (#435).
    @Published var reachingApps: [InsightsAppSummary] = []
    @Published private(set) var reachingKey: String?
    @Published var hasMoreReachingApps = false
    /// Why the list above could not be shown, said where the list would be:
    /// the main banner sits under the Apps tab's sheet.
    @Published var reachingError: String?
    /// The Apps-tab destination whose apps the sheet is showing.
    @Published var sharedDestination: InsightsDestinationSummary?
    @Published var recordingEnabled = true
    @Published var isLoading = false
    @Published var errorMessage: String?
    @Published var acceptMessage: String?
    @Published var accepted: Set<UUID> = []
    @Published var confirmingPurge = false
    @Published var hasMoreApps = false
    @Published var hasMoreDestinations = false
    @Published var hasMoreUnresolved = false
    @Published var hasMoreProposals = false
    @Published private(set) var source: InsightsDataSource = .rawEvents

    var changedAppCount: Int { Set(findings.map(\.appIdentity)).count }

    private weak var state: AppState?
    private var attached = false

    func attach(_ state: AppState) {
        self.state = state
        guard !attached else { return }
        attached = true
        reload()
    }

    var sourceNote: String {
        source.explanation + " Recording is \(recordingEnabled ? "on" : "off") and runs in every mode."
    }

    var namingNote: String {
        overview?.namingNote
            ?? "Names come from DNS answers seen on this Mac. Apps that resolve names themselves are shown as raw addresses."
    }

    // MARK: Loading

    func reload() {
        errorMessage = nil
        acceptMessage = nil
        if InsightsDemoData.isEnabled {
            loadDemoData()
            return
        }
        refreshRecordingState()
        loadOverview()
        if section != .findings {
            findings = []
            loadFindings(offset: 0)
        }
        switch section {
        case .apps:
            apps = []
            destinations = []
            loadApps(offset: 0)
        case .unresolved:
            unresolved = []
            // The Apps tab's sheet shares this list; don't show its apps under
            // the No Name address while that list reloads.
            reachingGeneration += 1
            reachingKey = nil
            reachingApps = []
            loadUnresolved(offset: 0)
        case .proposals:
            proposals = []
            loadProposals(offset: 0)
        case .findings:
            findings = []
            loadFindings(offset: 0)
        }
    }

    func select(_ app: InsightsAppSummary) {
        selectedApp = app
        destinations = []
        if InsightsDemoData.isEnabled {
            destinations = InsightsDemoData.destinations(for: app.appIdentity)
            return
        }
        loadDestinations(offset: 0)
    }

    /// Demo mode has no helper, so every query returns nothing and this screen
    /// cannot be reviewed or screenshotted before it ships. Guarded by the same
    /// environment variable as the rest of the demo harness, so an installed
    /// copy never sees it.
    private func loadDemoData() {
        isLoading = false
        recordingEnabled = true
        hasMoreApps = false
        hasMoreDestinations = false
        hasMoreUnresolved = false
        hasMoreProposals = false
        hasMoreReachingApps = false
        apps = InsightsDemoData.apps
        unresolved = InsightsDemoData.unresolved
        proposals = InsightsDemoData.proposals
        findings = InsightsDemoData.findings
        if selectedApp == nil { selectedApp = apps.first }
        destinations = InsightsDemoData.destinations(for: selectedApp?.appIdentity ?? "")
        if let entry = selectedUnresolved.flatMap({ old in unresolved.first { $0.id == old.id } }) ?? unresolved.first {
            selectUnresolved(entry)
        }
    }

    // MARK: The apps behind one destination (#435)

    func selectUnresolved(_ entry: InsightsUnresolvedDestination) {
        selectedUnresolved = entry
        loadReachingApps(key: entry.remoteIP, excludesLookups: true, offset: 0)
    }

    /// The Apps tab's "also contacted by N other apps" note, opened up.
    func showApps(reaching destination: InsightsDestinationSummary) {
        sharedDestination = destination
        if InsightsDemoData.isEnabled {
            reachingKey = destination.destinationKey
            reachingApps = InsightsDemoData.apps(reaching: destination.destinationKey,
                                                 owner: destination.appIdentity,
                                                 otherApps: destination.otherAppCount,
                                                 connections: destination.connectionCount)
            return
        }
        loadReachingApps(key: destination.destinationKey, excludesLookups: false, offset: 0)
    }

    func loadMoreReachingApps() {
        guard let key = reachingKey else { return }
        loadReachingApps(key: key, excludesLookups: reachingExcludesLookups, offset: reachingApps.count)
    }

    private var reachingExcludesLookups = false
    /// Bumped by every new list, so a reply for an earlier one (same address
    /// opened from the other screen, or a page of a list since reloaded) is
    /// dropped exactly.
    private var reachingGeneration = 0

    private func loadReachingApps(key: String, excludesLookups: Bool, offset: Int) {
        if offset == 0 {
            reachingGeneration += 1
            reachingKey = key
            reachingExcludesLookups = excludesLookups
            reachingApps = []
            hasMoreReachingApps = false
            reachingError = nil
        }
        if InsightsDemoData.isEnabled {
            reachingApps = InsightsDemoData.apps(reaching: key)
            return
        }
        guard let helper = state?.helper,
              let request = query(.apps, offset: offset, destinationKey: key,
                                  excludesLookups: excludesLookups) else { return }
        isLoading = true
        let generation = reachingGeneration
        helper.insightsReport(request) { [weak self] report, error in
            guard let self else { return }
            // A reply for a list the reader has already left must not end the
            // loading state of the one they are looking at now.
            guard self.reachingGeneration == generation else { return }
            self.isLoading = false
            guard let report else { self.reachingError = error ?? "The helper didn't answer."; return }
            // A helper from before the destination filter ignores it, sends
            // every app and never echoes the key; listing those under this
            // address would be wrong.
            guard report.destinationKey == key else {
                self.reachingError = "FreeSnitch's background helper hasn't been updated yet. Quit and reopen FreeSnitch to see which apps reached this address."
                return
            }
            self.source = report.source
            self.reachingApps = offset == 0 ? report.apps : self.reachingApps + report.apps
            self.hasMoreReachingApps = report.hasMore
        }
    }

    func loadMoreApps() { loadApps(offset: apps.count) }
    func loadMoreDestinations() { loadDestinations(offset: destinations.count) }
    func loadMoreUnresolved() { loadUnresolved(offset: unresolved.count) }
    func loadMoreProposals() { loadProposals(offset: proposals.count) }
    func loadMoreFindings() { loadFindings(offset: findings.count) }

    /// Whether the next page would be refused. The view asks so it can say so
    /// rather than offering a button that returns nothing (#136).
    var atPageLimit: Bool {
        let loaded = [apps.count, destinations.count, unresolved.count, proposals.count, findings.count,
                      reachingApps.count]
        return loaded.contains { $0 > Self.pageSize * Self.maximumPages }
    }

    private func query(_ kind: InsightsQueryKind, offset: Int, appIdentity: String? = nil,
                       destinationKey: String? = nil, excludesLookups: Bool? = nil) -> InsightsQuery? {
        guard offset <= Self.pageSize * Self.maximumPages else { return nil }
        let now = Date()
        return InsightsQuery(kind: kind,
                             appIdentity: appIdentity,
                             destinationKey: destinationKey,
                             excludesLookups: excludesLookups,
                             since: now.addingTimeInterval(-range.seconds),
                             until: now,
                             limit: Self.pageSize,
                             offset: offset)
    }

    private func loadApps(offset: Int) {
        guard let helper = state?.helper, let request = query(.apps, offset: offset) else { return }
        isLoading = true
        helper.insightsReport(request) { [weak self] report, error in
            guard let self else { return }
            self.isLoading = false
            guard let report else { self.errorMessage = error; return }
            self.source = report.source
            self.apps = offset == 0 ? report.apps : self.apps + report.apps
            self.hasMoreApps = report.hasMore
            // App-first: land on something rather than an empty right pane.
            if self.selectedApp == nil, let first = self.apps.first {
                self.selectedApp = first
            }
            if self.selectedApp != nil, self.destinations.isEmpty {
                self.loadDestinations(offset: 0)
            }
        }
    }

    private func loadDestinations(offset: Int) {
        guard let helper = state?.helper,
              let app = selectedApp,
              let request = query(.destinations, offset: offset, appIdentity: app.appIdentity) else { return }
        isLoading = true
        helper.insightsReport(request) { [weak self] report, error in
            guard let self else { return }
            self.isLoading = false
            guard let report else { self.errorMessage = error; return }
            self.source = report.source
            self.destinations = offset == 0 ? report.destinations : self.destinations + report.destinations
            self.hasMoreDestinations = report.hasMore
        }
    }

    private func loadUnresolved(offset: Int) {
        guard let helper = state?.helper, let request = query(.unresolved, offset: offset) else { return }
        isLoading = true
        helper.insightsReport(request) { [weak self] report, error in
            guard let self else { return }
            self.isLoading = false
            guard let report else { self.errorMessage = error; return }
            self.source = report.source
            self.unresolved = offset == 0 ? report.unresolved : self.unresolved + report.unresolved
            self.hasMoreUnresolved = report.hasMore
            // Like the Apps tab: land on a row rather than an empty pane, and
            // keep the one the reader picked when it is still in the list.
            guard offset == 0 else { return }
            let kept = self.selectedUnresolved.flatMap { old in self.unresolved.first { $0.id == old.id } }
            if let entry = kept ?? self.unresolved.first {
                self.selectUnresolved(entry)
            } else {
                self.selectedUnresolved = nil
                self.reachingKey = nil
                self.reachingApps = []
            }
        }
    }

    private func loadFindings(offset: Int) {
        guard let helper = state?.helper, let request = query(.findings, offset: offset) else { return }
        isLoading = true
        helper.insightsReport(request) { [weak self] report, error in
            guard let self else { return }
            self.isLoading = false
            guard let report else { self.errorMessage = error; return }
            self.source = report.source
            self.findings = offset == 0 ? report.findings : self.findings + report.findings
        }
    }

    private func loadProposals(offset: Int) {
        guard let helper = state?.helper, let request = query(.proposals, offset: offset) else { return }
        isLoading = true
        helper.insightsReport(request) { [weak self] report, error in
            guard let self else { return }
            self.isLoading = false
            guard let report else { self.errorMessage = error; return }
            self.source = report.source
            // Do not keep proposing something the user already decided. The
            // helper remains the authority at acceptance time, but filtering
            // here keeps the screen honest while preserving the bounded query.
            let novel = report.proposals.filter { !self.isCoveredByExistingRule($0) }
            self.proposals = offset == 0 ? novel : self.proposals + novel
            self.hasMoreProposals = report.hasMore
        }
    }

    private func loadOverview() {
        guard let helper = state?.helper, let request = query(.overview, offset: 0) else { return }
        helper.insightsReport(request) { [weak self] report, _ in
            guard let self, let report else { return }
            self.overview = report.overview
            self.recordingEnabled = report.recordingEnabled
        }
    }

    private func refreshRecordingState() {
        state?.helper.queryInsightsRecordingEnabled { [weak self] enabled in
            self?.recordingEnabled = enabled
        }
    }

    // MARK: Actions

    func setRecording(_ enabled: Bool) {
        recordingEnabled = enabled
        state?.helper.setInsightsRecordingEnabled(enabled) { [weak self] ok, message in
            guard let self else { return }
            guard ok else {
                self.recordingEnabled = !enabled
                self.errorMessage = message ?? "The helper refused the recording change."
                return
            }
            self.reload()
        }
    }

    func purge() {
        state?.helper.purgeInsights { [weak self] ok, message in
            guard let self else { return }
            guard ok else {
                self.errorMessage = message ?? "The helper refused the purge."
                return
            }
            self.accepted = []
            self.selectedApp = nil
            self.selectedUnresolved = nil
            self.reload()
        }
    }

    /// The destination view's shortcut into a proposal: same shape as the ones
    /// on the proposals tab, still a proposal.
    func proposeRule(for destination: InsightsDestinationSummary, app: InsightsAppSummary) {
        let proposal = InsightsProposedRule(appIdentity: app.appIdentity,
                                            appDisplayName: app.displayName,
                                            processBundleId: app.processBundleId,
                                            processPath: app.processPath,
                                            domain: destination.resolvedDomain,
                                            remoteIP: destination.remoteIP,
                                            connectionCount: destination.connectionCount,
                                            otherAppCount: destination.otherAppCount,
                                            lastSeen: destination.lastSeen)
        guard !isCoveredByExistingRule(proposal) else {
            acceptMessage = "A rule already covers \(proposal.destinationLabel) for \(proposal.appDisplayName)."
            return
        }
        if !proposals.contains(where: { $0.id == proposal.id }) {
            proposals.insert(proposal, at: 0)
        }
        section = .proposals
    }

    /// A proposal built from an address with no DNS answer. It can only ever be
    /// address-pinned, which the proposal card already says out loud. `app`
    /// comes from the apps behind this address, so its count is its own.
    func proposeRule(forUnresolved entry: InsightsUnresolvedDestination, app: InsightsAppSummary) {
        let proposal = InsightsProposedRule(appIdentity: app.appIdentity,
                                            appDisplayName: app.displayName,
                                            processBundleId: app.processBundleId,
                                            processPath: app.processPath,
                                            domain: nil,
                                            remoteIP: entry.remoteIP,
                                            connectionCount: app.connectionCount,
                                            otherAppCount: max(0, entry.appCount - 1),
                                            lastSeen: entry.lastSeen)
        proposeRule(for: proposal)
    }

    func proposeRule(for proposal: InsightsProposedRule) {
        guard !isCoveredByExistingRule(proposal) else {
            acceptMessage = "A rule already covers \(proposal.destinationLabel) for \(proposal.appDisplayName)."
            return
        }
        if !proposals.contains(where: { $0.id == proposal.id }) { proposals.insert(proposal, at: 0) }
        section = .proposals
    }

    private func isCoveredByExistingRule(_ proposal: InsightsProposedRule) -> Bool {
        guard let rules = state?.rules else { return false }
        return proposal.isCovered(by: rules)
    }

    /// D2: this is the only path from a proposal to a rule, and a person is
    /// standing on it.
    func accept(_ proposal: InsightsProposedRule, widened: Bool) {
        guard let state else { return }
        let rule = widened
            ? proposal.widenedRule(profile: state.activeProfile)
            : proposal.rule(profile: state.activeProfile)
        guard let rule else {
            errorMessage = "That suggestion cannot be widened, because no DNS name is known for the destination."
            return
        }
        state.helper.addRule(rule) { [weak self] ok, message in
            guard let self else { return }
            guard ok else {
                self.errorMessage = message ?? "The helper rejected the suggested rule."
                return
            }
            self.accepted.insert(proposal.id)
            self.acceptMessage = widened
                ? "Added a rule blocking \(proposal.destinationLabel) for every app."
                : "Added a rule blocking \(proposal.destinationLabel) for \(proposal.appDisplayName)."
            state.refreshRules()
        }
    }
}
