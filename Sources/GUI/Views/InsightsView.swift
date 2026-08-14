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

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            notices
            content
            Divider()
            footer
        }
        .onAppear { model.attach(state) }
        .alert("Delete all Insights history?", isPresented: $model.confirmingPurge) {
            Button("Cancel", role: .cancel) {}
            Button("Delete everything", role: .destructive) { model.purge() }
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

            Toggle("Recording", isOn: Binding(get: { model.recordingEnabled },
                                              set: { model.setRecording($0) }))
                .toggleStyle(.switch)
                .controlSize(.small)

            Button {
                model.reload()
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .help("Reload")

            Button("Purge…", role: .destructive) {
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
            return "FreeSnitch is in Silent Allow: every connection is permitted. Insights still records, and nothing on this screen is in force."
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
                sectionTitle("Apps", subtitle: "\(model.apps.count) recorded")
                if model.apps.isEmpty && !model.isLoading {
                    emptyState("Nothing recorded in this range yet.")
                } else {
                    // A real List: system selection highlight and arrow keys.
                    // Styled as content, not as a sidebar: the only translucent
                    // band in the window is the window's own sidebar.
                    List(selection: appSelection) {
                        ForEach(model.apps) { app in
                            appRow(app)
                        }
                        if model.hasMoreApps {
                            Button("Load more apps") { model.loadMoreApps() }
                                .buttonStyle(.link)
                        }
                    }
                    .listStyle(.inset)
                }
            }
            .frame(width: 280)

            Divider()

            VStack(alignment: .leading, spacing: 0) {
                if let app = model.selectedApp {
                    sectionTitle(app.displayName,
                                 subtitle: "\(app.destinationCount) destinations, \(app.connectionCount) connections")
                    if model.destinations.isEmpty && !model.isLoading {
                        emptyState("No destinations recorded for this app in this range.")
                    } else {
                        List {
                            ForEach(model.destinations) { destination in
                                destinationRow(destination, app: app)
                            }
                            if model.hasMoreDestinations {
                                Button("Load more destinations") { model.loadMoreDestinations() }
                                    .buttonStyle(.link)
                            }
                        }
                        .listStyle(.inset)
                    }
                } else {
                    emptyState("Select an app to see what it talked to.")
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
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

    private func appRow(_ app: InsightsAppSummary) -> some View {
        HStack(spacing: 8) {
            if let icon = AppIcon.resolve(bundleId: app.processBundleId, path: app.processPath, name: app.displayName) {
                Image(nsImage: icon).resizable().frame(width: 20, height: 20)
            } else {
                Image(systemName: "app.dashed").foregroundStyle(.secondary)
            }
            VStack(alignment: .leading, spacing: 1) {
                Text(app.displayName).font(.body).lineLimit(1)
                Text("\(app.destinationCount) destinations · \(PSFormat.compactCount(app.connectionCount)) connections")
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            Text(PSFormat.bytes(app.bytesIn + app.bytesOut))
                .font(.caption).foregroundStyle(.secondary).monospacedDigit()
        }
    }

    private func destinationRow(_ destination: InsightsDestinationSummary, app: InsightsAppSummary) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Text(destination.displayName).font(.body)
                if !destination.isNameKnown {
                    PSChip("no DNS name seen", color: .orange, icon: "questionmark.circle")
                }
                Spacer()
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
                Button("Propose a rule") { model.proposeRule(for: destination, app: app) }
                    .controlSize(.small)
            }
        }
        .padding(.vertical, 4)
    }

    // MARK: Unresolved addresses

    private var unresolvedSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            sectionTitle("Addresses with no DNS answer",
                         subtitle: "\(model.unresolved.count) in this range",
                         note: InsightsUnresolvedDestination.signalWording)
            if model.unresolved.isEmpty && !model.isLoading {
                emptyState("Every recorded address had a DNS answer in this range.")
            } else {
                List {
                    ForEach(model.unresolved) { entry in
                        VStack(alignment: .leading, spacing: 3) {
                            HStack(spacing: 8) {
                                Text(entry.remoteIP).font(.body.monospaced())
                                Spacer()
                                Text("\(PSFormat.compactCount(entry.connectionCount)) connections")
                                    .font(.caption).foregroundStyle(.secondary).monospacedDigit()
                                Text(PSFormat.bytes(entry.bytesIn + entry.bytesOut))
                                    .font(.caption).foregroundStyle(.tertiary).monospacedDigit()
                            }
                            Text(entry.appNames.isEmpty
                                 ? "\(entry.appCount) app\(entry.appCount == 1 ? "" : "s")"
                                 : "reached by \(entry.appNames.joined(separator: ", "))")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        .padding(.vertical, 2)
                    }
                    if model.hasMoreUnresolved {
                        Button("Load more addresses") { model.loadMoreUnresolved() }
                            .buttonStyle(.link)
                    }
                }
                .listStyle(.inset)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    // MARK: Changed behaviour

    private var findingsSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            sectionTitle("New after update",
                         subtitle: "observed difference, not a verdict",
                         note: "These findings compare destinations observed under different offline app builds. They do not establish causation or intent. Apps without a reliable containing-app version are labelled unknown and are not guessed.")
            if model.findings.isEmpty && !model.isLoading {
                emptyState("No changed destinations in this range.")
            } else {
                List {
                    ForEach(model.findings) { finding in
                        VStack(alignment: .leading, spacing: 5) {
                            HStack(spacing: 8) {
                                Text(finding.displayName).font(.body.weight(.semibold))
                                Text(finding.versionLabel)
                                    .font(.caption.monospaced())
                                    .foregroundStyle(finding.versionKnown ? AnyShapeStyle(.secondary) : AnyShapeStyle(Color.orange))
                                Spacer()
                            }
                            HStack(spacing: 8) {
                                Text(finding.destination).font(.body)
                                PSChip(finding.wording, color: .orange, icon: "exclamationmark.magnifyingglass")
                                Text("\(finding.connectionCount) connection\(finding.connectionCount == 1 ? "" : "s")")
                                    .font(.caption).foregroundStyle(.secondary)
                                Spacer()
                            }
                            Text(finding.evidence).font(.caption).foregroundStyle(.secondary)
                            if let proposal = finding.proposedRule() {
                                Button("Propose a rule") { model.proposeRule(for: proposal) }
                                    .controlSize(.small)
                            }
                        }
                        .padding(.vertical, 4)
                    }
                }
                .listStyle(.inset)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    // MARK: Proposals

    private var proposalsSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            sectionTitle("Proposed rules",
                         subtitle: "nothing here is in force",
                         note: "Each proposal is app-specific and, wherever a name is known, scoped to that name rather than to an address. FreeSnitch never turns a proposal into a rule by itself: you accept them one at a time.")
            if let message = model.acceptMessage {
                Label(message, systemImage: "checkmark.circle")
                    .font(.callout)
                    .foregroundStyle(.green)
                    .padding(.horizontal, 12).padding(.bottom, 6)
            }
            if model.proposals.isEmpty && !model.isLoading {
                emptyState("No proposals in this range.")
            } else {
                List {
                    ForEach(model.proposals) { proposal in
                        proposalRow(proposal)
                    }
                    if model.hasMoreProposals {
                        Button("Load more proposals") { model.loadMoreProposals() }
                            .buttonStyle(.link)
                    }
                }
                .listStyle(.inset)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private func proposalRow(_ proposal: InsightsProposedRule) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 8) {
                Text("\(proposal.appDisplayName) may not reach \(proposal.destinationLabel)").font(.body)
                if proposal.isDomainScoped {
                    PSChip("domain rule", color: .green, icon: "globe")
                } else {
                    PSChip("address-pinned", color: .orange, icon: "number")
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
                    Button(proposal.requiresExplicitIPChoice
                           ? "Block this address for \(proposal.appDisplayName) anyway"
                           : "Block for \(proposal.appDisplayName)") {
                        model.accept(proposal, widened: false)
                    }
                    .controlSize(.small)

                    if proposal.isDomainScoped {
                        Button("Block for every app") { model.accept(proposal, widened: true) }
                            .controlSize(.small)
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

    private var footer: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(model.sourceNote).font(.footnote).foregroundStyle(.secondary)
            Text(model.namingNote).font(.footnote).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background(.bar)
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
        case .unresolved: return "Addresses with no DNS answer"
        case .proposals: return "Proposed rules"
        case .findings: return "New after update"
        }
    }

    /// What the segmented control shows. The full label is a sentence and would
    /// force the switcher to the width of the window; the section header below
    /// still spells it out.
    var shortLabel: String {
        switch self {
        case .apps: return "Apps"
        case .unresolved: return "Unresolved"
        case .proposals: return "Proposals"
        case .findings: return "Changed"
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
        apps = InsightsDemoData.apps
        unresolved = InsightsDemoData.unresolved
        proposals = InsightsDemoData.proposals
        findings = InsightsDemoData.findings
        if selectedApp == nil { selectedApp = apps.first }
        destinations = InsightsDemoData.destinations(for: selectedApp?.appIdentity ?? "")
    }

    func loadMoreApps() { loadApps(offset: apps.count) }
    func loadMoreDestinations() { loadDestinations(offset: destinations.count) }
    func loadMoreUnresolved() { loadUnresolved(offset: unresolved.count) }
    func loadMoreProposals() { loadProposals(offset: proposals.count) }
    func loadMoreFindings() { loadFindings(offset: findings.count) }

    private func query(_ kind: InsightsQueryKind, offset: Int, appIdentity: String? = nil) -> InsightsQuery? {
        guard offset <= Self.pageSize * Self.maximumPages else { return nil }
        let now = Date()
        return InsightsQuery(kind: kind,
                             appIdentity: appIdentity,
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
        return rules.contains { rule in
            guard rule.enabled else { return false }
            let destinationMatches: Bool
            if let domain = proposal.domain {
                destinationMatches = rule.remoteHost?.lowercased() == domain.lowercased()
            } else if let remoteIP = proposal.remoteIP {
                destinationMatches = rule.remoteIP == remoteIP || rule.remoteHost == remoteIP
            } else {
                return false
            }
            guard destinationMatches else { return false }

            // A selector-free rule is wider and therefore covers this app too.
            let hasAppSelector = rule.processBundleId != nil || rule.processPath != nil || rule.processName != nil
            guard hasAppSelector else { return true }
            if let bundle = proposal.processBundleId, rule.processBundleId == bundle { return true }
            if let path = proposal.processPath, rule.processPath == path { return true }
            return rule.processName == proposal.appDisplayName
        }
    }

    /// D2: this is the only path from a proposal to a rule, and a person is
    /// standing on it.
    func accept(_ proposal: InsightsProposedRule, widened: Bool) {
        guard let state else { return }
        let rule = widened
            ? proposal.widenedRule(profile: state.activeProfile)
            : proposal.rule(profile: state.activeProfile)
        guard let rule else {
            errorMessage = "That proposal cannot be widened, because no DNS name is known for the destination."
            return
        }
        state.helper.addRule(rule) { [weak self] ok, message in
            guard let self else { return }
            guard ok else {
                self.errorMessage = message ?? "The helper rejected the proposed rule."
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
