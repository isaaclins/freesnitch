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
            header
            enforcementBanner
            behaviourBanner
            Divider().background(PSTheme.stroke)
            content
            Divider().background(PSTheme.stroke)
            footer
        }
        .background(PSTheme.bgPrimary)
        .onAppear { model.attach(state) }
        .alert("Delete all Insights history?", isPresented: $model.confirmingPurge) {
            Button("Cancel", role: .cancel) {}
            Button("Delete everything", role: .destructive) { model.purge() }
        } message: {
            Text("This removes every recorded connection, every DNS answer and every daily rollup, including the database write-ahead log. It cannot be undone.")
        }
    }

    // MARK: Header

    private var header: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Insights").font(.system(size: 15, weight: .semibold))
                    .foregroundColor(PSTheme.textPrimary)
                Text("What each app talked to, and what you could do about it.")
                    .font(.system(size: 11)).foregroundColor(PSTheme.textMuted)
            }
            Spacer()
            Picker("", selection: $model.range) {
                ForEach(InsightsRange.allCases) { range in
                    Text(range.label).tag(range)
                }
            }
            .pickerStyle(.menu)
            .frame(width: 150)
            .onChange(of: model.range) { _ in model.reload() }

            Toggle("Recording", isOn: Binding(get: { model.recordingEnabled },
                                              set: { model.setRecording($0) }))
                .toggleStyle(.switch)
                .font(.system(size: 11))
                .foregroundColor(PSTheme.textSecondary)

            Button {
                model.reload()
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .buttonStyle(.plain)
            .foregroundColor(PSTheme.textSecondary)
            .help("Reload")

            Button(role: .destructive) {
                model.confirmingPurge = true
            } label: {
                Text("Purge…").font(.system(size: 11, weight: .semibold))
            }
            .foregroundColor(PSTheme.accentRed)
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
    }

    /// D9's non-negotiable sentence. If nothing is being blocked, say so here,
    /// not somewhere in Settings.
    @ViewBuilder private var enforcementBanner: some View {
        if let message = notBlockingMessage {
            HStack(spacing: 8) {
                Image(systemName: "exclamationmark.shield")
                    .foregroundColor(PSTheme.accentYellow)
                Text(message)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(PSTheme.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer()
            }
            .padding(.horizontal, 14).padding(.vertical, 8)
            .background(PSTheme.accentYellow.opacity(0.12))
        }
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

    private var behaviourBanner: some View {
        Group {
            if !model.findings.isEmpty {
                HStack(spacing: 8) {
                    Image(systemName: "arrow.triangle.2.circlepath").foregroundColor(PSTheme.accentYellow)
                    Text("\(model.changedAppCount) app\(model.changedAppCount == 1 ? "" : "s") changed behaviour after updating")
                        .font(.system(size: 11, weight: .medium)).foregroundColor(PSTheme.textPrimary)
                    Spacer()
                }
                .padding(.horizontal, 14).padding(.vertical, 7)
                .background(PSTheme.accentYellow.opacity(0.12))
            }
        }
    }

    // MARK: Sections

    private var content: some View {
        VStack(spacing: 0) {
            Picker("", selection: $model.section) {
                ForEach(InsightsSection.allCases) { section in
                    Text(section.label).tag(section)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .padding(.horizontal, 14).padding(.vertical, 8)
            .onChange(of: model.section) { _ in model.reload() }

            if let error = model.errorMessage {
                errorRow(error)
            }

            switch model.section {
            case .apps: appsSection
            case .unresolved: unresolvedSection
            case .proposals: proposalsSection
            case .findings: findingsSection
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func errorRow(_ message: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "exclamationmark.triangle").foregroundColor(PSTheme.accentRed)
            Text(message).font(.system(size: 11)).foregroundColor(PSTheme.textPrimary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer()
        }
        .padding(.horizontal, 14).padding(.vertical, 6)
        .background(PSTheme.accentRed.opacity(0.12))
    }

    // MARK: Apps and their destinations

    private var appsSection: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 0) {
                sectionTitle("Apps", subtitle: "\(model.apps.count) recorded")
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(model.apps) { app in
                            appRow(app)
                        }
                        if model.hasMoreApps {
                            Button("Load more apps") { model.loadMoreApps() }
                                .buttonStyle(.plain)
                                .font(.system(size: 11))
                                .foregroundColor(PSTheme.accentBlue)
                                .padding(8)
                        }
                        if model.apps.isEmpty && !model.isLoading {
                            emptyRow("Nothing recorded in this range yet.")
                        }
                    }
                }
            }
            .frame(width: 300)
            .background(PSTheme.bgSidebar)

            Divider().background(PSTheme.stroke)

            VStack(alignment: .leading, spacing: 0) {
                if let app = model.selectedApp {
                    sectionTitle(app.displayName,
                                 subtitle: "\(app.destinationCount) destinations, \(app.connectionCount) connections")
                    ScrollView {
                        LazyVStack(spacing: 0) {
                            ForEach(model.destinations) { destination in
                                destinationRow(destination, app: app)
                            }
                            if model.hasMoreDestinations {
                                Button("Load more destinations") { model.loadMoreDestinations() }
                                    .buttonStyle(.plain)
                                    .font(.system(size: 11))
                                    .foregroundColor(PSTheme.accentBlue)
                                    .padding(8)
                            }
                            if model.destinations.isEmpty && !model.isLoading {
                                emptyRow("No destinations recorded for this app in this range.")
                            }
                        }
                    }
                } else {
                    emptyRow("Select an app to see what it talked to.")
                    Spacer()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
    }

    private func appRow(_ app: InsightsAppSummary) -> some View {
        let selected = model.selectedApp?.appIdentity == app.appIdentity
        return HStack(spacing: 8) {
            if let icon = AppIcon.resolve(bundleId: app.processBundleId, path: app.processPath, name: app.displayName) {
                Image(nsImage: icon).resizable().frame(width: 20, height: 20)
            } else {
                Image(systemName: "app.dashed").foregroundColor(PSTheme.textMuted)
            }
            VStack(alignment: .leading, spacing: 1) {
                Text(app.displayName).font(.system(size: 12, weight: .medium))
                    .foregroundColor(PSTheme.textPrimary).lineLimit(1)
                Text("\(app.destinationCount) destinations · \(PSFormat.compactCount(app.connectionCount)) connections")
                    .font(.system(size: 10)).foregroundColor(PSTheme.textMuted).lineLimit(1)
            }
            Spacer()
            Text(PSFormat.bytes(app.bytesIn + app.bytesOut))
                .font(.system(size: 10)).foregroundColor(PSTheme.textSecondary)
        }
        .padding(.horizontal, 10).padding(.vertical, 6)
        .background(selected ? PSTheme.accent.opacity(0.18) : Color.clear)
        .contentShape(Rectangle())
        .onTapGesture { model.select(app) }
    }

    private func destinationRow(_ destination: InsightsDestinationSummary, app: InsightsAppSummary) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Text(destination.displayName)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(PSTheme.textPrimary)
                if !destination.isNameKnown {
                    PSChip("no DNS name seen", color: PSTheme.accentYellow, icon: "questionmark.circle")
                }
                Spacer()
                Text("\(PSFormat.compactCount(destination.connectionCount)) connections")
                    .font(.system(size: 10)).foregroundColor(PSTheme.textSecondary)
                Text(PSFormat.bytes(destination.bytesIn + destination.bytesOut))
                    .font(.system(size: 10)).foregroundColor(PSTheme.textMuted)
            }
            HStack(spacing: 8) {
                if let note = destination.correlationNote {
                    PSChip(note, color: PSTheme.accentBlue, icon: "person.2")
                }
                if destination.isNameKnown, let ip = destination.remoteIP {
                    Text(ip).font(.system(size: 10, design: .monospaced))
                        .foregroundColor(PSTheme.textMuted)
                }
                Spacer()
                Button("Propose a rule") { model.proposeRule(for: destination, app: app) }
                    .buttonStyle(.plain)
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundColor(PSTheme.accentBlue)
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background(PSTheme.bgRow.opacity(0.5))
        .overlay(Divider().background(PSTheme.stroke), alignment: .bottom)
    }

    // MARK: Unresolved addresses

    private var unresolvedSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            sectionTitle("Addresses with no DNS answer",
                         subtitle: "\(model.unresolved.count) in this range")
            Text(InsightsUnresolvedDestination.signalWording)
                .font(.system(size: 11)).foregroundColor(PSTheme.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal, 14).padding(.bottom, 8)
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(model.unresolved) { entry in
                        VStack(alignment: .leading, spacing: 3) {
                            HStack(spacing: 8) {
                                Text(entry.remoteIP)
                                    .font(.system(size: 12, weight: .medium, design: .monospaced))
                                    .foregroundColor(PSTheme.textPrimary)
                                Spacer()
                                Text("\(PSFormat.compactCount(entry.connectionCount)) connections")
                                    .font(.system(size: 10)).foregroundColor(PSTheme.textSecondary)
                                Text(PSFormat.bytes(entry.bytesIn + entry.bytesOut))
                                    .font(.system(size: 10)).foregroundColor(PSTheme.textMuted)
                            }
                            Text(entry.appNames.isEmpty
                                 ? "\(entry.appCount) app\(entry.appCount == 1 ? "" : "s")"
                                 : "reached by \(entry.appNames.joined(separator: ", "))")
                                .font(.system(size: 10)).foregroundColor(PSTheme.textMuted)
                        }
                        .padding(.horizontal, 14).padding(.vertical, 8)
                        .overlay(Divider().background(PSTheme.stroke), alignment: .bottom)
                    }
                    if model.unresolved.isEmpty && !model.isLoading {
                        emptyRow("Every recorded address had a DNS answer in this range.")
                    }
                    if model.hasMoreUnresolved {
                        Button("Load more addresses") { model.loadMoreUnresolved() }
                            .buttonStyle(.plain)
                            .font(.system(size: 11))
                            .foregroundColor(PSTheme.accentBlue)
                            .padding(8)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    // MARK: Changed behaviour

    private var findingsSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            sectionTitle("New after update", subtitle: "observed difference, not a verdict")
            Text("These findings compare destinations observed under different offline app builds. They do not establish causation or intent. Apps without a reliable containing-app version are labelled unknown and are not guessed.")
                .font(.system(size: 11)).foregroundColor(PSTheme.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal, 14).padding(.bottom, 8)
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(model.findings) { finding in
                        VStack(alignment: .leading, spacing: 5) {
                            HStack(spacing: 8) {
                                Text(finding.displayName).font(.system(size: 12, weight: .semibold))
                                    .foregroundColor(PSTheme.textPrimary)
                                Text(finding.versionLabel).font(.system(size: 10, design: .monospaced))
                                    .foregroundColor(finding.versionKnown ? PSTheme.textSecondary : PSTheme.accentYellow)
                                Spacer()
                            }
                            HStack(spacing: 8) {
                                Text(finding.destination).font(.system(size: 12, weight: .medium))
                                    .foregroundColor(PSTheme.textPrimary)
                                PSChip(finding.wording, color: PSTheme.accentYellow, icon: "exclamationmark.magnifyingglass")
                                Text("\(finding.connectionCount) connection\(finding.connectionCount == 1 ? "" : "s")")
                                    .font(.system(size: 10)).foregroundColor(PSTheme.textSecondary)
                                Spacer()
                            }
                            Text(finding.evidence).font(.system(size: 10)).foregroundColor(PSTheme.textMuted)
                            if let proposal = finding.proposedRule() {
                                Button("Propose a rule") { model.proposeRule(for: proposal) }
                                    .font(.system(size: 10, weight: .semibold))
                            }
                        }
                        .padding(.horizontal, 14).padding(.vertical, 9)
                        .overlay(Divider().background(PSTheme.stroke), alignment: .bottom)
                    }
                    if model.findings.isEmpty && !model.isLoading { emptyRow("No changed destinations in this range.") }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    // MARK: Proposals

    private var proposalsSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            sectionTitle("Proposed rules", subtitle: "nothing here is in force")
            Text("Each proposal is app-specific and, wherever a name is known, scoped to that name rather than to an address. FreeSnitch never turns a proposal into a rule by itself: you accept them one at a time.")
                .font(.system(size: 11)).foregroundColor(PSTheme.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal, 14).padding(.bottom, 8)
            if let message = model.acceptMessage {
                Text(message).font(.system(size: 11)).foregroundColor(PSTheme.accentGreen)
                    .padding(.horizontal, 14).padding(.bottom, 6)
            }
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(model.proposals) { proposal in
                        proposalRow(proposal)
                    }
                    if model.proposals.isEmpty && !model.isLoading {
                        emptyRow("No proposals in this range.")
                    }
                    if model.hasMoreProposals {
                        Button("Load more proposals") { model.loadMoreProposals() }
                            .buttonStyle(.plain)
                            .font(.system(size: 11))
                            .foregroundColor(PSTheme.accentBlue)
                            .padding(8)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private func proposalRow(_ proposal: InsightsProposedRule) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 8) {
                Text("\(proposal.appDisplayName) may not reach \(proposal.destinationLabel)")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(PSTheme.textPrimary)
                if proposal.isDomainScoped {
                    PSChip("domain rule", color: PSTheme.accentGreen, icon: "globe")
                } else {
                    PSChip("address-pinned", color: PSTheme.accentYellow, icon: "number")
                }
                if proposal.otherAppCount > 0 {
                    PSChip("also contacted by \(proposal.otherAppCount) other app\(proposal.otherAppCount == 1 ? "" : "s")",
                           color: PSTheme.accentBlue, icon: "person.2")
                }
                Spacer()
            }
            Text(proposal.evidence)
                .font(.system(size: 10)).foregroundColor(PSTheme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            if proposal.requiresExplicitIPChoice {
                Text("No DNS name was ever seen for this address, so this rule can only pin the address itself. Addresses rotate, and a pinned rule silently stops matching when they do. Accept it only if you want that.")
                    .font(.system(size: 10)).foregroundColor(PSTheme.accentYellow)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack(spacing: 10) {
                if model.accepted.contains(proposal.id) {
                    Label("Added to your rules", systemImage: "checkmark.circle")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundColor(PSTheme.accentGreen)
                } else {
                    Button(proposal.requiresExplicitIPChoice
                           ? "Block this address for \(proposal.appDisplayName) anyway"
                           : "Block for \(proposal.appDisplayName)") {
                        model.accept(proposal, widened: false)
                    }
                    .font(.system(size: 10, weight: .semibold))

                    if proposal.isDomainScoped {
                        Button("Block for every app") { model.accept(proposal, widened: true) }
                            .font(.system(size: 10))
                    }
                }
                Spacer()
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 9)
        .overlay(Divider().background(PSTheme.stroke), alignment: .bottom)
    }

    // MARK: Shared pieces

    private func sectionTitle(_ title: String, subtitle: String) -> some View {
        HStack(spacing: 6) {
            Text(title).font(.system(size: 12, weight: .semibold)).foregroundColor(PSTheme.textPrimary)
            Text(subtitle).font(.system(size: 10)).foregroundColor(PSTheme.textMuted)
            Spacer()
            if model.isLoading { ProgressView().controlSize(.small) }
        }
        .padding(.horizontal, 14).padding(.vertical, 8)
    }

    private func emptyRow(_ text: String) -> some View {
        Text(text).font(.system(size: 11)).foregroundColor(PSTheme.textMuted)
            .padding(.horizontal, 14).padding(.vertical, 10)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(model.sourceNote).font(.system(size: 10)).foregroundColor(PSTheme.textMuted)
            Text(model.namingNote).font(.system(size: 10)).foregroundColor(PSTheme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 14).padding(.vertical, 8)
        .background(PSTheme.bgSecondary)
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
        loadDestinations(offset: 0)
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
