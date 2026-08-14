import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct RulesManagerView: View {
    @EnvironmentObject var state: AppState
    let systemExtension: SystemExtensionManager
    @State private var selectedCategory: Category = .all
    @State private var searchText: String = ""
    @State private var selectedRuleIDs: Set<UUID> = []
    @State private var sortOrder: [KeyPathComparator<Rule>] = [KeyPathComparator(\Rule.displayProcessName)]
    @State private var sidebarAcceptsSelection = false
    @State private var showingBlocklistHelp = false
    @State private var showingRuleEditor = false
    @State private var showingImporter = false
    @State private var showingExporter = false
    @State private var exportDocument = RuleJSONDocument(rules: [])
    @State private var pendingImportRules: [Rule] = []
    @State private var showingImportConfirmation = false
    @State private var pendingRemovalIDs: Set<UUID> = []
    @State private var showingRemoveConfirmation = false
    @State private var errorMessage: String?
    @State private var showingError = false
    @ObservedObject private var profileClient = ProfileClient.shared

    enum Category: Hashable {
        case all
        case active
        case deny
        case recentChanges
        case recentlyUsed
        case temporary
        case unapproved
        case group(String)
        case blocklist(UUID)
    }

    var body: some View {
        VStack(spacing: 0) {
            HelperBanner(systemExtension: systemExtension)
            HStack(spacing: 0) {
                sidebar.frame(width: 204)
                Divider()
                mainPane
                Divider()
                infoPane.frame(width: 240)
            }
        }
        .sheet(isPresented: $showingRuleEditor) {
            RuleEditorView(activeProfileName: profileClient.activeProfileName) { rule in addRule(rule) }
        }
        .fileImporter(isPresented: $showingImporter, allowedContentTypes: [.json]) { result in
            importRules(from: result)
        }
        .fileExporter(isPresented: $showingExporter,
                      document: exportDocument,
                      contentType: .json,
                      defaultFilename: "freesnitch-rules") { result in
            if case .failure(let error) = result {
                showError("Could not export rules: \(error.localizedDescription)")
            }
        }
        .confirmationDialog("Replace all rules?",
                            isPresented: $showingImportConfirmation,
                            titleVisibility: .visible) {
            Button("Replace Rules", role: .destructive) {
                replaceRules(with: pendingImportRules)
            }
            Button("Cancel", role: .cancel) { pendingImportRules.removeAll() }
        } message: {
            Text("Importing \(pendingImportRules.count) rules will replace the \(state.rules.count) rules currently in FreeSnitch.")
        }
        .confirmationDialog("Remove selected rules?",
                            isPresented: $showingRemoveConfirmation,
                            titleVisibility: .visible) {
            Button("Remove Rules", role: .destructive) {
                removeRules(withIDs: pendingRemovalIDs)
            }
            Button("Cancel", role: .cancel) { pendingRemovalIDs.removeAll() }
        } message: {
            Text("This permanently removes \(pendingRemovalIDs.count) rules from FreeSnitch.")
        }
        .alert("Rules Manager", isPresented: $showingError) {
            Button("OK", role: .cancel) { showingError = false }
        } message: {
            Text(errorMessage ?? "The requested operation could not be completed.")
        }
    }

    /// The sidebar is a real `List`, so it inherits Finder's sidebar metrics,
    /// selection, keyboard traversal and accessibility instead of imitating
    /// them with buttons and hand-drawn highlight rectangles.
    private var sidebar: some View {
        List(selection: sidebarSelection) {
            Section("Rules") {
                navRow(.all, label: "All Rules", icon: "list.bullet", count: state.rules.count)
                navRow(.active, label: "Allow", icon: "checkmark.circle.fill", color: .green, count: state.rules.filter { $0.enabled && $0.action == .allow }.count)
                navRow(.deny, label: "Deny", icon: "minus.circle.fill", color: .red, count: state.rules.filter { $0.action == .deny }.count)
                navRow(.recentChanges, label: "Recent Changes", icon: "clock.fill", count: recentChangesCount)
                navRow(.recentlyUsed, label: "Recently Used", icon: "clock.arrow.circlepath", count: state.rules.filter { $0.lastUsedAt != nil }.count)
                navRow(.temporary, label: "Temporary", icon: "hourglass", color: .orange, count: state.rules.filter { $0.temporary }.count)
                navRow(.unapproved, label: "Unapproved", icon: "questionmark.circle.fill", count: state.rules.filter { $0.action == .ask }.count)
            }

            Section("Rule Groups") {
                groupRow("iCloud Services", icon: "icloud.fill")
                groupRow("macOS Services", icon: "applelogo")
                groupRow("Apple Apps", icon: "app.gift")
                groupRow("Third Party Apps", icon: "shippingbox")
            }

            Section {
                if !state.enforcementEnabled && state.blocklists.contains(where: { $0.enabled }) {
                    Label("Enforcement is off", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                        .help(Self.enforcementOffExplanation)
                }
                ForEach(state.blocklists) { b in
                    blocklistRow(b)
                }
            } header: {
                blocklistsHeader
            }
        }
        .listStyle(.sidebar)
        .onAppear {
            DispatchQueue.main.async { sidebarAcceptsSelection = true }
        }
    }

    static let blocklistExplanation = "Blocklists filter DNS names only. They do not stop connections made to hardcoded IP addresses or names resolved by an app's own encrypted DNS, such as Chrome and Firefox DoH."
    static let enforcementOffExplanation = "Enforcement is off, so enabled blocklists are currently blocking nothing."

    /// Six lines of explanation used to sit permanently in the sidebar, which
    /// is not what a Mac app does with reference text. It now lives behind the
    /// info affordance next to the header, revealed on hover.
    private var blocklistsHeader: some View {
        HStack(spacing: 4) {
            Text("Blocklists")
            Image(systemName: "info.circle")
                .imageScale(.small)
                .foregroundStyle(.secondary)
            Spacer(minLength: 0)
        }
        .contentShape(Rectangle())
        .onHover { hovering in
            showingBlocklistHelp = hovering
        }
        // The width has to be set before fixedSize, or the text is measured
        // unwrapped and the popover clips its last lines. No .help() here: the
        // tooltip fired at the same time as the popover and the two overlapped.
        .popover(isPresented: $showingBlocklistHelp, arrowEdge: .trailing) {
            Text(Self.blocklistExplanation)
                .font(.callout)
                .frame(width: 250, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
                .padding(14)
        }
    }

    /// `List` owns selection, so category changes arrive through this binding
    /// rather than from a tap handler on every row. Rejecting nil keeps a
    /// category always selected, the way Finder never clears its sidebar.
    ///
    /// Writes are ignored until the list has appeared. Roughly one launch in
    /// three, the freshly focused outline reported a selection of its own
    /// before anyone touched it, and the window opened on "iCloud Services"
    /// instead of "All Rules". A real click cannot arrive in the same runloop
    /// pass as onAppear, so only that spurious first write is dropped.
    private var sidebarSelection: Binding<Category?> {
        Binding(
            get: { selectedCategory },
            set: { newValue in
                guard sidebarAcceptsSelection else { return }
                guard let newValue, newValue != selectedCategory else { return }
                selectCategory(newValue)
            }
        )
    }

    private func navRow(_ cat: Category, label: String, icon: String, color: Color = .accentColor, count: Int) -> some View {
        Label {
            Text(label)
        } icon: {
            Image(systemName: icon).foregroundStyle(color)
        }
        .badge(count)
        .tag(cat)
    }

    private func groupRow(_ label: String, icon: String) -> some View {
        Label {
            Text(label)
        } icon: {
            Image(systemName: icon).foregroundStyle(Color.accentColor)
        }
        .tag(Category.group(label))
        .help("Rule Groups are categories for viewing rules, not enforcement switches.")
    }

    private func blocklistRow(_ b: BlocklistInfo) -> some View {
        HStack(spacing: 8) {
            Toggle("", isOn: Binding(
                get: { b.enabled },
                set: { setBlocklist(b, enabled: $0) }
            ))
            .toggleStyle(.checkbox)
            .labelsHidden()
            .help("Enable or disable this blocklist.")
            Label {
                Text(b.name).lineLimit(1)
            } icon: {
                Image(systemName: "shield.lefthalf.filled").foregroundStyle(.red)
            }
        }
        .tag(Category.blocklist(b.id))
    }

    private var mainPane: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            rulesList
        }
    }

    /// One content bar, carrying the section title, the count and the actions,
    /// on the system bar material.
    ///
    /// It replaces a strip of borderless glyphs above a 22pt bold title that
    /// repeated what the window title bar already says. Mail and Finder put the
    /// section and its count in one bar and never restate the title in the
    /// content.
    private var toolbar: some View {
        HStack(spacing: 10) {
            Text(categoryTitle)
                .font(.headline)
                .lineLimit(1)
            Text("\(filteredRules.count)")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .monospacedDigit()
            Spacer(minLength: 12)
            NativeSearchField(text: searchBinding)
                .frame(width: 180)
            Button(action: { showingImporter = true }) {
                Image(systemName: "tray.and.arrow.down.fill")
            }
            .buttonStyle(.borderless)
            .disabled(!state.helperConnected)
            .help(state.helperConnected
                  ? "Import rules from a FreeSnitch export, or from a legacy plain JSON array. This replaces the current rules."
                  : "Approve the FreeSnitch helper before importing rules.")
            Button(action: { exportRules() }) {
                Image(systemName: "tray.and.arrow.up.fill")
            }
            .buttonStyle(.borderless)
            .disabled(state.rules.isEmpty)
            .help(state.rules.isEmpty ? "There are no rules to export." : "Export rules as a \(RuleExportDocument.formatIdentifier) document the CLI can import.")
            Button(action: { showingRuleEditor = true }) {
                Image(systemName: "plus")
            }
            .buttonStyle(.borderless)
            .disabled(!state.helperConnected)
            .help(state.helperConnected ? "Add a rule." : "Approve the FreeSnitch helper before adding rules.")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(.bar)
    }

    private var rulesList: some View {
        VStack(spacing: 0) {
            if filteredRules.isEmpty {
                emptyState
            } else {
                rulesTable
            }
        }
    }

    /// A real `Table`, which brings sortable and resizable column headers,
    /// `NSTableView` selection and keyboard traversal for free.
    ///
    /// The hand-drawn rows it replaces showed four fixed glyphs on every row
    /// (person, dot, check, cross) that were painted identically regardless of
    /// the rule, so the list could not tell you whether a rule allowed or
    /// denied anything. Those are now actual columns backed by actual fields.
    ///
    /// Only the four columns that fit the default window are shown. Direction,
    /// Scope and Priority stay in the Information pane: this window carries two
    /// sidebars plus the info pane, which leaves the table about 443pt, and
    /// each extra column pushed the total past it. The table then scrolled
    /// sideways and hid Action, which is the one column a firewall must never
    /// hide.
    ///
    /// The widths are min/max, never `ideal`: an `ideal` width is taken as the
    /// layout width rather than a hint, so the columns refused to shrink and
    /// scrolled instead.
    private var rulesTable: some View {
        Table(sortedRules, selection: $selectedRuleIDs, sortOrder: $sortOrder) {
            TableColumn("Process", value: \.displayProcessName) { rule in
                Label {
                    Text(rule.displayProcessName).lineLimit(1)
                } icon: {
                    if let icon = AppIcon.resolve(bundleId: rule.processBundleId,
                                                  path: rule.processPath,
                                                  name: rule.processName) {
                        Image(nsImage: icon).resizable().frame(width: 16, height: 16)
                    } else {
                        Image(systemName: "questionmark.app.dashed")
                            .foregroundStyle(.secondary)
                    }
                }
                .help(rule.processPath ?? rule.displayProcessName)
            }
            .width(min: 104)

            TableColumn("Destination", value: \.displayDestination) { rule in
                Text(rule.displayDestination)
                    .lineLimit(1)
                    .help(rule.displayDestination)
            }
            .width(min: 104)

            TableColumn("Action", value: \.actionSortKey) { rule in
                Label(rule.actionLabel, systemImage: rule.actionSymbol)
                    .foregroundStyle(rule.actionTint)
            }
            .width(min: 62, max: 96)

            TableColumn("Status", value: \.statusSortKey) { rule in
                Text(rule.statusLabel)
                    .foregroundStyle(rule.enabled ? AnyShapeStyle(.primary) : AnyShapeStyle(.secondary))
            }
            .width(min: 64, max: 104)
        }
    }

    private var sortedRules: [Rule] {
        filteredRules.sorted(using: sortOrder)
    }

    private var emptyState: some View {
        VStack(spacing: 10) {
            Spacer()
            Image(systemName: emptyIcon)
                .font(.system(size: 38)).foregroundStyle(.secondary)
            Text(emptyTitle)
                .font(.headline).foregroundStyle(.secondary)
            Text(emptySubtitle)
                .font(.callout).foregroundStyle(.secondary)
                .multilineTextAlignment(.center).frame(maxWidth: 360)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptyIcon: String {
        if case .blocklist = selectedCategory { return "shield.lefthalf.filled" }
        if !state.helperConnected { return "bolt.horizontal.circle" }
        return "list.bullet"
    }

    private var emptyTitle: String {
        if case .blocklist(let id) = selectedCategory {
            return state.blocklists.first(where: { $0.id == id })?.name ?? "Blocklist"
        }
        if !state.helperConnected { return "Helper not running" }
        if state.rules.isEmpty { return "No rules yet" }
        return "Nothing in \(categoryTitle)"
    }

    private var emptySubtitle: String {
        if case .blocklist(let id) = selectedCategory {
            let count = state.blocklists.first(where: { $0.id == id })?.entryCount ?? 0
            return "This blocklist contains \(count) domain entries. Enable or refresh it in Settings under Blocklists."
        }
        if !state.helperConnected {
            return "Rules are managed by the FreeSnitch helper. Approve it in System Settings under General > Login Items. This window fills in on its own once it connects."
        }
        if state.rules.isEmpty {
            return "Rules are created automatically when you allow or deny a connection alert."
        }
        return "No rules match this filter."
    }

    private var categoryTitle: String {
        switch selectedCategory {
        case .all: return "All Rules"
        case .active: return "Allow"
        case .deny: return "Deny"
        case .recentChanges: return "Recent Changes"
        case .recentlyUsed: return "Recently Used"
        case .temporary: return "Temporary"
        case .unapproved: return "Unapproved"
        case .group(let n): return n
        case .blocklist(let id): return state.blocklists.first(where: { $0.id == id })?.name ?? "Blocklist"
        }
    }

    private var recentCutoff: Date { Date().addingTimeInterval(-7 * 24 * 3600) }
    private var recentChangesCount: Int { state.rules.filter { $0.createdAt >= recentCutoff }.count }

    private var selectedRules: [Rule] {
        filteredRules.filter { selectedRuleIDs.contains($0.id) }
    }

    private var searchBinding: Binding<String> {
        Binding(
            get: { searchText },
            set: {
                searchText = $0
                clearSelection()
            }
        )
    }

    private var filteredRules: [Rule] {
        var rules = state.rules
        switch selectedCategory {
        case .all:
            break
        case .active:
            rules = rules.filter { $0.enabled && $0.action == .allow }
        case .deny:
            rules = rules.filter { $0.action == .deny }
        case .temporary:
            rules = rules.filter { $0.temporary }
        case .unapproved:
            rules = rules.filter { $0.action == .ask }
        case .recentChanges:
            rules = rules.filter { $0.createdAt >= recentCutoff }
                .sorted { $0.createdAt > $1.createdAt }
        case .recentlyUsed:
            rules = rules.filter { $0.lastUsedAt != nil }
                .sorted { ($0.lastUsedAt ?? .distantPast) > ($1.lastUsedAt ?? .distantPast) }
        case .group(let name):
            rules = rules.filter { $0.groupName == name }
        case .blocklist:
            // Blocklists are domain sets, not per-process rules; shown as info.
            rules = []
        }
        if !searchText.isEmpty {
            rules = rules.filter {
                ($0.processName ?? "").localizedCaseInsensitiveContains(searchText) ||
                ($0.remoteHost ?? "").localizedCaseInsensitiveContains(searchText)
            }
        }
        return rules
    }

    private var infoPane: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 6) {
                Text("Information").font(.headline)
                Spacer()
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(.bar)
            Divider()

            if selectedRules.count > 1 {
                multiRuleDetails(selectedRules)
            } else if let r = selectedRules.first {
                ruleDetails(r)
            } else {
                // Also a Form, so the inspector keeps one background from top
                // to bottom instead of a grouped card sitting on bare window
                // black whenever nothing is selected.
                Form {
                    Section {
                        Text("The filtering behavior of FreeSnitch is defined by the rules listed here.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        Text("Select a rule to see its details. See the FreeSnitch Help, chapter [Anatomy of a rule](https://github.com/isaaclins/freesnitch#anatomy-of-a-rule) for more information.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .formStyle(.grouped)
            }
        }
    }

    // A grouped Form scrolls itself and supplies its own group insets, so it
    // must not be wrapped in a ScrollView or given the old manual padding.
    @ViewBuilder
    private func ruleDetails(_ r: Rule) -> some View {
        Form {
            Section {
                infoField("Process", r.displayProcessName)
                if let p = r.processPath, !p.isEmpty { infoField("Path", p) }
                if let b = r.processBundleId, !b.isEmpty { infoField("Bundle ID", b) }
                infoField("Host", ruleHost(r))
                if let port = r.remotePort, port > 0 { infoField("Port", "\(port)") }
            }
            Section {
                infoField("Direction", r.directionLabel)
                infoField("Action", r.actionLabel)
                infoField("Scope", r.scopeLabel)
                infoField("Priority", "\(r.priority)")
                infoField("Applies to", r.profile == Profile.alwaysName ? "Always" : "Only in \(r.profile)")
                infoField("Status", r.statusLabel)
                infoField("Hits", "\(r.hitCount)")
                if let n = r.notes, !n.isEmpty { infoField("Notes", n) }
            }
            internetAccessPolicyDetails(for: r)
            // The actions belong inside the form. Sitting below it, they were
            // the only thing standing on the bare window background, which read
            // as a black strip pasted under the inspector.
            Section {
                HStack {
                    Button(r.enabled ? "Disable" : "Enable") { toggleRule(r) }
                    Spacer()
                    Button("Remove", role: .destructive) { removeRule(r) }
                }
            }
        }
        .formStyle(.grouped)
    }

    @ViewBuilder
    private func multiRuleDetails(_ rules: [Rule]) -> some View {
        Form {
            Section {
                infoField("Selected", "\(rules.count) rules")
            }
            summarySection("Process", items: summaryItems(rules) { $0.displayProcessName })
            summarySection("Action", items: summaryItems(rules) { $0.actionLabel })
            Section {
                HStack {
                    Button(allSelectedRulesDisabled ? "Enable" : "Disable") {
                        setRulesEnabled(!allSelectedRulesDisabled)
                    }
                    Spacer()
                    Button("Remove", role: .destructive) { removeSelectedRules() }
                }
            }
        }
        .formStyle(.grouped)
    }

    private func summarySection(_ title: String, items: [RuleSummaryItem]) -> some View {
        Section(title) {
            ForEach(items) { item in
                LabeledContent(item.label) {
                    Text("\(item.count)").monospacedDigit()
                }
            }
        }
    }

    private func summaryItems(_ rules: [Rule], by key: (Rule) -> String) -> [RuleSummaryItem] {
        Dictionary(grouping: rules, by: key)
            .map { RuleSummaryItem(label: $0.key, count: $0.value.count) }
            .sorted { $0.count > $1.count }
    }

    @ViewBuilder
    private func internetAccessPolicyDetails(for r: Rule) -> some View {
        if let policy = InternetAccessPolicyLoader.shared.policy(forProcessPath: r.processPath) {
            internetAccessPolicySection(policy, remoteHost: r.remoteHost)
        }
    }

    private func internetAccessPolicySection(_ policy: InternetAccessPolicy, remoteHost: String?) -> some View {
        let matches = policy.matchingConnections(for: remoteHost)
        return Section("Internet Access Policy") {
            if let developerName = policy.developerName, !developerName.isEmpty {
                infoField("Source", developerName)
            }
            infoField("Description", policy.applicationDescription)
            ForEach(Array(matches.enumerated()), id: \.offset) { item in
                infoField("Purpose", item.element.purpose)
                if let consequences = item.element.denyConsequences, !consequences.isEmpty {
                    infoField("If blocked", consequences)
                }
            }
        }
    }

    private func ruleHost(_ r: Rule) -> String {
        if let h = r.remoteHost, !h.isEmpty { return h }
        if let ip = r.remoteIP, !ip.isEmpty { return ip }
        return "Any"
    }

    private func infoField(_ label: String, _ value: String) -> some View {
        LabeledContent(label) {
            Text(value)
                .textSelection(.enabled)
                .multilineTextAlignment(.trailing)
                .help(value)
        }
    }

    private func selectCategory(_ category: Category) {
        selectedCategory = category
        clearSelection()
    }

    private func clearSelection() {
        selectedRuleIDs.removeAll()
    }

    private var allSelectedRulesDisabled: Bool {
        !selectedRules.isEmpty && selectedRules.allSatisfy { !$0.enabled }
    }

    private func addRule(_ rule: Rule) {
        state.helper.addRule(rule) { ok, message in
            guard ok else {
                showError("Could not add rule: \(message ?? "the helper rejected the rule")")
                return
            }
            state.refreshRules()
        }
    }

    private func importRules(from result: Result<URL, Error>) {
        guard state.helperConnected else {
            showError("Approve the FreeSnitch helper before importing rules.")
            return
        }
        do {
            let url: URL
            switch result {
            case .success(let selectedURL): url = selectedURL
            case .failure(let error):
                if (error as NSError).code == NSUserCancelledError { return }
                throw error
            }
            let accessed = url.startAccessingSecurityScopedResource()
            defer { if accessed { url.stopAccessingSecurityScopedResource() } }
            // Bound the file by its size before it is read into memory.
            let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
            try RuleExportCodec.validateEncodedSize(size)
            let data = try Data(contentsOf: url)
            // Decode and validate the whole batch before the confirmation
            // dialog appears: an import is all-or-nothing.
            pendingImportRules = try RuleExportCodec.decode(data).rules
            showingImportConfirmation = true
        } catch let error as RuleExportError {
            pendingImportRules.removeAll()
            showError("\(error.errorDescription ?? "The rule file could not be imported.") \(error.remediation)")
        } catch {
            pendingImportRules.removeAll()
            showError("Could not read the rule file: \(error.localizedDescription)")
        }
    }

    private func replaceRules(with rules: [Rule]) {
        pendingImportRules.removeAll()
        let existingRules = state.rules
        state.helper.replaceRules(rules, existing: existingRules) { ok, message in
            guard ok else {
                showError("Could not replace rules: \(message ?? "the helper rejected the import")")
                return
            }
            state.refreshRules()
            clearSelection()
        }
    }

    private func exportRules() {
        exportDocument = RuleJSONDocument(rules: state.rules)
        showingExporter = true
    }

    private func setBlocklist(_ blocklist: BlocklistInfo, enabled: Bool) {
        state.helper.setBlocklistEnabled(id: blocklist.id, enabled: enabled) { ok, message in
            guard ok else {
                showError("Could not change \(blocklist.name): \(message ?? "the helper rejected the change")")
                return
            }
            state.blocklists = state.blocklists.map { item in
                guard item.id == blocklist.id else { return item }
                var copy = item
                copy.enabled = enabled
                return copy
            }
        }
    }

    private func showError(_ message: String) {
        errorMessage = message
        showingError = true
    }

    private func toggleRule(_ r: Rule) {
        var copy = r
        copy.enabled.toggle()
        state.helper.addRule(copy) { ok, message in
            guard ok else {
                showError("Could not change the rule: \(message ?? "the helper rejected the update")")
                return
            }
            state.refreshRules()
        }
    }

    private func setRulesEnabled(_ enabled: Bool) {
        let rules = selectedRules
        guard !rules.isEmpty else { return }

        func updateNext(_ index: Int) {
            guard index < rules.count else {
                state.refreshRules()
                return
            }
            var copy = rules[index]
            copy.enabled = enabled
            state.helper.addRule(copy) { ok, message in
                if !ok {
                    showError("Could not change rule \(copy.id): \(message ?? "the helper rejected the update")")
                }
                updateNext(index + 1)
            }
        }

        updateNext(0)
    }

    private func removeRule(_ r: Rule) {
        removeRules(withIDs: [r.id])
    }

    private func removeSelectedRules() {
        let ids = Set(selectedRules.map(\.id))
        guard !ids.isEmpty else { return }
        if ids.count > 1 {
            pendingRemovalIDs = ids
            showingRemoveConfirmation = true
        } else {
            removeRules(withIDs: ids)
        }
    }

    private func removeRules(withIDs ids: Set<UUID>) {
        guard !ids.isEmpty else { return }
        let orderedIDs = Array(ids)

        func removeNext(_ index: Int) {
            guard index < orderedIDs.count else {
                pendingRemovalIDs.removeAll()
                state.refreshRules()
                clearSelection()
                return
            }
            state.helper.removeRule(id: orderedIDs[index]) { ok, message in
                if !ok {
                    showError("Could not remove rule \(orderedIDs[index]): \(message ?? "the helper rejected the removal")")
                }
                removeNext(index + 1)
            }
        }

        removeNext(0)
    }
}

/// Writes the canonical `freesnitch.rules.v1` document and reads both accepted
/// input shapes through the shared contract, so GUI and CLI backups are
/// interchangeable.
private struct RuleJSONDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.json] }

    let rules: [Rule]

    init(rules: [Rule]) {
        self.rules = rules
    }

    init(configuration: ReadConfiguration) throws {
        guard let data = configuration.file.regularFileContents else {
            throw CocoaError(.fileReadCorruptFile)
        }
        rules = try RuleExportCodec.decode(data).rules
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: try RuleExportCodec.encode(rules))
    }
}

private struct RuleEditorView: View {
    @Environment(\.dismiss) private var dismiss
    let activeProfileName: String
    let onSave: (Rule) -> Void
    /// New rules default to Always. Roughly all rules are location
    /// independent, and that default is what keeps profiles small.
    @State private var appliesTo = Profile.alwaysName
    @State private var processName = ""
    @State private var processBundleID = ""
    @State private var remoteHost = ""
    @State private var remoteIP = ""
    @State private var remotePort = ""
    @State private var direction: RuleDirection = .outgoing
    @State private var action: RuleAction = .allow
    @State private var scope: RuleScope = .domain
    @State private var enabled = true
    @State private var notes = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Add Rule")
                .font(.title2.weight(.semibold))
            Form {
                Section("Match") {
                    TextField("Process name", text: $processName)
                    TextField("Bundle ID", text: $processBundleID)
                    TextField("Host or domain", text: $remoteHost)
                    TextField("IP address", text: $remoteIP)
                    TextField("Port", text: $remotePort)
                        .onChange(of: remotePort) { value in
                            remotePort = value.filter { $0.isNumber }
                        }
                }
                Section("Decision") {
                    Picker("Direction", selection: $direction) {
                        ForEach(RuleDirection.allCases, id: \.self) { value in
                            Text(value.rawValue.capitalized).tag(value)
                        }
                    }
                    Picker("Action", selection: $action) {
                        ForEach(RuleAction.allCases, id: \.self) { value in
                            Text(value.rawValue.capitalized).tag(value)
                        }
                    }
                    Picker("Scope", selection: $scope) {
                        ForEach(RuleScope.allCases, id: \.self) { value in
                            Text(value.rawValue.capitalized).tag(value)
                        }
                    }
                    Toggle("Enabled", isOn: $enabled)
                    TextField("Notes", text: $notes)
                }
                Section("Applies to") {
                    RuleAppliesToPicker(profileName: $appliesTo, activeProfileName: activeProfileName)
                }
            }
            .formStyle(.grouped)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                Button("Add") { save() }
                    .buttonStyle(.borderedProminent)
                    .disabled(!canSave)
            }
        }
        .padding(20)
        .frame(width: 470, height: 520)
    }

    private var canSave: Bool {
        let hasMatch = [processName, processBundleID, remoteHost, remoteIP]
            .contains { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        return hasMatch || !remotePort.isEmpty
    }

    private func save() {
        let rule = Rule(
            processBundleId: optionalValue(processBundleID),
            processName: optionalValue(processName),
            remoteHost: optionalValue(remoteHost),
            remoteIP: optionalValue(remoteIP),
            remotePort: Int(remotePort),
            direction: direction,
            action: action,
            scope: scope,
            profile: appliesTo,
            notes: optionalValue(notes),
            enabled: enabled
        )
        onSave(rule)
        dismiss()
    }

    private func optionalValue(_ value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}

private struct RuleSummaryItem: Identifiable {
    let label: String
    let count: Int
    var id: String { label }
}

/// Display and sort keys for the rules `Table`.
///
/// These live next to the table rather than on the shared `Rule` model,
/// because they are presentation concerns and the model is also compiled into
/// the helper, the extension and the CLI.
extension Rule {
    var displayProcessName: String { processName ?? "Any Process" }

    var displayDestination: String {
        if let host = remoteHost, !host.isEmpty { return host }
        if let ip = remoteIP, !ip.isEmpty { return ip }
        if let port = remotePort, port > 0 { return "Port \(port)" }
        if let notes, !notes.isEmpty { return notes }
        return "Any"
    }

    var directionLabel: String { direction.rawValue.capitalized }
    var scopeLabel: String { scope.rawValue.capitalized }

    var actionLabel: String {
        switch action {
        case .allow: return "Allow"
        case .deny: return "Deny"
        case .ask: return "Ask"
        }
    }

    var actionSymbol: String {
        switch action {
        case .allow: return "checkmark.circle.fill"
        case .deny: return "minus.circle.fill"
        case .ask: return "questionmark.circle.fill"
        }
    }

    var actionTint: Color {
        switch action {
        case .allow: return .green
        case .deny: return .red
        case .ask: return .orange
        }
    }

    /// Sorting an action column alphabetically would interleave Allow and Ask.
    /// Deny first is the order that matters when auditing a firewall.
    var actionSortKey: Int {
        switch action {
        case .deny: return 0
        case .ask: return 1
        case .allow: return 2
        }
    }

    var statusLabel: String {
        if !enabled { return "Disabled" }
        if temporary { return "Temporary" }
        return "Enabled"
    }

    var statusSortKey: Int {
        if !enabled { return 0 }
        if temporary { return 1 }
        return 2
    }
}
