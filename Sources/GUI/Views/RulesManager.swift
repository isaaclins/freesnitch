import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct RulesManagerView: View {
    @EnvironmentObject var state: AppState
    let systemExtension: SystemExtensionManager
    @State private var selectedCategory: Category = .all
    @State private var searchText: String = ""
    @State private var selectedRuleIDs: Set<UUID> = []
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
                sidebar.frame(width: 220).background(PSTheme.bgSidebar)
                Divider().background(PSTheme.stroke)
                mainPane
                Divider().background(PSTheme.stroke)
                infoPane.frame(width: 240).background(PSTheme.bgSecondary)
            }
        }
        .background(PSTheme.bgPrimary)
        .preferredColorScheme(.dark)
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

    private var sidebar: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 2) {
                sidebarHeader("Rules")
                navRow(.all, label: "All Rules", icon: "list.bullet", count: state.rules.count)
                navRow(.active, label: "Active", icon: "checkmark.circle.fill", color: PSTheme.accentGreen, count: state.rules.filter { $0.enabled && $0.action == .allow }.count)
                navRow(.deny, label: "Deny", icon: "minus.circle.fill", color: PSTheme.accentRed, count: state.rules.filter { $0.action == .deny }.count)
                navRow(.recentChanges, label: "Recent Changes", icon: "clock.fill", count: recentChangesCount)
                navRow(.recentlyUsed, label: "Recently Used", icon: "clock.arrow.circlepath", count: state.rules.filter { $0.lastUsedAt != nil }.count)
                navRow(.temporary, label: "Temporary", icon: "hourglass", color: PSTheme.accentYellow, count: state.rules.filter { $0.temporary }.count)
                navRow(.unapproved, label: "Unapproved", icon: "questionmark.circle.fill", count: state.rules.filter { $0.action == .ask }.count, badge: true)

                sidebarHeader("Rule Groups").padding(.top, 8)
                Text("Categories only")
                    .font(.system(size: 10))
                    .foregroundColor(PSTheme.textMuted)
                    .padding(.horizontal, 10)
                groupRow("iCloud Services", icon: "icloud.fill")
                groupRow("macOS Services", icon: "applelogo")
                groupRow("Apple Apps", icon: "app.gift")
                groupRow("Third Party Apps", icon: "shippingbox")

                sidebarHeader("Blocklists").padding(.top, 8)
                Text("Blocklists filter DNS names only. They do not stop connections made to hardcoded IP addresses or names resolved by an app's own encrypted DNS, such as Chrome and Firefox DoH.")
                    .font(.system(size: 10))
                    .foregroundColor(PSTheme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 10)
                if !state.enforcementEnabled && state.blocklists.contains(where: { $0.enabled }) {
                    Text("Enforcement is off, so enabled blocklists are currently blocking nothing.")
                        .font(.system(size: 10))
                        .foregroundColor(PSTheme.textMuted)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.horizontal, 10)
                }
                ForEach(state.blocklists) { b in
                    blocklistRow(b)
                }
            }
            .padding(.vertical, 6)
        }
    }

    private func sidebarHeader(_ s: String) -> some View {
        HStack {
            Text(s).font(.system(size: 11, weight: .semibold)).foregroundColor(PSTheme.textMuted)
            Spacer()
        }.padding(.horizontal, 10).padding(.top, 6)
    }

    private func navRow(_ cat: Category, label: String, icon: String, color: Color = PSTheme.accentBlue, count: Int, badge: Bool = false) -> some View {
        Button(action: { selectCategory(cat) }) {
            HStack(spacing: 8) {
                Image(systemName: icon).foregroundColor(color)
                    .font(.system(size: 12)).frame(width: 16)
                Text(label).font(.system(size: 12)).foregroundColor(PSTheme.textPrimary)
                Spacer()
                if count > 0 {
                    Text("\(count)").font(.system(size: 10, weight: .semibold))
                        .padding(.horizontal, 6).padding(.vertical, 1)
                        .foregroundColor(.white)
                        .background(badge ? PSTheme.accentBlue : PSTheme.bgTertiary)
                        .clipShape(Capsule())
                }
            }
            .padding(.horizontal, 10).padding(.vertical, 4)
            .background(selectedCategory == cat ? PSTheme.accent.opacity(0.18) : Color.clear)
            .clipShape(RoundedRectangle(cornerRadius: 5))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func groupRow(_ label: String, icon: String) -> some View {
        Button(action: { selectCategory(.group(label)) }) {
            HStack(spacing: 8) {
                Image(systemName: icon).foregroundColor(PSTheme.accent).frame(width: 16)
                Text(label).font(.system(size: 12)).foregroundColor(PSTheme.textPrimary)
                Spacer()
            }
            .padding(.horizontal, 10).padding(.vertical, 3)
            .background(selectedCategory == .group(label) ? PSTheme.accent.opacity(0.18) : Color.clear)
            .clipShape(RoundedRectangle(cornerRadius: 5))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Rule Groups are categories for viewing rules, not enforcement switches.")
    }

    private func blocklistRow(_ b: BlocklistInfo) -> some View {
        Button(action: { selectCategory(.blocklist(b.id)) }) {
            HStack(spacing: 8) {
                Toggle("", isOn: Binding(
                    get: { b.enabled },
                    set: { setBlocklist(b, enabled: $0) }
                ))
                .toggleStyle(.checkbox)
                .controlSize(.mini)
                .labelsHidden()
                Image(systemName: "shield.lefthalf.filled").foregroundColor(PSTheme.accentRed).frame(width: 16)
                Text(b.name).font(.system(size: 12)).foregroundColor(PSTheme.textPrimary).lineLimit(1)
                Spacer()
            }
            .padding(.horizontal, 10).padding(.vertical, 3)
            .background(selectedCategory == .blocklist(b.id) ? PSTheme.accent.opacity(0.18) : Color.clear)
            .clipShape(RoundedRectangle(cornerRadius: 5))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Enable or disable this blocklist.")
    }

    private var mainPane: some View {
        VStack(spacing: 0) {
            toolbar
            Divider().background(PSTheme.stroke)
            rulesList
        }
    }

    private var toolbar: some View {
        HStack(spacing: 10) {
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass").foregroundColor(PSTheme.textMuted).font(.system(size: 11))
                TextField("Search", text: searchBinding).textFieldStyle(.plain).foregroundColor(PSTheme.textPrimary)
            }
            .padding(.horizontal, 10).padding(.vertical, 5)
            .background(PSTheme.bgTertiary)
            .clipShape(RoundedRectangle(cornerRadius: 6))
            Spacer()
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
        .padding(8)
        .foregroundColor(PSTheme.textSecondary)
    }

    private var rulesList: some View {
        VStack(spacing: 0) {
            HStack {
                Text(categoryTitle).font(.system(size: 22, weight: .bold)).foregroundColor(PSTheme.textPrimary)
                Text("\(filteredRules.count) rules").font(.system(size: 11)).foregroundColor(PSTheme.textMuted)
                Spacer()
            }.padding(.horizontal, 14).padding(.vertical, 10)

            HStack {
                Text("Process").font(.system(size: 10, weight: .semibold)).foregroundColor(PSTheme.textMuted)
                Spacer()
                Text("Rule").font(.system(size: 10, weight: .semibold)).foregroundColor(PSTheme.textMuted)
            }
            .padding(.horizontal, 14)

            Divider().background(PSTheme.stroke)

            if filteredRules.isEmpty {
                emptyState
            } else {
                List(selection: $selectedRuleIDs) {
                    ForEach(Array(filteredRules.enumerated()), id: \.element.id) { idx, r in
                        RuleRowView(rule: r, alt: idx % 2 == 1, selected: selectedRuleIDs.contains(r.id))
                            .contentShape(Rectangle())
                            .tag(r.id)
                            .listRowInsets(EdgeInsets())
                            .listRowBackground(Color.clear)
                            .listRowSeparator(.hidden)
                    }
                }
                .listStyle(.plain)
                .scrollContentBackground(.hidden)
                .tint(PSTheme.accent)
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 10) {
            Spacer()
            Image(systemName: emptyIcon)
                .font(.system(size: 38)).foregroundColor(PSTheme.textMuted)
            Text(emptyTitle)
                .font(.system(size: 15, weight: .semibold)).foregroundColor(PSTheme.textSecondary)
            Text(emptySubtitle)
                .font(.system(size: 12)).foregroundColor(PSTheme.textMuted)
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
        case .active: return "Active"
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
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "info.circle.fill").foregroundColor(PSTheme.accentBlue)
                Text("Information").font(.system(size: 14, weight: .semibold)).foregroundColor(PSTheme.textPrimary)
                Spacer()
            }
            if selectedRules.count > 1 {
                multiRuleDetails(selectedRules)
            } else if let r = selectedRules.first {
                ruleDetails(r)
            } else {
                Text("The filtering behavior of FreeSnitch is defined by the rules listed here.")
                    .font(.system(size: 12)).foregroundColor(PSTheme.textSecondary)
                Text("Select a rule to see its details. See the FreeSnitch Help, chapter [Anatomy of a rule](https://github.com/isaaclins/freesnitch#anatomy-of-a-rule) for more information.")
                    .font(.system(size: 11)).foregroundColor(PSTheme.textMuted)
                Spacer()
            }
        }
        .padding(14)
    }

    @ViewBuilder
    private func ruleDetails(_ r: Rule) -> some View {
        Divider().background(PSTheme.stroke)
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                infoField("Process", r.processName ?? "Any Process")
                if let p = r.processPath, !p.isEmpty { infoField("Path", p) }
                if let b = r.processBundleId, !b.isEmpty { infoField("Bundle ID", b) }
                infoField("Host", ruleHost(r))
                if let port = r.remotePort, port > 0 { infoField("Port", "\(port)") }
                infoField("Direction", r.direction.rawValue.capitalized)
                infoField("Action", r.action.rawValue.capitalized)
                infoField("Scope", r.scope.rawValue.capitalized)
                infoField("Priority", "\(r.priority)")
                infoField("Applies to", r.profile == Profile.alwaysName ? "Always" : "Only in \(r.profile)")
                infoField("Status", r.enabled ? "Enabled" : "Disabled")
                infoField("Hits", "\(r.hitCount)")
                if let n = r.notes, !n.isEmpty { infoField("Notes", n) }
                internetAccessPolicyDetails(for: r)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        HStack {
            Button(r.enabled ? "Disable" : "Enable") { toggleRule(r) }
                .buttonStyle(.bordered)
            Spacer()
            Button(role: .destructive) { removeRule(r) } label: { Text("Remove") }
                .buttonStyle(.borderedProminent).tint(.red)
        }
    }

    @ViewBuilder
    private func multiRuleDetails(_ rules: [Rule]) -> some View {
        Divider().background(PSTheme.stroke)
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                PSChip("\(rules.count) selected", color: PSTheme.accentBlue, icon: "checkmark.circle")
                summarySection("Process", items: summaryItems(rules) { $0.processName ?? "Any Process" })
                summarySection("Action", items: summaryItems(rules) { $0.action.rawValue.capitalized })
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        HStack {
            Button(allSelectedRulesDisabled ? "Enable" : "Disable") {
                setRulesEnabled(!allSelectedRulesDisabled)
            }
            .buttonStyle(.bordered)
            Spacer()
            Button(role: .destructive) { removeSelectedRules() } label: { Text("Remove") }
                .buttonStyle(.borderedProminent).tint(.red)
        }
    }

    private func summarySection(_ title: String, items: [RuleSummaryItem]) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.system(size: 10, weight: .semibold)).foregroundColor(PSTheme.textMuted)
            ForEach(items) { item in
                HStack(spacing: 6) {
                    Text(item.label).font(.system(size: 12)).foregroundColor(PSTheme.textPrimary)
                        .lineLimit(1)
                    Spacer(minLength: 4)
                    Text("\(item.count)").font(.system(size: 11, weight: .semibold))
                        .foregroundColor(PSTheme.textSecondary)
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
        return VStack(alignment: .leading, spacing: 8) {
            Divider().background(PSTheme.stroke)
            Text("Internet Access Policy")
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(PSTheme.accentBlue)
            if let developerName = policy.developerName, !developerName.isEmpty {
                infoField("Source", developerName)
            }
            infoField("Description", policy.applicationDescription)
            ForEach(Array(matches.enumerated()), id: \.offset) { item in
                VStack(alignment: .leading, spacing: 4) {
                    infoField("Purpose", item.element.purpose)
                    if let consequences = item.element.denyConsequences, !consequences.isEmpty {
                        infoField("If blocked", consequences)
                    }
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
        VStack(alignment: .leading, spacing: 1) {
            Text(label).font(.system(size: 10, weight: .semibold)).foregroundColor(PSTheme.textMuted)
            Text(value).font(.system(size: 12)).foregroundColor(PSTheme.textPrimary)
                .textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
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
                .foregroundColor(PSTheme.textPrimary)
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
        .background(PSTheme.bgPrimary)
        .preferredColorScheme(.dark)
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

struct RuleRowView: View {
    let rule: Rule
    let alt: Bool
    let selected: Bool

    var body: some View {
        HStack(spacing: 8) {
            if let icon = AppIcon.resolve(bundleId: rule.processBundleId, path: rule.processPath, name: rule.processName) {
                Image(nsImage: icon).resizable().frame(width: 16, height: 16)
            } else {
                Image(systemName: "person.crop.circle.dashed").foregroundColor(PSTheme.textSecondary)
                    .frame(width: 16)
            }
            Text(rule.processName ?? "Any Process").font(.system(size: 12)).foregroundColor(PSTheme.textPrimary)
                .lineLimit(1)
                .frame(width: 160, alignment: .leading)

            HStack(spacing: 6) {
                actionIcons
                if let n = ruleCount {
                    Text(n).font(.system(size: 10, weight: .semibold))
                        .padding(.horizontal, 6).padding(.vertical, 1)
                        .background(PSTheme.bgTertiary)
                        .clipShape(Capsule())
                        .foregroundColor(PSTheme.textSecondary)
                }
                Image(systemName: "exclamationmark.shield.fill")
                    .foregroundColor(PSTheme.accentRed)
                    .font(.system(size: 11))
                Text(rule.notes ?? rule.remoteHost ?? "")
                    .font(.system(size: 12))
                    .foregroundColor(PSTheme.textPrimary)
                Spacer()
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 6)
        .background(selected ? PSTheme.accent.opacity(0.18) : (alt ? PSTheme.bgRowAlt : PSTheme.bgRow))
    }

    private var actionIcons: some View {
        HStack(spacing: 3) {
            iconCell(systemName: "person.fill", color: PSTheme.textSecondary)
            iconCell(systemName: "circle.fill", color: PSTheme.accentBlue)
            iconCell(systemName: "checkmark", color: PSTheme.accentGreen)
            iconCell(systemName: "xmark", color: PSTheme.accentRed)
        }
    }

    private func iconCell(systemName: String, color: Color) -> some View {
        ZStack {
            RoundedRectangle(cornerRadius: 3).fill(PSTheme.bgTertiary).frame(width: 14, height: 14)
            Image(systemName: systemName).font(.system(size: 8, weight: .bold)).foregroundColor(color)
        }
    }

    private var ruleCount: String? {
        if let host = rule.remoteHost, host.allSatisfy({ $0.isNumber || $0 == "," }) {
            return host
        }
        if rule.priority > 0 { return "\(rule.priority)" }
        return nil
    }
}
