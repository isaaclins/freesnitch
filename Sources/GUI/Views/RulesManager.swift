import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct RulesManagerView: View {
    @EnvironmentObject var state: AppState
    let systemExtension: SystemExtensionManager
    @State private var selectedCategory: Category = .all
    /// The window's shared state: the search query, whichever field owns it,
    /// and the Find command's focus token.
    @ObservedObject var window: MainWindowModel
    @State private var selectedRuleIDs: Set<UUID> = []
    @State private var sortOrder: [KeyPathComparator<Rule>] = [KeyPathComparator(\Rule.displayProcessName)]
    @State private var sidebarAcceptsSelection = false
    @State private var showingBlocklistHelp = false
    /// Pending hover-open for the blocklist popover, cancelled when the pointer
    /// leaves before the dwell elapses.
    @State private var blocklistHelpHover: DispatchWorkItem?
    @State private var showingRuleEditor = false
    @State private var showingImporter = false
    @State private var showingExporter = false
    @State private var exportDocument = RuleJSONDocument(rules: [])
    @State private var pendingImportRules: [Rule] = []
    @State private var showingImportConfirmation = false
    @State private var pendingRemovalIDs: Set<UUID> = []
    @State private var showingRemoveConfirmation = false
    @State private var errorTitle = ""
    @State private var errorMessage: String?
    @State private var showingError = false
    /// The list being edited, if any (#97).
    @State private var editingBlocklist: BlocklistInfo?
    @State private var showingAddBlocklist = false
    /// Which pane owns the keyboard. Tab moves it, and the focused list shows
    /// the focused selection colour instead of the unfocused grey (#85).
    @FocusState private var focusedPane: RulesPane?
    /// The inspector's width, kept across launches the way a Mac app keeps the
    /// width of any pane the user has sized (#82).
    @AppStorage("FreeSnitch.RulesInspectorWidth") private var inspectorWidth: Double = 240
    /// The width the current drag started from, so the pane tracks the pointer
    /// instead of accumulating every delta on top of itself.
    @State private var inspectorDragStart: Double?
    @ObservedObject private var profileClient = ProfileClient.shared

    /// The query. It comes from the window's toolbar on the rules table, and
    /// from this page's own field while a blocklist is open (#96).
    private var searchText: String { window.searchText }

    private var searchBinding: Binding<String> {
        Binding(get: { window.searchText }, set: { window.searchText = $0 })
    }

    /// The blocklist currently open in the content pane, if any.
    private var openBlocklist: BlocklistInfo? {
        guard case .blocklist(let id) = selectedCategory else { return nil }
        return state.blocklists.first(where: { $0.id == id })
    }

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
                sidebar
                    .frame(width: 204)
                    .focused($focusedPane, equals: .categories)
                    .accessibilityLabel(RulesPane.categories.accessibilityLabel)
                Divider()
                mainPane
                    .focused($focusedPane, equals: .table)
                    .accessibilityLabel(RulesPane.table.accessibilityLabel)
                // The inspector is only on screen while something is selected,
                // rather than permanently spending a third of the window to say
                // that nothing is (#81).
                if !selectedRules.isEmpty {
                    inspectorDivider
                    infoPane
                        .frame(width: inspectorWidth)
                        .focusable()
                        .focused($focusedPane, equals: .inspector)
                        .paneFocusRing(focusedPane == .inspector)
                        .accessibilityLabel(RulesPane.inspector.accessibilityLabel)
                }
            }
            .paneTabTraversal { backwards in advanceFocus(backwards: backwards) }
        }
        // Escape clears the selection, which also dismisses the inspector.
        .onExitCommand { clearSelection() }
        // The window's toolbar drops its search field while a blocklist is
        // open, because the pane has its own (#96). Clearing the query on the
        // way in and out keeps a rules search from silently filtering a
        // blocklist, and the reverse.
        .onAppear { window.contentOwnsSearch = openBlocklist != nil }
        .onDisappear { window.contentOwnsSearch = false }
        .onChange(of: selectedCategory) { _ in
            let ownsSearch = openBlocklist != nil
            if ownsSearch != window.contentOwnsSearch {
                window.searchText = ""
                window.contentOwnsSearch = ownsSearch
            }
        }
        .sheet(isPresented: $showingRuleEditor) {
            RuleEditorView(activeProfileName: profileClient.activeProfileName) { rule in addRule(rule) }
        }
        .sheet(item: $editingBlocklist) { blocklist in
            BlocklistEditorView(blocklist: blocklist)
        }
        .sheet(isPresented: $showingAddBlocklist) {
            BlocklistEditorView(blocklist: nil)
        }
        .fileImporter(isPresented: $showingImporter, allowedContentTypes: [.json]) { result in
            importRules(from: result)
        }
        .fileExporter(isPresented: $showingExporter,
                      document: exportDocument,
                      contentType: .json,
                      defaultFilename: "freesnitch-rules") { result in
            if case .failure(let error) = result {
                showError("Could not export the rules", error.localizedDescription)
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
        // Every removal comes through here, from the table, the context menu
        // and the inspector alike. A single rule used to go straight through
        // without asking, and the inspector's Remove never asked at all (#115).
        .confirmationDialog(removalTitle,
                            isPresented: $showingRemoveConfirmation,
                            titleVisibility: .visible) {
            Button(pendingRemovalIDs.count == 1 ? "Remove Rule" : "Remove Rules", role: .destructive) {
                removeRules(withIDs: pendingRemovalIDs)
            }
            Button("Cancel", role: .cancel) { pendingRemovalIDs.removeAll() }
        } message: {
            Text(pendingRemovalIDs.count == 1
                 ? "The rule is deleted from FreeSnitch. The connection it covered follows the current mode again."
                 : "This permanently removes \(pendingRemovalIDs.count) rules from FreeSnitch.")
        }
        // The title states the problem. It used to be the name of this pane,
        // which told the reader nothing (#117).
        .alert(errorTitle, isPresented: $showingError) {
            Button("OK", role: .cancel) { showingError = false }
        } message: {
            if let errorMessage { Text(errorMessage) }
        }
    }

    /// The sidebar is a real `List`, so it inherits Finder's sidebar metrics,
    /// selection, keyboard traversal and accessibility instead of imitating
    /// them with buttons and hand-drawn highlight rectangles.
    ///
    /// Its title is a pane header rather than the list's first section header,
    /// so it sits on the same baseline as the other panes and its divider joins
    /// theirs (#77).
    private var sidebar: some View {
        HeaderedPane {
            PaneHeader("Rules", count: state.rules.count)
        } content: {
            VStack(spacing: 0) {
                sidebarList
                Divider()
                addBlocklistFooter
            }
        }
    }

    private var sidebarList: some View {
        List(selection: sidebarSelection) {
            Section {
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

            // No section header: the toggle is the header. Two lines saying
            // "Blocklists", one of them a title and one of them a switch, made
            // the reader look for the difference between them (#95).
            Section {
                enforcementRow
                ForEach(state.blocklists) { b in
                    blocklistRow(b)
                }
            }
        }
        .contextMenu(forSelectionType: Category.self) { categories in
            sidebarContextMenu(for: categories)
        }
        // Content, not a sidebar. A window gets exactly one translucent band,
        // the window's own sidebar; a second source list inside the content
        // paints a second material and the window ends up as a staircase of
        // three greys. This list is one surface with the table beside it,
        // separated by a divider and nothing else.
        .listStyle(.inset)
        .onAppear {
            DispatchQueue.main.async { sidebarAcceptsSelection = true }
        }
    }

    static let blocklistExplanation = "Blocklists filter DNS names only. They do not stop connections made to hardcoded IP addresses or names resolved by an app's own encrypted DNS, such as Chrome and Firefox DoH."
    static let enforcementOffExplanation = "Enforcement is off, so enabled blocklists are currently blocking nothing."

    /// The one thing a reader wants when they learn enforcement is off is to
    /// turn it on, so this is a real toggle rather than a warning label (#80).
    ///
    /// It is labelled for what it governs, "Blocklists", and carries the
    /// information affordance itself, because the explanation is about this
    /// switch and not about the heading above it (#95).
    ///
    /// It shows what the helper reports, not what the GUI last asked for: the
    /// switch is disabled and reads as pending while a change is in flight, and
    /// a refusal puts it back and says why, right here where it was flipped.
    private var enforcementRow: some View {
        VStack(alignment: .leading, spacing: 3) {
            Toggle(isOn: enforcementBinding) {
                Label {
                    HStack(spacing: 4) {
                        Text("Blocklists")
                            .lineLimit(1)
                        blocklistHelpButton
                    }
                } icon: {
                    Image(systemName: state.enforcementEnabled ? "shield.lefthalf.filled" : "shield.slash")
                        .foregroundStyle(enforcementTint)
                }
            }
            .toggleStyle(.switch)
            .controlSize(.mini)
            .disabled(state.enforcementChangePending || !state.helperConnected)
            .help(state.enforcementEnabled
                  ? "Blocklists are in force: the pf anchor is loaded and the DNS proxy is running."
                  : "Blocklists are off: FreeSnitch is watching and blocking nothing.")
            enforcementCaption
        }
        .padding(.vertical, 2)
    }

    @ViewBuilder
    private var enforcementCaption: some View {
        if let failure = state.enforcementFailure {
            enforcementCaptionText(failure, tint: .orange)
        } else if state.enforcementChangePending {
            enforcementCaptionText(state.enforcementEnabled
                                   ? "Turning enforcement on…"
                                   : "Turning enforcement off…",
                                   tint: .secondary)
        } else if !state.helperConnected {
            enforcementCaptionText("Approve the FreeSnitch helper to change this.", tint: .secondary)
        } else if state.enforcementEnabled {
            enforcementCaptionText("On: rules and blocklists are in force.", tint: .secondary)
        } else if state.blocklists.contains(where: { $0.enabled }) {
            enforcementCaptionText(Self.enforcementOffExplanation, tint: .secondary)
        } else {
            enforcementCaptionText("Off: FreeSnitch is only watching.", tint: .secondary)
        }
    }

    private func enforcementCaptionText(_ text: String, tint: Color) -> some View {
        Text(text)
            .font(.caption)
            .foregroundStyle(tint)
            .fixedSize(horizontal: false, vertical: true)
    }

    private var enforcementTint: Color {
        if state.enforcementChangePending { return .secondary }
        return state.enforcementEnabled ? .accentColor : .orange
    }

    /// Writes go through `AppState`, which is the single place that talks to
    /// the helper about enforcement, so this toggle uses exactly the path the
    /// Settings toggle does.
    private var enforcementBinding: Binding<Bool> {
        Binding(
            get: { state.enforcementEnabled },
            set: { newValue in
                guard !state.enforcementChangePending else { return }
                state.enforcementEnabled = newValue
            }
        )
    }

    /// Six lines of explanation used to sit permanently in the sidebar, which
    /// is not what a Mac app does with reference text. It lives behind the info
    /// affordance next to the header.
    ///
    /// The affordance is a real `Button`, so it takes keyboard focus and opens
    /// with Space or Return; hovering also opens it, but only after a delay, so
    /// that passing the pointer over the header on the way somewhere else does
    /// not throw a popover in the reader's face (#84).
    /// Adding a list of your own, under the lists (#97).
    ///
    /// It is a footer beneath the list rather than a last row inside it: a
    /// button placed in a `List` row never receives the click here, because the
    /// `NSTableView` underneath takes the event first, which is the same reason
    /// the row context menus had to move to the list itself.
    private var addBlocklistFooter: some View {
        HStack(spacing: 4) {
            Button {
                showingAddBlocklist = true
            } label: {
                Label("Add custom blocklist", systemImage: "plus")
                    .font(.callout)
            }
            .buttonStyle(.borderless)
            .disabled(!profileClient.isAvailable)
            .help(profileClient.isAvailable
                  ? "Add a list of your own, from a URL or by typing its entries."
                  : "Approve the FreeSnitch helper to add a blocklist.")
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
    }

    private var blocklistHelpButton: some View {
        Button {
            cancelBlocklistHelpHover()
            showingBlocklistHelp.toggle()
        } label: {
            Image(systemName: "info.circle")
                .imageScale(.small)
        }
        .buttonStyle(.borderless)
        .foregroundStyle(.secondary)
        .accessibilityLabel("About blocklists")
        .onHover { hovering in
            if hovering {
                scheduleBlocklistHelpHover()
            } else {
                cancelBlocklistHelpHover()
                showingBlocklistHelp = false
            }
        }
        // The width has to be set before fixedSize, or the text is measured
        // unwrapped and the popover clips its last lines.
        .popover(isPresented: $showingBlocklistHelp, arrowEdge: .trailing) {
            Text(Self.blocklistExplanation)
                .font(.callout)
                .frame(width: 250, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
                .padding(14)
        }
    }

    /// Hover opens the popover only after the pointer has stayed put. 0.75s is
    /// the dwell the report asked for and is close to the system tooltip delay.
    private func scheduleBlocklistHelpHover() {
        cancelBlocklistHelpHover()
        let work = DispatchWorkItem { showingBlocklistHelp = true }
        blocklistHelpHover = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.75, execute: work)
    }

    private func cancelBlocklistHelpHover() {
        blocklistHelpHover?.cancel()
        blocklistHelpHover = nil
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

    /// The same calls the checkbox and the refresh button make (#78).
    ///
    /// This is installed on the list rather than on the row: a per-row
    /// .contextMenu inside a List never sees the right click, because the
    /// NSTableView underneath takes the event first.
    @ViewBuilder
    private func sidebarContextMenu(for categories: Set<Category>) -> some View {
        if case .blocklist(let id) = categories.first,
           let blocklist = state.blocklists.first(where: { $0.id == id }) {
            Button(blocklist.enabled ? "Disable" : "Enable") {
                setBlocklist(blocklist, enabled: !blocklist.enabled)
            }
            .disabled(!state.helperConnected)
            Divider()
            Button("Refresh All Lists") { state.helper.refreshBlocklists() }
                .disabled(!state.helperConnected)
            CopyMenuItem(title: "Copy Name", value: blocklist.name)
        }
    }

    private var mainPane: some View {
        HeaderedPane {
            toolbar
        } content: {
            rulesList
        }
    }

    /// The section header for the content pane: title, count, and the actions
    /// that apply to what is in it.
    ///
    /// For rules, search is not here: it is an `NSSearchToolbarItem` in the
    /// window's real toolbar, like Finder's. A blocklist is a different kind of
    /// content with a different scope, so it carries its own field beside its
    /// own name, and the toolbar's field steps aside while it does (#96).
    @ViewBuilder
    private var toolbar: some View {
        if let blocklist = openBlocklist {
            blocklistHeader(blocklist)
        } else {
            rulesHeader
        }
    }

    private func blocklistHeader(_ blocklist: BlocklistInfo) -> some View {
        PaneHeader(blocklist.name, count: paneCount) {
            PaneSearchField(text: searchBinding,
                            placeholder: "Search \(blocklist.name)",
                            focusToken: window.searchFocusToken)
                .frame(width: 220, height: 22)
                .accessibilityLabel("Search this blocklist")
            Button {
                editingBlocklist = blocklist
            } label: {
                Image(systemName: "square.and.pencil")
            }
            .buttonStyle(.borderless)
            .help("Edit this blocklist")
            .accessibilityLabel("Edit this blocklist")
        }
    }

    private var rulesHeader: some View {
        PaneHeader(categoryTitle, count: paneCount) {
            Button(action: { showingImporter = true }) {
                Image(systemName: "tray.and.arrow.down.fill")
            }
            .buttonStyle(.borderless)
            .disabled(!state.helperConnected)
            .help(state.helperConnected
                  ? "Import rules from a FreeSnitch export, or from a legacy plain JSON array. This replaces the current rules."
                  : "Approve the FreeSnitch helper before importing rules.")
            .accessibilityLabel("Import rules")
            Button(action: { exportRules() }) {
                Image(systemName: "tray.and.arrow.up.fill")
            }
            .buttonStyle(.borderless)
            .disabled(state.rules.isEmpty)
            .help(state.rules.isEmpty ? "There are no rules to export." : "Export rules as a \(RuleExportDocument.formatIdentifier) document the CLI can import.")
            .accessibilityLabel("Export rules")
            Button(action: { showingRuleEditor = true }) {
                Image(systemName: "plus")
            }
            .buttonStyle(.borderless)
            .disabled(!state.helperConnected)
            .help(state.helperConnected ? "Add a rule." : "Approve the FreeSnitch helper before adding rules.")
            .accessibilityLabel("Add a rule")
        }
    }

    @ViewBuilder
    private var rulesList: some View {
        // A blocklist is not a set of rules, so this pane shows what is on it
        // instead of an empty rules table (#79).
        if case .blocklist(let id) = selectedCategory,
           let blocklist = state.blocklists.first(where: { $0.id == id }) {
            BlocklistEntriesView(blocklist: blocklist,
                                 searchText: searchText,
                                 onAllow: { domain in allowDespiteBlocklist(domain, from: blocklist) },
                                 onRemoveEntry: { domain in
                                     profileClient.removeBlocklistEntries(blocklist.id, domains: [domain])
                                 })
        } else {
            VStack(spacing: 0) {
                if filteredRules.isEmpty {
                    emptyState
                } else {
                    rulesTable
                }
            }
        }
    }

    /// The override the report asked for: one name allowed even though a list
    /// carries it. It is an ordinary allow rule with a high priority, created
    /// through the same path every other rule is created through, and it says
    /// in its notes where it came from.
    private func allowDespiteBlocklist(_ domain: String, from blocklist: BlocklistInfo) {
        let rule = Rule(processName: nil,
                        remoteHost: domain,
                        direction: .outgoing,
                        action: .allow,
                        scope: .domain,
                        priority: 90,
                        profile: Profile.alwaysName,
                        notes: "Allowed despite \(blocklist.name).",
                        enabled: true)
        addRule(rule)
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
    /// What the header counts: rules for a rule category, entries for a
    /// blocklist, because a blocklist pane holds no rules and reporting 0 there
    /// reads as an empty list rather than a different kind of content.
    private var paneCount: Int {
        if case .blocklist(let id) = selectedCategory {
            return state.blocklists.first(where: { $0.id == id })?.entryCount ?? 0
        }
        return filteredRules.count
    }

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
            // Wide enough for the longest value it can hold. At 64 it
            // truncated "Temporary" to "Tempora..." (#105).
            .width(min: 88, max: 120)
        }
        // A dragged column divider redistributes width instead of pushing the
        // columns behind it off the edge of the pane (#92).
        .background(TableColumnGuard())
        // Selection-aware, so right clicking a row that is not selected
        // selects it first and the menu applies to what the user just pointed
        // at, exactly like the Finder (#78).
        .contextMenu(forSelectionType: Rule.ID.self) { ids in
            rulesContextMenu(for: ids)
        }
    }

    /// Every item here calls the same function the corresponding button does.
    ///
    /// There is no Edit item because this app has no rule editor to open: the
    /// sheet only creates rules. Adding one from a context menu would be a new
    /// feature hiding in a menu, not the menu offering what the UI already has.
    @ViewBuilder
    private func rulesContextMenu(for ids: Set<Rule.ID>) -> some View {
        let rules = state.rules.filter { ids.contains($0.id) }
        if rules.isEmpty {
            Button("New Rule…") { showingRuleEditor = true }
                .disabled(!state.helperConnected)
        } else {
            if rules.contains(where: { !$0.enabled }) {
                Button("Enable") {
                    for rule in rules where !rule.enabled { toggleRule(rule) }
                }
            }
            if rules.contains(where: { $0.enabled }) {
                Button("Disable") {
                    for rule in rules where rule.enabled { toggleRule(rule) }
                }
            }
            Divider()
            if rules.count == 1, let rule = rules.first {
                CopyMenuItem(title: "Copy Destination", value: rule.displayDestination)
                CopyMenuItem(title: "Copy Process", value: rule.displayProcessName)
                if RowActions.canReveal(path: rule.processPath) {
                    Button("Reveal in Finder") { RowActions.revealInFinder(path: rule.processPath) }
                }
                Divider()
            }
            Button(rules.count == 1 ? "Delete Rule" : "Delete \(rules.count) Rules", role: .destructive) {
                pendingRemovalIDs = Set(rules.map(\.id))
                showingRemoveConfirmation = true
            }
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
            if showsLoginItemsButton {
                Button("Open Login Items") { SystemSettings.openLoginItems() }
                    .buttonStyle(.borderedProminent)
                    .padding(.top, 4)
            }
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// Only for the "helper not approved" state, and not while a blocklist is
    /// selected, where the empty pane is about the list rather than the helper.
    private var showsLoginItemsButton: Bool {
        if case .blocklist = selectedCategory { return false }
        if !searchText.isEmpty { return false }
        return !state.helperConnected
    }

    private var emptyIcon: String {
        if case .blocklist = selectedCategory { return "shield.lefthalf.filled" }
        if !searchText.isEmpty { return "magnifyingglass" }
        // Was `bolt.horizontal.circle`, which reads as a squiggle and says
        // nothing about a helper waiting for approval (#83).
        if !state.helperConnected { return "gearshape.badge.checkmark" }
        return "list.bullet"
    }

    private var emptyTitle: String {
        if case .blocklist(let id) = selectedCategory {
            return state.blocklists.first(where: { $0.id == id })?.name ?? "Blocklist"
        }
        // A search that matched nothing answers for itself. Blaming the helper
        // here was wrong whenever both were true at once.
        if !searchText.isEmpty { return "No Results" }
        if !state.helperConnected { return "Helper not running" }
        if state.rules.isEmpty { return "No rules yet" }
        return "Nothing in \(categoryTitle)"
    }

    private var emptySubtitle: String {
        if case .blocklist(let id) = selectedCategory {
            let count = state.blocklists.first(where: { $0.id == id })?.entryCount ?? 0
            return "This blocklist contains \(count) domain entries. Enable or refresh it in Settings under Blocklists."
        }
        if !searchText.isEmpty {
            return "No rule matches \u{201C}\(searchText)\u{201D}."
        }
        if !state.helperConnected {
            // One line. The button below does the navigating that three lines
            // of prose used to describe (#83).
            return "Approve FreeSnitch in Login Items, and this fills in on its own."
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
        HeaderedPane {
            PaneHeader("Information")
        } content: {
            infoPaneContent
        }
    }

    @ViewBuilder
    private var infoPaneContent: some View {
        VStack(alignment: .leading, spacing: 0) {
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
                    Button("Remove\u{2026}", role: .destructive) { confirmRemoval(of: [r.id]) }
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

    /// Every field copies on click (#94), so the pane behaves the way the Get
    /// Info panes it is modelled on do.
    ///
    /// A plain row rather than `LabeledContent`: a control placed in the value
    /// slot of a `LabeledContent` never receives the click, so the field looked
    /// copyable and did nothing.
    private func infoField(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(label)
            Spacer(minLength: 8)
            CopyableValue(value: value)
        }
    }

    private func selectCategory(_ category: Category) {
        selectedCategory = category
        clearSelection()
    }

    private func clearSelection() {
        selectedRuleIDs.removeAll()
        // The inspector leaves the Tab loop with the selection, so focus cannot
        // stay parked on a pane that no longer exists.
        if focusedPane == .inspector { focusedPane = .table }
    }

    /// The inspector's leading edge is a real drag handle: a divider on its
    /// own is one point wide and impossible to hit, so the hit area is widened
    /// without changing the layout, and the cursor says what it does (#82).
    ///
    /// The width is clamped, because a pane dragged to nothing is a pane the
    /// user cannot get back, and a Form needs a floor to lay its fields out.
    private var inspectorDivider: some View {
        // The handle is a real strip in the layout with the divider line drawn
        // down its middle, not an oversized overlay on a one point divider:
        // hit testing does not reliably reach an overlay outside its parent's
        // bounds, so that version looked draggable and was not.
        // The line is drawn rather than composed from a Divider: a Divider
        // takes its orientation from its layout context and has no intrinsic
        // height outside an HStack, so wrapping one in the strip produced a
        // 6x0 handle that was invisible and could not be hit.
        ZStack {
            Rectangle()
                .fill(Color(nsColor: .separatorColor))
                .frame(width: 1)
            PaneResizeHandle { dx in
                let start = inspectorDragStart ?? inspectorWidth
                if inspectorDragStart == nil { inspectorDragStart = start }
                // The pane is on the trailing edge, so dragging left makes it
                // wider.
                inspectorWidth = min(Self.inspectorMaxWidth,
                                     max(Self.inspectorMinWidth, start - Double(dx)))
            } onEnd: {
                inspectorDragStart = nil
            }
        }
        .frame(width: Self.inspectorHandleWidth)
        .accessibilityLabel("Resize the Information pane")
    }

    private static let inspectorHandleWidth: CGFloat = 6

    /// Below this the fields in the inspector cannot lay out; above it the pane
    /// starts eating the table it is describing.
    static let inspectorMinWidth: Double = 220
    static let inspectorMaxWidth: Double = 460

    /// Tab order is categories, rules, inspector. The first Tab press on a page
    /// nobody has touched puts focus on the category list rather than doing
    /// nothing (#85).
    private func advanceFocus(backwards: Bool) {
        let panes = availablePanes
        guard let current = focusedPane, let index = panes.firstIndex(of: current) else {
            focusedPane = panes.first
            return
        }
        let step = backwards ? panes.count - 1 : 1
        focusedPane = panes[(index + step) % panes.count]
    }

    /// The inspector is only in the loop while it is on screen (#81).
    private var availablePanes: [RulesPane] {
        selectedRules.isEmpty ? [.categories, .table] : RulesPane.allCases
    }

    private var allSelectedRulesDisabled: Bool {
        !selectedRules.isEmpty && selectedRules.allSatisfy { !$0.enabled }
    }

    private func addRule(_ rule: Rule) {
        state.helper.addRule(rule) { ok, message in
            guard ok else {
                showError("Could not add the rule", message ?? "The helper rejected it and did not say why.")
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
            showError("Could not read that file", error.localizedDescription)
        }
    }

    private func replaceRules(with rules: [Rule]) {
        pendingImportRules.removeAll()
        let existingRules = state.rules
        state.helper.replaceRules(rules, existing: existingRules) { ok, message in
            guard ok else {
                showError("Could not import the rules", message ?? "The helper rejected the import and did not say why.")
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
                showError("Could not change \(blocklist.name)", message ?? "The helper rejected the change and did not say why.")
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

    /// A rule the way the user reads it in the table: the process and where it
    /// was going, never the identifier the helper stores it under.
    static func describe(_ rule: Rule) -> String {
        let process = rule.processName ?? rule.processBundleId ?? "any process"
        let destination = rule.remoteHost ?? rule.remoteIP ?? "any destination"
        return "\(process) to \(destination)"
    }

    /// A title that names what failed, and a detail that says why. A rule is
    /// named the way the user sees it, never by its identifier (#117).
    private func showError(_ title: String, _ detail: String? = nil) {
        errorTitle = title
        errorMessage = detail
        showingError = true
    }

    private func toggleRule(_ r: Rule) {
        var copy = r
        copy.enabled.toggle()
        state.helper.addRule(copy) { ok, message in
            guard ok else {
                showError("Could not change the rule", message ?? "The helper rejected the change and did not say why.")
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
                    showError("Could not change the rule for \(Self.describe(copy))",
                              message ?? "The helper rejected the change and did not say why.")
                }
                updateNext(index + 1)
            }
        }

        updateNext(0)
    }

    private var removalTitle: String {
        guard pendingRemovalIDs.count == 1,
              let id = pendingRemovalIDs.first,
              let rule = state.rules.first(where: { $0.id == id }) else {
            return "Remove selected rules?"
        }
        return "Remove the rule for \(Self.describe(rule))?"
    }

    private func removeSelectedRules() {
        confirmRemoval(of: Set(selectedRules.map(\.id)))
    }

    /// One door for every removal, so the question is always asked.
    private func confirmRemoval(of ids: Set<UUID>) {
        guard !ids.isEmpty else { return }
        pendingRemovalIDs = ids
        showingRemoveConfirmation = true
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
                    let removed = state.rules.first { $0.id == orderedIDs[index] }
                    showError("Could not remove the rule for \(removed.map(Self.describe) ?? "that connection")",
                              message ?? "The helper rejected the removal and did not say why.")
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
