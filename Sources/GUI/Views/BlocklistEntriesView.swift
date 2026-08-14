import SwiftUI

/// What is actually on a blocklist.
///
/// Selecting a list used to show its entry count and an instruction to go
/// somewhere else, which answers a question nobody asked: the question people
/// have is whether one particular name is on the list (#79).
///
/// The list itself stays in the helper. This view holds exactly one page at a
/// time, asks for the next page by offset, and lets the helper do the
/// searching, because that is where the data already is. The largest bundled
/// list is over 300,000 names and none of them are ever in this process at
/// once.
struct BlocklistEntriesView: View {
    @EnvironmentObject var state: AppState
    let blocklist: BlocklistInfo
    /// The window's toolbar search field, shared with the rest of the page.
    let searchText: String
    /// Creating the override rule goes through the page's own rule path, so
    /// this view never talks to the helper about rules itself.
    let onAllow: (String) -> Void
    /// Taking a name off the list itself, which is a different thing from
    /// allowing it despite the list: this one changes the list (#97).
    var onRemoveEntry: ((String) -> Void)?

    @State private var page: BlocklistEntryPage?
    @State private var offset = 0
    @State private var errorMessage: String?
    @State private var isLoading = false
    @State private var selection: String?
    /// Identifies the newest request, so a slow answer for an old search or an
    /// old page cannot overwrite a newer one.
    @State private var requestToken = UUID()

    private static let pageSize = 100

    var body: some View {
        VStack(spacing: 0) {
            content
            Divider()
            footer
        }
        .onAppear { load(resettingOffset: true) }
        .onChange(of: blocklist.id) { _ in load(resettingOffset: true) }
        // The new value is passed in rather than read back off `self`: the
        // action closure belongs to the body that ran before the change, so
        // reading the property here queried one keystroke behind what the
        // field showed (#96).
        .onChange(of: searchText) { newValue in load(resettingOffset: true, query: newValue) }
    }

    @ViewBuilder
    private var content: some View {
        if let errorMessage {
            message(errorMessage, symbol: "exclamationmark.triangle.fill", tint: .orange)
        } else if isLoading && page == nil {
            VStack(spacing: 8) {
                Spacer()
                ProgressView()
                Text("Reading \(blocklist.name)\u{2026}")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                Spacer()
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if let page, page.entries.isEmpty {
            message(searchText.isEmpty
                    ? "This list has no entries yet. Refresh it to download them."
                    : "Nothing in \(blocklist.name) matches \u{201C}\(searchText)\u{201D}.",
                    symbol: searchText.isEmpty ? "shield.lefthalf.filled" : "magnifyingglass",
                    tint: .secondary)
        } else {
            List(selection: $selection) {
                ForEach(page?.entries ?? [], id: \.self) { entry in
                    Text(entry)
                        .font(.body.monospaced())
                        .lineLimit(1)
                        .tag(entry)
                }
            }
            .listStyle(.inset)
            .accessibilityLabel("Entries in \(blocklist.name)")
            .contextMenu(forSelectionType: String.self) { ids in
                if let entry = ids.first {
                    Button("Copy Domain") { RowActions.copy(entry) }
                    Divider()
                    Button("Allow \(entry) Anyway") { onAllow(entry) }
                        .disabled(!state.helperConnected)
                    if let onRemoveEntry {
                        Button("Remove from This List", role: .destructive) { onRemoveEntry(entry) }
                            .disabled(!ProfileClient.shared.isAvailable)
                    }
                }
            }
        }
    }

    private func message(_ text: String, symbol: String, tint: Color) -> some View {
        VStack(spacing: 8) {
            Spacer()
            Image(systemName: symbol)
                .font(.system(size: 30))
                .foregroundStyle(tint)
            Text(text)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 360)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// Says which slice of the list is on screen, because a page of a very long
    /// list is meaningless without it.
    private var footer: some View {
        HStack(spacing: 8) {
            Text(rangeLabel)
                .font(.caption)
                .foregroundStyle(.secondary)
                .monospacedDigit()
            Spacer(minLength: 8)
            Button {
                offset = max(0, offset - Self.pageSize)
                load(resettingOffset: false)
            } label: {
                Image(systemName: "chevron.left")
            }
            .buttonStyle(.borderless)
            .disabled(offset == 0 || isLoading)
            .help("Previous page")
            // An icon-only button needs a label of its own, or VoiceOver reads
            // it as whatever the enclosing pane is called.
            .accessibilityLabel("Previous page")
            Button {
                offset += Self.pageSize
                load(resettingOffset: false)
            } label: {
                Image(systemName: "chevron.right")
            }
            .buttonStyle(.borderless)
            .disabled(!hasNextPage || isLoading)
            .help("Next page")
            .accessibilityLabel("Next page")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
    }

    private var hasNextPage: Bool {
        guard let page else { return false }
        return page.offset + page.entries.count < page.total
    }

    private var rangeLabel: String {
        guard let page, page.total > 0 else {
            return searchText.isEmpty ? "No entries" : "No matches"
        }
        let first = page.offset + 1
        let last = page.offset + page.entries.count
        let scope = searchText.isEmpty ? "entries" : "matches"
        return "\(first) to \(last) of \(page.total) \(scope)"
    }

    private func load(resettingOffset: Bool, query: String? = nil) {
        let search = query ?? searchText
        if resettingOffset { offset = 0 }
        let token = UUID()
        requestToken = token
        isLoading = true
        if let demo = BlocklistEntriesDemo.page(for: blocklist,
                                                search: search,
                                                offset: offset,
                                                limit: Self.pageSize) {
            isLoading = false
            errorMessage = nil
            page = demo
            return
        }
        let request = BlocklistEntryQuery(blocklistID: blocklist.id,
                                        search: search,
                                        offset: offset,
                                        limit: Self.pageSize)
        state.helper.queryBlocklistEntries(request) { result, error in
            guard requestToken == token else { return }
            isLoading = false
            if let error {
                errorMessage = error
                page = nil
                return
            }
            errorMessage = nil
            page = result
        }
    }
}

/// Blocklist entries live in the helper, so in demo mode this screen would be
/// nothing but "the helper is not connected" and could not be reviewed before
/// shipping. This answers the same query the helper answers, with synthetic
/// names, and is inert unless FREESNITCH_DEMO is set.
enum BlocklistEntriesDemo {
    static func page(for blocklist: BlocklistInfo,
                     search: String,
                     offset: Int,
                     limit: Int) -> BlocklistEntryPage? {
        guard ProcessInfo.processInfo.environment["FREESNITCH_DEMO"] == "1" else { return nil }
        let all = entries(for: blocklist)
        let needle = search.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let matching = needle.isEmpty ? all : all.filter { $0.contains(needle) }
        let start = min(max(0, offset), matching.count)
        let end = min(start + limit, matching.count)
        return BlocklistEntryPage(entries: Array(matching[start..<end]),
                                  total: matching.count,
                                  offset: start)
    }

    private static func entries(for blocklist: BlocklistInfo) -> [String] {
        let stems = ["ads", "track", "metrics", "telemetry", "pixel", "beacon", "analytics", "collect"]
        let domains = ["doubleclick.net", "adnxs.com", "criteo.com", "scorecardresearch.com",
                       "adsrvr.org", "taboola.com", "outbrain.com", "branch.io"]
        // Every name distinct, the way a real list is: a generator that
        // repeats itself makes the pane look broken rather than full.
        return (0..<blocklist.entryCount).map { i in
            "\(stems[i % stems.count])\(i).\(domains[i % domains.count])"
        }
        .sorted()
    }
}
