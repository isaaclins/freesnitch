import SwiftUI

/// Adding a list of your own, and changing any list, including the ones that
/// shipped with the app (#97).
///
/// A blocklist used to be something FreeSnitch handed you: twelve sources, on
/// or off, take it or leave it. One wrong name on one of them and the only
/// remedy was to switch the whole list off. This is the editor: a name, a
/// source that can be a URL or nothing at all, and the entries themselves,
/// which can be added to and taken away from.
///
/// Edits are stored beside the list rather than inside it, so a refresh of the
/// source cannot silently undo them, and Reset puts the list back to exactly
/// what its source says.
struct BlocklistEditorView: View {
    @ObservedObject private var profileClient = ProfileClient.shared
    @Environment(\.dismiss) private var dismiss

    /// The list being edited, or nil when creating one.
    var blocklist: BlocklistInfo?

    @State private var name = ""
    @State private var sourceKind: SourceKind = .url
    @State private var url = ""
    @State private var entryText = ""
    @State private var newEntries = ""
    @State private var errorMessage: String?
    @State private var showingResetConfirmation = false
    /// True from the moment the helper is asked until it answers. The sheet
    /// used to close on the way out, so a refusal landed in a published error
    /// only the Profiles page renders and adding a list from the Rules sidebar
    /// failed with nothing on screen at all (#135).
    @State private var isSaving = false

    enum SourceKind: String, CaseIterable, Identifiable {
        case url
        case typed
        var id: String { rawValue }
        var title: String {
            switch self {
            case .url: return "Download from a URL"
            case .typed: return "Type the entries"
            }
        }
    }

    private var isCreating: Bool { blocklist == nil }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(isCreating ? "Add Blocklist" : "Edit \(blocklist?.name ?? "Blocklist")")
                .font(.headline)
            Form {
                Section {
                    TextField("Name", text: $name)
                }
                if isCreating {
                    Section {
                        Picker("Source", selection: $sourceKind) {
                            ForEach(SourceKind.allCases) { kind in
                                Text(kind.title).tag(kind)
                            }
                        }
                        .pickerStyle(.radioGroup)
                        if sourceKind == .url {
                            TextField("https://example.org/hosts.txt", text: $url)
                        } else {
                            entriesEditor(text: $entryText,
                                          caption: "One name per line. FreeSnitch keeps these itself; nothing is downloaded.")
                        }
                    }
                } else {
                    Section {
                        if hasSource {
                            TextField("Source", text: $url)
                            Text("Refreshing re-downloads this source. Your own additions and removals are kept.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        } else {
                            LabeledContent("Source", value: "Typed by you")
                        }
                    }
                    Section("Add entries") {
                        entriesEditor(text: $newEntries,
                                      caption: "One name per line. These stay on the list through every refresh.")
                    }
                    Section {
                        Button("Reset to what shipped", role: .destructive) {
                            showingResetConfirmation = true
                        }
                        .disabled(!profileClient.isAvailable)
                        Text("Removes your additions and restores anything you deleted, at the next refresh.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .formStyle(.grouped)
            if let errorMessage {
                Text(errorMessage)
                    .font(.callout)
                    .foregroundStyle(Color.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                if isSaving {
                    ProgressView()
                        .controlSize(.small)
                    Text("Waiting for the helper\u{2026}")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else if !profileClient.isAvailable {
                    Text("Approve the FreeSnitch helper to change blocklists.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(isSaving)
                Button(isCreating ? "Add" : "Save") { save() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(isSaving
                              || !profileClient.isAvailable
                              || name.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(20)
        .frame(width: 460)
        .onAppear { load() }
        .confirmationDialog("Reset \(blocklist?.name ?? "this list")?",
                            isPresented: $showingResetConfirmation,
                            titleVisibility: .visible) {
            Button("Reset", role: .destructive) {
                guard let blocklist else { return }
                isSaving = true
                profileClient.resetBlocklistEntries(blocklist.id) { ok, message in
                    finish(ok, message)
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Your additions and removals for this list are forgotten. The list goes back to exactly what its source says.")
        }
    }

    private var hasSource: Bool {
        !(blocklist?.url ?? "").trimmingCharacters(in: .whitespaces).isEmpty
    }

    private func entriesEditor(text: Binding<String>, caption: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            TextEditor(text: text)
                .font(.body.monospaced())
                .frame(height: 120)
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .strokeBorder(Color(nsColor: .separatorColor))
                )
            Text(caption)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private func load() {
        guard let blocklist else { return }
        name = blocklist.name
        url = blocklist.url
    }

    /// One request per change, each waiting for the helper before the next one
    /// is sent, and the sheet stays up until the last of them answers.
    private typealias Step = (@escaping (Bool, String?) -> Void) -> Void

    private func save() {
        errorMessage = nil
        let cleanName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if let blocklist {
            saveEdits(to: blocklist, named: cleanName)
        } else {
            create(named: cleanName)
        }
    }

    private func create(named cleanName: String) {
        switch sourceKind {
        case .url:
            let trimmedURL = url.trimmingCharacters(in: .whitespaces)
            do {
                _ = try BlocklistURLValidator.validate(trimmedURL)
            } catch {
                errorMessage = error.localizedDescription
                return
            }
            isSaving = true
            profileClient.addCustomBlocklist(name: cleanName, url: trimmedURL, profileName: nil) { ok, message in
                finish(ok, message)
            }
        case .typed:
            let domains = BlocklistDomain.normaliseText(entryText)
            guard !domains.isEmpty else {
                errorMessage = "None of those lines is a domain name."
                return
            }
            isSaving = true
            profileClient.addLocalBlocklist(name: cleanName, domains: domains, profileName: nil) { ok, message in
                finish(ok, message)
            }
        }
    }

    private func saveEdits(to blocklist: BlocklistInfo, named cleanName: String) {
        var steps: [Step] = []
        if cleanName != blocklist.name {
            steps.append { done in profileClient.renameBlocklist(blocklist.id, name: cleanName, completion: done) }
        }
        let trimmedURL = url.trimmingCharacters(in: .whitespaces)
        if hasSource, trimmedURL != blocklist.url {
            do {
                _ = try BlocklistURLValidator.validate(trimmedURL)
            } catch {
                errorMessage = error.localizedDescription
                return
            }
            steps.append { done in profileClient.updateBlocklistURL(blocklist.id, url: trimmedURL, completion: done) }
        }
        if !newEntries.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            let domains = BlocklistDomain.normaliseText(newEntries)
            guard !domains.isEmpty else {
                errorMessage = "None of those lines is a domain name."
                return
            }
            steps.append { done in profileClient.addBlocklistEntries(blocklist.id, domains: domains, completion: done) }
        }
        guard !steps.isEmpty else {
            dismiss()
            return
        }
        isSaving = true
        run(steps, from: 0)
    }

    private func run(_ steps: [Step], from index: Int) {
        guard index < steps.count else {
            finish(true, nil)
            return
        }
        let step = steps[index]
        step { ok, message in
            guard ok else {
                finish(false, message)
                return
            }
            run(steps, from: index + 1)
        }
    }

    private func finish(_ ok: Bool, _ message: String?) {
        isSaving = false
        guard ok else {
            errorMessage = message ?? "The helper refused the change and did not say why."
            return
        }
        dismiss()
    }
}
