import Foundation
import SQLite3

private let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

public final class RuleStore: @unchecked Sendable {
    public struct PolicyState: Sendable {
        public let mode: AppMode
        public let rules: [Rule]
        public let generation: UInt64

        public init(mode: AppMode, rules: [Rule], generation: UInt64) {
            self.mode = mode
            self.rules = rules
            self.generation = generation
        }
    }

    public struct PolicyDraft {
        public var mode: AppMode
        public var rules: [Rule]

        public init(mode: AppMode, rules: [Rule]) {
            self.mode = mode
            self.rules = rules
        }
    }

    public enum PolicyStoreError: Error {
        case generationExhausted
    }

    public enum StoreError: Error, LocalizedError, Equatable, Sendable {
        case profileNotFound(String)
        case profileAlreadyExists(String)
        case cannotDeleteDefaultProfile
        case cannotDeleteLastProfile
        case blocklistNotFound(UUID)
        case blocklistAlreadyExists(String)
        case invalidBlocklistName
        case invalidBlocklistURL(String)

        public var errorDescription: String? {
            switch self {
            case .profileNotFound(let name): return "Profile `\(name)` was not found."
            case .profileAlreadyExists(let name): return "Profile `\(name)` already exists."
            case .cannotDeleteDefaultProfile: return "The default profile cannot be deleted."
            case .cannotDeleteLastProfile: return "At least one profile must remain."
            case .blocklistNotFound(let id): return "Blocklist `\(id.uuidString)` was not found."
            case .blocklistAlreadyExists(let name): return "Blocklist `\(name)` already exists."
            case .invalidBlocklistName: return "The blocklist name cannot be empty."
            case .invalidBlocklistURL(let reason): return "Invalid blocklist URL: \(reason)."
            }
        }
    }

    public static let policyGenerationSettingKey = "policy_generation"
    private static let modeSettingKey = "mode"

    private var db: OpaquePointer?
    private let queue = DispatchQueue(label: "io.isaaclins.freesnitch.rulestore")
    public let path: String

    public init(path: String) throws {
        self.path = path
        let dir = (path as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        if sqlite3_open(path, &db) != SQLITE_OK {
            throw NSError(domain: "RuleStore", code: 1, userInfo: [NSLocalizedDescriptionKey: "open failed"])
        }
        try setup()
    }

    deinit { if db != nil { sqlite3_close(db) } }

    private func setup() throws {
        let ddl = """
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY,
            process_bundle_id TEXT,
            process_path TEXT,
            process_name TEXT,
            remote_host TEXT,
            remote_ip TEXT,
            remote_port INTEGER,
            direction TEXT,
            action TEXT,
            scope TEXT,
            priority INTEGER,
            profile TEXT,
            group_name TEXT,
            notes TEXT,
            enabled INTEGER,
            temporary INTEGER,
            created_at REAL,
            expires_at REAL,
            last_used_at REAL,
            hit_count INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_rules_profile ON rules(profile);
        CREATE INDEX IF NOT EXISTS idx_rules_process ON rules(process_path);
        CREATE INDEX IF NOT EXISTS idx_rules_host ON rules(remote_host);

        CREATE TABLE IF NOT EXISTS connections (
            id TEXT PRIMARY KEY,
            pid INTEGER,
            process_name TEXT,
            process_path TEXT,
            process_bundle_id TEXT,
            local_port INTEGER,
            remote_host TEXT,
            remote_ip TEXT,
            remote_port INTEGER,
            direction TEXT,
            status TEXT,
            protocol_name TEXT,
            bytes_in INTEGER,
            bytes_out INTEGER,
            country TEXT,
            country_code TEXT,
            latitude REAL,
            longitude REAL,
            first_seen REAL,
            last_seen REAL
        );
        CREATE INDEX IF NOT EXISTS idx_conn_status ON connections(status);
        CREATE INDEX IF NOT EXISTS idx_conn_pid ON connections(pid);
        CREATE INDEX IF NOT EXISTS idx_conn_last_seen ON connections(last_seen DESC);

        CREATE TABLE IF NOT EXISTS profiles (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE,
            mode TEXT,
            icon TEXT,
            is_active INTEGER
        );

        CREATE TABLE IF NOT EXISTS blocklists (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE,
            url TEXT,
            enabled INTEGER,
            last_updated REAL,
            entry_count INTEGER
        );

        CREATE TABLE IF NOT EXISTS profile_blocklists (
            profile_name TEXT NOT NULL,
            blocklist_id TEXT NOT NULL,
            PRIMARY KEY(profile_name, blocklist_id)
        );

        CREATE TABLE IF NOT EXISTS profile_network_bindings (
            id TEXT PRIMARY KEY,
            profile_name TEXT NOT NULL,
            gateway_mac TEXT NOT NULL UNIQUE,
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        """
        try exec(ddl)
        try seedProfiles()
        try seedBlocklists()
        try migrateLegacyRuleProfiles()
        try seedDefaultProfileBlocklists()
        try normalizeActiveProfile()
    }

    private func seedProfiles() throws {
        let defaults: [Profile] = [
            // A fresh install learns quietly instead of training the user to
            // reflexively click Allow through dozens of first-run prompts.
            // Insights says plainly that Silent Allow blocks nothing (D9).
            Profile(name: "default", mode: .silentAllow, icon: "shield", isActive: true),
            Profile(name: "home", mode: .silentAllow, icon: "house"),
            Profile(name: "public-wifi", mode: .alert, icon: "wifi.exclamationmark"),
            Profile(name: "lockdown", mode: .silentDeny, icon: "lock.shield")
        ]
        for p in defaults { try insertProfileIfMissing(p) }
    }

    private func seedBlocklists() throws {
        let defaults: [BlocklistInfo] = [
            BlocklistInfo(name: "1Hosts (Lite)", url: "https://o0.pages.dev/Lite/hosts.txt"),
            BlocklistInfo(name: "OISD (small)", url: "https://small.oisd.nl/"),
            BlocklistInfo(name: "StevenBlack unified", url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"),
            BlocklistInfo(name: "AdGuard DNS", url: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"),
            // HaGeZi deprecated the hosts format on 2026-08-01 and the GitHub
            // repository is gone, so the old raw.githubusercontent URL is a 404.
            // The GitLab mirror still publishes daily, in Adblock syntax, which
            // BlocklistManager already parses.
            BlocklistInfo(name: "HaGeZi Multi Light", url: "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adblock/light.txt"),
            BlocklistInfo(name: "URLhaus", url: "https://urlhaus.abuse.ch/downloads/hostfile/"),
            BlocklistInfo(name: "Anti-PopAds", url: "https://raw.githubusercontent.com/Yhonay/antipopads/master/hosts"),
            BlocklistInfo(name: "Peter Lowe", url: "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext")
        ]
        for b in defaults { try insertBlocklistIfMissing(b) }
    }

    /// Rules written before profiles became real used `default` for the one
    /// global rule set. Migrate those rows once so the seeded `default` place
    /// profile can remain a real, independently editable profile.
    private func migrateLegacyRuleProfiles() throws {
        guard getSettingLocked("profiles_rules_migrated") == nil else { return }
        try exec("UPDATE rules SET profile='\(Profile.alwaysName)' WHERE profile IS NULL OR profile='' OR profile='default';")
        try setSettingLocked("profiles_rules_migrated", "1")
    }

    /// Preserve the old all-enabled blocklist behavior for the seeded profiles
    /// only on the first profile-selection migration. Later edits are never
    /// overwritten on startup.
    private func seedDefaultProfileBlocklists() throws {
        guard getSettingLocked("profiles_blocklists_seeded") == nil else { return }
        var blocklistIDs: [String] = []
        var stmt: OpaquePointer?
        defer { if stmt != nil { sqlite3_finalize(stmt) } }
        // Seed from what is enabled today, so an upgrade preserves the lists
        // the user already chose instead of switching everything back on.
        guard sqlite3_prepare_v2(db, "SELECT id FROM blocklists WHERE enabled=1;", -1, &stmt, nil) == SQLITE_OK else { return }
        while sqlite3_step(stmt) == SQLITE_ROW {
            blocklistIDs.append(text(stmt, 0))
        }
        for profile in [Profile.defaultName, "home", "public-wifi", "lockdown"] {
            for id in blocklistIDs {
                try execute("INSERT OR IGNORE INTO profile_blocklists(profile_name,blocklist_id) VALUES(?,?);") { statement in
                    sqlite3_bind_text(statement, 1, profile, -1, SQLITE_TRANSIENT)
                    sqlite3_bind_text(statement, 2, id, -1, SQLITE_TRANSIENT)
                }
            }
        }
        try setSettingLocked("profiles_blocklists_seeded", "1")
    }

    private func normalizeActiveProfile() throws {
        var activeCount = 0
        var stmt: OpaquePointer?
        defer { if stmt != nil { sqlite3_finalize(stmt) } }
        if sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM profiles WHERE is_active=1;", -1, &stmt, nil) == SQLITE_OK,
           sqlite3_step(stmt) == SQLITE_ROW {
            activeCount = Int(sqlite3_column_int(stmt, 0))
        }
        guard activeCount == 1 else {
            try exec("UPDATE profiles SET is_active=0;")
            try execute("UPDATE profiles SET is_active=1 WHERE name=?;") { statement in
                sqlite3_bind_text(statement, 1, Profile.defaultName, -1, SQLITE_TRANSIENT)
            }
            return
        }
    }

    private func insertProfileIfMissing(_ p: Profile) throws {
        let sql = "INSERT OR IGNORE INTO profiles(id,name,mode,icon,is_active) VALUES (?,?,?,?,?);"
        try execute(sql) { stmt in
            sqlite3_bind_text(stmt, 1, p.id.uuidString, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 2, p.name, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 3, p.mode.rawValue, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 4, p.icon, -1, SQLITE_TRANSIENT)
            sqlite3_bind_int(stmt, 5, p.isActive ? 1 : 0)
        }
    }

    private func insertBlocklistIfMissing(_ b: BlocklistInfo) throws {
        let sql = "INSERT OR IGNORE INTO blocklists(id,name,url,enabled,last_updated,entry_count) VALUES (?,?,?,?,?,?);"
        try execute(sql) { stmt in
            sqlite3_bind_text(stmt, 1, b.id.uuidString, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 2, b.name, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 3, b.url, -1, SQLITE_TRANSIENT)
            sqlite3_bind_int(stmt, 4, b.enabled ? 1 : 0)
            if let d = b.lastUpdated { sqlite3_bind_double(stmt, 5, d.timeIntervalSince1970) } else { sqlite3_bind_null(stmt, 5) }
            sqlite3_bind_int(stmt, 6, Int32(b.entryCount))
        }
    }

    private func exec(_ sql: String) throws {
        try queue.sync { try execLocked(sql) }
    }

    private func execLocked(_ sql: String) throws {
        var err: UnsafeMutablePointer<CChar>?
        if sqlite3_exec(db, sql, nil, nil, &err) != SQLITE_OK {
            let msg = err.map { String(cString: $0) } ?? "unknown"
            sqlite3_free(err)
            throw NSError(domain: "RuleStore", code: 2, userInfo: [NSLocalizedDescriptionKey: msg])
        }
    }

    private func execute(_ sql: String, _ bind: (OpaquePointer?) -> Void) throws {
        try queue.sync { try executeLocked(sql, bind) }
    }

    private func executeLocked(_ sql: String, _ bind: (OpaquePointer?) -> Void) throws {
        var stmt: OpaquePointer?
        defer { if stmt != nil { sqlite3_finalize(stmt) } }
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw NSError(domain: "RuleStore", code: 3, userInfo: [NSLocalizedDescriptionKey: String(cString: sqlite3_errmsg(db))])
        }
        bind(stmt)
        let rc = sqlite3_step(stmt)
        if rc != SQLITE_DONE && rc != SQLITE_ROW {
            throw NSError(domain: "RuleStore", code: 4, userInfo: [NSLocalizedDescriptionKey: String(cString: sqlite3_errmsg(db))])
        }
    }

    private func setSettingLocked(_ key: String, _ value: String) throws {
        try executeLocked("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?);") { stmt in
            sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 2, value, -1, SQLITE_TRANSIENT)
        }
    }

    private func getSettingLocked(_ key: String) -> String? {
        var stmt: OpaquePointer?
        defer { if stmt != nil { sqlite3_finalize(stmt) } }
        guard sqlite3_prepare_v2(db, "SELECT value FROM settings WHERE key=?;", -1, &stmt, nil) == SQLITE_OK else { return nil }
        sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT)
        if sqlite3_step(stmt) == SQLITE_ROW { return text(stmt, 0) }
        return nil
    }

    public func policyState() -> PolicyState {
        queue.sync { policyStateLocked() }
    }

    /// The policy that should actually be enforced: the active profile's
    /// strictness plus exactly two rule layers, Always and that profile.
    /// The generation is the same committed policy generation, so existing
    /// snapshot gating is unchanged.
    public func activePolicyState() -> PolicyState {
        queue.sync {
            let generation = UInt64(getSettingLocked(Self.policyGenerationSettingKey) ?? "") ?? 0
            guard let profile = activeProfileLocked() else {
                return policyStateLocked()
            }
            return PolicyState(mode: profile.mode,
                               rules: layeredRulesLocked(profileName: profile.name),
                               generation: generation)
        }
    }

    public func profilePolicy(named name: String) throws -> ProfilePolicy {
        try queue.sync {
            guard let profile = profileLocked(named: name) else {
                throw StoreError.profileNotFound(name)
            }
            return profilePolicyLocked(profile)
        }
    }

    public func activeProfilePolicy() throws -> ProfilePolicy {
        try queue.sync {
            guard let profile = activeProfileLocked() else {
                throw StoreError.profileNotFound(Profile.defaultName)
            }
            return profilePolicyLocked(profile)
        }
    }

    private func profilePolicyLocked(_ profile: Profile) -> ProfilePolicy {
        ProfilePolicy(profile: profile,
                      alwaysRules: allRulesLocked(profile: Profile.alwaysName),
                      profileRules: allRulesLocked(profile: profile.name),
                      selectedBlocklistIDs: profileBlocklistIDsLocked(profileName: profile.name))
    }

    /// Applies one complete mode/rule mutation and its generation in a single
    /// SQLite transaction. The helper owns the closure, so a reload can
    /// validate the complete batch before this method commits anything.
    @discardableResult
    public func mutatePolicy(_ change: (inout PolicyDraft) throws -> Void) throws -> PolicyState {
        try queue.sync {
            let current = policyStateLocked()
            var draft = PolicyDraft(mode: current.mode, rules: current.rules)
            try change(&draft)
            guard current.generation < UInt64.max else {
                throw PolicyStoreError.generationExhausted
            }
            let nextGeneration = current.generation + 1

            try execLocked("BEGIN IMMEDIATE;")
            do {
                try replaceRulesLocked(draft.rules)
                try setSettingLocked(Self.modeSettingKey, draft.mode.rawValue)
                try setSettingLocked(Self.policyGenerationSettingKey, String(nextGeneration))
                try execLocked("COMMIT;")
            } catch {
                try? execLocked("ROLLBACK;")
                throw error
            }
            // Read the committed ordering back so the helper runtime and
            // every later authoritative snapshot use the same persisted rule
            // order, including priority tie-breaks.
            return policyStateLocked()
        }
    }

    private func policyStateLocked() -> PolicyState {
        // Missing means a genuinely fresh database. Existing installs retain
        // their stored choice, while a new user starts honestly in Silent
        // Allow and can move to Alert once Insights has a real picture.
        let mode = AppMode(rawValue: getSettingLocked(Self.modeSettingKey) ?? "") ?? .silentAllow
        let generation = UInt64(getSettingLocked(Self.policyGenerationSettingKey) ?? "") ?? 0
        return PolicyState(mode: mode, rules: allRulesLocked(profile: nil), generation: generation)
    }

    private func replaceRulesLocked(_ rules: [Rule]) throws {
        try execLocked("DELETE FROM rules;")
        for rule in rules { try upsertRuleLocked(rule) }
    }

    public func upsertRule(_ r: Rule) throws {
        try queue.sync { try upsertRuleLocked(r) }
    }

    private func upsertRuleLocked(_ r: Rule) throws {
        let sql = """
        INSERT OR REPLACE INTO rules(
            id, process_bundle_id, process_path, process_name, remote_host, remote_ip,
            remote_port, direction, action, scope, priority, profile, group_name, notes,
            enabled, temporary, created_at, expires_at, last_used_at, hit_count
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);
        """
        try executeLocked(sql) { stmt in
            sqlite3_bind_text(stmt, 1, r.id.uuidString, -1, SQLITE_TRANSIENT)
            bindOpt(stmt, 2, r.processBundleId)
            bindOpt(stmt, 3, r.processPath)
            bindOpt(stmt, 4, r.processName)
            bindOpt(stmt, 5, r.remoteHost)
            bindOpt(stmt, 6, r.remoteIP)
            if let p = r.remotePort { sqlite3_bind_int(stmt, 7, Int32(p)) } else { sqlite3_bind_null(stmt, 7) }
            sqlite3_bind_text(stmt, 8, r.direction.rawValue, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 9, r.action.rawValue, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 10, r.scope.rawValue, -1, SQLITE_TRANSIENT)
            sqlite3_bind_int(stmt, 11, Int32(r.priority))
            sqlite3_bind_text(stmt, 12, r.profile, -1, SQLITE_TRANSIENT)
            bindOpt(stmt, 13, r.groupName)
            bindOpt(stmt, 14, r.notes)
            sqlite3_bind_int(stmt, 15, r.enabled ? 1 : 0)
            sqlite3_bind_int(stmt, 16, r.temporary ? 1 : 0)
            sqlite3_bind_double(stmt, 17, r.createdAt.timeIntervalSince1970)
            if let e = r.expiresAt { sqlite3_bind_double(stmt, 18, e.timeIntervalSince1970) } else { sqlite3_bind_null(stmt, 18) }
            if let l = r.lastUsedAt { sqlite3_bind_double(stmt, 19, l.timeIntervalSince1970) } else { sqlite3_bind_null(stmt, 19) }
            sqlite3_bind_int(stmt, 20, Int32(r.hitCount))
        }
    }

    public func deleteRule(id: UUID) throws {
        try queue.sync {
            try executeLocked("DELETE FROM rules WHERE id=?;") { stmt in
                sqlite3_bind_text(stmt, 1, id.uuidString, -1, SQLITE_TRANSIENT)
            }
        }
    }

    public func allRules(profile: String? = nil) -> [Rule] {
        queue.sync { allRulesLocked(profile: profile) }
    }

    /// Returns the only allowed allow-rule composition: Always plus one
    /// profile. Calling this for a new profile does not copy or create rules.
    public func layeredRules(profileName: String) throws -> [Rule] {
        try queue.sync {
            guard profileLocked(named: profileName) != nil else {
                throw StoreError.profileNotFound(profileName)
            }
            return layeredRulesLocked(profileName: profileName)
        }
    }

    public func activeLayeredRules() -> [Rule] {
        queue.sync {
            guard let profile = activeProfileLocked() else { return allRulesLocked(profile: Profile.alwaysName) }
            return layeredRulesLocked(profileName: profile.name)
        }
    }

    private func layeredRulesLocked(profileName: String) -> [Rule] {
        let always = allRulesLocked(profile: Profile.alwaysName)
        guard profileName != Profile.alwaysName else { return always }
        return always + allRulesLocked(profile: profileName)
    }

    private func allRulesLocked(profile: String?) -> [Rule] {
        var rules: [Rule] = []
        let sql: String
        if profile != nil {
            sql = "SELECT * FROM rules WHERE profile=? ORDER BY priority DESC, created_at DESC;"
        } else {
            sql = "SELECT * FROM rules ORDER BY priority DESC, created_at DESC;"
        }
        var stmt: OpaquePointer?
        defer { if stmt != nil { sqlite3_finalize(stmt) } }
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        if let profile = profile { sqlite3_bind_text(stmt, 1, profile, -1, SQLITE_TRANSIENT) }
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let r = readRule(stmt) { rules.append(r) }
        }
        return rules
    }

    public func allProfiles() -> [Profile] {
        queue.sync { allProfilesLocked() }
    }

    public func profile(named name: String) -> Profile? {
        queue.sync { profileLocked(named: name) }
    }

    public func activeProfile() -> Profile? {
        queue.sync { activeProfileLocked() }
    }

    public func activeProfileName() -> String {
        queue.sync { activeProfileLocked()?.name ?? Profile.defaultName }
    }

    public func createProfile(
        name: String,
        mode: AppMode = .alert,
        icon: String = "shield",
        blocklistIDs: Set<UUID> = []
    ) throws -> Profile {
        let normalizedName = try ProfileNameValidator.normalized(name)
        return try queue.sync {
            guard profileLocked(named: normalizedName) == nil else {
                throw StoreError.profileAlreadyExists(normalizedName)
            }
            try validateBlocklistIDsLocked(blocklistIDs)
            let profile = Profile(name: normalizedName, mode: mode, icon: icon, blocklistIDs: blocklistIDs)
            try insertProfileLocked(profile)
            try replaceProfileBlocklistsLocked(profileName: normalizedName, blocklistIDs: blocklistIDs)
            return profile
        }
    }

    public func updateProfile(_ profile: Profile) throws -> Profile {
        let normalizedName = try ProfileNameValidator.normalized(profile.name)
        return try queue.sync {
            guard let current = profileLocked(id: profile.id) else {
                throw StoreError.profileNotFound(profile.name)
            }
            if current.name == Profile.defaultName && normalizedName != current.name {
                throw StoreError.profileNotFound("the default profile cannot be renamed")
            }
            if let duplicate = profileLocked(named: normalizedName), duplicate.id != current.id {
                throw StoreError.profileAlreadyExists(normalizedName)
            }
            try validateBlocklistIDsLocked(profile.blocklistIDs)

            try execLocked("BEGIN IMMEDIATE;")
            do {
                if current.name != normalizedName {
                    try executeLocked("UPDATE rules SET profile=? WHERE profile=?;") { stmt in
                        sqlite3_bind_text(stmt, 1, normalizedName, -1, SQLITE_TRANSIENT)
                        sqlite3_bind_text(stmt, 2, current.name, -1, SQLITE_TRANSIENT)
                    }
                    try executeLocked("UPDATE profile_network_bindings SET profile_name=? WHERE profile_name=?;") { stmt in
                        sqlite3_bind_text(stmt, 1, normalizedName, -1, SQLITE_TRANSIENT)
                        sqlite3_bind_text(stmt, 2, current.name, -1, SQLITE_TRANSIENT)
                    }
                    try executeLocked("UPDATE profile_blocklists SET profile_name=? WHERE profile_name=?;") { stmt in
                        sqlite3_bind_text(stmt, 1, normalizedName, -1, SQLITE_TRANSIENT)
                        sqlite3_bind_text(stmt, 2, current.name, -1, SQLITE_TRANSIENT)
                    }
                }
                try executeLocked("UPDATE profiles SET name=?,mode=?,icon=? WHERE id=?;") { stmt in
                    sqlite3_bind_text(stmt, 1, normalizedName, -1, SQLITE_TRANSIENT)
                    sqlite3_bind_text(stmt, 2, profile.mode.rawValue, -1, SQLITE_TRANSIENT)
                    sqlite3_bind_text(stmt, 3, profile.icon, -1, SQLITE_TRANSIENT)
                    sqlite3_bind_text(stmt, 4, profile.id.uuidString, -1, SQLITE_TRANSIENT)
                }
                try replaceProfileBlocklistsLocked(profileName: normalizedName, blocklistIDs: profile.blocklistIDs)
                try syncGlobalBlocklistEnabledLocked()
                try execLocked("COMMIT;")
            } catch {
                try? execLocked("ROLLBACK;")
                throw error
            }
            return Profile(id: profile.id, name: normalizedName, mode: profile.mode, icon: profile.icon,
                           isActive: current.isActive, blocklistIDs: profile.blocklistIDs)
        }
    }

    @discardableResult
    public func deleteProfile(name: String) throws -> Profile? {
        let normalizedName = try ProfileNameValidator.normalized(name)
        return try queue.sync {
            guard let profile = profileLocked(named: normalizedName) else {
                throw StoreError.profileNotFound(normalizedName)
            }
            guard profile.name != Profile.defaultName else {
                throw StoreError.cannotDeleteDefaultProfile
            }
            guard allProfilesLocked().count > 1 else {
                throw StoreError.cannotDeleteLastProfile
            }
            let replacement = profile.isActive
                ? (profileLocked(named: Profile.defaultName) ?? allProfilesLocked().first { $0.id != profile.id })
                : nil

            try execLocked("BEGIN IMMEDIATE;")
            do {
                try executeLocked("DELETE FROM rules WHERE profile=?;") { stmt in
                    sqlite3_bind_text(stmt, 1, profile.name, -1, SQLITE_TRANSIENT)
                }
                try executeLocked("DELETE FROM profile_blocklists WHERE profile_name=?;") { stmt in
                    sqlite3_bind_text(stmt, 1, profile.name, -1, SQLITE_TRANSIENT)
                }
                try executeLocked("DELETE FROM profile_network_bindings WHERE profile_name=?;") { stmt in
                    sqlite3_bind_text(stmt, 1, profile.name, -1, SQLITE_TRANSIENT)
                }
                try executeLocked("DELETE FROM profiles WHERE id=?;") { stmt in
                    sqlite3_bind_text(stmt, 1, profile.id.uuidString, -1, SQLITE_TRANSIENT)
                }
                if let replacement {
                    try executeLocked("UPDATE profiles SET is_active=0;") { _ in }
                    try executeLocked("UPDATE profiles SET is_active=1 WHERE id=?;") { stmt in
                        sqlite3_bind_text(stmt, 1, replacement.id.uuidString, -1, SQLITE_TRANSIENT)
                    }
                }
                try syncGlobalBlocklistEnabledLocked()
                try execLocked("COMMIT;")
            } catch {
                try? execLocked("ROLLBACK;")
                throw error
            }
            return replacement
        }
    }

    @discardableResult
    public func setActiveProfile(name: String) throws -> Profile {
        let normalizedName = try ProfileNameValidator.normalized(name)
        return try queue.sync {
            guard let profile = profileLocked(named: normalizedName) else {
                throw StoreError.profileNotFound(normalizedName)
            }
            try execLocked("BEGIN IMMEDIATE;")
            do {
                try execLocked("UPDATE profiles SET is_active=0;")
                try executeLocked("UPDATE profiles SET is_active=1 WHERE id=?;") { stmt in
                    sqlite3_bind_text(stmt, 1, profile.id.uuidString, -1, SQLITE_TRANSIENT)
                }
                try syncGlobalBlocklistEnabledLocked()
                try execLocked("COMMIT;")
            } catch {
                try? execLocked("ROLLBACK;")
                throw error
            }
            return Profile(id: profile.id, name: profile.name, mode: profile.mode, icon: profile.icon,
                           isActive: true, blocklistIDs: profile.blocklistIDs)
        }
    }

    public func setProfileMode(name: String, mode: AppMode) throws -> Profile {
        guard let current = profile(named: name) else { throw StoreError.profileNotFound(name) }
        var updated = current
        updated.mode = mode
        return try updateProfile(updated)
    }

    /// Legacy callers receive the global enabled flag. Profile-aware callers
    /// must use `allBlocklists(forProfile:)`, which reads the selection table.
    public func allBlocklists() -> [BlocklistInfo] {
        queue.sync { allBlocklistsLocked(selectedIDs: nil) }
    }

    public func allBlocklists(forProfile profileName: String) throws -> [BlocklistInfo] {
        try queue.sync {
            guard profileLocked(named: profileName) != nil else {
                throw StoreError.profileNotFound(profileName)
            }
            return allBlocklistsLocked(selectedIDs: profileBlocklistIDsLocked(profileName: profileName))
        }
    }

    public func selectedBlocklistIDs(profileName: String) throws -> Set<UUID> {
        try queue.sync {
            guard profileLocked(named: profileName) != nil else {
                throw StoreError.profileNotFound(profileName)
            }
            return profileBlocklistIDsLocked(profileName: profileName)
        }
    }

    public func setBlocklistEnabled(
        id: UUID,
        profileName: String,
        enabled: Bool
    ) throws {
        try queue.sync {
            guard profileLocked(named: profileName) != nil else {
                throw StoreError.profileNotFound(profileName)
            }
            guard blocklistExistsLocked(id: id) else { throw StoreError.blocklistNotFound(id) }
            if enabled {
                try executeLocked("INSERT OR IGNORE INTO profile_blocklists(profile_name,blocklist_id) VALUES(?,?);") { stmt in
                    sqlite3_bind_text(stmt, 1, profileName, -1, SQLITE_TRANSIENT)
                    sqlite3_bind_text(stmt, 2, id.uuidString, -1, SQLITE_TRANSIENT)
                }
            } else {
                try executeLocked("DELETE FROM profile_blocklists WHERE profile_name=? AND blocklist_id=?;") { stmt in
                    sqlite3_bind_text(stmt, 1, profileName, -1, SQLITE_TRANSIENT)
                    sqlite3_bind_text(stmt, 2, id.uuidString, -1, SQLITE_TRANSIENT)
                }
            }
            try syncGlobalBlocklistEnabledLocked()
        }
    }

    public func setProfileBlocklists(profileName: String, blocklistIDs: Set<UUID>) throws {
        try queue.sync {
            guard profileLocked(named: profileName) != nil else {
                throw StoreError.profileNotFound(profileName)
            }
            try validateBlocklistIDsLocked(blocklistIDs)
            try replaceProfileBlocklistsLocked(profileName: profileName, blocklistIDs: blocklistIDs)
            try syncGlobalBlocklistEnabledLocked()
        }
    }

    public func addCustomBlocklist(
        name: String,
        url: String,
        enabled: Bool = true,
        profileName: String? = nil,
        allowLocalhostHTTPForInjectedTest: Bool = false
    ) throws -> BlocklistInfo {
        let cleanName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanName.isEmpty, cleanName.utf8.count <= 256 else {
            throw StoreError.invalidBlocklistName
        }
        do {
            _ = try BlocklistURLValidator.validate(url, allowLocalhostHTTPForInjectedTest: allowLocalhostHTTPForInjectedTest)
        } catch {
            throw StoreError.invalidBlocklistURL(error.localizedDescription)
        }
        return try queue.sync {
            if blocklistNamedLocked(cleanName) != nil {
                throw StoreError.blocklistAlreadyExists(cleanName)
            }
            if let profileName, profileLocked(named: profileName) == nil {
                throw StoreError.profileNotFound(profileName)
            }
            let blocklist = BlocklistInfo(name: cleanName, url: url, enabled: enabled)
            try insertBlocklistLocked(blocklist)
            if let profileName, enabled {
                try executeLocked("INSERT INTO profile_blocklists(profile_name,blocklist_id) VALUES(?,?);") { stmt in
                    sqlite3_bind_text(stmt, 1, profileName, -1, SQLITE_TRANSIENT)
                    sqlite3_bind_text(stmt, 2, blocklist.id.uuidString, -1, SQLITE_TRANSIENT)
                }
            }
            try syncGlobalBlocklistEnabledLocked()
            return blocklistLocked(id: blocklist.id) ?? blocklist
        }
    }

    public func updateBlocklistURL(
        id: UUID,
        url: String,
        allowLocalhostHTTPForInjectedTest: Bool = false
    ) throws -> BlocklistInfo {
        do {
            _ = try BlocklistURLValidator.validate(url, allowLocalhostHTTPForInjectedTest: allowLocalhostHTTPForInjectedTest)
        } catch {
            throw StoreError.invalidBlocklistURL(error.localizedDescription)
        }
        return try queue.sync {
            guard var current = blocklistLocked(id: id) else { throw StoreError.blocklistNotFound(id) }
            try executeLocked("UPDATE blocklists SET url=? WHERE id=?;") { stmt in
                sqlite3_bind_text(stmt, 1, url, -1, SQLITE_TRANSIENT)
                sqlite3_bind_text(stmt, 2, id.uuidString, -1, SQLITE_TRANSIENT)
            }
            current.url = url
            return current
        }
    }

    public func deleteBlocklist(id: UUID) throws {
        try queue.sync {
            guard blocklistExistsLocked(id: id) else { throw StoreError.blocklistNotFound(id) }
            try execLocked("BEGIN IMMEDIATE;")
            do {
                try executeLocked("DELETE FROM profile_blocklists WHERE blocklist_id=?;") { stmt in
                    sqlite3_bind_text(stmt, 1, id.uuidString, -1, SQLITE_TRANSIENT)
                }
                try executeLocked("DELETE FROM blocklists WHERE id=?;") { stmt in
                    sqlite3_bind_text(stmt, 1, id.uuidString, -1, SQLITE_TRANSIENT)
                }
                try syncGlobalBlocklistEnabledLocked()
                try execLocked("COMMIT;")
            } catch {
                try? execLocked("ROLLBACK;")
                throw error
            }
        }
    }

    public func updateBlocklist(_ b: BlocklistInfo) throws {
        try queue.sync {
            guard blocklistExistsLocked(id: b.id) else { throw StoreError.blocklistNotFound(b.id) }
            try executeLocked("UPDATE blocklists SET enabled=?, last_updated=?, entry_count=? WHERE id=?;") { stmt in
                sqlite3_bind_int(stmt, 1, b.enabled ? 1 : 0)
                if let d = b.lastUpdated { sqlite3_bind_double(stmt, 2, d.timeIntervalSince1970) } else { sqlite3_bind_null(stmt, 2) }
                sqlite3_bind_int(stmt, 3, Int32(b.entryCount))
                sqlite3_bind_text(stmt, 4, b.id.uuidString, -1, SQLITE_TRANSIENT)
            }
        }
    }

    public func bindGatewayMAC(_ rawMAC: String, toProfile profileName: String) throws -> ProfileNetworkBinding {
        let canonical: String
        do {
            canonical = try GatewayMAC.canonical(rawMAC)
        } catch {
            throw ProfileValidationError.invalidGatewayMAC(error.localizedDescription)
        }
        return try queue.sync {
            guard profileLocked(named: profileName) != nil else {
                throw StoreError.profileNotFound(profileName)
            }
            let binding = ProfileNetworkBinding(profileName: profileName, gatewayMAC: canonical)
            try execLocked("BEGIN IMMEDIATE;")
            do {
                // One gateway can select only one profile. Rebinding is an
                // explicit user action, never a side effect of watching it.
                try executeLocked("DELETE FROM profile_network_bindings WHERE gateway_mac=?;") { stmt in
                    sqlite3_bind_text(stmt, 1, canonical, -1, SQLITE_TRANSIENT)
                }
                try insertNetworkBindingLocked(binding)
                try execLocked("COMMIT;")
            } catch {
                try? execLocked("ROLLBACK;")
                throw error
            }
            return binding
        }
    }

    public func unbindGatewayMAC(_ rawMAC: String) throws {
        let canonical: String
        do {
            canonical = try GatewayMAC.canonical(rawMAC)
        } catch {
            throw ProfileValidationError.invalidGatewayMAC(error.localizedDescription)
        }
        try queue.sync {
            try executeLocked("DELETE FROM profile_network_bindings WHERE gateway_mac=?;") { stmt in
                sqlite3_bind_text(stmt, 1, canonical, -1, SQLITE_TRANSIENT)
            }
        }
    }

    public func networkBinding(forGatewayMAC rawMAC: String) -> ProfileNetworkBinding? {
        guard let canonical = GatewayMAC.normalized(rawMAC) else { return nil }
        return queue.sync { networkBindingLocked(gatewayMAC: canonical) }
    }

    public func allNetworkBindings() -> [ProfileNetworkBinding] {
        queue.sync { allNetworkBindingsLocked() }
    }

    public func recordConnection(_ c: Connection) throws {
        let sql = """
        INSERT OR REPLACE INTO connections(
            id,pid,process_name,process_path,process_bundle_id,local_port,remote_host,remote_ip,
            remote_port,direction,status,protocol_name,bytes_in,bytes_out,country,country_code,
            latitude,longitude,first_seen,last_seen
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);
        """
        try execute(sql) { stmt in
            sqlite3_bind_text(stmt, 1, c.id.uuidString, -1, SQLITE_TRANSIENT)
            sqlite3_bind_int(stmt, 2, c.pid)
            sqlite3_bind_text(stmt, 3, c.processName, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 4, c.processPath, -1, SQLITE_TRANSIENT)
            bindOpt(stmt, 5, c.processBundleId)
            sqlite3_bind_int(stmt, 6, Int32(c.localPort))
            sqlite3_bind_text(stmt, 7, c.remoteHost, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 8, c.remoteIP, -1, SQLITE_TRANSIENT)
            sqlite3_bind_int(stmt, 9, Int32(c.remotePort))
            sqlite3_bind_text(stmt, 10, c.direction.rawValue, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 11, c.status.rawValue, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 12, c.protocolName, -1, SQLITE_TRANSIENT)
            sqlite3_bind_int64(stmt, 13, c.bytesIn)
            sqlite3_bind_int64(stmt, 14, c.bytesOut)
            bindOpt(stmt, 15, c.country)
            bindOpt(stmt, 16, c.countryCode)
            if let v = c.latitude { sqlite3_bind_double(stmt, 17, v) } else { sqlite3_bind_null(stmt, 17) }
            if let v = c.longitude { sqlite3_bind_double(stmt, 18, v) } else { sqlite3_bind_null(stmt, 18) }
            sqlite3_bind_double(stmt, 19, c.firstSeen.timeIntervalSince1970)
            sqlite3_bind_double(stmt, 20, c.lastSeen.timeIntervalSince1970)
        }
    }

    public func recentConnections(limit: Int = 200, status: Connection.Status? = nil) -> [Connection] {
        queue.sync {
            var out: [Connection] = []
            let sql: String
            if let s = status {
                sql = "SELECT * FROM connections WHERE status='\(s.rawValue)' ORDER BY last_seen DESC LIMIT \(limit);"
            } else {
                sql = "SELECT * FROM connections ORDER BY last_seen DESC LIMIT \(limit);"
            }
            var stmt: OpaquePointer?
            defer { if stmt != nil { sqlite3_finalize(stmt) } }
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
            while sqlite3_step(stmt) == SQLITE_ROW {
                if let c = readConn(stmt) { out.append(c) }
            }
            return out
        }
    }

    public func setSetting(_ key: String, _ value: String) throws {
        try queue.sync { try setSettingLocked(key, value) }
    }

    public func getSetting(_ key: String) -> String? {
        queue.sync { getSettingLocked(key) }
    }

    // MARK: - profile and blocklist helpers
    private func allProfilesLocked() -> [Profile] {
        var out: [Profile] = []
        var stmt: OpaquePointer?
        defer { if stmt != nil { sqlite3_finalize(stmt) } }
        guard sqlite3_prepare_v2(db, "SELECT id,name,mode,icon,is_active FROM profiles ORDER BY name;", -1, &stmt, nil) == SQLITE_OK else { return [] }
        while sqlite3_step(stmt) == SQLITE_ROW {
            let id = UUID(uuidString: text(stmt, 0)) ?? UUID()
            let name = text(stmt, 1)
            let mode = AppMode(rawValue: text(stmt, 2)) ?? .alert
            let icon = text(stmt, 3)
            let active = sqlite3_column_int(stmt, 4) == 1
            out.append(Profile(id: id, name: name, mode: mode, icon: icon, isActive: active,
                              blocklistIDs: profileBlocklistIDsLocked(profileName: name)))
        }
        return out
    }

    private func profileLocked(named name: String) -> Profile? {
        var stmt: OpaquePointer?
        defer { if stmt != nil { sqlite3_finalize(stmt) } }
        guard sqlite3_prepare_v2(db, "SELECT id,name,mode,icon,is_active FROM profiles WHERE lower(name)=lower(?) LIMIT 1;", -1, &stmt, nil) == SQLITE_OK else { return nil }
        sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        return profileFromRow(stmt)
    }

    private func profileLocked(id: UUID) -> Profile? {
        var stmt: OpaquePointer?
        defer { if stmt != nil { sqlite3_finalize(stmt) } }
        guard sqlite3_prepare_v2(db, "SELECT id,name,mode,icon,is_active FROM profiles WHERE id=? LIMIT 1;", -1, &stmt, nil) == SQLITE_OK else { return nil }
        sqlite3_bind_text(stmt, 1, id.uuidString, -1, SQLITE_TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        return profileFromRow(stmt)
    }

    private func activeProfileLocked() -> Profile? {
        var stmt: OpaquePointer?
        defer { if stmt != nil { sqlite3_finalize(stmt) } }
        guard sqlite3_prepare_v2(db, "SELECT id,name,mode,icon,is_active FROM profiles WHERE is_active=1 ORDER BY name LIMIT 1;", -1, &stmt, nil) == SQLITE_OK else { return nil }
        guard sqlite3_step(stmt) == SQLITE_ROW else { return profileLocked(named: Profile.defaultName) }
        return profileFromRow(stmt)
    }

    private func profileFromRow(_ stmt: OpaquePointer?) -> Profile {
        let id = UUID(uuidString: text(stmt, 0)) ?? UUID()
        let name = text(stmt, 1)
        let mode = AppMode(rawValue: text(stmt, 2)) ?? .alert
        let icon = text(stmt, 3)
        let active = sqlite3_column_int(stmt, 4) == 1
        return Profile(id: id, name: name, mode: mode, icon: icon, isActive: active,
                       blocklistIDs: profileBlocklistIDsLocked(profileName: name))
    }

    private func insertProfileLocked(_ profile: Profile) throws {
        try executeLocked("INSERT INTO profiles(id,name,mode,icon,is_active) VALUES (?,?,?,?,?);") { stmt in
            sqlite3_bind_text(stmt, 1, profile.id.uuidString, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 2, profile.name, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 3, profile.mode.rawValue, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 4, profile.icon, -1, SQLITE_TRANSIENT)
            sqlite3_bind_int(stmt, 5, profile.isActive ? 1 : 0)
        }
    }

    private func profileBlocklistIDsLocked(profileName: String) -> Set<UUID> {
        var out: Set<UUID> = []
        var stmt: OpaquePointer?
        defer { if stmt != nil { sqlite3_finalize(stmt) } }
        guard sqlite3_prepare_v2(db, "SELECT blocklist_id FROM profile_blocklists WHERE profile_name=?;", -1, &stmt, nil) == SQLITE_OK else { return out }
        sqlite3_bind_text(stmt, 1, profileName, -1, SQLITE_TRANSIENT)
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let id = UUID(uuidString: text(stmt, 0)) { out.insert(id) }
        }
        return out
    }

    private func replaceProfileBlocklistsLocked(profileName: String, blocklistIDs: Set<UUID>) throws {
        try executeLocked("DELETE FROM profile_blocklists WHERE profile_name=?;") { stmt in
            sqlite3_bind_text(stmt, 1, profileName, -1, SQLITE_TRANSIENT)
        }
        for id in blocklistIDs {
            try executeLocked("INSERT INTO profile_blocklists(profile_name,blocklist_id) VALUES(?,?);") { stmt in
                sqlite3_bind_text(stmt, 1, profileName, -1, SQLITE_TRANSIENT)
                sqlite3_bind_text(stmt, 2, id.uuidString, -1, SQLITE_TRANSIENT)
            }
        }
    }

    /// Keeps the legacy global `blocklists.enabled` column equal to the active
    /// profile's selection, so the existing DNS blocklist loader keeps working
    /// unchanged while selection becomes per profile. Deny sets compose, so
    /// any number of them may be selected at once.
    private func syncGlobalBlocklistEnabledLocked() throws {
        guard let active = activeProfileLocked() else { return }
        let selected = profileBlocklistIDsLocked(profileName: active.name)
        try execLocked("UPDATE blocklists SET enabled=0;")
        for id in selected {
            try executeLocked("UPDATE blocklists SET enabled=1 WHERE id=?;") { stmt in
                sqlite3_bind_text(stmt, 1, id.uuidString, -1, SQLITE_TRANSIENT)
            }
        }
    }

    private func validateBlocklistIDsLocked(_ ids: Set<UUID>) throws {
        for id in ids where !blocklistExistsLocked(id: id) {
            throw StoreError.blocklistNotFound(id)
        }
    }

    private func blocklistExistsLocked(id: UUID) -> Bool {
        blocklistLocked(id: id) != nil
    }

    private func blocklistLocked(id: UUID) -> BlocklistInfo? {
        var stmt: OpaquePointer?
        defer { if stmt != nil { sqlite3_finalize(stmt) } }
        guard sqlite3_prepare_v2(db, "SELECT id,name,url,enabled,last_updated,entry_count FROM blocklists WHERE id=? LIMIT 1;", -1, &stmt, nil) == SQLITE_OK else { return nil }
        sqlite3_bind_text(stmt, 1, id.uuidString, -1, SQLITE_TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        return blocklistFromRow(stmt)
    }

    private func blocklistNamedLocked(_ name: String) -> BlocklistInfo? {
        var stmt: OpaquePointer?
        defer { if stmt != nil { sqlite3_finalize(stmt) } }
        guard sqlite3_prepare_v2(db, "SELECT id,name,url,enabled,last_updated,entry_count FROM blocklists WHERE lower(name)=lower(?) LIMIT 1;", -1, &stmt, nil) == SQLITE_OK else { return nil }
        sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        return blocklistFromRow(stmt)
    }

    private func blocklistFromRow(_ stmt: OpaquePointer?) -> BlocklistInfo {
        let id = UUID(uuidString: text(stmt, 0)) ?? UUID()
        let name = text(stmt, 1)
        let url = text(stmt, 2)
        let enabled = sqlite3_column_int(stmt, 3) == 1
        let last: Date? = sqlite3_column_type(stmt, 4) == SQLITE_NULL ? nil : Date(timeIntervalSince1970: sqlite3_column_double(stmt, 4))
        let count = Int(sqlite3_column_int(stmt, 5))
        return BlocklistInfo(id: id, name: name, url: url, enabled: enabled, lastUpdated: last, entryCount: count)
    }

    private func allBlocklistsLocked(selectedIDs: Set<UUID>?) -> [BlocklistInfo] {
        var out: [BlocklistInfo] = []
        var stmt: OpaquePointer?
        defer { if stmt != nil { sqlite3_finalize(stmt) } }
        guard sqlite3_prepare_v2(db, "SELECT id,name,url,enabled,last_updated,entry_count FROM blocklists ORDER BY name;", -1, &stmt, nil) == SQLITE_OK else { return [] }
        while sqlite3_step(stmt) == SQLITE_ROW {
            var value = blocklistFromRow(stmt)
            if let selectedIDs { value.enabled = selectedIDs.contains(value.id) }
            out.append(value)
        }
        return out
    }

    private func insertBlocklistLocked(_ blocklist: BlocklistInfo) throws {
        try executeLocked("INSERT INTO blocklists(id,name,url,enabled,last_updated,entry_count) VALUES (?,?,?,?,?,?);") { stmt in
            sqlite3_bind_text(stmt, 1, blocklist.id.uuidString, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 2, blocklist.name, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 3, blocklist.url, -1, SQLITE_TRANSIENT)
            sqlite3_bind_int(stmt, 4, blocklist.enabled ? 1 : 0)
            if let d = blocklist.lastUpdated { sqlite3_bind_double(stmt, 5, d.timeIntervalSince1970) } else { sqlite3_bind_null(stmt, 5) }
            sqlite3_bind_int(stmt, 6, Int32(blocklist.entryCount))
        }
    }

    private func insertNetworkBindingLocked(_ binding: ProfileNetworkBinding) throws {
        try executeLocked("INSERT INTO profile_network_bindings(id,profile_name,gateway_mac,created_at) VALUES(?,?,?,?);") { stmt in
            sqlite3_bind_text(stmt, 1, binding.id.uuidString, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 2, binding.profileName, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 3, binding.gatewayMAC, -1, SQLITE_TRANSIENT)
            sqlite3_bind_double(stmt, 4, binding.createdAt.timeIntervalSince1970)
        }
    }

    private func networkBindingLocked(gatewayMAC: String) -> ProfileNetworkBinding? {
        var stmt: OpaquePointer?
        defer { if stmt != nil { sqlite3_finalize(stmt) } }
        guard sqlite3_prepare_v2(db, "SELECT id,profile_name,gateway_mac,created_at FROM profile_network_bindings WHERE gateway_mac=? LIMIT 1;", -1, &stmt, nil) == SQLITE_OK else { return nil }
        sqlite3_bind_text(stmt, 1, gatewayMAC, -1, SQLITE_TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        return ProfileNetworkBinding(
            id: UUID(uuidString: text(stmt, 0)) ?? UUID(),
            profileName: text(stmt, 1),
            gatewayMAC: text(stmt, 2),
            createdAt: Date(timeIntervalSince1970: sqlite3_column_double(stmt, 3))
        )
    }

    private func allNetworkBindingsLocked() -> [ProfileNetworkBinding] {
        var out: [ProfileNetworkBinding] = []
        var stmt: OpaquePointer?
        defer { if stmt != nil { sqlite3_finalize(stmt) } }
        guard sqlite3_prepare_v2(db, "SELECT id,profile_name,gateway_mac,created_at FROM profile_network_bindings ORDER BY created_at DESC;", -1, &stmt, nil) == SQLITE_OK else { return [] }
        while sqlite3_step(stmt) == SQLITE_ROW {
            out.append(ProfileNetworkBinding(
                id: UUID(uuidString: text(stmt, 0)) ?? UUID(),
                profileName: text(stmt, 1),
                gatewayMAC: text(stmt, 2),
                createdAt: Date(timeIntervalSince1970: sqlite3_column_double(stmt, 3))
            ))
        }
        return out
    }

    // MARK: - helpers
    private func bindOpt(_ stmt: OpaquePointer?, _ idx: Int32, _ s: String?) {
        if let s = s { sqlite3_bind_text(stmt, idx, s, -1, SQLITE_TRANSIENT) } else { sqlite3_bind_null(stmt, idx) }
    }
    private func text(_ stmt: OpaquePointer?, _ idx: Int32) -> String {
        guard let p = sqlite3_column_text(stmt, idx) else { return "" }
        return String(cString: p)
    }
    private func textOpt(_ stmt: OpaquePointer?, _ idx: Int32) -> String? {
        if sqlite3_column_type(stmt, idx) == SQLITE_NULL { return nil }
        return text(stmt, idx)
    }
    private func readRule(_ stmt: OpaquePointer?) -> Rule? {
        let id = UUID(uuidString: text(stmt, 0)) ?? UUID()
        let bundleId = textOpt(stmt, 1)
        let path = textOpt(stmt, 2)
        let name = textOpt(stmt, 3)
        let host = textOpt(stmt, 4)
        let ip = textOpt(stmt, 5)
        let port: Int? = sqlite3_column_type(stmt, 6) == SQLITE_NULL ? nil : Int(sqlite3_column_int(stmt, 6))
        let dir = RuleDirection(rawValue: text(stmt, 7)) ?? .outgoing
        let action = RuleAction(rawValue: text(stmt, 8)) ?? .ask
        let scope = RuleScope(rawValue: text(stmt, 9)) ?? .domain
        let priority = Int(sqlite3_column_int(stmt, 10))
        let profile = text(stmt, 11)
        let group = textOpt(stmt, 12)
        let notes = textOpt(stmt, 13)
        let enabled = sqlite3_column_int(stmt, 14) == 1
        let temp = sqlite3_column_int(stmt, 15) == 1
        let created = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 16))
        let exp: Date? = sqlite3_column_type(stmt, 17) == SQLITE_NULL ? nil : Date(timeIntervalSince1970: sqlite3_column_double(stmt, 17))
        let last: Date? = sqlite3_column_type(stmt, 18) == SQLITE_NULL ? nil : Date(timeIntervalSince1970: sqlite3_column_double(stmt, 18))
        let hits = Int(sqlite3_column_int(stmt, 19))
        return Rule(id: id, processBundleId: bundleId, processPath: path, processName: name, remoteHost: host, remoteIP: ip, remotePort: port, direction: dir, action: action, scope: scope, priority: priority, profile: profile, groupName: group, notes: notes, enabled: enabled, temporary: temp, createdAt: created, expiresAt: exp, lastUsedAt: last, hitCount: hits)
    }
    private func readConn(_ stmt: OpaquePointer?) -> Connection? {
        let id = UUID(uuidString: text(stmt, 0)) ?? UUID()
        let pid = sqlite3_column_int(stmt, 1)
        let pname = text(stmt, 2)
        let ppath = text(stmt, 3)
        let bid = textOpt(stmt, 4)
        let lp = Int(sqlite3_column_int(stmt, 5))
        let host = text(stmt, 6)
        let ip = text(stmt, 7)
        let rp = Int(sqlite3_column_int(stmt, 8))
        let dir = RuleDirection(rawValue: text(stmt, 9)) ?? .outgoing
        let status = Connection.Status(rawValue: text(stmt, 10)) ?? .established
        let proto = text(stmt, 11)
        let bin = sqlite3_column_int64(stmt, 12)
        let bout = sqlite3_column_int64(stmt, 13)
        let cn = textOpt(stmt, 14)
        let cc = textOpt(stmt, 15)
        let lat: Double? = sqlite3_column_type(stmt, 16) == SQLITE_NULL ? nil : sqlite3_column_double(stmt, 16)
        let lon: Double? = sqlite3_column_type(stmt, 17) == SQLITE_NULL ? nil : sqlite3_column_double(stmt, 17)
        let fs = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 18))
        let ls = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 19))
        return Connection(id: id, pid: pid, processName: pname, processPath: ppath, processBundleId: bid, localPort: lp, remoteHost: host, remoteIP: ip, remotePort: rp, direction: dir, status: status, protocolName: proto, bytesIn: bin, bytesOut: bout, country: cn, countryCode: cc, latitude: lat, longitude: lon, firstSeen: fs, lastSeen: ls)
    }
}
