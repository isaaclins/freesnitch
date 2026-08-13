import Foundation
import SQLite3
import Darwin

private let insightsSQLiteTransient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

/// Root-owned evidence storage. Evidence is separate from RuleStore and is not
/// placed in the user's app-group state.
final class InsightsStore: @unchecked Sendable {
    static let defaultPath = "/Library/Application Support/FreeSnitch/Insights/insights.sqlite"

    private var db: OpaquePointer?
    private let queue = DispatchQueue(label: "io.isaaclins.freesnitch.insights-store")
    private let fileManager = FileManager.default
    private let expectedUID: uid_t
    let path: String

    init(path: String = InsightsStore.defaultPath, expectedUID: uid_t = 0) throws {
        self.path = URL(fileURLWithPath: path).standardizedFileURL.path
        self.expectedUID = expectedUID
        try open()
    }

    deinit {
        if let db { sqlite3_close(db) }
    }

    var recordingEnabled: Bool {
        queue.sync { (try? settingLocked("recording_enabled")) != "0" }
    }

    func setRecordingEnabled(_ enabled: Bool) throws {
        try queue.sync {
            try executeLocked("INSERT OR REPLACE INTO settings(key,value) VALUES('recording_enabled',?);") { statement in
                try self.bindText(statement, index: 1, value: enabled ? "1" : "0")
            }
        }
    }

    func record(_ observations: [FlowObservation]) throws {
        guard !observations.isEmpty else { return }
        try queue.sync {
            guard try settingLocked("recording_enabled") != "0" else { return }
            for observation in observations { try observation.validate() }
            try executeLocked("BEGIN IMMEDIATE;")
            do {
                for observation in observations {
                    try insertLocked(observation)
                    try rollupLocked(observation)
                }
                try executeLocked("COMMIT;")
                try verifyDatabaseFilesLocked()
            } catch {
                _ = try? executeLocked("ROLLBACK;")
                throw error
            }
        }
    }

    func recordDNSMappings(_ mappings: [DNSMapping]) throws {
        guard !mappings.isEmpty else { return }
        try queue.sync {
            guard try settingLocked("recording_enabled") != "0" else { return }
            for mapping in mappings { try mapping.validate() }
            try executeLocked("BEGIN IMMEDIATE;")
            do {
                for mapping in mappings { try upsertDNSMappingLocked(mapping) }
                try executeLocked("COMMIT;")
                try verifyDatabaseFilesLocked()
            } catch {
                _ = try? executeLocked("ROLLBACK;")
                throw error
            }
        }
    }

    /// Deletes expired raw evidence and old UTC-day rollups. Call this from a
    /// helper maintenance queue, never from an XPC reply callback.
    func prune(now: Date = Date()) throws {
        try queue.sync {
            let rawCutoff = now.timeIntervalSince1970 - InsightsLimits.rawRetention
            let dayCutoff = utcDay(for: now.addingTimeInterval(-Double(InsightsLimits.rollupRetentionDays) * 24 * 60 * 60))
            try executeLocked("BEGIN IMMEDIATE;")
            do {
                try executeLocked("DELETE FROM flow_observations WHERE observed_at < ?;") { statement in
                    try self.bindDouble(statement, index: 1, value: rawCutoff)
                }
                // The DNS answer map is evidence, not a resolver cache. Its
                // TTL says when the answer stops being routable, not when the
                // observation stops being true, and deleting it at TTL would
                // erase every destination name minutes after it was learned and
                // make almost every address look unresolved. It therefore ages
                // out with the raw events it explains.
                try executeLocked("DELETE FROM dns_mappings WHERE observed_at < ?;") { statement in
                    try self.bindDouble(statement, index: 1, value: rawCutoff)
                }
                try executeLocked("DELETE FROM daily_rollups WHERE utc_day < ?;") { statement in
                    try self.bindText(statement, index: 1, value: dayCutoff)
                }
                try executeLocked("DELETE FROM versioned_rollups WHERE utc_day < ?;") { statement in
                    try self.bindText(statement, index: 1, value: dayCutoff)
                }
                try executeLocked("COMMIT;")
                try verifyDatabaseFilesLocked()
            } catch {
                _ = try? executeLocked("ROLLBACK;")
                throw error
            }
        }
    }

    /// Close first so SQLite releases WAL/SHM handles, remove all three files,
    /// and reopen a clean schema.
    func purge() throws {
        try queue.sync {
            guard let current = db else { throw storeError("database is closed") }
            let result = sqlite3_close(current)
            guard result == SQLITE_OK else { throw storeError("database close failed: \(result)") }
            db = nil
            do {
                for suffix in ["", "-wal", "-shm"] {
                    let file = path + suffix
                    var info = stat()
                    if lstat(file, &info) == 0 {
                        guard (info.st_mode & S_IFMT) == S_IFREG,
                              info.st_uid == expectedUID,
                              (info.st_mode & 0o7777) == 0o600 else {
                            throw storeError("refusing insecure purge path: \(file)")
                        }
                        try fileManager.removeItem(atPath: file)
                    } else if errno != ENOENT {
                        throw storeError("cannot inspect purge path: \(file)")
                    }
                }
                try openLocked()
            } catch {
                db = nil
                throw error
            }
        }
    }

    private func open() throws {
        try queue.sync { try openLocked() }
    }

    private func openLocked() throws {
        let directory = (path as NSString).deletingLastPathComponent
        let sharedParent = (directory as NSString).deletingLastPathComponent
        try secureSharedParent(sharedParent)
        try secureDirectory(directory)
        let existingFiles = try inspectExistingDatabaseFiles()

        var handle: OpaquePointer?
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
        let openResult = sqlite3_open_v2(path, &handle, flags, nil)
        guard openResult == SQLITE_OK, let handle else {
            let message = handle.map { String(cString: sqlite3_errmsg($0)) } ?? "database open failed"
            if let handle { sqlite3_close(handle) }
            throw storeError("\(message) (sqlite code \(openResult))")
        }
        db = handle
        do {
            if !existingFiles.contains(path) { try secureNewPath(path, mode: 0o600) }
            try execLocked("PRAGMA journal_mode=WAL;")
            try execLocked("PRAGMA synchronous=NORMAL;")
            try execLocked("""
                CREATE TABLE IF NOT EXISTS flow_observations (
                    id TEXT PRIMARY KEY,
                    observed_at REAL NOT NULL,
                    pid INTEGER NOT NULL,
                    process_bundle_id TEXT,
                    process_path TEXT NOT NULL,
                    process_name TEXT NOT NULL,
                    process_version TEXT,
                    remote_host TEXT NOT NULL,
                    remote_ip TEXT NOT NULL,
                    remote_port INTEGER NOT NULL,
                    direction TEXT NOT NULL,
                    protocol_name TEXT NOT NULL,
                    bytes_in INTEGER,
                    bytes_out INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_insights_observed_at ON flow_observations(observed_at);
                CREATE TABLE IF NOT EXISTS dns_mappings (
                    domain TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    observed_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY(domain, ip)
                );
                CREATE INDEX IF NOT EXISTS idx_insights_dns_domain ON dns_mappings(domain);
                CREATE INDEX IF NOT EXISTS idx_insights_dns_expiry ON dns_mappings(expires_at);
                CREATE INDEX IF NOT EXISTS idx_insights_dns_ip ON dns_mappings(ip);
                CREATE INDEX IF NOT EXISTS idx_insights_destination ON flow_observations(remote_host, remote_ip);
                CREATE TABLE IF NOT EXISTS versioned_rollups (
                    app_identity TEXT NOT NULL,
                    app_version TEXT NOT NULL,
                    destination_key TEXT NOT NULL,
                    utc_day TEXT NOT NULL,
                    connection_count INTEGER NOT NULL,
                    PRIMARY KEY(app_identity, app_version, destination_key, utc_day)
                );
                CREATE INDEX IF NOT EXISTS idx_insights_versioned_rollup_app ON versioned_rollups(app_identity, app_version);
                CREATE TABLE IF NOT EXISTS daily_rollups (
                    app_identity TEXT NOT NULL,
                    destination_key TEXT NOT NULL,
                    utc_day TEXT NOT NULL,
                    connection_count INTEGER NOT NULL,
                    PRIMARY KEY(app_identity, destination_key, utc_day)
                );
                CREATE INDEX IF NOT EXISTS idx_insights_rollup_day ON daily_rollups(utc_day);
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                INSERT OR IGNORE INTO settings(key,value) VALUES('recording_enabled','1');
                """)
            // Rollups carry bytes as well as counts. Older stores were created
            // before those columns existed, so they are added in place rather
            // than requiring a purge.
            try addColumnIfMissingLocked(table: "flow_observations", column: "process_version")
            try addColumnIfMissingLocked(table: "daily_rollups", column: "bytes_in")
            try addColumnIfMissingLocked(table: "daily_rollups", column: "bytes_out")
            try verifyDatabaseFilesLocked()
        } catch {
            sqlite3_close(handle)
            db = nil
            throw error
        }
    }

    private func insertLocked(_ observation: FlowObservation) throws {
        try executeLocked("""
            INSERT OR IGNORE INTO flow_observations(
                id,observed_at,pid,process_bundle_id,process_path,process_name,process_version,
                remote_host,remote_ip,remote_port,direction,protocol_name,bytes_in,bytes_out
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?);
            """) { statement in
                try self.bindText(statement, index: 1, value: observation.id.uuidString)
                try self.bindDouble(statement, index: 2, value: observation.observedAt.timeIntervalSince1970)
                try self.bindInt(statement, index: 3, value: observation.pid)
                try self.bindOptionalText(statement, index: 4, value: observation.processBundleId)
                try self.bindText(statement, index: 5, value: observation.processPath)
                try self.bindText(statement, index: 6, value: observation.processName)
                try self.bindOptionalText(statement, index: 7, value: observation.processVersion)
                try self.bindText(statement, index: 8, value: observation.remoteHost)
                try self.bindText(statement, index: 9, value: observation.remoteIP)
                try self.bindInt(statement, index: 10, value: Int32(observation.remotePort))
                try self.bindText(statement, index: 11, value: observation.direction.rawValue)
                try self.bindText(statement, index: 12, value: observation.protocolName)
                try self.bindOptionalInt64(statement, index: 13, value: observation.bytesIn)
                try self.bindOptionalInt64(statement, index: 14, value: observation.bytesOut)
            }
    }

    private func upsertDNSMappingLocked(_ mapping: DNSMapping) throws {
        try executeLocked("""
            INSERT INTO dns_mappings(domain,ip,observed_at,expires_at) VALUES(?,?,?,?)
            ON CONFLICT(domain,ip) DO UPDATE SET
                observed_at=excluded.observed_at,
                expires_at=excluded.expires_at
            WHERE excluded.expires_at > dns_mappings.expires_at;
            """) { statement in
                try self.bindText(statement, index: 1, value: mapping.domain)
                try self.bindText(statement, index: 2, value: mapping.ip)
                try self.bindDouble(statement, index: 3, value: mapping.observedAt.timeIntervalSince1970)
                try self.bindDouble(statement, index: 4, value: mapping.expiresAt.timeIntervalSince1970)
            }
    }

    private func rollupLocked(_ observation: FlowObservation) throws {
        let app = observation.processBundleId?.isEmpty == false
            ? observation.processBundleId!
            : observation.processPath
        let destination = PFHostValidator.kind(for: observation.remoteHost) == .hostname
            ? observation.remoteHost
            : observation.remoteIP
        guard !app.isEmpty, !destination.isEmpty else { return }
        try executeLocked("""
            INSERT INTO daily_rollups(app_identity,destination_key,utc_day,connection_count,bytes_in,bytes_out)
            VALUES (?,?,?,1,?,?)
            ON CONFLICT(app_identity,destination_key,utc_day)
            DO UPDATE SET connection_count=connection_count+1,
                          bytes_in=bytes_in+excluded.bytes_in,
                          bytes_out=bytes_out+excluded.bytes_out;
            """) { statement in
                try self.bindText(statement, index: 1, value: app)
                try self.bindText(statement, index: 2, value: destination)
                try self.bindText(statement, index: 3, value: self.utcDay(for: observation.observedAt))
                try self.bindInt64(statement, index: 4, value: observation.bytesIn ?? 0)
                try self.bindInt64(statement, index: 5, value: observation.bytesOut ?? 0)
            }
        if let version = observation.processVersion {
            try executeLocked("""
                INSERT INTO versioned_rollups(app_identity,app_version,destination_key,utc_day,connection_count)
                VALUES (?,?,?,?,1)
                ON CONFLICT(app_identity,app_version,destination_key,utc_day)
                DO UPDATE SET connection_count=connection_count+1;
                """) { statement in
                    try self.bindText(statement, index: 1, value: app)
                    try self.bindText(statement, index: 2, value: version)
                    try self.bindText(statement, index: 3, value: destination)
                    try self.bindText(statement, index: 4, value: self.utcDay(for: observation.observedAt))
                }
        }
    }

    private func addColumnIfMissingLocked(table: String, column: String) throws {
        var present = false
        try queryLocked("PRAGMA table_info(\(table));") { statement in
            if let name = self.columnText(statement, index: 1), name == column { present = true }
        }
        guard !present else { return }
        try execLocked("ALTER TABLE \(table) ADD COLUMN \(column) INTEGER NOT NULL DEFAULT 0;")
    }

    private func settingLocked(_ key: String) throws -> String? {
        var statement: OpaquePointer?
        defer { if let statement { sqlite3_finalize(statement) } }
        try prepareLocked("SELECT value FROM settings WHERE key=?;", statement: &statement)
        try bindText(statement, index: 1, value: key)
        let result = sqlite3_step(statement)
        if result == SQLITE_DONE { return nil }
        guard result == SQLITE_ROW else { throw storeError(sqliteMessage()) }
        guard let value = sqlite3_column_text(statement, 0) else { throw storeError("setting value is null") }
        return String(cString: value)
    }

    private func executeLocked(_ sql: String, bind: ((OpaquePointer?) throws -> Void)? = nil) throws {
        var statement: OpaquePointer?
        defer { if let statement { sqlite3_finalize(statement) } }
        try prepareLocked(sql, statement: &statement)
        try bind?(statement)
        guard sqlite3_step(statement) == SQLITE_DONE else { throw storeError(sqliteMessage()) }
    }

    private func prepareLocked(_ sql: String, statement: inout OpaquePointer?) throws {
        let result = sqlite3_prepare_v2(db, sql, -1, &statement, nil)
        guard result == SQLITE_OK else { throw storeError(sqliteMessage(code: result)) }
    }

    private func execLocked(_ sql: String) throws {
        var error: UnsafeMutablePointer<CChar>?
        let result = sqlite3_exec(db, sql, nil, nil, &error)
        guard result == SQLITE_OK else {
            let message = error.map { String(cString: $0) } ?? sqliteMessage(code: result)
            sqlite3_free(error)
            throw storeError(message)
        }
    }

    private func bindText(_ statement: OpaquePointer?, index: Int32, value: String) throws {
        guard sqlite3_bind_text(statement, index, value, -1, insightsSQLiteTransient) == SQLITE_OK else {
            throw storeError(sqliteMessage())
        }
    }

    private func bindOptionalText(_ statement: OpaquePointer?, index: Int32, value: String?) throws {
        if let value { try bindText(statement, index: index, value: value) }
        else { try bindNull(statement, index: index) }
    }

    private func bindDouble(_ statement: OpaquePointer?, index: Int32, value: Double) throws {
        guard sqlite3_bind_double(statement, index, value) == SQLITE_OK else { throw storeError(sqliteMessage()) }
    }

    private func bindInt(_ statement: OpaquePointer?, index: Int32, value: Int32) throws {
        guard sqlite3_bind_int(statement, index, value) == SQLITE_OK else { throw storeError(sqliteMessage()) }
    }

    private func bindOptionalInt64(_ statement: OpaquePointer?, index: Int32, value: Int64?) throws {
        if let value { try bindInt64(statement, index: index, value: value) }
        else { try bindNull(statement, index: index) }
    }

    private func bindInt64(_ statement: OpaquePointer?, index: Int32, value: Int64) throws {
        guard sqlite3_bind_int64(statement, index, value) == SQLITE_OK else { throw storeError(sqliteMessage()) }
    }

    private func bindNull(_ statement: OpaquePointer?, index: Int32) throws {
        guard sqlite3_bind_null(statement, index) == SQLITE_OK else { throw storeError(sqliteMessage()) }
    }

    private func secureSharedParent(_ directory: String) throws {
        var info = stat()
        guard lstat(directory, &info) == 0 else {
            throw storeError("shared support directory is missing: \(directory)")
        }
        guard (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == expectedUID,
              (info.st_mode & 0o022) == 0 else {
            throw storeError("insecure shared support directory: \(directory)")
        }
    }

    private func secureDirectory(_ directory: String) throws {
        var info = stat()
        if lstat(directory, &info) == 0 {
            try verifyPath(directory, info: info, kind: S_IFDIR, mode: 0o700)
            return
        }
        guard errno == ENOENT else { throw storeError("cannot inspect Insights directory") }
        try fileManager.createDirectory(atPath: directory, withIntermediateDirectories: false,
                                        attributes: [.posixPermissions: 0o700])
        try secureNewPath(directory, mode: 0o700, kind: S_IFDIR)
    }

    private func inspectExistingDatabaseFiles() throws -> Set<String> {
        var existing = Set<String>()
        for suffix in ["", "-wal", "-shm"] {
            let file = path + suffix
            var info = stat()
            if lstat(file, &info) == 0 {
                try verifyPath(file, info: info, kind: S_IFREG, mode: 0o600)
                existing.insert(file)
            } else if errno != ENOENT {
                throw storeError("cannot inspect store file: \(file)")
            }
        }
        return existing
    }

    private func secureNewPath(_ file: String, mode: Int16, kind: mode_t? = nil) throws {
        guard chown(file, expectedUID, gid_t.max) == 0 else { throw storeError("cannot set owner: \(file)") }
        guard chmod(file, mode_t(mode)) == 0 else { throw storeError("cannot set mode: \(file)") }
        var info = stat()
        guard lstat(file, &info) == 0 else { throw storeError("cannot verify path: \(file)") }
        try verifyPath(file, info: info, kind: kind ?? S_IFREG, mode: mode)
    }

    private func verifyPath(_ file: String, info: stat, kind: mode_t, mode: Int16) throws {
        guard (info.st_mode & S_IFMT) == kind,
              info.st_uid == expectedUID,
              (info.st_mode & 0o7777) == mode_t(mode) else {
            throw storeError("insecure owner, type, or mode: \(file)")
        }
    }

    private func verifyDatabaseFilesLocked() throws {
        for suffix in ["", "-wal", "-shm"] {
            let file = path + suffix
            var info = stat()
            if lstat(file, &info) == 0 {
                try verifyPath(file, info: info, kind: S_IFREG, mode: 0o600)
            } else if errno != ENOENT {
                throw storeError("cannot inspect database companion: \(file)")
            }
        }
    }

    private func sqliteMessage(code: Int32? = nil) -> String {
        if let db { return String(cString: sqlite3_errmsg(db)) }
        return "sqlite error\(code.map { " (code \($0))" } ?? "")"
    }

    private func utcDay(for date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withFullDate]
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        return formatter.string(from: date)
    }

    private func storeError(_ message: String) -> NSError {
        NSError(domain: "InsightsStore", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}

// MARK: - Bounded read API
//
// Every query here is paginated and every range is bounded by the caller's
// validated `InsightsQuery`. A year of rollups is never materialised: rows are
// aggregated by SQLite and one page at a time is handed back.
//
// Nothing in this section re-validates the CONTENT of stored rows. Bounds are
// enforced on the request and on the encoded payload; judging stored content on
// the way out is what hid every rule from the user in #57.
extension InsightsStore {
    /// Raw events carry per-flow detail for 14 days. Older ranges can only be
    /// answered by the daily rollups.
    private static func source(for query: InsightsQuery, now: Date) -> InsightsDataSource {
        query.since >= now.addingTimeInterval(-InsightsLimits.rawRetention) ? .rawEvents : .dailyRollups
    }

    private static let appIdentitySQL = "COALESCE(NULLIF(process_bundle_id,''), process_path)"
    /// The hostname the app asked for when one was recorded, otherwise the
    /// address it connected to.
    private static let destinationSQL =
        "CASE WHEN remote_host <> '' AND remote_host <> remote_ip THEN remote_host ELSE remote_ip END"

    func report(for query: InsightsQuery, now: Date = Date()) throws -> InsightsReport {
        try query.validate(now: now)
        return try queue.sync {
            let source = Self.source(for: query, now: now)
            let recording = (try? settingLocked("recording_enabled")) != "0"
            let page: (apps: [InsightsAppSummary],
                       destinations: [InsightsDestinationSummary],
                       unresolved: [InsightsUnresolvedDestination],
                       proposals: [InsightsProposedRule],
                       findings: [InsightsBehaviourFinding],
                       overview: InsightsOverview?,
                       hasMore: Bool)
            switch query.kind {
            case .apps:
                let result = try appsLocked(query, source: source)
                page = (result.rows, [], [], [], [], nil, result.hasMore)
            case .destinations:
                let result = try destinationsLocked(query, source: source)
                page = ([], result.rows, [], [], [], nil, result.hasMore)
            case .unresolved:
                let result = try unresolvedLocked(query, source: source)
                page = ([], [], result.rows, [], [], nil, result.hasMore)
            case .proposals:
                let result = try proposalsLocked(query, source: source)
                page = ([], [], [], result.rows, [], nil, result.hasMore)
            case .findings:
                let result = try findingsLocked(query, source: source)
                page = ([], [], [], [], result.rows, nil, result.hasMore)
            case .overview:
                page = ([], [], [], [], [], try overviewLocked(recordingEnabled: recording), false)
            }
            return InsightsReport(kind: query.kind,
                                  generatedAt: now,
                                  rangeStart: query.since,
                                  rangeEnd: query.until,
                                  source: source,
                                  recordingEnabled: recording,
                                  limit: query.limit,
                                  offset: query.offset,
                                  hasMore: page.hasMore,
                                  apps: page.apps,
                                  destinations: page.destinations,
                                  unresolved: page.unresolved,
                                  proposals: page.proposals,
                                  findings: page.findings,
                                  overview: page.overview)
        }
    }

    // MARK: Apps

    private func appsLocked(_ query: InsightsQuery,
                            source: InsightsDataSource) throws -> (rows: [InsightsAppSummary], hasMore: Bool) {
        var rows: [InsightsAppSummary] = []
        switch source {
        case .rawEvents:
            let sql = """
                SELECT \(Self.appIdentitySQL) AS app,
                       MAX(process_name), MAX(process_bundle_id), MAX(process_path),
                       COUNT(DISTINCT \(Self.destinationSQL)),
                       COUNT(*), COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0), MAX(observed_at)
                FROM flow_observations
                WHERE observed_at >= ? AND observed_at <= ?
                GROUP BY app
                ORDER BY COUNT(*) DESC, app ASC
                LIMIT ? OFFSET ?;
                """
            try queryLocked(sql, bind: { statement in
                try self.bindRawRange(statement, query: query)
                try self.bindPage(statement, query: query, firstIndex: 3)
            }) { statement in
                guard let identity = self.columnText(statement, index: 0), !identity.isEmpty else { return }
                rows.append(InsightsAppSummary(
                    appIdentity: identity,
                    displayName: self.columnText(statement, index: 1) ?? Self.fallbackName(for: identity),
                    processBundleId: self.columnText(statement, index: 2),
                    processPath: self.columnText(statement, index: 3),
                    destinationCount: Int(self.columnInt64(statement, index: 4)),
                    connectionCount: Int(self.columnInt64(statement, index: 5)),
                    bytesIn: self.columnInt64(statement, index: 6),
                    bytesOut: self.columnInt64(statement, index: 7),
                    lastSeen: self.columnDate(statement, index: 8)))
            }
        case .dailyRollups:
            let sql = """
                SELECT app_identity, COUNT(DISTINCT destination_key), SUM(connection_count),
                       COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0), MAX(utc_day)
                FROM daily_rollups
                WHERE utc_day >= ? AND utc_day <= ?
                GROUP BY app_identity
                ORDER BY SUM(connection_count) DESC, app_identity ASC
                LIMIT ? OFFSET ?;
                """
            try queryLocked(sql, bind: { statement in
                try self.bindDayRange(statement, query: query)
                try self.bindPage(statement, query: query, firstIndex: 3)
            }) { statement in
                guard let identity = self.columnText(statement, index: 0), !identity.isEmpty else { return }
                rows.append(InsightsAppSummary(
                    appIdentity: identity,
                    displayName: Self.fallbackName(for: identity),
                    processBundleId: identity.hasPrefix("/") ? nil : identity,
                    processPath: identity.hasPrefix("/") ? identity : nil,
                    destinationCount: Int(self.columnInt64(statement, index: 1)),
                    connectionCount: Int(self.columnInt64(statement, index: 2)),
                    bytesIn: self.columnInt64(statement, index: 3),
                    bytesOut: self.columnInt64(statement, index: 4),
                    lastSeen: self.columnText(statement, index: 5).flatMap(self.date(fromUTCDay:))))
            }
        }
        return trim(rows, limit: query.limit)
    }

    // MARK: Destinations

    private func destinationsLocked(_ query: InsightsQuery,
                                    source: InsightsDataSource) throws -> (rows: [InsightsDestinationSummary], hasMore: Bool) {
        guard let app = query.appIdentity else { return ([], false) }
        var raw: [(key: String, ip: String?, count: Int, bytesIn: Int64, bytesOut: Int64, lastSeen: Date?)] = []
        switch source {
        case .rawEvents:
            let sql = """
                SELECT \(Self.destinationSQL) AS dest, MAX(remote_ip),
                       COUNT(*), COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0), MAX(observed_at)
                FROM flow_observations
                WHERE observed_at >= ? AND observed_at <= ? AND \(Self.appIdentitySQL) = ?
                GROUP BY dest
                ORDER BY COUNT(*) DESC, dest ASC
                LIMIT ? OFFSET ?;
                """
            try queryLocked(sql, bind: { statement in
                try self.bindRawRange(statement, query: query)
                try self.bindText(statement, index: 3, value: app)
                try self.bindPage(statement, query: query, firstIndex: 4)
            }) { statement in
                guard let key = self.columnText(statement, index: 0), !key.isEmpty else { return }
                raw.append((key,
                            self.columnText(statement, index: 1),
                            Int(self.columnInt64(statement, index: 2)),
                            self.columnInt64(statement, index: 3),
                            self.columnInt64(statement, index: 4),
                            self.columnDate(statement, index: 5)))
            }
        case .dailyRollups:
            let sql = """
                SELECT destination_key, SUM(connection_count),
                       COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0), MAX(utc_day)
                FROM daily_rollups
                WHERE utc_day >= ? AND utc_day <= ? AND app_identity = ?
                GROUP BY destination_key
                ORDER BY SUM(connection_count) DESC, destination_key ASC
                LIMIT ? OFFSET ?;
                """
            try queryLocked(sql, bind: { statement in
                try self.bindDayRange(statement, query: query)
                try self.bindText(statement, index: 3, value: app)
                try self.bindPage(statement, query: query, firstIndex: 4)
            }) { statement in
                guard let key = self.columnText(statement, index: 0), !key.isEmpty else { return }
                raw.append((key,
                            nil,
                            Int(self.columnInt64(statement, index: 1)),
                            self.columnInt64(statement, index: 2),
                            self.columnInt64(statement, index: 3),
                            self.columnText(statement, index: 4).flatMap(self.date(fromUTCDay:))))
            }
        }

        var rows: [InsightsDestinationSummary] = []
        rows.reserveCapacity(raw.count)
        for entry in raw {
            rows.append(InsightsDestinationSummary(
                appIdentity: app,
                destinationKey: entry.key,
                resolvedDomain: try resolvedDomainLocked(key: entry.key, remoteIP: entry.ip),
                remoteIP: entry.ip?.isEmpty == false ? entry.ip : (PFHostValidator.kind(for: entry.key) == .ip ? entry.key : nil),
                connectionCount: entry.count,
                bytesIn: entry.bytesIn,
                bytesOut: entry.bytesOut,
                otherAppCount: try otherAppCountLocked(destination: entry.key, excluding: app, query: query, source: source),
                lastSeen: entry.lastSeen))
        }
        return trim(rows, limit: query.limit)
    }

    /// Co-occurrence only: how many OTHER apps reached the same destination in
    /// the same range. It reports what was observed and claims nothing else.
    private func otherAppCountLocked(destination: String,
                                     excluding app: String,
                                     query: InsightsQuery,
                                     source: InsightsDataSource) throws -> Int {
        var count = 0
        switch source {
        case .rawEvents:
            let sql = """
                SELECT COUNT(DISTINCT \(Self.appIdentitySQL))
                FROM flow_observations
                WHERE observed_at >= ? AND observed_at <= ?
                  AND \(Self.destinationSQL) = ? AND \(Self.appIdentitySQL) <> ?;
                """
            try queryLocked(sql, bind: { statement in
                try self.bindRawRange(statement, query: query)
                try self.bindText(statement, index: 3, value: destination)
                try self.bindText(statement, index: 4, value: app)
            }) { statement in
                count = Int(self.columnInt64(statement, index: 0))
            }
        case .dailyRollups:
            let sql = """
                SELECT COUNT(DISTINCT app_identity)
                FROM daily_rollups
                WHERE utc_day >= ? AND utc_day <= ?
                  AND destination_key = ? AND app_identity <> ?;
                """
            try queryLocked(sql, bind: { statement in
                try self.bindDayRange(statement, query: query)
                try self.bindText(statement, index: 3, value: destination)
                try self.bindText(statement, index: 4, value: app)
            }) { statement in
                count = Int(self.columnInt64(statement, index: 0))
            }
        }
        return count
    }

    // MARK: Unresolved addresses

    private func unresolvedLocked(_ query: InsightsQuery,
                                  source: InsightsDataSource) throws -> (rows: [InsightsUnresolvedDestination], hasMore: Bool) {
        var rows: [InsightsUnresolvedDestination] = []
        switch source {
        case .rawEvents:
            let sql = """
                SELECT remote_ip, COUNT(*), COUNT(DISTINCT \(Self.appIdentitySQL)),
                       COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0), MAX(observed_at)
                FROM flow_observations
                WHERE observed_at >= ? AND observed_at <= ?
                  AND remote_ip <> ''
                  AND (remote_host = '' OR remote_host = remote_ip)
                  AND NOT EXISTS (SELECT 1 FROM dns_mappings WHERE dns_mappings.ip = flow_observations.remote_ip)
                GROUP BY remote_ip
                ORDER BY COUNT(*) DESC, remote_ip ASC
                LIMIT ? OFFSET ?;
                """
            var pending: [(ip: String, count: Int, apps: Int, bytesIn: Int64, bytesOut: Int64, lastSeen: Date?)] = []
            try queryLocked(sql, bind: { statement in
                try self.bindRawRange(statement, query: query)
                try self.bindPage(statement, query: query, firstIndex: 3)
            }) { statement in
                guard let ip = self.columnText(statement, index: 0), !ip.isEmpty else { return }
                pending.append((ip,
                                Int(self.columnInt64(statement, index: 1)),
                                Int(self.columnInt64(statement, index: 2)),
                                self.columnInt64(statement, index: 3),
                                self.columnInt64(statement, index: 4),
                                self.columnDate(statement, index: 5)))
            }
            for entry in pending {
                rows.append(InsightsUnresolvedDestination(
                    remoteIP: entry.ip,
                    connectionCount: entry.count,
                    appCount: entry.apps,
                    appNames: try unresolvedAppNamesLocked(ip: entry.ip, query: query),
                    bytesIn: entry.bytesIn,
                    bytesOut: entry.bytesOut,
                    lastSeen: entry.lastSeen))
            }
        case .dailyRollups:
            let sql = """
                SELECT destination_key, SUM(connection_count), COUNT(DISTINCT app_identity),
                       COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0), MAX(utc_day)
                FROM daily_rollups
                WHERE utc_day >= ? AND utc_day <= ?
                  AND NOT EXISTS (SELECT 1 FROM dns_mappings WHERE dns_mappings.ip = daily_rollups.destination_key)
                GROUP BY destination_key
                ORDER BY SUM(connection_count) DESC, destination_key ASC
                LIMIT ? OFFSET ?;
                """
            try queryLocked(sql, bind: { statement in
                try self.bindDayRange(statement, query: query)
                try self.bindPage(statement, query: query, firstIndex: 3)
            }) { statement in
                // A rollup key is a hostname when one was known, and SQLite
                // cannot tell the two apart, so the address test happens here.
                guard let key = self.columnText(statement, index: 0),
                      PFHostValidator.kind(for: key) == .ip else { return }
                rows.append(InsightsUnresolvedDestination(
                    remoteIP: key,
                    connectionCount: Int(self.columnInt64(statement, index: 1)),
                    appCount: Int(self.columnInt64(statement, index: 2)),
                    appNames: [],
                    bytesIn: self.columnInt64(statement, index: 3),
                    bytesOut: self.columnInt64(statement, index: 4),
                    lastSeen: self.columnText(statement, index: 5).flatMap(self.date(fromUTCDay:))))
            }
        }
        return trim(rows, limit: query.limit)
    }

    private func unresolvedAppNamesLocked(ip: String, query: InsightsQuery) throws -> [String] {
        var names: [String] = []
        let sql = """
            SELECT DISTINCT process_name FROM flow_observations
            WHERE observed_at >= ? AND observed_at <= ? AND remote_ip = ?
            ORDER BY process_name ASC LIMIT ?;
            """
        try queryLocked(sql, bind: { statement in
            try self.bindRawRange(statement, query: query)
            try self.bindText(statement, index: 3, value: ip)
            try self.bindInt(statement, index: 4, value: Int32(InsightsLimits.maxUnresolvedAppNames))
        }) { statement in
            if let name = self.columnText(statement, index: 0), !name.isEmpty { names.append(name) }
        }
        return names
    }

    // MARK: Proposals

    private func proposalsLocked(_ query: InsightsQuery,
                                 source: InsightsDataSource) throws -> (rows: [InsightsProposedRule], hasMore: Bool) {
        var candidates: [(app: String, name: String?, bundle: String?, path: String?,
                          key: String, ip: String?, count: Int, lastSeen: Date?)] = []
        switch source {
        case .rawEvents:
            let sql = """
                SELECT \(Self.appIdentitySQL) AS app, MAX(process_name), MAX(process_bundle_id), MAX(process_path),
                       \(Self.destinationSQL) AS dest, MAX(remote_ip), COUNT(*), MAX(observed_at)
                FROM flow_observations
                WHERE observed_at >= ? AND observed_at <= ?
                GROUP BY app, dest
                ORDER BY COUNT(*) DESC, app ASC, dest ASC
                LIMIT ? OFFSET ?;
                """
            try queryLocked(sql, bind: { statement in
                try self.bindRawRange(statement, query: query)
                try self.bindPage(statement, query: query, firstIndex: 3)
            }) { statement in
                guard let app = self.columnText(statement, index: 0), !app.isEmpty,
                      let key = self.columnText(statement, index: 4), !key.isEmpty else { return }
                candidates.append((app,
                                   self.columnText(statement, index: 1),
                                   self.columnText(statement, index: 2),
                                   self.columnText(statement, index: 3),
                                   key,
                                   self.columnText(statement, index: 5),
                                   Int(self.columnInt64(statement, index: 6)),
                                   self.columnDate(statement, index: 7)))
            }
        case .dailyRollups:
            let sql = """
                SELECT app_identity, destination_key, SUM(connection_count), MAX(utc_day)
                FROM daily_rollups
                WHERE utc_day >= ? AND utc_day <= ?
                GROUP BY app_identity, destination_key
                ORDER BY SUM(connection_count) DESC, app_identity ASC, destination_key ASC
                LIMIT ? OFFSET ?;
                """
            try queryLocked(sql, bind: { statement in
                try self.bindDayRange(statement, query: query)
                try self.bindPage(statement, query: query, firstIndex: 3)
            }) { statement in
                guard let app = self.columnText(statement, index: 0), !app.isEmpty,
                      let key = self.columnText(statement, index: 1), !key.isEmpty else { return }
                candidates.append((app,
                                   nil,
                                   app.hasPrefix("/") ? nil : app,
                                   app.hasPrefix("/") ? app : nil,
                                   key,
                                   nil,
                                   Int(self.columnInt64(statement, index: 2)),
                                   self.columnText(statement, index: 3).flatMap(self.date(fromUTCDay:))))
            }
        }

        var rows: [InsightsProposedRule] = []
        rows.reserveCapacity(candidates.count)
        for candidate in candidates {
            let domain = try resolvedDomainLocked(key: candidate.key, remoteIP: candidate.ip)
            let address = candidate.ip?.isEmpty == false
                ? candidate.ip
                : (PFHostValidator.kind(for: candidate.key) == .ip ? candidate.key : nil)
            // An address-pinned proposal is only offered when no name was ever
            // seen. With neither a name nor a usable address there is nothing
            // a rule could match, so no proposal is made at all.
            guard domain != nil || address != nil else { continue }
            rows.append(InsightsProposedRule(
                appIdentity: candidate.app,
                appDisplayName: candidate.name ?? Self.fallbackName(for: candidate.app),
                processBundleId: candidate.bundle?.isEmpty == false ? candidate.bundle : nil,
                processPath: candidate.path?.isEmpty == false ? candidate.path : nil,
                domain: domain,
                remoteIP: address,
                connectionCount: candidate.count,
                otherAppCount: try otherAppCountLocked(destination: candidate.key,
                                                       excluding: candidate.app,
                                                       query: query,
                                                       source: source),
                lastSeen: candidate.lastSeen))
        }
        let trimmed = trim(rows, limit: query.limit)
        // Breadth first: a destination several apps reach is the one worth
        // looking at, and the page itself is already bounded.
        let ordered = trimmed.rows.sorted {
            if $0.otherAppCount != $1.otherAppCount { return $0.otherAppCount > $1.otherAppCount }
            if $0.connectionCount != $1.connectionCount { return $0.connectionCount > $1.connectionCount }
            if $0.appIdentity != $1.appIdentity { return $0.appIdentity < $1.appIdentity }
            return $0.destinationLabel < $1.destinationLabel
        }
        return (ordered, trimmed.hasMore)
    }

    // MARK: Prepared contact history

    /// Builds the bounded evidence set used by Alert mode. This method is only
    /// called by helper background work or a helper query, never by the
    /// extension's verdict callback.
    func contactSnapshot(now: Date = Date()) throws -> InsightsContactSnapshot {
        try queue.sync {
            var contacts: [InsightsContact] = []
            let sql = """
                SELECT app_identity, destination FROM (
                    SELECT \(Self.appIdentitySQL) AS app_identity, \(Self.destinationSQL) AS destination
                    FROM flow_observations
                    WHERE observed_at >= ?
                    UNION
                    SELECT app_identity, destination_key AS destination
                    FROM daily_rollups
                )
                WHERE app_identity <> '' AND destination <> ''
                GROUP BY app_identity, destination
                ORDER BY app_identity ASC, destination ASC
                LIMIT ?;
                """
            try queryLocked(sql, bind: { statement in
                try self.bindDouble(statement, index: 1, value: now.timeIntervalSince1970 - InsightsLimits.rawRetention)
                try self.bindInt(statement, index: 2, value: Int32(InsightsLimits.maxContactCount + 1))
            }) { statement in
                guard let app = self.columnText(statement, index: 0),
                      let destination = self.columnText(statement, index: 1),
                      !app.isEmpty,
                      app.utf8.count <= InsightsLimits.maxPathLength,
                      !destination.isEmpty,
                      (PFHostValidator.kind(for: destination) == .hostname || PFHostValidator.kind(for: destination) == .ip) else {
                    throw InsightsValidationError.invalidContactSnapshot("stored contact")
                }
                contacts.append(InsightsContact(appIdentity: app, destination: destination))
            }
            let truncated = contacts.count > InsightsLimits.maxContactCount
            if truncated { contacts.removeLast() }
            let snapshot = InsightsContactSnapshot(contacts: contacts, preparedAt: now, truncated: truncated)
            try snapshot.validate(now: now)
            return snapshot
        }
    }

    // MARK: Changed-after-update findings

    private func findingsLocked(_ query: InsightsQuery,
                               source: InsightsDataSource) throws -> (rows: [InsightsBehaviourFinding], hasMore: Bool) {
        // Versioned raw observations retain process names and first-seen times.
        // A year-old rollup deliberately cannot manufacture those details, so
        // it yields no finding rather than guessing an app build.
        struct Group {
            let app: String
            let name: String
            let version: String?
            let destination: String
            let first: Date
            let count: Int
        }
        var groups: [Group] = []
        if source == .rawEvents {
        let sql = """
            SELECT \(Self.appIdentitySQL) AS app, MAX(process_name), process_version,
                   \(Self.destinationSQL) AS destination, MIN(observed_at), COUNT(*)
            FROM flow_observations
            WHERE observed_at >= ? AND observed_at <= ?
            GROUP BY app, process_version, destination
            ORDER BY app ASC, MIN(observed_at) ASC, destination ASC
            LIMIT ?;
            """
        try queryLocked(sql, bind: { statement in
            try self.bindRawRange(statement, query: query)
            try self.bindInt(statement, index: 3, value: Int32(InsightsLimits.maxContactCount + 1))
        }) { statement in
            guard let app = self.columnText(statement, index: 0), !app.isEmpty,
                  let name = self.columnText(statement, index: 1),
                  let destination = self.columnText(statement, index: 3),
                  let first = self.columnDate(statement, index: 4) else { return }
            let version = self.columnText(statement, index: 2)
            groups.append(Group(app: app, name: name, version: version, destination: destination,
                                 first: first, count: Int(self.columnInt64(statement, index: 5))))
        }
        }
        if source == .dailyRollups {
            let rollupSQL = """
                SELECT app_identity, app_version, destination_key, MIN(utc_day), SUM(connection_count)
                FROM versioned_rollups
                WHERE utc_day >= ? AND utc_day <= ?
                GROUP BY app_identity, app_version, destination_key
                ORDER BY app_identity ASC, MIN(utc_day) ASC, destination_key ASC
                LIMIT ?;
                """
            try queryLocked(rollupSQL, bind: { statement in
                try self.bindDayRange(statement, query: query)
                try self.bindInt(statement, index: 3, value: Int32(InsightsLimits.maxContactCount + 1))
            }) { statement in
                guard let app = self.columnText(statement, index: 0), !app.isEmpty,
                      let version = self.columnText(statement, index: 1), !version.isEmpty,
                      let destination = self.columnText(statement, index: 2),
                      let day = self.columnText(statement, index: 3),
                      let first = self.date(fromUTCDay: day) else { return }
                groups.append(Group(app: app, name: Self.fallbackName(for: app), version: version,
                                    destination: destination, first: first,
                                    count: Int(self.columnInt64(statement, index: 4))))
            }
        }

        var findings: [InsightsBehaviourFinding] = []
        let byApp = Dictionary(grouping: groups, by: \.app)
        for (app, appGroups) in byApp {
            let ordered = appGroups.sorted { $0.first < $1.first }
            var baseline = Set<String>()
            var currentVersion: String?
            var updateVersion: String?
            var oldVersion: String?
            for group in ordered {
                if let version = group.version {
                    if version != currentVersion {
                        if !baseline.isEmpty {
                            updateVersion = version
                            oldVersion = currentVersion
                        }
                        currentVersion = version
                    }
                    if let updateVersion, updateVersion == version,
                       !baseline.contains(group.destination) {
                        findings.append(InsightsBehaviourFinding(
                            appIdentity: app,
                            displayName: group.name,
                            oldVersion: oldVersion,
                            newVersion: version,
                            destination: group.destination,
                            firstSeen: group.first,
                            connectionCount: group.count,
                            versionKnown: true))
                    }
                } else if let currentVersion, !baseline.contains(group.destination) {
                    // An unknown build never starts or replaces a baseline. It
                    // may be shown as unknown when it adds a destination after
                    // a reliable build, but no version is guessed.
                    findings.append(InsightsBehaviourFinding(
                        appIdentity: app,
                        displayName: group.name,
                        oldVersion: currentVersion,
                        newVersion: nil,
                        destination: group.destination,
                        firstSeen: group.first,
                        connectionCount: group.count,
                        versionKnown: false))
                }
                baseline.insert(group.destination)
            }
        }
        findings.sort {
            if $0.appIdentity != $1.appIdentity { return $0.appIdentity < $1.appIdentity }
            if $0.firstSeen != $1.firstSeen { return $0.firstSeen < $1.firstSeen }
            return $0.destination < $1.destination
        }
        return trim(findings, limit: query.limit)
    }

    // MARK: Overview

    private func overviewLocked(recordingEnabled: Bool) throws -> InsightsOverview {
        var observations = 0
        var oldest: Date?
        var newest: Date?
        var apps = 0
        var mappings = 0
        var rollups = 0
        try queryLocked("SELECT COUNT(*), MIN(observed_at), MAX(observed_at), COUNT(DISTINCT \(Self.appIdentitySQL)) FROM flow_observations;") { statement in
            observations = Int(self.columnInt64(statement, index: 0))
            oldest = self.columnDate(statement, index: 1)
            newest = self.columnDate(statement, index: 2)
            apps = Int(self.columnInt64(statement, index: 3))
        }
        try queryLocked("SELECT COUNT(*) FROM dns_mappings;") { statement in
            mappings = Int(self.columnInt64(statement, index: 0))
        }
        try queryLocked("SELECT COUNT(*) FROM daily_rollups;") { statement in
            rollups = Int(self.columnInt64(statement, index: 0))
        }
        return InsightsOverview(recordingEnabled: recordingEnabled,
                                rawObservationCount: observations,
                                dnsMappingCount: mappings,
                                rollupRowCount: rollups,
                                appCount: apps,
                                oldestObservation: oldest,
                                newestObservation: newest)
    }

    // MARK: Naming

    /// Names come from the DNS answers this Mac actually saw. There is no
    /// reverse lookup and no online lookup here, by design (D5).
    private func resolvedDomainLocked(key: String, remoteIP: String?) throws -> String? {
        if PFHostValidator.kind(for: key) == .hostname { return key }
        let address = remoteIP?.isEmpty == false ? remoteIP! : key
        guard PFHostValidator.kind(for: address) == .ip else { return nil }
        var domain: String?
        try queryLocked("SELECT domain FROM dns_mappings WHERE ip = ? ORDER BY observed_at DESC LIMIT 1;",
                        bind: { statement in try self.bindText(statement, index: 1, value: address) }) { statement in
            if let value = self.columnText(statement, index: 0), !value.isEmpty { domain = value }
        }
        return domain
    }

    // MARK: Plumbing

    private func trim<Row>(_ rows: [Row], limit: Int) -> (rows: [Row], hasMore: Bool) {
        guard rows.count > limit else { return (rows, false) }
        return (Array(rows.prefix(limit)), true)
    }

    private static func fallbackName(for identity: String) -> String {
        identity.hasPrefix("/") ? (identity as NSString).lastPathComponent : identity
    }

    private func bindRawRange(_ statement: OpaquePointer?, query: InsightsQuery) throws {
        try bindDouble(statement, index: 1, value: query.since.timeIntervalSince1970)
        try bindDouble(statement, index: 2, value: query.until.timeIntervalSince1970)
    }

    private func bindDayRange(_ statement: OpaquePointer?, query: InsightsQuery) throws {
        try bindText(statement, index: 1, value: utcDay(for: query.since))
        try bindText(statement, index: 2, value: utcDay(for: query.until))
    }

    /// One row over the page size proves there is a next page without ever
    /// fetching it.
    private func bindPage(_ statement: OpaquePointer?, query: InsightsQuery, firstIndex: Int32) throws {
        try bindInt(statement, index: firstIndex, value: Int32(min(query.limit, InsightsLimits.maxQueryPageSize) + 1))
        try bindInt(statement, index: firstIndex + 1, value: Int32(min(query.offset, InsightsLimits.maxQueryOffset)))
    }

    private func queryLocked(_ sql: String,
                             bind: ((OpaquePointer?) throws -> Void)? = nil,
                             row: (OpaquePointer?) throws -> Void) throws {
        var statement: OpaquePointer?
        defer { if let statement { sqlite3_finalize(statement) } }
        try prepareLocked(sql, statement: &statement)
        try bind?(statement)
        while true {
            let result = sqlite3_step(statement)
            if result == SQLITE_DONE { return }
            guard result == SQLITE_ROW else { throw storeError(sqliteMessage()) }
            try row(statement)
        }
    }

    private func columnText(_ statement: OpaquePointer?, index: Int32) -> String? {
        guard let value = sqlite3_column_text(statement, index) else { return nil }
        return String(cString: value)
    }

    private func columnInt64(_ statement: OpaquePointer?, index: Int32) -> Int64 {
        sqlite3_column_int64(statement, index)
    }

    private func columnDate(_ statement: OpaquePointer?, index: Int32) -> Date? {
        guard sqlite3_column_type(statement, index) != SQLITE_NULL else { return nil }
        let seconds = sqlite3_column_double(statement, index)
        guard seconds.isFinite, seconds > 0 else { return nil }
        return Date(timeIntervalSince1970: seconds)
    }

    private func date(fromUTCDay day: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withFullDate]
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        return formatter.date(from: day)
    }
}
