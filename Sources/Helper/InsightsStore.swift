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
                try executeLocked("DELETE FROM dns_mappings WHERE expires_at < ?;") { statement in
                    try self.bindDouble(statement, index: 1, value: now.timeIntervalSince1970)
                }
                try executeLocked("DELETE FROM daily_rollups WHERE utc_day < ?;") { statement in
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
                id,observed_at,pid,process_bundle_id,process_path,process_name,
                remote_host,remote_ip,remote_port,direction,protocol_name,bytes_in,bytes_out
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);
            """) { statement in
                try self.bindText(statement, index: 1, value: observation.id.uuidString)
                try self.bindDouble(statement, index: 2, value: observation.observedAt.timeIntervalSince1970)
                try self.bindInt(statement, index: 3, value: observation.pid)
                try self.bindOptionalText(statement, index: 4, value: observation.processBundleId)
                try self.bindText(statement, index: 5, value: observation.processPath)
                try self.bindText(statement, index: 6, value: observation.processName)
                try self.bindText(statement, index: 7, value: observation.remoteHost)
                try self.bindText(statement, index: 8, value: observation.remoteIP)
                try self.bindInt(statement, index: 9, value: Int32(observation.remotePort))
                try self.bindText(statement, index: 10, value: observation.direction.rawValue)
                try self.bindText(statement, index: 11, value: observation.protocolName)
                try self.bindOptionalInt64(statement, index: 12, value: observation.bytesIn)
                try self.bindOptionalInt64(statement, index: 13, value: observation.bytesOut)
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
            INSERT INTO daily_rollups(app_identity,destination_key,utc_day,connection_count)
            VALUES (?,?,?,1)
            ON CONFLICT(app_identity,destination_key,utc_day)
            DO UPDATE SET connection_count=connection_count+1;
            """) { statement in
                try self.bindText(statement, index: 1, value: app)
                try self.bindText(statement, index: 2, value: destination)
                try self.bindText(statement, index: 3, value: self.utcDay(for: observation.observedAt))
            }
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
        if let value {
            guard sqlite3_bind_int64(statement, index, value) == SQLITE_OK else { throw storeError(sqliteMessage()) }
        } else { try bindNull(statement, index: index) }
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
