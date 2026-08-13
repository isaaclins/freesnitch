import Foundation
import SQLite3
import Darwin

private let insightsSQLiteTransient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

/// Root-owned evidence storage. This is intentionally separate from RuleStore:
/// evidence is not GUI/app-group state and must not become user-readable.
final class InsightsStore: @unchecked Sendable {
    static let defaultPath = "/Library/Application Support/FreeSnitch/insights.sqlite"

    private var db: OpaquePointer?
    private let queue = DispatchQueue(label: "io.isaaclins.freesnitch.insights-store")
    private let fileManager = FileManager.default
    let path: String

    init(path: String = InsightsStore.defaultPath) throws {
        self.path = URL(fileURLWithPath: path).standardizedFileURL.path
        try open()
    }

    deinit {
        if let db { sqlite3_close(db) }
    }

    var recordingEnabled: Bool {
        queue.sync { settingLocked("recording_enabled") != "0" }
    }

    func setRecordingEnabled(_ enabled: Bool) throws {
        try queue.sync {
            try executeLocked("INSERT OR REPLACE INTO settings(key,value) VALUES('recording_enabled',?);") { statement in
                sqlite3_bind_text(statement, 1, enabled ? "1" : "0", -1, insightsSQLiteTransient)
            }
        }
    }

    func record(_ observations: [FlowObservation]) throws {
        guard !observations.isEmpty else { return }
        try queue.sync {
            guard settingLocked("recording_enabled") != "0" else { return }
            for observation in observations { try observation.validate() }
            try executeLocked("BEGIN IMMEDIATE;")
            do {
                for observation in observations {
                    try insertLocked(observation)
                    try rollupLocked(observation)
                }
                try executeLocked("COMMIT;")
                secureDatabaseFilesLocked()
            } catch {
                _ = try? executeLocked("ROLLBACK;")
                throw error
            }
        }
    }

    /// Deletes expired raw evidence and old rollups. Call this from a helper
    /// maintenance queue, never from an XPC reply callback.
    func prune(now: Date = Date()) throws {
        try queue.sync {
            let rawCutoff = now.timeIntervalSince1970 - InsightsLimits.rawRetention
            let dayCutoff = utcDay(for: now.addingTimeInterval(-Double(InsightsLimits.rollupRetentionDays) * 24 * 60 * 60))
            try executeLocked("BEGIN IMMEDIATE;")
            do {
                try executeLocked("DELETE FROM flow_observations WHERE observed_at < ?;") { statement in
                    sqlite3_bind_double(statement, 1, rawCutoff)
                }
                try executeLocked("DELETE FROM daily_rollups WHERE utc_day < ?;") { statement in
                    sqlite3_bind_text(statement, 1, dayCutoff, -1, insightsSQLiteTransient)
                }
                try executeLocked("COMMIT;")
                secureDatabaseFilesLocked()
            } catch {
                _ = try? executeLocked("ROLLBACK;")
                throw error
            }
        }
    }

    /// SQLite keeps WAL and shared-memory files open while the database is
    /// live. Close first, remove all three files, then reopen and recreate the
    /// schema so purge has an observable, honest result.
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
                        guard (info.st_mode & S_IFMT) == S_IFREG else { throw storeError("purge path is not a regular file") }
                        try fileManager.removeItem(atPath: file)
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
        try secureDirectory(directory)
        try rejectSymlink(path)
        var handle: OpaquePointer?
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
        guard sqlite3_open_v2(path, &handle, flags, nil) == SQLITE_OK, let handle else {
            if let handle { sqlite3_close(handle) }
            throw storeError("database open failed")
        }
        db = handle
        do {
            try chmodAndVerify(path, mode: 0o600)
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
                """)
            secureDatabaseFilesLocked()
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
                sqlite3_bind_text(statement, 1, observation.id.uuidString, -1, insightsSQLiteTransient)
                sqlite3_bind_double(statement, 2, observation.observedAt.timeIntervalSince1970)
                sqlite3_bind_int(statement, 3, observation.pid)
                self.bind(statement, 4, observation.processBundleId)
                sqlite3_bind_text(statement, 5, observation.processPath, -1, insightsSQLiteTransient)
                sqlite3_bind_text(statement, 6, observation.processName, -1, insightsSQLiteTransient)
                sqlite3_bind_text(statement, 7, observation.remoteHost, -1, insightsSQLiteTransient)
                sqlite3_bind_text(statement, 8, observation.remoteIP, -1, insightsSQLiteTransient)
                sqlite3_bind_int(statement, 9, Int32(observation.remotePort))
                sqlite3_bind_text(statement, 10, observation.direction.rawValue, -1, insightsSQLiteTransient)
                sqlite3_bind_text(statement, 11, observation.protocolName, -1, insightsSQLiteTransient)
                if let bytes = observation.bytesIn { sqlite3_bind_int64(statement, 12, bytes) } else { sqlite3_bind_null(statement, 12) }
                if let bytes = observation.bytesOut { sqlite3_bind_int64(statement, 13, bytes) } else { sqlite3_bind_null(statement, 13) }
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
                sqlite3_bind_text(statement, 1, app, -1, insightsSQLiteTransient)
                sqlite3_bind_text(statement, 2, destination, -1, insightsSQLiteTransient)
                sqlite3_bind_text(statement, 3, self.utcDay(for: observation.observedAt), -1, insightsSQLiteTransient)
            }
    }

    private func settingLocked(_ key: String) -> String? {
        var statement: OpaquePointer?
        defer { if let statement { sqlite3_finalize(statement) } }
        guard sqlite3_prepare_v2(db, "SELECT value FROM settings WHERE key=?;", -1, &statement, nil) == SQLITE_OK else { return nil }
        sqlite3_bind_text(statement, 1, key, -1, insightsSQLiteTransient)
        guard sqlite3_step(statement) == SQLITE_ROW, let value = sqlite3_column_text(statement, 0) else { return nil }
        return String(cString: value)
    }

    private func executeLocked(_ sql: String, bind: ((OpaquePointer?) -> Void)? = nil) throws {
        var statement: OpaquePointer?
        defer { if let statement { sqlite3_finalize(statement) } }
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw storeError(String(cString: sqlite3_errmsg(db)))
        }
        bind?(statement)
        guard sqlite3_step(statement) == SQLITE_DONE else {
            throw storeError(String(cString: sqlite3_errmsg(db)))
        }
    }

    private func execLocked(_ sql: String) throws {
        var error: UnsafeMutablePointer<CChar>?
        guard sqlite3_exec(db, sql, nil, nil, &error) == SQLITE_OK else {
            let message = error.map { String(cString: $0) } ?? "sqlite error"
            sqlite3_free(error)
            throw storeError(message)
        }
    }

    private func bind(_ statement: OpaquePointer?, _ index: Int32, _ value: String?) {
        if let value { sqlite3_bind_text(statement, index, value, -1, insightsSQLiteTransient) }
        else { sqlite3_bind_null(statement, index) }
    }

    private func secureDirectory(_ directory: String) throws {
        try rejectSymlink(directory)
        if !fileManager.fileExists(atPath: directory) {
            try fileManager.createDirectory(atPath: directory, withIntermediateDirectories: true,
                                            attributes: [.posixPermissions: 0o700])
        }
        try chmodAndVerify(directory, mode: 0o700)
    }

    private func rejectSymlink(_ file: String) throws {
        var info = stat()
        if lstat(file, &info) == 0, (info.st_mode & S_IFMT) == S_IFLNK {
            throw storeError("refusing symlink path: \(file)")
        }
    }

    private func chmodAndVerify(_ file: String, mode: Int16) throws {
        guard chmod(file, mode_t(mode)) == 0 else { throw storeError("cannot secure path: \(file)") }
        var info = stat()
        guard lstat(file, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG || (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == 0,
              (info.st_mode & 0o7777) == mode_t(mode) else {
            throw storeError("insecure owner or mode: \(file)")
        }
    }

    private func secureDatabaseFilesLocked() {
        for suffix in ["", "-wal", "-shm"] {
            let file = path + suffix
            var info = stat()
            if lstat(file, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG {
                _ = chmod(file, 0o600)
            }
        }
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
