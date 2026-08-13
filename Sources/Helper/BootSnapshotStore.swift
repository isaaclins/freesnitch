import Foundation
import Darwin

/// The helper owns the boot snapshot. The network extension never receives a
/// filesystem path and never gets access to the helper's state-changing XPC API.
final class BootSnapshotStore: @unchecked Sendable {
    private let lock = NSLock()
    private let fileManager = FileManager.default
    private let directoryURL = AppConstants.sharedDataDir
    private let fileURL = AppConstants.bootSnapshotURL
    private let maximumSize = 16 * 1024 * 1024

    func read() throws -> SharedRuleBridge.Snapshot {
        lock.lock()
        defer { lock.unlock() }

        try requireSecureDirectory()
        try requireSecureFile()
        let data = try Data(contentsOf: fileURL)
        guard !data.isEmpty, data.count <= maximumSize else {
            throw failure("boot snapshot is empty or too large")
        }
        return try SharedRuleBridge.decodeBootSnapshot(data)
    }

    func write(_ snapshot: SharedRuleBridge.Snapshot) throws {
        lock.lock()
        defer { lock.unlock() }

        guard geteuid() == 0 else {
            throw failure("boot snapshot writes require the root helper")
        }
        try prepareSecureDirectory()
        let data = try SharedRuleBridge.encodeBootSnapshot(snapshot)
        guard data.count <= maximumSize else {
            throw failure("boot snapshot is too large")
        }

        let temporaryURL = directoryURL.appendingPathComponent(
            ".boot-snapshot.\(UUID().uuidString).tmp",
            isDirectory: false
        )
        do {
            try data.write(to: temporaryURL, options: [])
            try setOwnerAndMode(temporaryURL, mode: 0o644)
            let renamed = temporaryURL.path.withCString { source in
                fileURL.path.withCString { destination in
                    Darwin.rename(source, destination) == 0
                }
            }
            guard renamed else { throw failure("could not atomically replace boot snapshot") }
            try requireSecureFile()
        } catch {
            try? fileManager.removeItem(at: temporaryURL)
            throw error
        }
    }

    private func prepareSecureDirectory() throws {
        var info = stat()
        if lstat(directoryURL.path, &info) != 0 {
            guard errno == ENOENT else { throw failure("could not inspect boot snapshot directory") }
            try fileManager.createDirectory(at: directoryURL, withIntermediateDirectories: true)
            try setOwnerAndMode(directoryURL, mode: 0o755)
        }
        try requireSecureDirectory()
    }

    private func requireSecureDirectory() throws {
        var info = stat()
        guard lstat(directoryURL.path, &info) == 0 else {
            throw failure("boot snapshot directory is unavailable")
        }
        guard (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR),
              info.st_uid == uid_t(0),
              (info.st_mode & mode_t(0o022)) == 0 else {
            throw failure("boot snapshot directory is not root-owned and non-writable")
        }
    }

    private func requireSecureFile() throws {
        var info = stat()
        guard lstat(fileURL.path, &info) == 0 else {
            throw failure("boot snapshot is unavailable")
        }
        guard (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              info.st_uid == uid_t(0),
              (info.st_mode & mode_t(0o022)) == 0 else {
            throw failure("boot snapshot is not a root-owned regular file")
        }
    }

    private func setOwnerAndMode(_ url: URL, mode: mode_t) throws {
        let ownerChanged = url.path.withCString { path in
            Darwin.chown(path, uid_t(0), gid_t(0)) == 0
        }
        guard ownerChanged else { throw failure("could not set boot snapshot owner") }
        let modeChanged = url.path.withCString { path in
            Darwin.chmod(path, mode) == 0
        }
        guard modeChanged else { throw failure("could not set boot snapshot permissions") }
    }

    private func failure(_ message: String) -> NSError {
        NSError(domain: "BootSnapshotStore", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
