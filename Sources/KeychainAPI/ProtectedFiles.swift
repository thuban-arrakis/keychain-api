import Foundation
import Darwin

func openRegularFile(
    at path: String,
    maximumBytes: Int,
    requirePrivateMode: Bool
) throws -> Int32 {
    var info = stat()
    let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else {
        throw fail("A required local file could not be opened safely.", exitCode: 3)
    }
    guard fstat(descriptor, &info) == 0 else {
        close(descriptor)
        throw fail("A required local file could not be inspected safely.", exitCode: 3)
    }
    guard (info.st_mode & S_IFMT) == S_IFREG,
          info.st_uid == geteuid(),
          info.st_size >= 0,
          info.st_size <= maximumBytes else {
        close(descriptor)
        throw fail("A required local file failed ownership, type, or size checks.", exitCode: 3)
    }
    if requirePrivateMode && (info.st_mode & 0o077) != 0 {
        close(descriptor)
        throw fail("The policy file must have mode 0600 or stricter.", exitCode: 3)
    }
    return descriptor
}

func readBoundedData(from handle: FileHandle, into data: inout Data, maximumBytes: Int, overflow: SafeFailure) throws {
    do {
        while let chunk = try handle.read(upToCount: min(16384, maximumBytes - data.count + 1)), !chunk.isEmpty {
            let remaining = maximumBytes - data.count
            guard chunk.count <= remaining else {
                data.append(chunk.prefix(remaining))
                throw overflow
            }
            data.append(chunk)
        }
    } catch let failure as SafeFailure {
        throw failure
    } catch {
        throw fail("A data stream could not be read safely.", exitCode: overflow.exitCode)
    }
}

func readRegularFile(
    at path: String,
    maximumBytes: Int,
    requirePrivateMode: Bool
) throws -> Data {
    let descriptor = try openRegularFile(at: path, maximumBytes: maximumBytes, requirePrivateMode: requirePrivateMode)
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    var data = Data()
    try readBoundedData(from: handle, into: &data, maximumBytes: maximumBytes,
                        overflow: fail("A required local file exceeded the safe size limit.", exitCode: 3))
    return data
}

private func hasNoExtendedACL(_ descriptor: Int32) -> Bool {
    errno = 0
    guard let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
        // Darwin returns ENOENT when a valid file descriptor has no ACL.
        return errno == ENOENT
    }
    defer { acl_free(UnsafeMutableRawPointer(acl)) }
    var entry: acl_entry_t?
    errno = 0
    return acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == -1 && errno == EINVAL
}


private func openPrivateParent(of path: String) throws -> Int32 {
    let parts = path.split(separator: "/", omittingEmptySubsequences: false)
    guard path.hasPrefix("/"), !containsControlCharacters(path),
          parts.count >= 3, parts.first == "",
          parts.dropFirst().allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
        throw fail("Protected file requires an absolute, non-traversing file path.", exitCode: 3)
    }
    var parent = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard parent >= 0 else { throw fail("Protected file directory could not be opened.", exitCode: 3) }
    do {
        for part in parts.dropFirst().dropLast() {
            let next = openat(parent, String(part), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard next >= 0 else { throw fail("Protected file directory path was unsafe.", exitCode: 3) }
            close(parent)
            parent = next
            var info = stat()
            guard fstat(parent, &info) == 0,
                  (info.st_uid == 0 || info.st_uid == geteuid()),
                  (info.st_mode & 0o022) == 0 || (info.st_mode & S_ISVTX) != 0 else {
                throw fail("Protected file directory ancestry was unsafe.", exitCode: 3)
            }
        }
        var parentInfo = stat()
        guard fstat(parent, &parentInfo) == 0,
              parentInfo.st_uid == geteuid(), (parentInfo.st_mode & 0o077) == 0,
              hasNoExtendedACL(parent) else {
            throw fail("Protected file requires an owner-only directory.", exitCode: 3)
        }
    } catch {
        close(parent)
        throw error
    }
    return parent
}

// Opt-in response sink. Reserve a new file before credentials or network access;
// never expose the unsanitized response through the normal output channel.
final class ProtectedResponseFile {
    private let directory: Int32
    private var descriptor: Int32
    private let name: String
    private var committed = false

    init(path: String) throws {
        let parent = try openPrivateParent(of: path)
        let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        let leaf = String(parts.last!)
        let file = openat(parent, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else {
            close(parent)
            throw fail("Secret output must be a new file; existing files and symlinks are refused.", exitCode: 3)
        }
        var info = stat()
        guard fchmod(file, 0o600) == 0, fstat(file, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == geteuid(),
              (info.st_mode & 0o777) == 0o600, info.st_nlink == 1, info.st_size == 0,
              hasNoExtendedACL(file) else {
            close(file)
            close(parent)
            throw fail("Secret output file failed safety checks.", exitCode: 3)
        }
        directory = parent
        descriptor = file
        name = leaf
    }

    deinit {
        if descriptor >= 0 { close(descriptor) }
        close(directory)
        // Retain even a partial/empty file on failure: the remote mutation may
        // have succeeded. Never silently retry or delete the only response.
    }

    func commit(_ data: Data) throws -> [String: Any] {
        guard !committed, !data.isEmpty, data.count <= maximumResponseBytes else {
            throw fail("Secret output could not be committed; do not retry a remote mutation.", exitCode: 5)
        }
        var parentInfo = stat()
        var beforeWrite = stat()
        guard fstat(directory, &parentInfo) == 0, parentInfo.st_uid == geteuid(),
              (parentInfo.st_mode & 0o077) == 0, hasNoExtendedACL(directory),
              fstat(descriptor, &beforeWrite) == 0, beforeWrite.st_uid == geteuid(),
              (beforeWrite.st_mode & 0o777) == 0o600, beforeWrite.st_nlink == 1,
              hasNoExtendedACL(descriptor) else {
            throw fail("Secret output permissions changed. Remote mutation may have succeeded; do not retry.", exitCode: 5)
        }
        let written = data.withUnsafeBytes { buffer -> Bool in
            guard let base = buffer.baseAddress else { return false }
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.write(descriptor, base.advanced(by: offset), buffer.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { return false }
                offset += count
            }
            return true
        }
        var fileInfo = stat()
        var linkInfo = stat()
        guard written, fsync(descriptor) == 0, fsync(directory) == 0,
              fstat(descriptor, &fileInfo) == 0,
              fstatat(directory, name, &linkInfo, AT_SYMLINK_NOFOLLOW) == 0,
              fileInfo.st_ino == linkInfo.st_ino, fileInfo.st_dev == linkInfo.st_dev,
              (fileInfo.st_mode & S_IFMT) == S_IFREG,
              fileInfo.st_uid == geteuid(), (fileInfo.st_mode & 0o777) == 0o600,
              fileInfo.st_nlink == 1, fileInfo.st_size == data.count,
              hasNoExtendedACL(descriptor), hasNoExtendedACL(directory) else {
            throw fail("Secret response persistence was not verified. Remote mutation may have succeeded; do not retry.", exitCode: 5)
        }
        let closeResult = close(descriptor)
        descriptor = -1
        guard closeResult == 0 else {
            throw fail("Secret response close was not verified. Remote mutation may have succeeded; do not retry.", exitCode: 5)
        }
        committed = true
        return ["ok": true, "secret_output_file_written": true, "secret_output": false]
    }
}
