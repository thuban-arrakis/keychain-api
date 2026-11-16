import Foundation
import Security
import LocalAuthentication
import Darwin
import Network

private let maximumPolicyBytes = 1 * 1024 * 1024
private let maximumBodyBytes = 1 * 1024 * 1024
private let maximumResponseBytes = 8 * 1024 * 1024

private struct SafeFailure: Error {
    let message: String
    let exitCode: Int32

    init(_ message: String, exitCode: Int32 = 1) {
        self.message = message
        self.exitCode = exitCode
    }
}

private func fail(_ message: String, exitCode: Int32 = 1) -> SafeFailure {
    SafeFailure(message, exitCode: exitCode)
}

private func writeError(_ message: String) {
    FileHandle.standardError.write(Data((message + "\n").utf8))
}

private func containsControlCharacters(_ value: String) -> Bool {
    value.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
}

private func isSafeMetadata(_ value: String, maximumLength: Int = 256) -> Bool {
    !value.isEmpty && value.count <= maximumLength && !containsControlCharacters(value)
}

private func dataContainsAnySecret(_ data: Data, secrets: [String]) -> Bool {
    secrets.contains { secret in
        !secret.isEmpty && data.range(of: Data(secret.utf8)) != nil
    }
}

private func objectContainsAnySecret(_ object: Any, secrets: [String]) -> Bool {
    if let string = object as? String {
        return secrets.contains { !$0.isEmpty && string.contains($0) }
    }
    if let array = object as? [Any] {
        return array.contains { objectContainsAnySecret($0, secrets: secrets) }
    }
    if let dictionary = object as? [String: Any] {
        return dictionary.contains { key, value in
            secrets.contains { !$0.isEmpty && key.contains($0) }
                || objectContainsAnySecret(value, secrets: secrets)
        }
    }
    return false
}

private let redactedValue = "[REDACTED]"

private func normalizedJSONKey(_ key: String) -> String {
    String(key.lowercased().unicodeScalars.filter { CharacterSet.alphanumerics.contains($0) })
}

private func isSensitiveJSONKey(_ key: String) -> Bool {
    let normalized = normalizedJSONKey(key)
    let exact = Set([
        "authorization", "cookie", "cookies", "credential", "credentials", "key",
        "passphrase", "passwd", "password", "privatekey", "proxyauthorization",
        "recoverycode", "recoverycodes", "session", "sessionid", "sessions",
        "setcookie", "totp"
    ])
    let modifiedKeyNames = [
        "apikey", "accesskey", "authkey", "encryptionkey", "privatekey",
        "secretkey", "signingkey"
    ]
    let capabilityURLKey = normalized == "uploadurl"
        || normalized == "downloadurl"
        || normalized.contains("presignedurl")
        || normalized.contains("signedurl")
        || (normalized.contains("hosted") && normalized.contains("download"))
    return exact.contains(normalized)
        || normalized.contains("password")
        || normalized.contains("secret")
        || normalized.contains("privatekey")
        || normalized.contains("apikey")
        || normalized.contains("token")
        || normalized.contains("credential")
        || capabilityURLKey
        || modifiedKeyNames.contains(where: normalized.contains)
}

private func looksLikeCredentialValue(_ value: String) -> Bool {
    let lowercase = value.lowercased()
    if lowercase.hasPrefix("bearer ") || lowercase.hasPrefix("basic ") {
        return true
    }
    if value.contains("-----BEGIN ") && value.contains("PRIVATE KEY-----") {
        return true
    }
    if value.range(
        of: "^(?:cfut_|cfat_|cfk_)[A-Za-z0-9_-]{20,}$",
        options: .regularExpression
    ) != nil {
        return true
    }
    if value.range(
        of: "^[A-Za-z0-9_-]{12,}\\.[A-Za-z0-9_-]{12,}\\.[A-Za-z0-9_-]{12,}$",
        options: .regularExpression
    ) != nil {
        return true
    }
    if let components = URLComponents(string: value),
       components.scheme != nil,
       components.host != nil,
       (components.user != nil || components.password != nil) {
        return true
    }
    return false
}

private func pathHasCredentialContext(_ relativePath: String) -> Bool {
    guard let components = URLComponents(string: relativePath) else { return false }
    let sensitiveSegments = Set([
        "apikey", "apikeys", "credential", "credentials", "password", "passwords",
        "privatekey", "privatekeys", "secret", "secrets", "sshkey", "sshkeys",
        "token", "tokens"
    ])
    return components.percentEncodedPath.split(separator: "/").contains { segment in
        sensitiveSegments.contains(normalizedJSONKey(String(segment)))
    }
}

private func objectDeclaresCredentialContext(_ dictionary: [String: Any]) -> Bool {
    let discriminatorKeys = Set(["category", "kind", "purpose", "type"])
    let credentialWords = ["apikey", "credential", "password", "privatekey", "secret", "token"]
    for (key, value) in dictionary {
        guard discriminatorKeys.contains(normalizedJSONKey(key)),
              let text = value as? String else { continue }
        let normalizedValue = normalizedJSONKey(text)
        if credentialWords.contains(where: normalizedValue.contains) {
            return true
        }
    }
    return false
}

private func sanitizedAPIObject(
    _ object: Any,
    forbiddenSecrets: [String],
    credentialContext: Bool = false,
    depth: Int = 0
) -> Any {
    guard depth <= 64 else { return redactedValue }
    if let string = object as? String {
        if forbiddenSecrets.contains(where: { !$0.isEmpty && string.contains($0) })
            || looksLikeCredentialValue(string) {
            return redactedValue
        }
        return string
    }
    if let array = object as? [Any] {
        return array.map {
            sanitizedAPIObject(
                $0,
                forbiddenSecrets: forbiddenSecrets,
                credentialContext: credentialContext,
                depth: depth + 1
            )
        }
    }
    if let dictionary = object as? [String: Any] {
        let localCredentialContext = credentialContext || objectDeclaresCredentialContext(dictionary)
        let ambiguousCarrierKeys = Set(["content", "data", "material", "plaintext", "raw", "value"])
        var sanitized: [String: Any] = [:]
        for (key, value) in dictionary {
            let normalizedKey = normalizedJSONKey(key)
            if isSensitiveJSONKey(key)
                || (localCredentialContext && ambiguousCarrierKeys.contains(normalizedKey)) {
                sanitized[key] = redactedValue
            } else {
                sanitized[key] = sanitizedAPIObject(
                    value,
                    forbiddenSecrets: forbiddenSecrets,
                    credentialContext: localCredentialContext,
                    depth: depth + 1
                )
            }
        }
        return sanitized
    }
    return object
}

private func encodedJSON(_ object: Any, forbiddenSecrets: [String] = []) throws -> Data {
    guard JSONSerialization.isValidJSONObject(object) else {
        throw fail("Refused to emit invalid JSON.")
    }
    guard !objectContainsAnySecret(object, secrets: forbiddenSecrets) else {
        throw fail("Refused to emit a response containing credential material.")
    }
    let data = try JSONSerialization.data(
        withJSONObject: object,
        options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    )
    guard !dataContainsAnySecret(data, secrets: forbiddenSecrets) else {
        throw fail("Refused to emit a response containing credential material.")
    }
    return data
}

private func emitJSON(_ object: Any, forbiddenSecrets: [String] = []) throws {
    let data = try encodedJSON(object, forbiddenSecrets: forbiddenSecrets)
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data("\n".utf8))
}

private struct FileMetadata {
    let descriptor: Int32
    let size: Int
}

private func openRegularFile(
    at path: String,
    maximumBytes: Int,
    requirePrivateMode: Bool
) throws -> FileMetadata {
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
    return FileMetadata(descriptor: descriptor, size: Int(info.st_size))
}

private func readRegularFile(
    at path: String,
    maximumBytes: Int,
    requirePrivateMode: Bool
) throws -> Data {
    let metadata = try openRegularFile(
        at: path,
        maximumBytes: maximumBytes,
        requirePrivateMode: requirePrivateMode
    )
    let handle = FileHandle(fileDescriptor: metadata.descriptor, closeOnDealloc: true)
    guard let data = try? handle.readToEnd(), data.count <= maximumBytes else {
        throw fail("A required local file could not be read safely.", exitCode: 3)
    }
    return data
}

// Opt-in response sink. Reserve a new file before credentials or network access;
// never expose the unsanitized response through the normal output channel.
private final class ProtectedResponseFile {
    private let directory: Int32
    private var descriptor: Int32
    private let name: String
    private var committed = false

    private static func hasNoExtendedACL(_ descriptor: Int32) -> Bool {
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

    init(path: String) throws {
        let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        guard path.hasPrefix("/"), !containsControlCharacters(path),
              parts.count >= 3, parts.first == "",
              parts.dropFirst().allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw fail("Secret output requires an absolute, non-traversing file path.", exitCode: 3)
        }
        var parent = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard parent >= 0 else { throw fail("Secret output directory could not be opened.", exitCode: 3) }
        do {
            for part in parts.dropFirst().dropLast() {
                let next = openat(parent, String(part), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard next >= 0 else { throw fail("Secret output directory path was unsafe.", exitCode: 3) }
                close(parent)
                parent = next
                var info = stat()
                guard fstat(parent, &info) == 0,
                      (info.st_uid == 0 || info.st_uid == geteuid()),
                      (info.st_mode & 0o022) == 0 || (info.st_mode & S_ISVTX) != 0 else {
                    throw fail("Secret output directory ancestry was unsafe.", exitCode: 3)
                }
            }
            var parentInfo = stat()
            guard fstat(parent, &parentInfo) == 0,
                  parentInfo.st_uid == geteuid(), (parentInfo.st_mode & 0o077) == 0,
                  Self.hasNoExtendedACL(parent) else {
                throw fail("Secret output requires an owner-only directory.", exitCode: 3)
            }
        } catch {
            close(parent)
            throw error
        }
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
              Self.hasNoExtendedACL(file) else {
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
              (parentInfo.st_mode & 0o077) == 0, Self.hasNoExtendedACL(directory),
              fstat(descriptor, &beforeWrite) == 0, beforeWrite.st_uid == geteuid(),
              (beforeWrite.st_mode & 0o777) == 0o600, beforeWrite.st_nlink == 1,
              Self.hasNoExtendedACL(descriptor) else {
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
              Self.hasNoExtendedACL(descriptor), Self.hasNoExtendedACL(directory) else {
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

private enum CredentialPlacement {
    case bearer
    case basic(username: String)
    case header(name: String, prefix: String)
}

private struct CredentialPolicy {
    let service: String
    let account: String
    let placement: CredentialPlacement
}

private func forbiddenCredentialArtifacts(
    profile: ProfilePolicy,
    secrets: [String]
) -> [String] {
    var artifacts = Set(secrets)
    for (credential, secret) in zip(profile.credentials, secrets) {
        artifacts.insert(Data(secret.utf8).base64EncodedString())
        if case .basic(let username) = credential.placement {
            artifacts.insert(Data((username + ":" + secret).utf8).base64EncodedString())
        }
    }
    return Array(artifacts)
}

private enum BodyPolicy: String {
    case none
    case json
    case optionalJSON = "optional-json"
}

private enum ResponsePolicy: String {
    case json
    case empty
    case jsonOrEmpty = "json-or-empty"
}

private enum JSONMediaType: String {
    case json = "application/json"
    case jsonAPI = "application/vnd.api+json"
}

private func parseJSONMediaType(_ raw: Any?) throws -> JSONMediaType {
    guard let raw else { return .json }
    guard let value = raw as? String,
          let mediaType = JSONMediaType(rawValue: value) else {
        throw fail("A policy profile contains an invalid JSON media type.", exitCode: 3)
    }
    return mediaType
}

private enum PathPolicy {
    case exact(String)
    case prefix(String)
}

private struct OperationPolicy {
    let methods: Set<String>
    let path: PathPolicy
    let body: BodyPolicy
    let response: ResponsePolicy

    func permits(method: String, relativePath: String) -> Bool {
        guard methods.contains(method),
              let components = URLComponents(string: relativePath) else {
            return false
        }
        switch path {
        case .exact(let target):
            return relativePath == target
        case .prefix(let prefix):
            return components.percentEncodedPath.hasPrefix(prefix)
        }
    }

    var uniqueKey: String {
        let pathKey: String
        switch path {
        case .exact(let target): pathKey = "exact:" + target
        case .prefix(let prefix): pathKey = "prefix:" + prefix
        }
        return methods.sorted().joined(separator: ",") + "|" + pathKey
    }
}

private struct SOCKSProxyPolicy {
    let port: UInt16
}

private func parseSOCKSProxy(_ raw: Any?) throws -> SOCKSProxyPolicy? {
    guard let raw else { return nil }
    guard let dictionary = raw as? [String: Any],
          hasOnlyKeys(dictionary, allowed: ["type", "host", "port"]),
          dictionary["type"] as? String == "socks5",
          dictionary["host"] as? String == "127.0.0.1",
          let port = dictionary["port"] as? Int,
          (1024...65535).contains(port) else {
        throw fail("A policy profile contains an invalid loopback SOCKS proxy.", exitCode: 3)
    }
    guard #available(macOS 14.0, *) else {
        throw fail("Configured SOCKS proxy requires macOS 14 or newer; direct fallback is forbidden.", exitCode: 3)
    }
    return SOCKSProxyPolicy(port: UInt16(port))
}

private struct ProfilePolicy {
    let name: String
    let origin: URL
    let mediaType: JSONMediaType
    let proxy: SOCKSProxyPolicy?
    let credentials: [CredentialPolicy]
    let operations: [OperationPolicy]
}

private struct PolicyStore {
    let profiles: [String: ProfilePolicy]

    static var path: String {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".config/codex/keychain-api.json", isDirectory: false)
            .path
    }

    static func load() throws -> PolicyStore {
        let data = try readRegularFile(
            at: path,
            maximumBytes: maximumPolicyBytes,
            requirePrivateMode: true
        )
        guard let object = try? JSONSerialization.jsonObject(with: data),
              let root = object as? [String: Any],
              root["version"] as? Int == 1,
              let rawProfiles = root["profiles"] as? [String: Any],
              !rawProfiles.isEmpty,
              rawProfiles.count <= 100 else {
            throw fail("The Keychain API policy is invalid.", exitCode: 3)
        }
        var profiles: [String: ProfilePolicy] = [:]
        for (name, value) in rawProfiles {
            guard name.range(of: "^[a-z0-9][a-z0-9.-]{0,62}$", options: .regularExpression) != nil,
                  let dictionary = value as? [String: Any] else {
                throw fail("The Keychain API policy contains an invalid profile.", exitCode: 3)
            }
            profiles[name] = try parseProfile(name: name, dictionary: dictionary)
        }
        return PolicyStore(profiles: profiles)
    }
}

private func hasOnlyKeys(_ dictionary: [String: Any], allowed: Set<String>) -> Bool {
    Set(dictionary.keys).isSubset(of: allowed)
}

private func parseOrigin(_ raw: Any?) throws -> URL {
    guard let value = raw as? String,
          let components = URLComponents(string: value),
          components.scheme == "https",
          let host = components.host,
          !host.isEmpty,
          components.user == nil,
          components.password == nil,
          components.query == nil,
          components.fragment == nil,
          components.path.isEmpty || components.path == "/",
          let url = components.url else {
        throw fail("A policy profile contains an invalid HTTPS origin.", exitCode: 3)
    }
    return url
}

private func validateHeaderName(_ value: String) -> Bool {
    guard value.range(of: "^[!#$%&'*+.^_`|~A-Za-z0-9-]{1,64}$", options: .regularExpression) != nil else {
        return false
    }
    let blocked = Set([
        "authorization", "connection", "content-length", "cookie", "host",
        "proxy-authorization", "set-cookie", "te", "trailer", "transfer-encoding", "upgrade"
    ])
    return !blocked.contains(value.lowercased())
}

private func parseCredential(_ raw: Any) throws -> CredentialPolicy {
    guard let dictionary = raw as? [String: Any],
          hasOnlyKeys(dictionary, allowed: ["service", "account", "type", "header", "prefix", "username"]),
          let service = dictionary["service"] as? String,
          let account = dictionary["account"] as? String,
          let type = dictionary["type"] as? String,
          isSafeMetadata(service),
          isSafeMetadata(account) else {
        throw fail("A policy profile contains an invalid credential reference.", exitCode: 3)
    }

    let placement: CredentialPlacement
    switch type {
    case "bearer":
        guard dictionary["header"] == nil,
              dictionary["prefix"] == nil,
              dictionary["username"] == nil else {
            throw fail("A bearer credential policy contains unsupported fields.", exitCode: 3)
        }
        placement = .bearer
    case "basic":
        guard dictionary["header"] == nil,
              dictionary["prefix"] == nil,
              let username = dictionary["username"] as? String,
              isSafeMetadata(username),
              !username.contains(":") else {
            throw fail("A basic credential policy is invalid.", exitCode: 3)
        }
        placement = .basic(username: username)
    case "header":
        guard dictionary["username"] == nil,
              let header = dictionary["header"] as? String,
              validateHeaderName(header) else {
            throw fail("A header credential policy is invalid.", exitCode: 3)
        }
        let prefix = dictionary["prefix"] as? String ?? ""
        guard prefix.count <= 100, !containsControlCharacters(prefix) else {
            throw fail("A credential header prefix is invalid.", exitCode: 3)
        }
        placement = .header(name: header, prefix: prefix)
    default:
        throw fail("A policy profile uses an unsupported authentication type.", exitCode: 3)
    }

    return CredentialPolicy(service: service, account: account, placement: placement)
}

private let supportedHTTPMethods = Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"])

private func safeRelativeComponents(_ value: String) -> URLComponents? {
    guard value.hasPrefix("/"),
          value.count <= 8192,
          !containsControlCharacters(value),
          !value.contains("#"),
          !value.contains("\\"),
          let components = URLComponents(string: value),
          components.scheme == nil,
          components.host == nil,
          components.user == nil,
          components.password == nil,
          components.fragment == nil,
          components.percentEncodedPath.hasPrefix("/"),
          !components.percentEncodedPath.contains("%"),
          !components.percentEncodedPath.contains("//"),
          !components.percentEncodedPath.split(separator: "/").contains(where: { $0 == "." || $0 == ".." }) else {
        return nil
    }
    return components
}

private func validateOperationPath(_ value: String) -> Bool {
    safeRelativeComponents(value) != nil
}

private func validateOperationPrefix(_ value: String) -> Bool {
    guard value.hasSuffix("/"),
          let components = safeRelativeComponents(value),
          components.query == nil else {
        return false
    }
    return components.percentEncodedPath == value
}

private func parseOperation(_ raw: Any) throws -> OperationPolicy {
    guard let dictionary = raw as? [String: Any],
          hasOnlyKeys(dictionary, allowed: ["method", "methods", "path", "path_prefix", "body", "response"]),
          let bodyValue = dictionary["body"] as? String,
          let responseValue = dictionary["response"] as? String,
          let body = BodyPolicy(rawValue: bodyValue),
          let response = ResponsePolicy(rawValue: responseValue) else {
        throw fail("A policy profile contains an invalid operation.", exitCode: 3)
    }

    if let rawMethod = dictionary["method"] as? String,
       let path = dictionary["path"] as? String,
       dictionary["methods"] == nil,
       dictionary["path_prefix"] == nil {
        guard supportedHTTPMethods.contains(rawMethod),
              validateOperationPath(path) else {
            throw fail("A policy profile contains an invalid exact operation.", exitCode: 3)
        }
        if (rawMethod == "GET" || rawMethod == "HEAD") && body != .none {
            throw fail("GET and HEAD operations cannot have request bodies.", exitCode: 3)
        }
        if rawMethod == "HEAD" && response != .empty {
            throw fail("HEAD operations must use an empty response policy.", exitCode: 3)
        }
        return OperationPolicy(
            methods: [rawMethod],
            path: .exact(path),
            body: body,
            response: response
        )
    }

    if let rawMethods = dictionary["methods"] as? [String],
       let pathPrefix = dictionary["path_prefix"] as? String,
       dictionary["method"] == nil,
       dictionary["path"] == nil {
        let methods = Set(rawMethods)
        guard !methods.isEmpty,
              methods.count == rawMethods.count,
              methods.isSubset(of: supportedHTTPMethods),
              validateOperationPrefix(pathPrefix) else {
            throw fail("A policy profile contains an invalid prefix operation.", exitCode: 3)
        }
        return OperationPolicy(
            methods: methods,
            path: .prefix(pathPrefix),
            body: body,
            response: response
        )
    }

    throw fail("A policy operation must define either an exact path or a path prefix.", exitCode: 3)
}

private func parseProfile(name: String, dictionary: [String: Any]) throws -> ProfilePolicy {
    guard hasOnlyKeys(dictionary, allowed: ["origin", "media_type", "proxy", "credentials", "operations"]),
          let rawCredentials = dictionary["credentials"] as? [Any],
          (1...8).contains(rawCredentials.count),
          let rawOperations = dictionary["operations"] as? [Any],
          (1...50).contains(rawOperations.count) else {
        throw fail("A policy profile has an invalid shape.", exitCode: 3)
    }
    let origin = try parseOrigin(dictionary["origin"])
    let mediaType = try parseJSONMediaType(dictionary["media_type"])
    let proxy = try parseSOCKSProxy(dictionary["proxy"])
    if proxy != nil {
        // CFNetwork bypasses SOCKS for loopback destinations even with failover disabled.
        // Limit this option to DNS API origins; never silently proxy a local/IP origin.
        let dnsNamePattern = #"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9](?:[a-z0-9-]{0,57}[a-z0-9])?)$"#
        guard let host = origin.host?.lowercased(),
              host.count <= 253,
              host.range(of: dnsNamePattern, options: .regularExpression) != nil,
              !host.hasSuffix(".local"), !host.hasSuffix(".localhost"),
              !host.hasSuffix(".localdomain") else {
            throw fail("Configured SOCKS proxy requires a non-local DNS API origin.", exitCode: 3)
        }
    }
    let credentials = try rawCredentials.map(parseCredential)
    let operations = try rawOperations.map(parseOperation)

    var headerNames = Set<String>()
    for credential in credentials {
        let headerName: String
        switch credential.placement {
        case .bearer, .basic: headerName = "authorization"
        case .header(let name, _): headerName = name.lowercased()
        }
        guard headerNames.insert(headerName).inserted else {
            throw fail("A policy profile defines a credential header more than once.", exitCode: 3)
        }
    }

    var operationKeys = Set<String>()
    for operation in operations {
        guard operationKeys.insert(operation.uniqueKey).inserted else {
            throw fail("A policy profile defines an operation more than once.", exitCode: 3)
        }
    }
    return ProfilePolicy(
        name: name,
        origin: origin,
        mediaType: mediaType,
        proxy: proxy,
        credentials: credentials,
        operations: operations
    )
}

private enum KeychainReader {
    private static func query(
        for credential: CredentialPolicy,
        returnData: Bool,
        context suppliedContext: LAContext? = nil
    ) throws -> [CFString: Any] {
        var defaultKeychain: SecKeychain?
        guard SecKeychainCopyDefault(&defaultKeychain) == errSecSuccess, let defaultKeychain else {
            throw fail("The default login keychain is unavailable.", exitCode: 4)
        }
        let context: LAContext
        if let suppliedContext {
            context = suppliedContext
        } else {
            context = LAContext()
            context.interactionNotAllowed = true
        }
        return [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: credential.service,
            kSecAttrAccount: credential.account,
            kSecAttrSynchronizable: kCFBooleanFalse as Any,
            kSecMatchSearchList: [defaultKeychain],
            kSecMatchLimit: kSecMatchLimitOne,
            kSecUseAuthenticationContext: context,
            returnData ? kSecReturnData : kSecReturnAttributes: true
        ]
    }

    static func exists(_ credential: CredentialPolicy) throws -> Bool {
        let query = try query(for: credential, returnData: false)
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess: return true
        case errSecItemNotFound: return false
        case errSecInteractionNotAllowed, errSecAuthFailed, errSecUserCanceled:
            throw fail("Keychain access was not authorized or is unavailable.", exitCode: 4)
        default:
            throw fail("Keychain lookup failed safely.", exitCode: 4)
        }
    }

    static func value(_ credential: CredentialPolicy) throws -> String {
        let query = try query(for: credential, returnData: true)
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess: break
        case errSecItemNotFound:
            throw fail("A credential required by this profile is not present in the login keychain.", exitCode: 4)
        case errSecInteractionNotAllowed, errSecAuthFailed, errSecUserCanceled:
            throw fail("Keychain access was not authorized or is unavailable.", exitCode: 4)
        default:
            throw fail("Keychain retrieval failed safely.", exitCode: 4)
        }

        guard var data = result as? Data, !data.isEmpty, data.count <= 4096 else {
            throw fail("A Keychain item has no usable credential value.", exitCode: 4)
        }
        defer { data.resetBytes(in: 0..<data.count) }
        guard let value = String(data: data, encoding: .utf8),
              !value.isEmpty,
              value.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            throw fail("A Keychain item is not a valid single-line credential.", exitCode: 4)
        }
        return value
    }

    static func authorize(_ credential: CredentialPolicy, context: LAContext) throws {
        let query = try query(for: credential, returnData: true, context: context)
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess: break
        case errSecItemNotFound:
            throw fail("A credential required by this profile is not present in the login keychain.", exitCode: 4)
        case errSecUserCanceled:
            throw fail("Keychain authorization was canceled.", exitCode: 4)
        case errSecInteractionNotAllowed, errSecAuthFailed:
            throw fail("Keychain authorization was denied or is unavailable.", exitCode: 4)
        default:
            throw fail("Keychain authorization failed safely.", exitCode: 4)
        }

        guard var data = result as? Data else {
            throw fail("A Keychain item has no usable credential value.", exitCode: 4)
        }
        result = nil
        defer { data.resetBytes(in: 0..<data.count) }
        guard !data.isEmpty,
              data.count <= 4096,
              data.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            throw fail("A Keychain item is not a valid single-line credential.", exitCode: 4)
        }
    }
}

private final class RedirectBlocker: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            completionHandler(.performDefaultHandling, nil)
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

private final class APITransport {
    private let redirectBlocker = RedirectBlocker()
    private let session: URLSession

    init(proxy: SOCKSProxyPolicy? = nil) throws {
        let configuration = try Self.sessionConfiguration(proxy: proxy)
        session = URLSession(configuration: configuration, delegate: redirectBlocker, delegateQueue: nil)
    }

    static func sessionConfiguration(proxy: SOCKSProxyPolicy?) throws -> URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 45
        configuration.httpMaximumConnectionsPerHost = 2
        configuration.tlsMinimumSupportedProtocolVersion = .TLSv12
        if let proxy {
            guard #available(macOS 14.0, *) else {
                throw fail("Configured SOCKS proxy requires macOS 14 or newer; direct fallback is forbidden.", exitCode: 3)
            }
            // The endpoint is deliberately not configurable beyond its loopback port.
            var socks = ProxyConfiguration(socksv5Proxy: .hostPort(
                host: "127.0.0.1", port: NWEndpoint.Port(rawValue: proxy.port)!
            ))
            socks.allowFailover = false
            socks.excludedDomains = []
            socks.matchDomains = []
            configuration.proxyConfigurations = [socks]
        }
        return configuration
    }

    deinit {
        session.invalidateAndCancel()
    }

    private static func effectivePort(_ url: URL) -> Int {
        url.port ?? 443
    }

    static func requestURL(
        origin: URL,
        relativePath: String,
        method: String,
        operation: OperationPolicy
    ) throws -> URL {
        guard operation.permits(method: method, relativePath: relativePath),
              let relativeComponents = safeRelativeComponents(relativePath) else {
            throw fail("The request path is outside the selected policy operation.", exitCode: 2)
        }

        var targetComponents = URLComponents(url: origin, resolvingAgainstBaseURL: false)
        targetComponents?.percentEncodedPath = relativeComponents.percentEncodedPath
        targetComponents?.percentEncodedQuery = relativeComponents.percentEncodedQuery
        guard let url = targetComponents?.url,
              let finalComponents = URLComponents(url: url, resolvingAgainstBaseURL: false),
              url.scheme == origin.scheme,
              url.host == origin.host,
              effectivePort(url) == effectivePort(origin),
              url.user == nil,
              url.password == nil,
              url.fragment == nil,
              finalComponents.percentEncodedPath == relativeComponents.percentEncodedPath,
              finalComponents.percentEncodedQuery == relativeComponents.percentEncodedQuery else {
            throw fail("The request path is outside the selected policy operation.", exitCode: 2)
        }
        return url
    }

    func send(
        profile: ProfilePolicy,
        operation: OperationPolicy,
        method: String,
        relativePath: String,
        body: Data?,
        secrets: [String],
        secretOutput: ProtectedResponseFile? = nil
    ) async throws -> Any {
        let url = try Self.requestURL(
            origin: profile.origin,
            relativePath: relativePath,
            method: method,
            operation: operation
        )
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.timeoutInterval = 30
        request.setValue(profile.mediaType.rawValue, forHTTPHeaderField: "Accept")

        for (credential, secret) in zip(profile.credentials, secrets) {
            switch credential.placement {
            case .bearer:
                request.setValue("Bearer \(secret)", forHTTPHeaderField: "Authorization")
            case .basic(let username):
                let encoded = Data((username + ":" + secret).utf8).base64EncodedString()
                request.setValue("Basic \(encoded)", forHTTPHeaderField: "Authorization")
            case .header(let name, let prefix):
                request.setValue(prefix + secret, forHTTPHeaderField: name)
            }
        }

        guard !((method == "GET" || method == "HEAD") && body != nil) else {
            throw fail("GET and HEAD requests cannot have a body.", exitCode: 2)
        }
        let forbiddenArtifacts = forbiddenCredentialArtifacts(profile: profile, secrets: secrets)
        switch (operation.body, body) {
        case (.none, nil), (.optionalJSON, nil):
            break
        case (.json, .some(let body)), (.optionalJSON, .some(let body)):
            guard !dataContainsAnySecret(body, secrets: forbiddenArtifacts) else {
                throw fail("Refused a request body containing credential material.", exitCode: 2)
            }
            request.httpBody = body
            request.setValue(profile.mediaType.rawValue, forHTTPHeaderField: "Content-Type")
        default:
            throw fail("The request body does not match the selected policy operation.", exitCode: 2)
        }

        let bytes: URLSession.AsyncBytes
        let response: URLResponse
        do {
            (bytes, response) = try await session.bytes(for: request)
        } catch {
            throw fail("No API response was received. A remote mutation may have succeeded; verify state before retrying.", exitCode: 5)
        }
        guard let http = response as? HTTPURLResponse,
              let responseURL = http.url,
              responseURL.scheme == profile.origin.scheme,
              responseURL.host == profile.origin.host,
              Self.effectivePort(responseURL) == Self.effectivePort(profile.origin),
              responseURL.user == nil,
              responseURL.password == nil else {
            throw fail("The API response origin did not match policy.", exitCode: 5)
        }
        guard (200...299).contains(http.statusCode) else {
            throw fail("The API rejected the request (HTTP \(http.statusCode)).", exitCode: 5)
        }

        if operation.response == .empty {
            return ["ok": true, "status": http.statusCode]
        }
        if http.expectedContentLength > maximumResponseBytes {
            throw fail("The API response exceeded the safe size limit.", exitCode: 5)
        }

        var data = Data()
        defer { data.resetBytes(in: 0..<data.count) }
        let expectedSize = http.expectedContentLength > 0 ? Int(http.expectedContentLength) : 0
        data.reserveCapacity(min(expectedSize, maximumResponseBytes))
        do {
            for try await byte in bytes {
                guard data.count < maximumResponseBytes else {
                    throw fail("The API response exceeded the safe size limit.", exitCode: 5)
                }
                data.append(byte)
            }
        } catch let failure as SafeFailure {
            throw failure
        } catch {
            throw fail("The API response ended unexpectedly. A remote mutation may have succeeded; verify state before retrying.", exitCode: 5)
        }
        if data.isEmpty && operation.response == .jsonOrEmpty {
            guard secretOutput == nil else {
                throw fail("No secret response was saved. A remote mutation may have succeeded; verify state before retrying.", exitCode: 5)
            }
            return ["ok": true, "status": http.statusCode]
        }
        guard let mediaType = http.mimeType?.lowercased(),
              mediaType == "application/json" || mediaType.hasSuffix("+json") else {
            throw fail("The API returned an unexpected response type.", exitCode: 5)
        }
        guard !dataContainsAnySecret(data, secrets: forbiddenArtifacts),
              let object = try? JSONSerialization.jsonObject(with: data) else {
            throw fail("The API response was unsafe or was not valid JSON.", exitCode: 5)
        }
        guard !objectContainsAnySecret(object, secrets: forbiddenArtifacts) else {
            throw fail("The API response contained credential material.", exitCode: 5)
        }
        if let secretOutput {
            return try secretOutput.commit(data)
        }
        return sanitizedAPIObject(
            object,
            forbiddenSecrets: forbiddenArtifacts,
            credentialContext: pathHasCredentialContext(relativePath)
        )
    }
}

private func readJSONBody(at path: String) throws -> Data {
    let data = try readRegularFile(at: path, maximumBytes: maximumBodyBytes, requirePrivateMode: false)
    guard let object = try? JSONSerialization.jsonObject(with: data),
          object is [String: Any] || object is [Any],
          JSONSerialization.isValidJSONObject(object),
          let normalized = try? JSONSerialization.data(withJSONObject: object) else {
        throw fail("The request body file is not a valid JSON object or array.", exitCode: 2)
    }
    return normalized
}

private struct RequestOptions {
    let method: String
    let path: String
    let bodyFile: String?
    let secretOutputFile: String?
}

private func parseRequestOptions(_ arguments: [String]) throws -> RequestOptions {
    let allowed = Set(["--method", "--path", "--body-file", "--secret-output-file"])
    var values: [String: String] = [:]
    var index = 0
    while index < arguments.count {
        let option = arguments[index]
        guard allowed.contains(option), index + 1 < arguments.count else {
            throw fail("Unsupported or incomplete request option.", exitCode: 2)
        }
        guard values[option] == nil else {
            throw fail("A request option was provided more than once.", exitCode: 2)
        }
        values[option] = arguments[index + 1]
        index += 2
    }
    guard let method = values["--method"],
          let path = values["--path"],
          !method.isEmpty,
          !path.isEmpty else {
        throw fail("request requires --method and --path.", exitCode: 2)
    }
    return RequestOptions(method: method, path: path, bodyFile: values["--body-file"],
                          secretOutputFile: values["--secret-output-file"])
}

private func operationForRequest(profile: ProfilePolicy, method: String, relativePath: String) throws -> OperationPolicy {
    guard supportedHTTPMethods.contains(method),
          safeRelativeComponents(relativePath) != nil else {
        throw fail("The request method or path is invalid.", exitCode: 2)
    }
    guard let operation = profile.operations.first(where: {
        $0.permits(method: method, relativePath: relativePath)
    }) else {
        throw fail("The requested method and path are not allowed by policy.", exitCode: 2)
    }
    return operation
}

private func runSelfTest() throws {
    guard try parseJSONMediaType(nil) == .json,
          try parseJSONMediaType("application/json") == .json,
          try parseJSONMediaType("application/vnd.api+json") == .jsonAPI else {
        throw fail("Self-test failed: JSON media-type policy.")
    }
    var invalidMediaTypeRejected = false
    do {
        _ = try parseJSONMediaType("application/json\r\nX-Unsafe: value")
    } catch is SafeFailure {
        invalidMediaTypeRejected = true
    }
    guard invalidMediaTypeRejected else {
        throw fail("Self-test failed: JSON media-type restriction.")
    }

    guard try parseSOCKSProxy(nil) == nil else {
        throw fail("Self-test failed: absent proxy policy.")
    }
    func requireProxyPolicyRefusal(_ action: () throws -> Void) throws {
        do {
            try action()
        } catch let failure as SafeFailure where failure.exitCode == 3 {
            return
        }
        throw fail("Self-test failed: unsafe proxy policy accepted.")
    }
    let proxyFixture: [String: Any] = ["type": "socks5", "host": "127.0.0.1", "port": 49153]
    let profileFixture: [String: Any] = [
        "origin": "https://api.example.invalid",
        "credentials": [["service": "inert.test", "account": "inert", "type": "bearer"]],
        "operations": [["method": "GET", "path": "/", "body": "none", "response": "json"]]
    ]
    guard try parseProfile(name: "fixture", dictionary: profileFixture).proxy == nil else {
        throw fail("Self-test failed: unconfigured profile acquired a proxy.")
    }
    let unchanged = try APITransport.sessionConfiguration(proxy: nil)
    for invalid: [String: Any] in [
        ["type": "http", "host": "127.0.0.1", "port": 49153],
        ["type": "socks5", "host": "localhost", "port": 49153],
        ["type": "socks5", "host": "0.0.0.0", "port": 49153],
        ["type": "socks5", "host": "192.0.2.1", "port": 49153],
        ["type": "socks5", "host": "127.0.0.1", "port": 0],
        ["type": "socks5", "host": "127.0.0.1", "port": 65536],
        ["type": "socks5", "host": "127.0.0.1", "port": NSNumber(value: 49153.5)],
        ["type": "socks5", "host": "127.0.0.1", "port": "49153"],
        ["type": "socks5", "host": "127.0.0.1", "port": true],
        ["type": "socks5", "host": "127.0.0.1", "port": 49153, "password": "INERT"],
        ["type": "socks5", "host": "127.0.0.1", "port": 49153, "allow_failover": true]
    ] {
        try requireProxyPolicyRefusal { _ = try parseSOCKSProxy(invalid) }
    }
    if #available(macOS 14.0, *) {
        guard let proxy = try parseSOCKSProxy(proxyFixture), proxy.port == 49153 else {
            throw fail("Self-test failed: proxy policy parsing.")
        }
        var proxiedProfile = profileFixture
        proxiedProfile["proxy"] = proxyFixture
        guard try parseProfile(name: "fixture", dictionary: proxiedProfile).proxy?.port == 49153 else {
            throw fail("Self-test failed: proxied profile parsing.")
        }
        for origin in [
            "https://127.0.0.1", "https://[::1]", "https://localhost",
            "https://api.localhost", "https://api.local", "https://api.localdomain",
            "https://192.0.2.1", "https://0x7f.0.0.1", "https://0x7f.0x0.0x0.0x1",
            "https://api.example.invalid.", "https://api..example.invalid"
        ] {
            try requireProxyPolicyRefusal {
                var invalid = proxiedProfile
                invalid["origin"] = origin
                _ = try parseProfile(name: "fixture", dictionary: invalid)
            }
        }
        let proxied = try APITransport.sessionConfiguration(proxy: proxy)
        guard proxied.proxyConfigurations.count == 1,
              !proxied.proxyConfigurations[0].allowFailover,
              proxied.proxyConfigurations[0].excludedDomains.isEmpty,
              proxied.proxyConfigurations[0].matchDomains.isEmpty,
              proxied.tlsMinimumSupportedProtocolVersion == .TLSv12,
              proxied.httpCookieStorage == nil,
              proxied.urlCredentialStorage == nil else {
            throw fail("Self-test failed: fail-closed proxy session configuration.")
        }
        guard unchanged.proxyConfigurations.isEmpty else {
            throw fail("Self-test failed: unconfigured profile transport changed.")
        }
    } else {
        try requireProxyPolicyRefusal { _ = try parseSOCKSProxy(proxyFixture) }
        try requireProxyPolicyRefusal {
            _ = try APITransport.sessionConfiguration(proxy: SOCKSProxyPolicy(port: 49153))
        }
    }

    let capabilityURLFixture = sanitizedAPIObject([
        "hosted-state-download": "https://archive.invalid/v1/object/INERT_CAPABILITY",
        "upload-url": "https://upload.invalid/INERT_CAPABILITY"
    ], forbiddenSecrets: [])
    guard let capabilityURLs = capabilityURLFixture as? [String: Any],
          capabilityURLs["hosted-state-download"] as? String == redactedValue,
          capabilityURLs["upload-url"] as? String == redactedValue else {
        throw fail("Self-test failed: capability-URL redaction.")
    }

    let origin = URL(string: "https://example.invalid")!
    let prefixOperation = try parseOperation([
        "methods": supportedHTTPMethods.sorted(),
        "path_prefix": "/v1/",
        "body": "optional-json",
        "response": "json-or-empty"
    ])
    let allowed = try APITransport.requestURL(
        origin: origin,
        relativePath: "/v1/status?limit=1",
        method: "GET",
        operation: prefixOperation
    )
    guard allowed.absoluteString == "https://example.invalid/v1/status?limit=1" else {
        throw fail("Self-test failed: URL construction.")
    }
    var alternateOriginRejected = false
    do {
        _ = try APITransport.requestURL(
            origin: origin,
            relativePath: "//attacker.invalid/v1/status",
            method: "GET",
            operation: prefixOperation
        )
    } catch is SafeFailure {
        alternateOriginRejected = true
    }
    guard alternateOriginRejected else {
        throw fail("Self-test failed: origin restriction.")
    }

    var encodedTraversalRejected = false
    do {
        _ = try APITransport.requestURL(
            origin: origin,
            relativePath: "/v1/%2e%2e/admin",
            method: "GET",
            operation: prefixOperation
        )
    } catch is SafeFailure {
        encodedTraversalRejected = true
    }
    guard encodedTraversalRejected else {
        throw fail("Self-test failed: encoded traversal restriction.")
    }
    var prefixConfusionRejected = false
    do {
        _ = try APITransport.requestURL(
            origin: origin,
            relativePath: "/v10/status",
            method: "GET",
            operation: prefixOperation
        )
    } catch is SafeFailure {
        prefixConfusionRejected = true
    }
    guard prefixConfusionRejected else {
        throw fail("Self-test failed: path-prefix boundary.")
    }

    let inertMarker = "INERT_SELF_TEST_MARKER"
    var outputTripwirePassed = false
    do {
        _ = try encodedJSON(["value": inertMarker], forbiddenSecrets: [inertMarker])
    } catch is SafeFailure {
        outputTripwirePassed = true
    }
    guard outputTripwirePassed else {
        throw fail("Self-test failed: output tripwire.")
    }
    let redactionFixture: [String: Any] = [
        "default_password": "INERT_PASSWORD_VALUE",
        "nested": ["api_token": "INERT_TOKEN_VALUE", "status": "ok"]
    ]
    guard let redacted = sanitizedAPIObject(redactionFixture, forbiddenSecrets: []) as? [String: Any],
          redacted["default_password"] as? String == redactedValue,
          let nested = redacted["nested"] as? [String: Any],
          nested["api_token"] as? String == redactedValue,
          nested["status"] as? String == "ok" else {
        throw fail("Self-test failed: response redaction.")
    }
    let createdCredentialMarker = "INERT_TEST_ONLY_CREATED_VALUE"
    let createdCredentialFixture: [String: Any] = [
        "result": [
            "id": "INERT_TEST_ONLY_ID",
            "status": "active",
            "value": createdCredentialMarker
        ]
    ]
    let sanitizedCreatedCredential = sanitizedAPIObject(
        createdCredentialFixture,
        forbiddenSecrets: [],
        credentialContext: true
    )
    let sanitizedCreatedData = try encodedJSON(sanitizedCreatedCredential)
    guard sanitizedCreatedData.range(of: Data(createdCredentialMarker.utf8)) == nil,
          let createdRoot = sanitizedCreatedCredential as? [String: Any],
          let createdResult = createdRoot["result"] as? [String: Any],
          createdResult["value"] as? String == redactedValue,
          createdResult["status"] as? String == "active" else {
        throw fail("Self-test failed: credential-context redaction.")
    }
    let neutralValue = "INERT_TEST_ONLY_PUBLIC_VALUE"
    let neutralFixture = sanitizedAPIObject(
        ["value": neutralValue, "monkey": "safe", "keynote": "safe"],
        forbiddenSecrets: []
    )
    guard let neutral = neutralFixture as? [String: Any],
          neutral["value"] as? String == neutralValue,
          neutral["monkey"] as? String == "safe",
          neutral["keynote"] as? String == "safe" else {
        throw fail("Self-test failed: neutral response preservation.")
    }
    let escapedMarker = "INERT_TEST_ONLY_\"ESCAPED"
    let escapedData = try JSONSerialization.data(withJSONObject: ["note": escapedMarker])
    guard !dataContainsAnySecret(escapedData, secrets: [escapedMarker]),
          let escapedObject = try? JSONSerialization.jsonObject(with: escapedData),
          objectContainsAnySecret(escapedObject, secrets: [escapedMarker]) else {
        throw fail("Self-test failed: parsed-object credential tripwire.")
    }
    try runProtectedResponseFileSelfTest()
    try emitJSON([
        "keychain_read": false,
        "network_used": false,
        "protected_file_tests_passed": true,
        "passed": true
    ])
}

private func runProtectedResponseFileSelfTest() throws {
    let files = FileManager.default
    let directory = "/private/tmp/keychain-api-sink-self-test-" + UUID().uuidString
    try files.createDirectory(atPath: directory, withIntermediateDirectories: false,
                              attributes: [.posixPermissions: 0o700])
    defer { try? files.removeItem(atPath: directory) }
    let path = directory + "/response.json"
    let marker = "INERT_PROTECTED_FILE_SELF_TEST"
    let bytes = try JSONSerialization.data(withJSONObject: ["result": ["client_secret": marker]])
    let sink = try ProtectedResponseFile(path: path)
    let receipt = try sink.commit(bytes)
    guard try readRegularFile(at: path, maximumBytes: 4096, requirePrivateMode: true) == bytes,
          try encodedJSON(receipt).range(of: Data(marker.utf8)) == nil else {
        throw fail("Self-test failed: protected file bytes or receipt.")
    }
    func requireRefusal(_ action: () throws -> Void) throws {
        do { try action() } catch is SafeFailure { return }
        throw fail("Self-test failed: unsafe secret file was accepted.")
    }
    try requireRefusal { _ = try ProtectedResponseFile(path: path) }
    try requireRefusal { _ = try sink.commit(bytes) }
    try requireRefusal { _ = try ProtectedResponseFile(path: directory + "/../unsafe.json") }
    try requireRefusal { _ = try ProtectedResponseFile(path: "relative.json") }
    try files.createSymbolicLink(atPath: directory + "/link.json", withDestinationPath: path)
    try requireRefusal { _ = try ProtectedResponseFile(path: directory + "/link.json") }
    try files.createSymbolicLink(atPath: directory + "/linked-directory", withDestinationPath: directory)
    try requireRefusal { _ = try ProtectedResponseFile(path: directory + "/linked-directory/new.json") }
    let publicDirectory = directory + "/not-private"
    try files.createDirectory(atPath: publicDirectory, withIntermediateDirectories: false,
                              attributes: [.posixPermissions: 0o755])
    guard chmod(publicDirectory, 0o755) == 0 else { throw fail("Self-test fixture setup failed.") }
    try requireRefusal { _ = try ProtectedResponseFile(path: publicDirectory + "/new.json") }
    guard try readRegularFile(at: path, maximumBytes: 4096, requirePrivateMode: true) == bytes else {
        throw fail("Self-test failed: existing secret file was modified.")
    }
}

private func usage() -> String {
    """
    Usage:
      keychain-api status <profile>
      keychain-api authorize <profile>
      keychain-api request <profile> --method <METHOD> --path <PATH> [--body-file <JSON_FILE>] [--secret-output-file <NEW_JSON_FILE>]
      keychain-api self-test

    Secret output: requires a NEW file in an existing owner-only directory.
    Saves the JSON response directly as mode 0600; prints only a fixed receipt.
    Existing files, symlinks, and traversal are refused. Never retry a timed-out
    mutation without checking provider state. Default output is unchanged.

    Policy: ~/.config/codex/keychain-api.json
    """
}

@main
private enum KeychainAPICLI {
    static func main() async {
        do {
            let arguments = Array(CommandLine.arguments.dropFirst())
            guard let command = arguments.first else {
                throw fail(usage(), exitCode: 2)
            }

            switch command {
            case "help", "--help", "-h":
                guard arguments.count == 1 else { throw fail("help accepts no arguments.", exitCode: 2) }
                print(usage())

            case "self-test":
                guard arguments.count == 1 else { throw fail("self-test accepts no arguments.", exitCode: 2) }
                try runSelfTest()

            case "status":
                guard arguments.count == 2 else { throw fail("status requires one profile.", exitCode: 2) }
                let store = try PolicyStore.load()
                let profileName = arguments[1]
                guard let profile = store.profiles[profileName] else {
                    throw fail("The requested profile is not defined.", exitCode: 2)
                }
                var results: [[String: Any]] = []
                for (index, credential) in profile.credentials.enumerated() {
                    results.append([
                        "found": try KeychainReader.exists(credential),
                        "index": index + 1
                    ])
                }
                try emitJSON([
                    "credentials": results,
                    "network_used": false,
                    "profile": profile.name,
                    "secret_read": false
                ])

            case "authorize":
                guard arguments.count == 2 else { throw fail("authorize requires one profile.", exitCode: 2) }
                let store = try PolicyStore.load()
                let profileName = arguments[1]
                guard let profile = store.profiles[profileName] else {
                    throw fail("The requested profile is not defined.", exitCode: 2)
                }
                let context = LAContext()
                context.interactionNotAllowed = false
                context.localizedReason = "Allow access to configured API credentials."
                context.touchIDAuthenticationAllowableReuseDuration = 0
                defer { context.invalidate() }
                for credential in profile.credentials {
                    try KeychainReader.authorize(credential, context: context)
                }
                try emitJSON([
                    "credentials_read": profile.credentials.count,
                    "network_used": false,
                    "profile": profile.name,
                    "secret_output": false,
                    "secret_read": true
                ])

            case "request":
                guard arguments.count >= 6 else { throw fail("request arguments are incomplete.", exitCode: 2) }
                let store = try PolicyStore.load()
                let profileName = arguments[1]
                guard let profile = store.profiles[profileName] else {
                    throw fail("The requested profile is not defined.", exitCode: 2)
                }
                let options = try parseRequestOptions(Array(arguments.dropFirst(2)))
                let operation = try operationForRequest(
                    profile: profile,
                    method: options.method,
                    relativePath: options.path
                )
                let body = try options.bodyFile.map(readJSONBody)
                let bodyMatchesPolicy: Bool
                switch operation.body {
                case .none:
                    bodyMatchesPolicy = body == nil
                case .json:
                    bodyMatchesPolicy = body != nil && options.method != "GET" && options.method != "HEAD"
                case .optionalJSON:
                    bodyMatchesPolicy = body == nil || (options.method != "GET" && options.method != "HEAD")
                }
                guard bodyMatchesPolicy else {
                    throw fail("The request body does not match policy.", exitCode: 2)
                }

                guard options.secretOutputFile == nil || operation.response != .empty else {
                    throw fail("Secret output requires a JSON response policy.", exitCode: 2)
                }
                let transport = try APITransport(proxy: profile.proxy)
                let secretOutput = try options.secretOutputFile.map { try ProtectedResponseFile(path: $0) }

                var secrets = try profile.credentials.map(KeychainReader.value)
                defer {
                    for index in secrets.indices {
                        secrets[index].removeAll(keepingCapacity: false)
                    }
                }
                let result = try await transport.send(
                    profile: profile,
                    operation: operation,
                    method: options.method,
                    relativePath: options.path,
                    body: body,
                    secrets: secrets,
                    secretOutput: secretOutput
                )
                let forbiddenArtifacts = forbiddenCredentialArtifacts(profile: profile, secrets: secrets)
                try emitJSON(result, forbiddenSecrets: forbiddenArtifacts)

            default:
                throw fail("Unknown command.\n\n" + usage(), exitCode: 2)
            }
        } catch let failure as SafeFailure {
            writeError(failure.message)
            exit(failure.exitCode)
        } catch {
            writeError("The operation failed safely; no credential or raw diagnostic was printed.")
            exit(1)
        }
    }
}
