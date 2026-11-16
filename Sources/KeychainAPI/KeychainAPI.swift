import Foundation
import Security
import LocalAuthentication
import Darwin
import Network

private let maximumPolicyBytes = 1 * 1024 * 1024
private let maximumBodyBytes = 1 * 1024 * 1024
private let maximumResponseBytes = 8 * 1024 * 1024
private let maximumCredentialBytes = 4096

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

private func credentialArtifacts(_ secrets: [String]) -> [String] {
    Array(Set(secrets + secrets.map { Data($0.utf8).base64EncodedString() }))
}

private func checkedJSON(_ data: Data, forbiddenSecrets: [String], exitCode: Int32) throws -> Any {
    guard !dataContainsAnySecret(data, secrets: forbiddenSecrets),
          let object = try? JSONSerialization.jsonObject(with: data),
          !objectContainsAnySecret(object, secrets: forbiddenSecrets) else {
        throw fail("JSON was invalid or contained authentication credential material.", exitCode: exitCode)
    }
    return object
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

private func openRegularFile(
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

private func readBoundedData(from handle: FileHandle, into data: inout Data, maximumBytes: Int, overflow: SafeFailure) throws {
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

private func readRegularFile(
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
private final class ProtectedResponseFile {
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

private enum CredentialPlacement {
    case bearer
    case onePasswordServiceAccount
    case apiKey
    case basic(username: String)
    case header(name: String, prefix: String)

    var isOnePassword: Bool {
        if case .onePasswordServiceAccount = self { return true }
        return false
    }

    func requestHeader(secret: String) throws -> (name: String, value: String) {
        switch self {
        case .onePasswordServiceAccount:
            throw fail("Service account tokens cannot be sent as HTTP headers.", exitCode: 3)
        case .bearer:
            return ("Authorization", "Bearer \(secret)")
        case .apiKey:
            return ("Authorization", "APIKey \(secret)")
        case .basic(let username):
            let encoded = Data((username + ":" + secret).utf8).base64EncodedString()
            return ("Authorization", "Basic \(encoded)")
        case .header(let name, let prefix):
            return (name, prefix + secret)
        }
    }
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
    var artifacts = Set(credentialArtifacts(secrets))
    for (credential, secret) in zip(profile.credentials, secrets) {
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

    func validate(method: String, hasBody: Bool) throws {
        guard !hasBody || (self != .none && method != "GET" && method != "HEAD"),
              hasBody || self != .json else {
            throw fail("The request body does not match the selected policy operation.", exitCode: 2)
        }
    }
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

private enum ProfileOperations {
    case http([OperationPolicy])
    case onePassword(Set<String>)

    func permits(command: String) -> Bool {
        guard case .onePassword(let commands) = self else { return false }
        return commands.contains(command)
    }
}

private struct ProfilePolicy {
    let name: String
    let origin: URL
    let mediaType: JSONMediaType
    let proxy: SOCKSProxyPolicy?
    let credentials: [CredentialPolicy]
    let operations: ProfileOperations

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

    if ["onepassword-service-account", "api-key", "bearer"].contains(type) {
        guard dictionary["header"] == nil, dictionary["prefix"] == nil, dictionary["username"] == nil else {
            throw fail("The credential policy contains unsupported fields for its authentication type.", exitCode: 3)
        }
    }
    let placement: CredentialPlacement
    switch type {
    case "onepassword-service-account": placement = .onePasswordServiceAccount
    case "api-key": placement = .apiKey
    case "bearer": placement = .bearer
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
        guard let prefix = (dictionary["prefix"] ?? "") as? String,
              prefix.count <= 100, !containsControlCharacters(prefix) else {
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
          (1...128).contains(rawOperations.count) else {
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
    let operations: ProfileOperations
    if credentials.contains(where: { $0.placement.isOnePassword }) {
        guard credentials.count == 1, proxy == nil, isTrustedOnePasswordOrigin(origin) else {
            throw fail("A 1Password profile requires one credential, a trusted account origin, and no proxy.", exitCode: 3)
        }
        var commands = Set<String>()
        for raw in rawOperations {
            guard let operation = raw as? [String: Any], hasOnlyKeys(operation, allowed: ["command"]),
                  let command = operation["command"] as? String, isSafeOnePasswordCommand(command),
                  commands.insert(command).inserted else {
                throw fail("1Password operations must contain unique command entries.", exitCode: 3)
            }
        }
        operations = .onePassword(commands)
    } else {
        let httpOperations = try rawOperations.map(parseOperation)
        guard Set(httpOperations.map(\.uniqueKey)).count == httpOperations.count else {
            throw fail("A policy profile defines an operation more than once.", exitCode: 3)
        }
        operations = .http(httpOperations)
    }

    var headerNames = Set<String>()
    for credential in credentials {
        let headerName: String
        switch credential.placement {
        case .bearer, .apiKey, .basic, .onePasswordServiceAccount: headerName = "authorization"
        case .header(let name, _): headerName = name.lowercased()
        }
        guard headerNames.insert(headerName).inserted else {
            throw fail("A policy profile defines a credential header more than once.", exitCode: 3)
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


// 1Password service accounts use SRP through the official CLI, never bearer auth.
private func isSafeOnePasswordCommand(_ command: String) -> Bool {
    guard command.range(of: #"^[a-z]+(?:-[a-z]+)*(?: [a-z]+(?:-[a-z]+)*){0,2}$"#,
                        options: .regularExpression) != nil else { return false }
    // Exclude local execution, shell injection, session management, and updater commands.
    let roots: Set<String> = ["item", "vault", "document", "user", "group", "service-account", "environment", "read", "whoami"]
    let groups: Set<String> = ["item", "item template", "vault", "vault user", "vault group", "document",
                               "user", "user recovery", "group", "group user", "service-account", "environment", "environment secret"]
    return !groups.contains(command)
        && (command.split(separator: " ").first.map { roots.contains(String($0)) } ?? false)
}

private func readProtectedInput(at path: String, maximumBytes: Int) throws -> Data {
    let parent = try openPrivateParent(of: path)
    defer { close(parent) }
    let name = URL(fileURLWithPath: path).lastPathComponent
    let fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { throw fail("Private input could not be opened safely.", exitCode: 3) }
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    var info = stat()
    guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
          info.st_uid == geteuid(), (info.st_mode & 0o077) == 0,
          info.st_nlink == 1, info.st_size >= 0, info.st_size <= maximumBytes,
          hasNoExtendedACL(fd) else {
        throw fail("Private input failed ownership, permissions, or size checks.", exitCode: 3)
    }
    var data = Data()
    try readBoundedData(from: handle, into: &data, maximumBytes: maximumBytes,
                        overflow: fail("Private input exceeded its size limit.", exitCode: 3))
    return data
}

private func validateOnePasswordArgumentValue(_ value: String, command: String) throws {
    guard isSafeMetadata(value, maximumLength: 4096),
          !looksLikeCredentialValue(value), !value.hasPrefix("ops_") else {
        throw fail("CLI arguments must contain only non-secret metadata.", exitCode: 2)
    }
    if value.hasPrefix("op://") {
        guard command == "read", let url = URLComponents(string: value),
              url.scheme == "op", url.user == nil, url.password == nil, url.fragment == nil,
              url.queryItems?.allSatisfy({
                  ($0.name == "attribute" && ["value", "type", "title", "id", "purpose", "otp"].contains($0.value ?? ""))
                    || ($0.name == "ssh-format" && $0.value == "openssh")
              }) ?? true else {
            throw fail("Invalid secret reference or unsupported reference query.", exitCode: 2)
        }
    } else {
        guard !value.hasPrefix("-"), !value.contains("="), !value.contains("://") else {
            throw fail("Inline assignments, URLs, stdin, and short flags are refused; use a protected input file for secrets.", exitCode: 2)
        }
    }
}

private func validateOnePasswordArguments(_ arguments: [String], command: String) throws {
    guard isSafeOnePasswordCommand(command), arguments.count <= 128 else {
        throw fail("Invalid 1Password command or too many arguments.", exitCode: 2)
    }
    let blocked: Set<String> = [
        "--account", "--session", "--config", "--debug", "--cache", "--format", "--encoding",
        "--help", "--version", "--template", "--out-file", "--file-mode", "--input", "--output",
        "--password", "--value", "--secret", "--token", "--url", "--notes", "--description"
    ]
    for argument in arguments {
        guard isSafeMetadata(argument, maximumLength: 4096) else {
            throw fail("CLI arguments must be nonempty metadata within the size limit.", exitCode: 2)
        }
        if argument.hasPrefix("--") {
            let parts = argument.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
            let flag = parts[0]
            guard flag.range(of: #"^--[a-z][a-z0-9-]*$"#, options: .regularExpression) != nil,
                  !blocked.contains(flag), (!flag.contains("file") || flag == "--file-name"),
                  !flag.contains("output"), !flag.contains("input"), !flag.contains("template") else {
                throw fail("CLI authentication, control, and file flags are managed by the helper.", exitCode: 2)
            }
            if parts.count == 2, !parts[1].isEmpty {
                try validateOnePasswordArgumentValue(parts[1], command: command)
            }
        } else {
            try validateOnePasswordArgumentValue(argument, command: command)
        }
    }
}

private enum OnePasswordInput {
    case template(Data)
    case document(Data, argumentIndex: Int)

    var data: Data {
        switch self {
        case .template(let data), .document(let data, _): return data
        }
    }

    func arguments(_ arguments: [String], withPath path: String) -> [String] {
        switch self {
        case .template: return arguments + ["--template", path]
        case .document(_, let index):
            var result = arguments
            result.insert(path, at: index)
            return result
        }
    }
}

private func prepareOnePasswordInput(_ input: Data?, command: String, arguments: [String]) throws -> OnePasswordInput? {
    switch command {
    case "document create", "document edit":
        guard let input else { throw fail("Document uploads require --input-file.", exitCode: 2) }
        let index = command == "document edit" ? 1 : 0
        if index == 1 {
            guard let item = arguments.first, !item.hasPrefix("-") else {
                throw fail("Document edit requires an item identifier first.", exitCode: 2)
            }
        }
        let metadata = Array(arguments.dropFirst(index))
        // Every document upload option takes one metadata value, in split or attached form.
        var optionIndex = 0
        while optionIndex < metadata.count {
            let parts = metadata[optionIndex].split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard let flag = parts.first, ["--title", "--tags", "--vault", "--file-name"].contains(String(flag)) else {
                throw fail("Unsupported document upload option.", exitCode: 2)
            }
            if parts.count == 1 {
                guard optionIndex + 1 < metadata.count, !metadata[optionIndex + 1].hasPrefix("-") else {
                    throw fail("Document upload options require a value.", exitCode: 2)
                }
                optionIndex += 1
            }
            optionIndex += 1
        }
        return .document(input, argumentIndex: index)
    case "item create", "item edit":
        guard let input else { return nil }
        guard input.count <= maximumBodyBytes,
              (try? JSONSerialization.jsonObject(with: input)) is [String: Any] else {
            throw fail("Item templates must contain a JSON object within the size limit.", exitCode: 2)
        }
        return .template(input)
    default:
        guard input == nil else { throw fail("This command does not accept a protected input file.", exitCode: 2) }
        return nil
    }
}

private func onePasswordProtectedResponse(_ data: Data, command: String, token: String) throws -> Data {
    let artifacts = credentialArtifacts([token])
    guard !dataContainsAnySecret(data, secrets: artifacts) else {
        throw fail("The CLI response echoed the authentication credential; output was refused.", exitCode: 5)
    }
    if data.isEmpty { return try encodedJSON(["ok": true]) }
    if let object = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) {
        guard !objectContainsAnySecret(object, secrets: artifacts) else {
            throw fail("The CLI response echoed the authentication credential; output was refused.", exitCode: 5)
        }
        if command != "read", command != "document get", JSONSerialization.isValidJSONObject(object) { return data }
    }
    // Binary downloads and plaintext field values remain private inside a JSON envelope.
    return try encodedJSON(["encoding": "base64", "data": data.base64EncodedString()])
}

private func isTrustedOnePasswordOrigin(_ origin: URL) -> Bool {
    guard origin.scheme == "https", origin.port == nil,
          origin.user == nil, origin.password == nil,
          origin.query == nil, origin.fragment == nil,
          origin.path.isEmpty || origin.path == "/",
          let host = origin.host?.lowercased(),
          host.range(of: #"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.1password\.(com|eu|ca)$"#,
                     options: .regularExpression) != nil else { return false }
    return true
}

private func validateOnePasswordTokenOrigin(_ token: String, expected: URL) throws {
    guard token.hasPrefix("ops_"), token.count <= maximumCredentialBytes else {
        throw fail("The Keychain entry is not a supported 1Password service account token.", exitCode: 4)
    }
    var encoded = String(token.dropFirst(4))
    guard encoded.range(of: #"^[A-Za-z0-9_-]+={0,2}$"#, options: .regularExpression) != nil else {
        throw fail("The 1Password service account token has an invalid encoding.", exitCode: 4)
    }
    encoded = encoded.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    encoded += String(repeating: "=", count: (4 - encoded.count % 4) % 4)
    guard let data = Data(base64Encoded: encoded),
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let address = object["signInAddress"] as? String,
          let origin = URL(string: address.contains("://") ? address : "https://" + address),
          isTrustedOnePasswordOrigin(origin), isTrustedOnePasswordOrigin(expected),
          origin.host?.lowercased() == expected.host?.lowercased() else {
        throw fail("The token sign-in destination does not match the approved 1Password origin.", exitCode: 4)
    }
}

private func verifiedOnePasswordExecutable() throws -> URL {
    let url = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".local/share/keychain-api/op")
    let descriptor = try openRegularFile(at: url.path, maximumBytes: 150 * 1024 * 1024, requirePrivateMode: true)
    close(descriptor)
    var code: SecStaticCode?
    var requirement: SecRequirement?
    let rule = #"anchor apple generic and certificate leaf[subject.OU] = "2BUA8C4S2C""#
    guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess,
          let code,
          SecRequirementCreateWithString(rule as CFString, [], &requirement) == errSecSuccess,
          let requirement,
          SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else {
        throw fail("The 1Password CLI failed vendor signature verification.", exitCode: 3)
    }
    return url
}

private func runOnePasswordCommand(
    profile: ProfilePolicy, token: String, executable: URL,
    command: String, arguments: [String], input: OnePasswordInput? = nil,
    timeoutSeconds: TimeInterval = 40
) throws -> OnePasswordResult {
    try validateOnePasswordTokenOrigin(token, expected: profile.origin)
    let files = FileManager.default
    let directory = URL(fileURLWithPath: "/private/tmp", isDirectory: true).appendingPathComponent("keychain-op-" + UUID().uuidString, isDirectory: true)
    try files.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? files.removeItem(at: directory) }
    let process = Process()
    process.executableURL = executable
    var commandArguments = arguments
    if let input {
        let path = directory.appendingPathComponent("input").path
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw fail("Private CLI input could not be created.", exitCode: 3) }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        try handle.write(contentsOf: input.data)
        try handle.close()
        commandArguments = input.arguments(arguments, withPath: path)
    }
    process.arguments = ["--config", directory.path, "--cache=false", "--format=json", "--no-color"]
        + command.split(separator: " ").map(String.init) + commandArguments
    // No inherited proxy, debug, alternate account, session, or TLS override variables.
    process.environment = [
        "PATH": "/usr/bin:/bin", "HOME": files.homeDirectoryForCurrentUser.path,
        "TMPDIR": directory.path, "OP_SERVICE_ACCOUNT_TOKEN": token,
        "OP_BIOMETRIC_UNLOCK_ENABLED": "false", "OP_DEBUG": "false", "OP_CACHE": "false"
    ]
    process.standardInput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    let output = Pipe()
    process.standardOutput = output
    try process.run()
    defer {
        if process.isRunning { kill(process.processIdentifier, SIGKILL); process.waitUntilExit() }
    }
    let deadlineQueue = DispatchQueue(label: "keychain-api.onepassword-deadline")
    let deadlineExpired = DispatchSemaphore(value: 0)
    let timeout = DispatchWorkItem {
        if process.isRunning { deadlineExpired.signal(); process.terminate() }
    }
    let hardTimeout = DispatchWorkItem { if process.isRunning { kill(process.processIdentifier, SIGKILL) } }
    deadlineQueue.asyncAfter(deadline: .now() + timeoutSeconds, execute: timeout)
    deadlineQueue.asyncAfter(deadline: .now() + timeoutSeconds + 5, execute: hardTimeout)
    defer { timeout.cancel(); hardTimeout.cancel() }
    var data = Data()
    var failure: SafeFailure?
    do {
        try readBoundedData(from: output.fileHandleForReading, into: &data, maximumBytes: maximumResponseBytes,
                            overflow: fail("The 1Password response exceeded the safe size limit.", exitCode: 5))
    } catch {
        failure = fail("The 1Password output could not be read completely. Check protected output and remote state before retrying.", exitCode: 5)
        if process.isRunning { kill(process.processIdentifier, SIGKILL) }
    }
    process.waitUntilExit()
    timeout.cancel()
    hardTimeout.cancel()
    // Drain any deadline callback already executing before classifying a graceful exit.
    let timedOut = deadlineQueue.sync { deadlineExpired.wait(timeout: .now()) == .success }
    if failure == nil && (timedOut || process.terminationReason != .exit || process.terminationStatus != 0) {
        failure = fail("The 1Password command failed. Check protected output and remote state before retrying; raw diagnostics were suppressed.", exitCode: 5)
    }
    return OnePasswordResult(data: data, failure: failure)
}

private struct OnePasswordResult {
    let data: Data
    let failure: SafeFailure?

    func requireSuccess() throws -> Data {
        if let failure { throw failure }
        return data
    }
}

private func saveOnePasswordResult(_ result: OnePasswordResult, command: String, token: String,
                                   output: ProtectedResponseFile) throws -> [String: Any] {
    if result.data.isEmpty, let failure = result.failure { throw failure }
    let data = try onePasswordProtectedResponse(result.data, command: command, token: token)
    let receipt = try output.commit(data)
    // A failed command can still return a one-time value. Keep that recovery evidence private.
    if let failure = result.failure { throw failure }
    return receipt
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

    private static func readData(_ credential: CredentialPolicy, context: LAContext? = nil) throws -> Data {
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
            throw fail("Keychain access was not authorized or is unavailable.", exitCode: 4)
        default:
            throw fail("Keychain retrieval failed safely.", exitCode: 4)
        }
        guard var data = result as? Data else {
            throw fail("A Keychain item has no usable credential value.", exitCode: 4)
        }
        result = nil
        guard !data.isEmpty, data.count <= maximumCredentialBytes,
              data.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            data.resetBytes(in: 0..<data.count)
            throw fail("A Keychain item is not a valid single-line credential.", exitCode: 4)
        }
        return data
    }

    static func value(_ credential: CredentialPolicy) throws -> String {
        var data = try readData(credential)
        defer { data.resetBytes(in: 0..<data.count) }
        return String(decoding: data, as: UTF8.self)
    }

    static func authorize(_ credential: CredentialPolicy, context: LAContext) throws {
        var data = try readData(credential, context: context)
        data.resetBytes(in: 0..<data.count)
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
            let header = try credential.placement.requestHeader(secret: secret)
            request.setValue(header.value, forHTTPHeaderField: header.name)
        }

        try operation.body.validate(method: method, hasBody: body != nil)
        let forbiddenArtifacts = forbiddenCredentialArtifacts(profile: profile, secrets: secrets)
        if let body {
            _ = try checkedJSON(body, forbiddenSecrets: forbiddenArtifacts, exitCode: 2)
            request.httpBody = body
            request.setValue(profile.mediaType.rawValue, forHTTPHeaderField: "Content-Type")
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
        let object = try checkedJSON(data, forbiddenSecrets: forbiddenArtifacts, exitCode: 5)
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

private func parseOptionPairs(_ arguments: [String], allowed: Set<String>) throws -> [String: String] {
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
    return values
}

private func parseRequestOptions(_ arguments: [String]) throws -> RequestOptions {
    let values = try parseOptionPairs(arguments, allowed: ["--method", "--path", "--body-file", "--secret-output-file"])
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
    guard case .http(let operations) = profile.operations else {
        throw fail("HTTP requests require an HTTP profile; use op for 1Password commands.", exitCode: 2)
    }
    guard let operation = operations.first(where: {
        $0.permits(method: method, relativePath: relativePath)
    }) else {
        throw fail("The requested method and path are not allowed by policy.", exitCode: 2)
    }
    return operation
}


private func expectFailure(_ label: String, exitCode: Int32? = nil, _ action: () throws -> Void) throws {
    do { try action() } catch let error as SafeFailure {
        guard exitCode == nil || error.exitCode == exitCode else {
            throw fail("Self-test failed: unexpected exit code for " + label + ".")
        }
        return
    }
    throw fail("Self-test failed: expected refusal for " + label + ".")
}

private func runOnePasswordSelfTest() throws {
    let origin = URL(string: "https://team.1password.com")!
    func fixture(_ address: String) throws -> String {
        let bytes = try JSONSerialization.data(withJSONObject: ["signInAddress": address])
        return "ops_" + bytes.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    try validateOnePasswordTokenOrigin(fixture("team.1password.com"), expected: origin)
    for address in ["other.1password.com", "team.1password.com.evil.invalid", "http://team.1password.com",
                    "team.1password.com:443", "team.1password.com/path", "user@team.1password.com",
                    "team.1password.com?query=x", "team.1password.com#fragment"] {
        try expectFailure("1Password input") { try validateOnePasswordTokenOrigin(fixture(address), expected: origin) }
    }
    try expectFailure("1Password input") { _ = try CredentialPlacement.onePasswordServiceAccount.requestHeader(secret: "INERT") }
    let credential: [String: Any] = ["service": "inert.test", "account": "inert", "type": "onepassword-service-account"]
    let commands = ["whoami", "vault list", "item create", "document get", "vault group grant", "read"]
    let profile: [String: Any] = ["origin": origin.absoluteString, "credentials": [credential],
                                  "operations": commands.map { ["command": $0] }]
    let cliProfile = try parseProfile(name: "test", dictionary: profile)
    guard cliProfile.operations.permits(command: "item create"), !cliProfile.operations.permits(command: "item delete") else {
        throw fail("Self-test failed: native CLI operation allowlist.")
    }
    for command in ["run", "inject", "signin", "update", "plugin run", "vault", "item template", "item get --debug"] {
        var invalid = profile; invalid["operations"] = [["command": command]]
        try expectFailure("unsupported CLI operation", exitCode: 3) { _ = try parseProfile(name: "test", dictionary: invalid) }
    }
    let httpOperation: [String: Any] = ["method": "GET", "path": "/v1/status", "body": "none", "response": "json"]
    for operations: [Any] in [[], [["command": "whoami"], ["command": "whoami"]], [httpOperation],
                              [["command": "whoami", "method": "GET"]], [["command": "whoami"], httpOperation]] {
        var invalid = profile; invalid["operations"] = operations
        try expectFailure("invalid or mixed CLI operations", exitCode: 3) { _ = try parseProfile(name: "test", dictionary: invalid) }
    }
    var obsolete = profile; obsolete["op_commands"] = commands
    try expectFailure("obsolete parallel command policy", exitCode: 3) { _ = try parseProfile(name: "test", dictionary: obsolete) }
    var httpProfile = profile
    httpProfile["credentials"] = [["service": "inert.test", "account": "inert", "type": "bearer"]]
    try expectFailure("CLI operations on HTTP profile", exitCode: 3) { _ = try parseProfile(name: "test", dictionary: httpProfile) }
    try expectFailure("HTTP dispatch on CLI profile", exitCode: 2) {
        _ = try operationForRequest(profile: cliProfile, method: "GET", relativePath: "/v1/status")
    }
    try validateOnePasswordArguments(["item-id", "--vault", "vault-id", "--reveal"], command: "item get")
    try validateOnePasswordArguments(["--generate-password=letters,digits,32", "--favorite=false"], command: "item create")
    try validateOnePasswordArguments(["op://vault/item/field?attribute=otp"], command: "read")
    for arguments in [["--session", "INERT"], ["--debug"], ["--config=/tmp"], ["-o", "output"],
                      ["--out-file", "output"], ["--template", "input"], ["field=INERT"], ["-"],
                      ["--value", "INERT"], ["--session=INERT"], ["--template=input"],
                      ["--value=INERT"], ["https://example.invalid"], ["--", "--debug"]] {
        try expectFailure("1Password input") { try validateOnePasswordArguments(arguments, command: "item get") }
    }
    _ = try prepareOnePasswordInput(Data("{}".utf8), command: "item create", arguments: [])
    _ = try prepareOnePasswordInput(Data(), command: "document create", arguments: ["--vault", "vault-id"])
    _ = try prepareOnePasswordInput(Data(), command: "document create", arguments: ["--vault=vault-id", "--tags="])
    try expectFailure("1Password input") { _ = try prepareOnePasswordInput(nil, command: "document create", arguments: ["/private/file"]) }
    try expectFailure("1Password input") { _ = try prepareOnePasswordInput(Data(), command: "document edit", arguments: []) }
    try expectFailure("1Password input") { _ = try prepareOnePasswordInput(Data("[]".utf8), command: "item create", arguments: []) }
    try expectFailure("1Password input") { _ = try prepareOnePasswordInput(Data("{}".utf8), command: "item list", arguments: []) }
    let fixtureBytes = Data([0, 255, 10])
    let envelope = try onePasswordProtectedResponse(fixtureBytes, command: "document get", token: "INERT_AUTH")
    guard let object = try JSONSerialization.jsonObject(with: envelope) as? [String: String],
          object["encoding"] == "base64", Data(base64Encoded: object["data"] ?? "") == fixtureBytes else {
        throw fail("Self-test failed: binary response preservation.")
    }
    try expectFailure("1Password input") { _ = try onePasswordProtectedResponse(Data("INERT_AUTH".utf8), command: "read", token: "INERT_AUTH") }
    for encoded in [#"{"value":"INERT_\u0041UTH"}"#, #""INERT_\u0041UTH""#] {
        for command in ["item get", "read"] {
            try expectFailure("escaped CLI credential echo", exitCode: 5) {
                _ = try onePasswordProtectedResponse(Data(encoded.utf8), command: command, token: "INERT_AUTH")
            }
        }
    }

    let files = FileManager.default
    let directory = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
        .appendingPathComponent("keychain-op-test-" + UUID().uuidString, isDirectory: true)
    try files.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? files.removeItem(at: directory) }
    let inputPath = directory.appendingPathComponent("private.json").path
    _ = try ProtectedResponseFile(path: inputPath).commit(Data("[]".utf8))
    guard try readProtectedInput(at: inputPath, maximumBytes: 1024) == Data("[]".utf8) else {
        throw fail("Self-test failed: private input read.")
    }
    try files.createSymbolicLink(atPath: directory.appendingPathComponent("link").path, withDestinationPath: inputPath)
    try expectFailure("1Password input") { _ = try readProtectedInput(at: directory.appendingPathComponent("link").path, maximumBytes: 1024) }
    guard chmod(inputPath, 0o644) == 0 else { throw fail("Self-test fixture setup failed.") }
    try expectFailure("1Password input") { _ = try readProtectedInput(at: inputPath, maximumBytes: 1024) }

    // Exercise subprocess launch/collection with an inert local executable, not a real account.
    let executable = directory.appendingPathComponent("fixture")
    let template = Data(#"{"title":"INERT_PRIVATE_INPUT"}"#.utf8)
    let expectedInput = directory.appendingPathComponent("expected-input")
    try template.write(to: expectedInput)
    let script = """
    #!/bin/sh
    [ "$1" = '--config' ] || exit 20
    [ "$OP_DEBUG:$OP_CACHE:$OP_BIOMETRIC_UNLOCK_ENABLED" = 'false:false:false' ] || exit 21
    [ -z "${OP_CONNECT_HOST+x}${OP_CONNECT_TOKEN+x}${OP_SESSION+x}${HTTPS_PROXY+x}" ] || exit 22
    [ "$(/usr/bin/stat -f %Lp "$2")" = '700' ] || exit 23
    case "$*" in *INERT_PRIVATE_INPUT*) exit 24;; esac
    case "$6 $7" in
      'item create') [ "$8" = '--template' ] && [ "$9" = "$2/input" ] || exit 25;;
      'document create') [ "$8" = "$2/input" ] || exit 25;;
      'document edit') [ "$8" = 'item-id' ] && [ "$9" = "$2/input" ] || exit 25;;
      'user get') ;;
      *) exit 25;;
    esac
    if [ "$6" != 'user' ]; then
      [ -f "$2/input" ] || exit 26
      [ "$(/usr/bin/stat -f %Lp "$2/input")" = '600' ] || exit 25
      /usr/bin/cmp -s "$2/input" '\(expectedInput.path)' || exit 26
    fi
    printf '{"type":"SERVICE_ACCOUNT","state":"ACTIVE","temporary_path":"%s"}\\n' "$2"
    """
    try Data(script.utf8).write(to: executable)
    guard chmod(executable.path, 0o700) == 0 else { throw fail("Self-test fixture setup failed.") }
    let output = try runOnePasswordCommand(profile: cliProfile, token: fixture("team.1password.com"),
                                          executable: executable, command: "user get", arguments: ["--me"])
    guard let identity = try JSONSerialization.jsonObject(with: output.requireSuccess()) as? [String: Any],
          identity["type"] as? String == "SERVICE_ACCOUNT" else {
        throw fail("Self-test failed: CLI process lifecycle.")
    }
    for (command, arguments) in [("item create", [String]()), ("document create", []), ("document edit", ["item-id"])] {
        let input = try prepareOnePasswordInput(template, command: command, arguments: arguments)
        let result = try runOnePasswordCommand(profile: cliProfile, token: fixture("team.1password.com"),
                                              executable: executable, command: command, arguments: arguments, input: input)
        guard let object = try JSONSerialization.jsonObject(with: result.requireSuccess()) as? [String: Any],
              let temporaryPath = object["temporary_path"] as? String,
              !files.fileExists(atPath: temporaryPath) else {
            throw fail("Self-test failed: private CLI input delivery or cleanup.")
        }
    }
    try Data((script + "\nprintf INERT_STDERR >&2\nexit 7\n").utf8).write(to: executable)
    let failed = try runOnePasswordCommand(profile: cliProfile, token: fixture("team.1password.com"),
                                          executable: executable, command: "item create", arguments: [], input: .template(template))
    let recoveryPath = directory.appendingPathComponent("failed-response.json").path
    try expectFailure("failed CLI output recovery", exitCode: 5) {
        _ = try saveOnePasswordResult(failed, command: "item create", token: "INERT_AUTH",
                                     output: ProtectedResponseFile(path: recoveryPath))
    }
    guard failed.failure != nil, failed.data.range(of: Data("INERT_STDERR".utf8)) == nil,
          try readProtectedInput(at: recoveryPath, maximumBytes: 4096) == failed.data,
          let failedObject = try JSONSerialization.jsonObject(with: failed.data) as? [String: Any],
          let failedTemporaryPath = failedObject["temporary_path"] as? String,
          !files.fileExists(atPath: failedTemporaryPath) else {
        throw fail("Self-test failed: failed CLI output was lost or temporary data was retained.")
    }
    try Data((script + "\ntrap 'exit 0' TERM\nwhile :; do :; done\n").utf8).write(to: executable)
    let expired = try runOnePasswordCommand(profile: cliProfile, token: fixture("team.1password.com"),
                                           executable: executable, command: "user get", arguments: ["--me"], timeoutSeconds: 1)
    try expectFailure("deadline despite graceful subprocess exit", exitCode: 5) { _ = try expired.requireSuccess() }
    guard !expired.data.isEmpty else { throw fail("Self-test failed: timeout response capture.") }
}

private func runSelfTest() throws {
    try runOnePasswordSelfTest()
    let marker = "INERT_AUTH_SELF_TEST"
    let authFixture: [String: Any] = [
        "service": "inert.test", "account": "inert", "type": "api-key"
    ]
    let apiKey = try parseCredential(authFixture).placement.requestHeader(secret: marker)
    let bearer = try CredentialPlacement.bearer.requestHeader(secret: marker)
    let basic = try CredentialPlacement.basic(username: "inert").requestHeader(secret: marker)
    let custom = try CredentialPlacement.header(name: "X-Test", prefix: "Test ").requestHeader(secret: marker)
    guard apiKey.name == "Authorization", apiKey.value == "APIKey " + marker,
          bearer.name == "Authorization", bearer.value == "Bearer " + marker,
          basic.name == "Authorization", basic.value == "Basic " + Data(("inert:" + marker).utf8).base64EncodedString(),
          custom.name == "X-Test", custom.value == "Test " + marker else {
        throw fail("Self-test failed: credential header schemes.")
    }
    try expectFailure("credential policy", exitCode: 3) {
        var invalid = authFixture
        invalid["prefix"] = "arbitrary "
        _ = try parseCredential(invalid)
    }
    try expectFailure("credential policy", exitCode: 3) {
        _ = try parseCredential([
            "service": "inert.test", "account": "inert", "type": "header",
            "header": "Authorization", "prefix": "arbitrary "
        ])
    }
    try expectFailure("credential policy", exitCode: 3) {
        _ = try parseProfile(name: "inert", dictionary: [
            "origin": "https://example.invalid",
            "credentials": [authFixture, ["service": "inert.test", "account": "inert", "type": "bearer"]],
            "operations": [["method": "GET", "path": "/v1/check", "body": "none", "response": "json"]]
        ])
    }
    for prefix: Any in [true, 1, ["value": "INERT"]] {
        try expectFailure("malformed header prefix", exitCode: 3) {
            _ = try parseCredential(["service": "inert.test", "account": "inert", "type": "header",
                                     "header": "X-Test", "prefix": prefix])
        }
    }
    for policy in [BodyPolicy.none, .json, .optionalJSON] {
        try expectFailure("GET body refusal", exitCode: 2) { try policy.validate(method: "GET", hasBody: true) }
    }
    try expectFailure("required JSON body", exitCode: 2) { try BodyPolicy.json.validate(method: "POST", hasBody: false) }
    try expectFailure("forbidden body", exitCode: 2) { try BodyPolicy.none.validate(method: "POST", hasBody: true) }
    try BodyPolicy.json.validate(method: "POST", hasBody: true)
    try BodyPolicy.optionalJSON.validate(method: "GET", hasBody: false)
    guard try parseJSONMediaType(nil) == .json,
          try parseJSONMediaType("application/json") == .json,
          try parseJSONMediaType("application/vnd.api+json") == .jsonAPI else {
        throw fail("Self-test failed: JSON media-type policy.")
    }
    try expectFailure("JSON media-type restriction") {
        _ = try parseJSONMediaType("application/json\r\nX-Unsafe: value")
    }

    guard try parseSOCKSProxy(nil) == nil else {
        throw fail("Self-test failed: absent proxy policy.")
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
        try expectFailure("proxy policy", exitCode: 3) { _ = try parseSOCKSProxy(invalid) }
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
            try expectFailure("proxy policy", exitCode: 3) {
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
        try expectFailure("proxy policy", exitCode: 3) { _ = try parseSOCKSProxy(proxyFixture) }
        try expectFailure("proxy policy", exitCode: 3) {
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
    try expectFailure("origin restriction") {
        _ = try APITransport.requestURL(
            origin: origin,
            relativePath: "//attacker.invalid/v1/status",
            method: "GET",
            operation: prefixOperation
        )
    }

    try expectFailure("encoded traversal restriction") {
        _ = try APITransport.requestURL(
            origin: origin,
            relativePath: "/v1/%2e%2e/admin",
            method: "GET",
            operation: prefixOperation
        )
    }
    try expectFailure("path-prefix boundary") {
        _ = try APITransport.requestURL(
            origin: origin,
            relativePath: "/v10/status",
            method: "GET",
            operation: prefixOperation
        )
    }

    let inertMarker = "INERT_SELF_TEST_MARKER"
    try expectFailure("output tripwire") {
        _ = try encodedJSON(["value": inertMarker], forbiddenSecrets: [inertMarker])
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
    for exitCode: Int32 in [2, 5] {
        try expectFailure("escaped JSON credential echo", exitCode: exitCode) {
            _ = try checkedJSON(escapedData, forbiddenSecrets: [escapedMarker], exitCode: exitCode)
        }
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
    try expectFailure("protected file", exitCode: nil) { _ = try ProtectedResponseFile(path: path) }
    try expectFailure("protected file", exitCode: nil) { _ = try sink.commit(bytes) }
    try expectFailure("protected file", exitCode: nil) { _ = try ProtectedResponseFile(path: directory + "/../unsafe.json") }
    try expectFailure("protected file", exitCode: nil) { _ = try ProtectedResponseFile(path: "relative.json") }
    try files.createSymbolicLink(atPath: directory + "/link.json", withDestinationPath: path)
    try expectFailure("protected file", exitCode: nil) { _ = try ProtectedResponseFile(path: directory + "/link.json") }
    try files.createSymbolicLink(atPath: directory + "/linked-directory", withDestinationPath: directory)
    try expectFailure("protected file", exitCode: nil) { _ = try ProtectedResponseFile(path: directory + "/linked-directory/new.json") }
    let publicDirectory = directory + "/not-private"
    try files.createDirectory(atPath: publicDirectory, withIntermediateDirectories: false,
                              attributes: [.posixPermissions: 0o755])
    guard chmod(publicDirectory, 0o755) == 0 else { throw fail("Self-test fixture setup failed.") }
    try expectFailure("protected file", exitCode: nil) { _ = try ProtectedResponseFile(path: publicDirectory + "/new.json") }
    guard try readRegularFile(at: path, maximumBytes: 4096, requirePrivateMode: true) == bytes else {
        throw fail("Self-test failed: existing secret file was modified.")
    }
    let inputPath = directory + "/bounded-input"
    let input = Data(repeating: 0x61, count: 32769)
    try input.write(to: URL(fileURLWithPath: inputPath))
    for limit in [input.count, input.count - 1] {
        let handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: inputPath))
        defer { try? handle.close() }
        var data = Data()
        if limit == input.count {
            try readBoundedData(from: handle, into: &data, maximumBytes: limit, overflow: fail("INERT_SIZE_LIMIT", exitCode: 3))
            guard data == input else { throw fail("Self-test failed: bounded reader truncated input.") }
        } else {
            try expectFailure("bounded read limit", exitCode: 3) {
                try readBoundedData(from: handle, into: &data, maximumBytes: limit, overflow: fail("INERT_SIZE_LIMIT", exitCode: 3))
            }
            guard data == input.prefix(limit) else { throw fail("Self-test failed: bounded partial capture.") }
        }
    }
    let closedHandle = try FileHandle(forReadingFrom: URL(fileURLWithPath: inputPath))
    try closedHandle.close()
    var unread = Data()
    try expectFailure("bounded read I/O error", exitCode: 3) {
        try readBoundedData(from: closedHandle, into: &unread, maximumBytes: 10, overflow: fail("INERT_SIZE_LIMIT", exitCode: 3))
    }
}

private func usage() -> String {
    """
    Usage:
      keychain-api status <profile>
      keychain-api authorize <profile>
      keychain-api request <profile> --method <METHOD> --path <PATH> [--body-file <JSON_FILE>] [--secret-output-file <NEW_JSON_FILE>]
      keychain-api op <profile> --command <COMMAND> --secret-output-file <NEW_JSON_FILE> [--args-file <JSON_FILE>] [--input-file <PRIVATE_FILE>]
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

            case "op":
                guard arguments.count >= 6 else { throw fail("op arguments are incomplete.", exitCode: 2) }
                let store = try PolicyStore.load()
                guard let profile = store.profiles[arguments[1]], case .onePassword = profile.operations else {
                    throw fail("op requires a 1Password service-account profile.", exitCode: 2)
                }
                let options = try parseOptionPairs(Array(arguments.dropFirst(2)), allowed: [
                    "--command", "--args-file", "--input-file", "--secret-output-file"
                ])
                guard let command = options["--command"], profile.operations.permits(command: command),
                      let outputPath = options["--secret-output-file"] else {
                    throw fail("op requires a policy-allowed command and a new protected output file.", exitCode: 2)
                }
                let rawArguments = try options["--args-file"].map { path -> [String] in
                    let data = try readProtectedInput(at: path, maximumBytes: maximumBodyBytes)
                    guard let array = try? JSONSerialization.jsonObject(with: data) as? [String] else {
                        throw fail("CLI arguments must be a private JSON array of non-secret strings.", exitCode: 3)
                    }
                    return array
                } ?? []
                try validateOnePasswordArguments(rawArguments, command: command)
                let input = try options["--input-file"].map { try readProtectedInput(at: $0, maximumBytes: maximumResponseBytes) }
                let preparedInput = try prepareOnePasswordInput(input, command: command, arguments: rawArguments)
                let secretOutput = try ProtectedResponseFile(path: outputPath)
                let executable = try verifiedOnePasswordExecutable()
                let token = try KeychainReader.value(profile.credentials[0])
                let result = try runOnePasswordCommand(profile: profile, token: token, executable: executable,
                                                      command: command, arguments: rawArguments, input: preparedInput)
                try emitJSON(saveOnePasswordResult(result, command: command, token: token, output: secretOutput))

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
                try operation.body.validate(method: options.method, hasBody: body != nil)

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
