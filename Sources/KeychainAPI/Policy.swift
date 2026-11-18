import Foundation

enum CredentialPlacement {
    case bearer
    case apiKey
    case basic(username: String)
    case header(name: String, prefix: String)

    var headerName: String {
        switch self {
        case .header(let name, _): return name
        case .bearer, .apiKey, .basic: return "Authorization"
        }
    }

    func requestHeader(secret: String) -> (name: String, value: String) {
        switch self {
        case .bearer:
            return (headerName, "Bearer \(secret)")
        case .apiKey:
            return (headerName, "APIKey \(secret)")
        case .basic(let username):
            let encoded = Data((username + ":" + secret).utf8).base64EncodedString()
            return (headerName, "Basic \(encoded)")
        case .header(_, let prefix):
            return (headerName, prefix + secret)
        }
    }
}

struct CredentialPolicy {
    let service: String
    let account: String
    let placement: CredentialPlacement
}

func forbiddenCredentialArtifacts(
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

enum BodyPolicy: String {
    case none
    case json
    case optionalJSON = "optional-json"

    func permits(method: String, hasBody: Bool) -> Bool {
        (!hasBody || (self != .none && method != "GET" && method != "HEAD"))
            && (hasBody || self != .json)
    }

    func validate(method: String, hasBody: Bool) throws {
        guard permits(method: method, hasBody: hasBody) else {
            throw fail("The request body does not match the selected policy operation.", exitCode: 2)
        }
    }
}

enum ResponsePolicy: String {
    case json
    case empty
    case jsonOrEmpty = "json-or-empty"
}

enum JSONMediaType: String {
    case json = "application/json"
    case jsonAPI = "application/vnd.api+json"
}

func parseJSONMediaType(_ raw: Any?) throws -> JSONMediaType {
    guard let raw else { return .json }
    guard let value = raw as? String,
          let mediaType = JSONMediaType(rawValue: value) else {
        throw fail("A policy profile contains an invalid JSON media type.", exitCode: 3)
    }
    return mediaType
}

enum PathPolicy {
    case exact(String)
    case prefix(String)
}

struct OperationPolicy {
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

struct SOCKSProxyPolicy {
    let port: UInt16
}

func parseSOCKSProxy(_ raw: Any?) throws -> SOCKSProxyPolicy? {
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

struct ProfilePolicy {
    let name: String
    let origin: URL
    let mediaType: JSONMediaType
    let proxy: SOCKSProxyPolicy?
    let credentials: [CredentialPolicy]
    let operations: [OperationPolicy]
}

struct PolicyStore {
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

func parseCredential(_ raw: Any) throws -> CredentialPolicy {
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
    case "api-key", "bearer":
        guard dictionary["header"] == nil, dictionary["prefix"] == nil, dictionary["username"] == nil else {
            throw fail("The credential policy contains unsupported fields for its authentication type.", exitCode: 3)
        }
        placement = type == "api-key" ? .apiKey : .bearer
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

let supportedHTTPMethods = Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"])

func safeRelativeComponents(_ value: String) -> URLComponents? {
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

func parseOperation(_ raw: Any) throws -> OperationPolicy {
    guard let dictionary = raw as? [String: Any],
          hasOnlyKeys(dictionary, allowed: ["method", "methods", "path", "path_prefix", "body", "response"]),
          let bodyValue = dictionary["body"] as? String,
          let responseValue = dictionary["response"] as? String,
          let body = BodyPolicy(rawValue: bodyValue),
          let response = ResponsePolicy(rawValue: responseValue) else {
        throw fail("A policy profile contains an invalid operation.", exitCode: 3)
    }

    let methods: Set<String>
    let path: PathPolicy
    if let rawMethod = dictionary["method"] as? String,
       let exactPath = dictionary["path"] as? String,
       dictionary["methods"] == nil,
       dictionary["path_prefix"] == nil {
        guard supportedHTTPMethods.contains(rawMethod),
              validateOperationPath(exactPath) else {
            throw fail("A policy profile contains an invalid exact operation.", exitCode: 3)
        }
        methods = [rawMethod]
        path = .exact(exactPath)
    } else if let rawMethods = dictionary["methods"] as? [String],
       let pathPrefix = dictionary["path_prefix"] as? String,
       dictionary["method"] == nil,
       dictionary["path"] == nil {
        methods = Set(rawMethods)
        guard !methods.isEmpty,
              methods.count == rawMethods.count,
              methods.isSubset(of: supportedHTTPMethods),
              validateOperationPrefix(pathPrefix) else {
            throw fail("A policy profile contains an invalid prefix operation.", exitCode: 3)
        }
        path = .prefix(pathPrefix)
    } else {
        throw fail("A policy operation must define either an exact path or a path prefix.", exitCode: 3)
    }

    guard methods.allSatisfy({ body.permits(method: $0, hasBody: false) || body.permits(method: $0, hasBody: true) }),
          !methods.contains("HEAD") || response != .json else {
        throw fail("An operation requires a body or response forbidden by its HTTP method.", exitCode: 3)
    }
    return OperationPolicy(methods: methods, path: path, body: body, response: response)
}

func parseProfile(name: String, dictionary: [String: Any]) throws -> ProfilePolicy {
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
    let operations = try rawOperations.map(parseOperation)
    guard Set(operations.map(\.uniqueKey)).count == operations.count else {
        throw fail("A policy profile defines an operation more than once.", exitCode: 3)
    }

    var headerNames = Set<String>()
    for credential in credentials {
        let headerName = credential.placement.headerName.lowercased()
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
