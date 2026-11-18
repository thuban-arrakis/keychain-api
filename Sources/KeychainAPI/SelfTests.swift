import Foundation
import Darwin

private func expectFailure(_ label: String, exitCode: Int32? = nil, _ action: () throws -> Void) throws {
    do { try action() } catch let error as SafeFailure {
        guard exitCode == nil || error.exitCode == exitCode else {
            throw fail("Self-test failed: unexpected exit code for " + label + ".")
        }
        return
    }
    throw fail("Self-test failed: expected refusal for " + label + ".")
}

func runSelfTest() async throws {
    try runOperationPolicySelfTests()
    try await runCLISelfTests()
    try await runHTTPTransportSelfTests()
    let marker = "INERT_AUTH_SELF_TEST"
    let authFixture: [String: Any] = [
        "service": "inert.test", "account": "inert", "type": "api-key"
    ]
    let apiKey = try parseCredential(authFixture).placement.requestHeader(secret: marker)
    let bearer = CredentialPlacement.bearer.requestHeader(secret: marker)
    let basic = CredentialPlacement.basic(username: "inert").requestHeader(secret: marker)
    let custom = CredentialPlacement.header(name: "X-Test", prefix: "Test ").requestHeader(secret: marker)
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
    let retiredCredential = ["service": "inert.test", "account": "inert", "type": "onepassword-service-account"]
    let commandOperations = [["command": "whoami"]]
    try expectFailure("retired service-account profile", exitCode: 3) {
        _ = try parseProfile(name: "fixture", dictionary: [
            "origin": "https://team.1password.com", "credentials": [retiredCredential], "operations": commandOperations
        ])
    }
    try expectFailure("unsupported credential type", exitCode: 3) {
        _ = try parseCredential(retiredCredential)
    }
    var unsupportedOperation = profileFixture
    unsupportedOperation["operations"] = commandOperations
    try expectFailure("command in HTTP operation policy", exitCode: 3) {
        _ = try parseProfile(name: "fixture", dictionary: unsupportedOperation)
    }
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

private func runOperationPolicySelfTests() throws {
    for method in ["GET", "HEAD"] {
        for pathFields: [String: Any] in [
            ["methods": [method], "path_prefix": "/v1/"],
            ["method": method, "path": "/v1/check"]
        ] {
            var operation = pathFields
            operation["body"] = "json"
            operation["response"] = "json-or-empty"
            try expectFailure("impossible required body on " + method, exitCode: 3) {
                _ = try parseOperation(operation)
            }
            operation["body"] = "optional-json"
            let parsed = try parseOperation(operation)
            try parsed.body.validate(method: method, hasBody: false)
            try expectFailure("body on " + method, exitCode: 2) {
                try parsed.body.validate(method: method, hasBody: true)
            }
            if method == "HEAD" {
                operation["response"] = "json"
                try expectFailure("HEAD requiring response bytes", exitCode: 3) {
                    _ = try parseOperation(operation)
                }
            }
        }
    }
    let mixed = try parseOperation([
        "methods": ["GET", "HEAD", "POST"], "path_prefix": "/v1/",
        "body": "optional-json", "response": "json-or-empty"
    ])
    guard mixed.permits(method: "GET", relativePath: "/v1/check"),
          mixed.permits(method: "POST", relativePath: "/v1/check") else {
        throw fail("Self-test failed: valid mixed-method operation rejected.")
    }
    try mixed.body.validate(method: "GET", hasBody: false)
    try mixed.body.validate(method: "POST", hasBody: true)
    try expectFailure("mixed operation with impossible GET body", exitCode: 3) {
        _ = try parseOperation([
            "methods": ["GET", "POST"], "path_prefix": "/v1/",
            "body": "json", "response": "json"
        ])
    }
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
