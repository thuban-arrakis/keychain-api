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

func runSelfTest() throws {
    try runOperationPolicySelfTests()
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
