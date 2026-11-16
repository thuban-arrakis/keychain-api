import Foundation

private struct HTTPFixtureBytes: AsyncSequence {
    let data: Data
    var interrupted = false

    struct AsyncIterator: AsyncIteratorProtocol {
        let source: HTTPFixtureBytes
        var index = 0

        mutating func next() async throws -> UInt8? {
            guard index < source.data.count else {
                if source.interrupted { throw URLError(.networkConnectionLost) }
                return nil
            }
            defer { index += 1 }
            return source.data[index]
        }
    }

    func makeAsyncIterator() -> AsyncIterator { AsyncIterator(source: self) }
}

private func expectHTTPFailure(_ label: String, exitCode: Int32 = 5,
                               _ action: () async throws -> Void) async throws {
    do { try await action() } catch let error as SafeFailure {
        guard error.exitCode == exitCode else {
            throw fail("Self-test failed: unexpected HTTP exit code for " + label + ".")
        }
        return
    }
    throw fail("Self-test failed: expected HTTP refusal for " + label + ".")
}

private struct HTTPFixture {
    let transport: APITransport
    let origin = URL(string: "https://api.example.invalid")!
    let operation = OperationPolicy(methods: ["POST"], path: .exact("/v1/items"), body: .json, response: .json)
    let requestBody = Data(#"{"name":"fixture"}"#.utf8)
    let marker = "INERT_HTTP_AUTH"

    init() throws { transport = try APITransport() }

    var profile: ProfilePolicy {
        ProfilePolicy(name: "inert", origin: origin, mediaType: .json, proxy: nil,
                      credentials: [CredentialPolicy(service: "inert.test", account: "inert", placement: .bearer)],
                      operations: .http([operation]))
    }

    func send(_ bytes: HTTPFixtureBytes, output: ProtectedResponseFile? = nil,
              status: Int = 200, contentType: String = "application/json", responseOrigin: URL? = nil) async throws -> Any {
        try await transport.send(profile: profile, operation: operation, method: "POST", relativePath: "/v1/items",
                                 body: requestBody, secrets: [marker], secretOutput: output) { request in
            guard request.url?.absoluteString == origin.absoluteString + "/v1/items",
                  request.httpMethod == "POST", request.httpBody == requestBody,
                  request.value(forHTTPHeaderField: "Authorization") == "Bearer " + marker,
                  request.value(forHTTPHeaderField: "Accept") == "application/json",
                  request.value(forHTTPHeaderField: "Content-Type") == "application/json" else {
                throw fail("Self-test failed: HTTP request construction.")
            }
            let response = HTTPURLResponse(url: responseOrigin ?? request.url!, statusCode: status,
                                           httpVersion: "HTTP/1.1", headerFields: ["Content-Type": contentType])!
            return (bytes, response)
        }
    }
}

private func checkHTTPRecovery(_ fixture: HTTPFixture, directory: URL) async throws {
    for (index, raw) in [#"{"value":"INERT_RECOVERY"}"#, #"{"value":"INERT_RECOVERY""#,
                         #"{"value":"escaped\u0020fixture"}"#].enumerated() {
        let data = Data(raw.utf8)
        let path = directory.appendingPathComponent("recovery-\(index).json").path
        try await expectHTTPFailure("interrupted response recovery") {
            _ = try await fixture.send(HTTPFixtureBytes(data: data, interrupted: true),
                                       output: ProtectedResponseFile(path: path))
        }
        guard try readProtectedInput(at: path, maximumBytes: maximumResponseBytes) == data else {
            throw fail("Self-test failed: interrupted HTTP response bytes were lost.")
        }
    }

    let overflow = Data(repeating: UInt8(ascii: "x"), count: maximumResponseBytes + 1)
    let path = directory.appendingPathComponent("overflow.json").path
    try await expectHTTPFailure("bounded overflow recovery") {
        _ = try await fixture.send(HTTPFixtureBytes(data: overflow), output: ProtectedResponseFile(path: path))
    }
    guard try readProtectedInput(at: path, maximumBytes: maximumResponseBytes) == overflow.prefix(maximumResponseBytes) else {
        throw fail("Self-test failed: HTTP overflow recovery did not retain its bounded prefix.")
    }
}

private func checkHTTPRecoveryRefusals(_ fixture: HTTPFixture, directory: URL) async throws {
    let escaped = #"{"value":"INERT_HTTP_\u0041UTH"}"#
    let duplicate = #"{"value":"safe","value":"INERT_HTTP_\u0041UTH"}"#
    let refused: [Data] = [Data(), Data(fixture.marker.utf8), Data(escaped.utf8),
                          Data(duplicate.utf8), Data(escaped.dropLast().utf8),
                          Data(#"{"value":"unknown\u"#.utf8), Data([0xff]), Data([0x7b, 0, 0x7d, 0])]
    for (index, data) in refused.enumerated() {
        let path = directory.appendingPathComponent("refused-\(index).json").path
        try await expectHTTPFailure("unsafe interrupted response") {
            _ = try await fixture.send(HTTPFixtureBytes(data: data, interrupted: true),
                                       output: ProtectedResponseFile(path: path))
        }
        guard try readProtectedInput(at: path, maximumBytes: maximumResponseBytes).isEmpty else {
            throw fail("Self-test failed: unsafe interrupted HTTP output was persisted.")
        }
    }
}

private func checkHTTPResponseValidation(_ fixture: HTTPFixture, directory: URL) async throws {
    let data = Data(#"{"id":"fixture"}"#.utf8)
    for (index, contentType, responseOrigin, status) in [
        (0, "text/html", fixture.origin, 200),
        (1, "application/json", URL(string: "https://other.example.invalid")!, 200),
        (2, "application/json", fixture.origin, 500)
    ] {
        let path = directory.appendingPathComponent("invalid-response-\(index).json").path
        try await expectHTTPFailure("response policy") {
            _ = try await fixture.send(HTTPFixtureBytes(data: data), output: ProtectedResponseFile(path: path),
                                       status: status, contentType: contentType, responseOrigin: responseOrigin)
        }
        guard try readProtectedInput(at: path, maximumBytes: maximumResponseBytes).isEmpty else {
            throw fail("Self-test failed: rejected HTTP response was persisted.")
        }
    }
    for raw in [#"{"value":"INERT_HTTP_AUTH"}"#, #"{"value":"INERT_HTTP_\u0041UTH"}"#,
                #"{"value":"safe","value":"INERT_HTTP_\u0041UTH"}"#, "not JSON"] {
        try await expectHTTPFailure("response credential or JSON validation") {
            _ = try await fixture.send(HTTPFixtureBytes(data: Data(raw.utf8)))
        }
    }
}

private func checkHTTPJSONCredentialEcho(_ fixture: HTTPFixture, directory: URL) async throws {
    for raw in [#"{"value":"safe","value":"INERT_HTTP_\u0041UTH"}"#,
                #"{"value":"INERT_HTTP_\u0041UTH","value":"safe"}"#,
                #"{"value":"safe","\u0076alue":"INERT_HTTP_\u0041UTH"}"#,
                #"{"INERT_HTTP_\u0041UTH":"safe"}"#] {
        let data = Data(raw.utf8)
        try await expectHTTPFailure("duplicate JSON member credential echo", exitCode: 2) {
            _ = try checkedJSON(data, forbiddenSecrets: [fixture.marker], exitCode: 2)
        }
        try await expectHTTPFailure("request-body credential echo before loading", exitCode: 2) {
            _ = try await fixture.transport.send(profile: fixture.profile, operation: fixture.operation,
                                                 method: "POST", relativePath: "/v1/items", body: data,
                                                 secrets: [fixture.marker]) { _ -> (HTTPFixtureBytes, URLResponse) in
                throw fail("Self-test failed: credential-bearing HTTP request reached its byte loader.")
            }
        }
    }
    let raw = #"{"name":"café","value":"escaped quote \" and slash \\ and smile \uD83D\uDE00","value":"last"}"#
    let data = Data(raw.utf8)
    let path = directory.appendingPathComponent("escaped-duplicates.json").path
    _ = try await fixture.send(HTTPFixtureBytes(data: data), output: ProtectedResponseFile(path: path))
    guard try readProtectedInput(at: path, maximumBytes: maximumResponseBytes) == data else {
        throw fail("Self-test failed: accepted JSON member bytes changed.")
    }
    let encodings: [String.Encoding] = [.utf16, .utf16LittleEndian, .utf16BigEndian,
                                       .utf32, .utf32LittleEndian, .utf32BigEndian]
    for encoding in encodings {
        guard let encoded = raw.data(using: encoding) else { throw fail("Self-test fixture encoding failed.") }
        try await expectHTTPFailure("non-UTF-8 JSON refusal") {
            _ = try await fixture.send(HTTPFixtureBytes(data: encoded))
        }
    }
}

func runHTTPTransportSelfTests() async throws {
    let fixture = try HTTPFixture()
    let files = FileManager.default
    let directory = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
        .appendingPathComponent("keychain-http-test-" + UUID().uuidString, isDirectory: true)
    try files.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? files.removeItem(at: directory) }

    let data = Data(#"{"id":"fixture","token":"INERT_CREATED_VALUE"}"#.utf8)
    let sanitized = try await fixture.send(HTTPFixtureBytes(data: data)) as? [String: String]
    guard sanitized?["id"] == "fixture", sanitized?["token"] == redactedValue else {
        throw fail("Self-test failed: HTTP response sanitization.")
    }
    let path = directory.appendingPathComponent("success.json").path
    let receipt = try await fixture.send(HTTPFixtureBytes(data: data), output: ProtectedResponseFile(path: path))
    guard let fields = receipt as? [String: Bool],
          fields == ["ok": true, "secret_output_file_written": true, "secret_output": false],
          try readProtectedInput(at: path, maximumBytes: maximumResponseBytes) == data else {
        throw fail("Self-test failed: HTTP protected output or fixed receipt.")
    }
    try await checkHTTPJSONCredentialEcho(fixture, directory: directory)
    try await checkHTTPResponseValidation(fixture, directory: directory)
    try await checkHTTPRecovery(fixture, directory: directory)
    try await checkHTTPRecoveryRefusals(fixture, directory: directory)
}
