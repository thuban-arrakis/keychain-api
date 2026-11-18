import Foundation

private func checkCLI(_ condition: @autoclosure () throws -> Bool, _ label: String) throws {
    guard try condition() else { throw fail("Self-test failed: CLI " + label + ".") }
}

func runCLISelfTests() async throws {
    let profile = try parseProfile(name: "http", dictionary: [
        "origin": "https://example.invalid",
        "credentials": [["service": "inert.test", "account": "inert", "type": "bearer"]],
        "operations": [["method": "GET", "path": "/status", "body": "none", "response": "json"]]
    ])
    let store = PolicyStore(profiles: [profile.name: profile])

    let files = FileManager.default
    let directory = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
        .appendingPathComponent("keychain-cli-test-" + UUID().uuidString, isDirectory: true)
    try files.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? files.removeItem(at: directory) }
    let output = directory.appendingPathComponent("existing.json")
    let existing = Data("{}".utf8)
    _ = try ProtectedResponseFile(path: output.path).commit(existing)
    let request = ["request", "http", "--method", "GET", "--path"]

    let cases: [(arguments: [String], exitCode: Int32, policyLoads: Int)] = [
        (["--version"], 0, 0),
        (["--version", "extra"], 2, 0),
        (["--verion"], 2, 0),
        (["op", "http", "--command", "whoami", "--secret-output-file", output.path], 2, 0),
        (request + ["/denied"], 2, 1),
        (request + ["/status", "--secret-output-file", output.path], 3, 1)
    ]
    for test in cases {
        var stdout = Data()
        var stderr = Data()
        var policyLoads = 0
        var credentialCalls = 0
        func unexpectedAccess() -> SafeFailure {
            credentialCalls += 1
            return fail("Unexpected credential access in CLI self-test.")
        }
        let dependencies = CLIDependencies(
            loadPolicy: { policyLoads += 1; return store },
            credentialExists: { _ in throw unexpectedAccess() },
            credentialValue: { _ in throw unexpectedAccess() },
            authorizeCredential: { _, _ in throw unexpectedAccess() },
            stdout: { stdout.append($0) },
            stderr: { stderr.append($0) }
        )
        let result = await runCLI(test.arguments, dependencies: dependencies)
        try checkCLI(result == test.exitCode, "exit code")
        try checkCLI(credentialCalls == 0 && policyLoads == test.policyLoads, "preflight access")
        if test.arguments == ["--version"] {
            try checkCLI(stdout == Data((ReleaseVersion.current + "\n").utf8) && stderr.isEmpty, "version output")
        } else {
            try checkCLI(stdout.isEmpty && !stderr.isEmpty, "refusal output")
        }
    }
    try checkCLI(try readRegularFile(at: output.path, maximumBytes: 4096, requirePrivateMode: true) == existing,
                 "existing output preserved")
}
