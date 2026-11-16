import Foundation
import Darwin

private struct CLIInvocation {
    let exitCode: Int32
    let stdout: Data
    let stderr: Data
    let policyLoads: Int
    let credentialReads: Int
    let executableLookups: Int
    let processRuns: Int
}

private func checkCLI(_ condition: @autoclosure () throws -> Bool, _ label: String) throws {
    guard try condition() else { throw fail("Self-test failed: CLI " + label + ".") }
}

private func checkCLIRefusal(_ result: CLIInvocation, exitCode: Int32) throws {
    try checkCLI(result.exitCode == exitCode && result.stdout.isEmpty && !result.stderr.isEmpty,
                 "refusal exit and output")
    try checkCLI(result.policyLoads == 1 && result.credentialReads == 0 &&
                 result.executableLookups == 0 && result.processRuns == 0,
                 "refusal before credential or subprocess access")
}

private func checkCLIVersion() async throws {
    for arguments in [["--version"], ["--version", "extra"], ["--verion"]] {
        var stdout = Data()
        var stderr = Data()
        var externalCalls = 0
        func unexpectedAccess() -> SafeFailure {
            externalCalls += 1
            return fail("Version command accessed an external dependency.")
        }
        let dependencies = CLIDependencies(
            loadPolicy: { throw unexpectedAccess() },
            credentialExists: { _ in throw unexpectedAccess() },
            credentialValue: { _ in throw unexpectedAccess() },
            authorizeCredential: { _, _ in throw unexpectedAccess() },
            onePasswordExecutable: { throw unexpectedAccess() },
            stdout: { stdout.append($0) },
            stderr: { stderr.append($0) }
        )
        let result = await runCLI(arguments, dependencies: dependencies)
        if arguments == ["--version"] {
            try checkCLI(result == 0 && stdout == Data((ReleaseVersion.current + "\n").utf8) && stderr.isEmpty,
                         "version output")
        } else {
            try checkCLI(result == 2 && stdout.isEmpty && !stderr.isEmpty, "version argument refusal")
        }
        try checkCLI(externalCalls == 0, "version must not access policy, credentials, or subprocesses")
    }
}

func runCLISelfTests() async throws {
    try await checkCLIVersion()
    let files = FileManager.default
    let directory = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
        .appendingPathComponent("keychain-cli-test-" + UUID().uuidString, isDirectory: true)
    try files.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? files.removeItem(at: directory) }

    let native = try parseProfile(name: "native", dictionary: [
        "origin": "https://team.1password.com",
        "credentials": [["service": "inert.test", "account": "inert", "type": "onepassword-service-account"]],
        "operations": [["command": "vault list"], ["command": "item create"]]
    ])
    let http = try parseProfile(name: "http", dictionary: [
        "origin": "https://example.invalid",
        "credentials": [["service": "inert.test", "account": "inert", "type": "bearer"]],
        "operations": [["method": "GET", "path": "/status", "body": "none", "response": "json"]]
    ])
    let store = PolicyStore(profiles: [native.name: native, http.name: http])
    let invocations = directory.appendingPathComponent("invocations")
    let executable = directory.appendingPathComponent("fixture")
    let response = Data("{\"response\":\"INERT_CLI_BODY\"}\n".utf8)
    let script = """
    #!/bin/sh
    umask 077
    printf 'run\\n' >> '\(invocations.path)'
    printf '{"response":"INERT_CLI_BODY"}\\n'
    if [ "$6 $7" = 'item create' ]; then
      printf 'INERT_RAW_DIAGNOSTIC\\n' >&2
      exit 7
    fi
    """
    try Data(script.utf8).write(to: executable)
    guard chmod(executable.path, 0o700) == 0 else { throw fail("Self-test fixture setup failed.") }

    func processCount() throws -> Int {
        guard files.fileExists(atPath: invocations.path) else { return 0 }
        return try readProtectedInput(at: invocations.path, maximumBytes: 4096).filter { $0 == 0x0a }.count
    }

    func invoke(_ arguments: [String], tokenOrigin: String = "team.1password.com") async throws -> CLIInvocation {
        // The fixture contains only a routing claim; it cannot authenticate to an account.
        let claim = try JSONSerialization.data(withJSONObject: ["signInAddress": tokenOrigin])
        let token = "ops_" + claim.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        var stdout = Data()
        var stderr = Data()
        var policyLoads = 0
        var credentialReads = 0
        var executableLookups = 0
        let processesBefore = try processCount()
        let dependencies = CLIDependencies(
            loadPolicy: { policyLoads += 1; return store },
            credentialExists: { _ in throw fail("Unexpected credential metadata lookup in CLI self-test.") },
            credentialValue: { _ in credentialReads += 1; return token },
            authorizeCredential: { _, _ in throw fail("Unexpected credential authorization in CLI self-test.") },
            onePasswordExecutable: { executableLookups += 1; return executable },
            stdout: { stdout.append($0) },
            stderr: { stderr.append($0) }
        )
        let exitCode = await runCLI(arguments, dependencies: dependencies)
        return CLIInvocation(exitCode: exitCode, stdout: stdout, stderr: stderr, policyLoads: policyLoads,
                             credentialReads: credentialReads, executableLookups: executableLookups,
                             processRuns: try processCount() - processesBefore)
    }

    func opArguments(_ command: String, output: URL, profile: String = "native") -> [String] {
        ["op", profile, "--command", command, "--secret-output-file", output.path]
    }

    let deniedOutput = directory.appendingPathComponent("denied.json")
    let denied = try await invoke(opArguments("item delete", output: deniedOutput))
    try checkCLIRefusal(denied, exitCode: 2)
    try checkCLI(!files.fileExists(atPath: deniedOutput.path), "denied policy must not reserve output")

    let wrongProfileOutput = directory.appendingPathComponent("wrong-profile.json")
    let wrongProfile = try await invoke(opArguments("vault list", output: wrongProfileOutput, profile: "http"))
    try checkCLIRefusal(wrongProfile, exitCode: 2)
    try checkCLI(!files.fileExists(atPath: wrongProfileOutput.path), "wrong profile must not reserve output")

    let httpOutput = directory.appendingPathComponent("wrong-transport.json")
    let wrongTransport = try await invoke([
        "request", "native", "--method", "GET", "--path", "/status", "--secret-output-file", httpOutput.path
    ])
    try checkCLIRefusal(wrongTransport, exitCode: 2)
    try checkCLI(!files.fileExists(atPath: httpOutput.path), "wrong transport must not reserve output")

    let existingOutput = directory.appendingPathComponent("existing.json")
    let existingBytes = Data("{}".utf8)
    _ = try ProtectedResponseFile(path: existingOutput.path).commit(existingBytes)
    let existing = try await invoke(opArguments("vault list", output: existingOutput))
    try checkCLIRefusal(existing, exitCode: 3)
    try checkCLI(try readProtectedInput(at: existingOutput.path, maximumBytes: 4096) == existingBytes,
                 "existing output preserved")

    let successOutput = directory.appendingPathComponent("success.json")
    let success = try await invoke(opArguments("vault list", output: successOutput))
    let receipt = try encodedJSON(["ok": true, "secret_output_file_written": true, "secret_output": false]) + Data([0x0a])
    try checkCLI(success.exitCode == 0 && success.stdout == receipt && success.stderr.isEmpty,
                 "success emits only the fixed receipt")
    try checkCLI(success.policyLoads == 1 && success.credentialReads == 1 &&
                 success.executableLookups == 1 && success.processRuns == 1, "success executes once")
    try checkCLI(try readProtectedInput(at: successOutput.path, maximumBytes: 4096) == response,
                 "success persists private response")

    let failureOutput = directory.appendingPathComponent("failed.json")
    let failed = try await invoke(opArguments("item create", output: failureOutput))
    try checkCLI(failed.exitCode == 5 && failed.stdout.isEmpty && !failed.stderr.isEmpty,
                 "failed command emits no success receipt")
    try checkCLI(failed.credentialReads == 1 && failed.executableLookups == 1 && failed.processRuns == 1,
                 "failed command is never retried")
    try checkCLI(try readProtectedInput(at: failureOutput.path, maximumBytes: 4096) == response,
                 "failed command retains private recovery evidence")
    try checkCLI(failed.stderr.range(of: Data("INERT_RAW_DIAGNOSTIC".utf8)) == nil &&
                 failed.stderr.range(of: Data("INERT_CLI_BODY".utf8)) == nil,
                 "failed command suppresses raw response and diagnostics")

    let originOutput = directory.appendingPathComponent("wrong-origin.json")
    let wrongOrigin = try await invoke(opArguments("vault list", output: originOutput), tokenOrigin: "other.1password.com")
    try checkCLI(wrongOrigin.exitCode == 4 && wrongOrigin.stdout.isEmpty && !wrongOrigin.stderr.isEmpty,
                 "wrong token origin fails safely")
    try checkCLI(wrongOrigin.credentialReads == 1 && wrongOrigin.executableLookups == 1 && wrongOrigin.processRuns == 0,
                 "token origin checked before subprocess launch")
    try checkCLI(try readProtectedInput(at: originOutput.path, maximumBytes: 4096).isEmpty,
                 "wrong token origin leaves only an empty private reservation")
}
