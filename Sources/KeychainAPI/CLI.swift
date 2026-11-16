import Foundation
import LocalAuthentication
import Darwin

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

func operationForRequest(profile: ProfilePolicy, method: String, relativePath: String) throws -> OperationPolicy {
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

// Only external effects vary in self-tests; parsing, authorization, execution,
// protected persistence, and exit classification use the production handlers.
struct CLIDependencies {
    let loadPolicy: () throws -> PolicyStore
    let credentialExists: (CredentialPolicy) throws -> Bool
    let credentialValue: (CredentialPolicy) throws -> String
    let authorizeCredential: (CredentialPolicy, LAContext) throws -> Void
    let onePasswordExecutable: () throws -> URL
    let stdout: (Data) -> Void
    let stderr: (Data) -> Void

    static var live: CLIDependencies {
        CLIDependencies(
            loadPolicy: PolicyStore.load,
            credentialExists: KeychainReader.exists,
            credentialValue: KeychainReader.value,
            authorizeCredential: { try KeychainReader.authorize($0, context: $1) },
            onePasswordExecutable: verifiedOnePasswordExecutable,
            stdout: { FileHandle.standardOutput.write($0) },
            stderr: { FileHandle.standardError.write($0) }
        )
    }
}

private func loadProfile(_ name: String, dependencies: CLIDependencies) throws -> ProfilePolicy {
    guard let profile = try dependencies.loadPolicy().profiles[name] else {
        throw fail("The requested profile is not defined.", exitCode: 2)
    }
    return profile
}

private func handleStatus(_ arguments: [String], dependencies: CLIDependencies) throws {
    guard arguments.count == 2 else { throw fail("status requires one profile.", exitCode: 2) }
    let profile = try loadProfile(arguments[1], dependencies: dependencies)
    var results: [[String: Any]] = []
    for (index, credential) in profile.credentials.enumerated() {
        results.append(["found": try dependencies.credentialExists(credential), "index": index + 1])
    }
    try emitJSON([
        "credentials": results, "network_used": false, "profile": profile.name, "secret_read": false
    ], write: dependencies.stdout)
}

private func handleAuthorize(_ arguments: [String], dependencies: CLIDependencies) throws {
    guard arguments.count == 2 else { throw fail("authorize requires one profile.", exitCode: 2) }
    let profile = try loadProfile(arguments[1], dependencies: dependencies)
    let context = LAContext()
    context.interactionNotAllowed = false
    context.localizedReason = "Allow access to configured API credentials."
    context.touchIDAuthenticationAllowableReuseDuration = 0
    defer { context.invalidate() }
    for credential in profile.credentials {
        try dependencies.authorizeCredential(credential, context)
    }
    try emitJSON([
        "credentials_read": profile.credentials.count, "network_used": false,
        "profile": profile.name, "secret_output": false, "secret_read": true
    ], write: dependencies.stdout)
}

private func handleOnePassword(_ arguments: [String], dependencies: CLIDependencies) throws {
    guard arguments.count >= 6 else { throw fail("op arguments are incomplete.", exitCode: 2) }
    let store = try dependencies.loadPolicy()
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
    let executable = try dependencies.onePasswordExecutable()
    let token = try dependencies.credentialValue(profile.credentials[0])
    let result = try runOnePasswordCommand(profile: profile, token: token, executable: executable,
                                          command: command, arguments: rawArguments, input: preparedInput)
    try emitJSON(saveOnePasswordResult(result, command: command, token: token, output: secretOutput),
                 write: dependencies.stdout)
}

private func handleRequest(_ arguments: [String], dependencies: CLIDependencies) async throws {
    guard arguments.count >= 6 else { throw fail("request arguments are incomplete.", exitCode: 2) }
    let profile = try loadProfile(arguments[1], dependencies: dependencies)
    let options = try parseRequestOptions(Array(arguments.dropFirst(2)))
    let operation = try operationForRequest(profile: profile, method: options.method, relativePath: options.path)
    let body = try options.bodyFile.map(readJSONBody)
    try operation.body.validate(method: options.method, hasBody: body != nil)
    guard options.secretOutputFile == nil || operation.response != .empty else {
        throw fail("Secret output requires a JSON response policy.", exitCode: 2)
    }
    let transport = try APITransport(proxy: profile.proxy)
    let secretOutput = try options.secretOutputFile.map { try ProtectedResponseFile(path: $0) }
    var secrets = try profile.credentials.map(dependencies.credentialValue)
    defer {
        for index in secrets.indices {
            secrets[index].removeAll(keepingCapacity: false)
        }
    }
    let result = try await transport.send(
        profile: profile, operation: operation, method: options.method, relativePath: options.path,
        body: body, secrets: secrets, secretOutput: secretOutput
    )
    let forbiddenArtifacts = forbiddenCredentialArtifacts(profile: profile, secrets: secrets)
    try emitJSON(result, forbiddenSecrets: forbiddenArtifacts, write: dependencies.stdout)
}

private func dispatchCLI(_ arguments: [String], dependencies: CLIDependencies) async throws {
    guard let command = arguments.first else { throw fail(usage(), exitCode: 2) }
    switch command {
    case "help", "--help", "-h":
        guard arguments.count == 1 else { throw fail("help accepts no arguments.", exitCode: 2) }
        dependencies.stdout(Data((usage() + "\n").utf8))
    case "self-test":
        guard arguments.count == 1 else { throw fail("self-test accepts no arguments.", exitCode: 2) }
        try await runSelfTest()
    case "status":
        try handleStatus(arguments, dependencies: dependencies)
    case "authorize":
        try handleAuthorize(arguments, dependencies: dependencies)
    case "op":
        try handleOnePassword(arguments, dependencies: dependencies)
    case "request":
        try await handleRequest(arguments, dependencies: dependencies)
    default:
        throw fail("Unknown command.\n\n" + usage(), exitCode: 2)
    }
}

func runCLI(_ arguments: [String], dependencies: CLIDependencies = .live) async -> Int32 {
    do {
        try await dispatchCLI(arguments, dependencies: dependencies)
        return 0
    } catch let failure as SafeFailure {
        dependencies.stderr(Data((failure.message + "\n").utf8))
        return failure.exitCode
    } catch {
        dependencies.stderr(Data("The operation failed safely; no credential or raw diagnostic was printed.\n".utf8))
        return 1
    }
}

@main
private enum KeychainAPICLI {
    static func main() async {
        let exitCode = await runCLI(Array(CommandLine.arguments.dropFirst()))
        if exitCode != 0 { exit(exitCode) }
    }
}
