import Foundation
import Security
import Darwin

// 1Password service accounts use SRP through the official CLI, never bearer auth.
func isSafeOnePasswordCommand(_ command: String) -> Bool {
    guard command.range(of: #"^[a-z]+(?:-[a-z]+)*(?: [a-z]+(?:-[a-z]+)*){0,2}$"#,
                        options: .regularExpression) != nil else { return false }
    // Exclude local execution, shell injection, session management, and updater commands.
    let roots: Set<String> = ["item", "vault", "document", "user", "group", "service-account", "environment", "read", "whoami"]
    let groups: Set<String> = ["item", "item template", "vault", "vault user", "vault group", "document",
                               "user", "user recovery", "group", "group user", "service-account", "environment", "environment secret"]
    return !groups.contains(command)
        && (command.split(separator: " ").first.map { roots.contains(String($0)) } ?? false)
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

func validateOnePasswordArguments(_ arguments: [String], command: String) throws {
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

enum OnePasswordInput {
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

func prepareOnePasswordInput(_ input: Data?, command: String, arguments: [String]) throws -> OnePasswordInput? {
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

func onePasswordProtectedResponse(_ data: Data, command: String, token: String) throws -> Data {
    let artifacts = credentialArtifacts([token])
    if data.isEmpty { return try encodedJSON(["ok": true]) }
    let expectsJSON = command != "read" && command != "document get"
    let object = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
    if expectsJSON || object != nil {
        try checkJSONCredentialEcho(data, forbiddenSecrets: artifacts, exitCode: 5)
    } else if dataContainsAnySecret(data, secrets: artifacts) {
        throw fail("The CLI response echoed the authentication credential; output was refused.", exitCode: 5)
    }
    if expectsJSON, let object, JSONSerialization.isValidJSONObject(object) {
        return data
    }
    // Binary downloads and plaintext field values remain private inside a JSON envelope.
    return try encodedJSON(["encoding": "base64", "data": data.base64EncodedString()])
}

func isTrustedOnePasswordOrigin(_ origin: URL) -> Bool {
    guard origin.scheme == "https", origin.port == nil,
          origin.user == nil, origin.password == nil,
          origin.query == nil, origin.fragment == nil,
          origin.path.isEmpty || origin.path == "/",
          let host = origin.host?.lowercased(),
          host.range(of: #"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.1password\.(com|eu|ca)$"#,
                     options: .regularExpression) != nil else { return false }
    return true
}

func validateOnePasswordTokenOrigin(_ token: String, expected: URL) throws {
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

func verifiedOnePasswordExecutable() throws -> URL {
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

func runOnePasswordCommand(
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

struct OnePasswordResult {
    let data: Data
    let failure: SafeFailure?

    func requireSuccess() throws -> Data {
        if let failure { throw failure }
        return data
    }
}

func saveOnePasswordResult(_ result: OnePasswordResult, command: String, token: String,
                                   output: ProtectedResponseFile) throws -> [String: Any] {
    if result.data.isEmpty, let failure = result.failure { throw failure }
    let data = try onePasswordProtectedResponse(result.data, command: command, token: token)
    let receipt = try output.commit(data)
    // A failed command can still return a one-time value. Keep that recovery evidence private.
    if let failure = result.failure { throw failure }
    return receipt
}
