import Foundation

func dataContainsAnySecret(_ data: Data, secrets: [String]) -> Bool {
    secrets.contains { secret in
        !secret.isEmpty && data.range(of: Data(secret.utf8)) != nil
    }
}

func objectContainsAnySecret(_ object: Any, secrets: [String]) -> Bool {
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

func credentialArtifacts(_ secrets: [String]) -> [String] {
    Array(Set(secrets + secrets.map { Data($0.utf8).base64EncodedString() }))
}

func checkedJSON(_ data: Data, forbiddenSecrets: [String], exitCode: Int32) throws -> Any {
    guard !dataContainsAnySecret(data, secrets: forbiddenSecrets),
          let object = try? JSONSerialization.jsonObject(with: data),
          !objectContainsAnySecret(object, secrets: forbiddenSecrets) else {
        throw fail("JSON was invalid or contained authentication credential material.", exitCode: exitCode)
    }
    return object
}

let redactedValue = "[REDACTED]"

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

func looksLikeCredentialValue(_ value: String) -> Bool {
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

func pathHasCredentialContext(_ relativePath: String) -> Bool {
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

func sanitizedAPIObject(
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

func encodedJSON(_ object: Any, forbiddenSecrets: [String] = []) throws -> Data {
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

func emitJSON(
    _ object: Any,
    forbiddenSecrets: [String] = [],
    write: (Data) -> Void = { FileHandle.standardOutput.write($0) }
) throws {
    let data = try encodedJSON(object, forbiddenSecrets: forbiddenSecrets)
    write(data)
    write(Data("\n".utf8))
}
