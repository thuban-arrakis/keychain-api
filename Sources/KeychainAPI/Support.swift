import Foundation

let maximumPolicyBytes = 1 * 1024 * 1024
let maximumBodyBytes = 1 * 1024 * 1024
let maximumResponseBytes = 8 * 1024 * 1024
let maximumCredentialBytes = 4096

struct SafeFailure: Error {
    let message: String
    let exitCode: Int32

    init(_ message: String, exitCode: Int32 = 1) {
        self.message = message
        self.exitCode = exitCode
    }
}

func fail(_ message: String, exitCode: Int32 = 1) -> SafeFailure {
    SafeFailure(message, exitCode: exitCode)
}

func containsControlCharacters(_ value: String) -> Bool {
    value.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
}

func isSafeMetadata(_ value: String, maximumLength: Int = 256) -> Bool {
    !value.isEmpty && value.count <= maximumLength && !containsControlCharacters(value)
}
