import Foundation
import Security
import LocalAuthentication

enum KeychainReader {
    private static func query(
        for credential: CredentialPolicy,
        returnData: Bool,
        context suppliedContext: LAContext? = nil
    ) throws -> [CFString: Any] {
        var defaultKeychain: SecKeychain?
        guard SecKeychainCopyDefault(&defaultKeychain) == errSecSuccess, let defaultKeychain else {
            throw fail("The default login keychain is unavailable.", exitCode: 4)
        }
        let context: LAContext
        if let suppliedContext {
            context = suppliedContext
        } else {
            context = LAContext()
            context.interactionNotAllowed = true
        }
        return [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: credential.service,
            kSecAttrAccount: credential.account,
            kSecAttrSynchronizable: kCFBooleanFalse as Any,
            kSecMatchSearchList: [defaultKeychain],
            kSecMatchLimit: kSecMatchLimitOne,
            kSecUseAuthenticationContext: context,
            returnData ? kSecReturnData : kSecReturnAttributes: true
        ]
    }

    static func exists(_ credential: CredentialPolicy) throws -> Bool {
        let query = try query(for: credential, returnData: false)
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess: return true
        case errSecItemNotFound: return false
        case errSecInteractionNotAllowed, errSecAuthFailed, errSecUserCanceled:
            throw fail("Keychain access was not authorized or is unavailable.", exitCode: 4)
        default:
            throw fail("Keychain lookup failed safely.", exitCode: 4)
        }
    }

    private static func readData(_ credential: CredentialPolicy, context: LAContext? = nil) throws -> Data {
        let query = try query(for: credential, returnData: true, context: context)
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess: break
        case errSecItemNotFound:
            throw fail("A credential required by this profile is not present in the login keychain.", exitCode: 4)
        case errSecUserCanceled:
            throw fail("Keychain authorization was canceled.", exitCode: 4)
        case errSecInteractionNotAllowed, errSecAuthFailed:
            throw fail("Keychain access was not authorized or is unavailable.", exitCode: 4)
        default:
            throw fail("Keychain retrieval failed safely.", exitCode: 4)
        }
        guard var data = result as? Data else {
            throw fail("A Keychain item has no usable credential value.", exitCode: 4)
        }
        result = nil
        guard !data.isEmpty, data.count <= maximumCredentialBytes,
              data.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            data.resetBytes(in: 0..<data.count)
            throw fail("A Keychain item is not a valid single-line credential.", exitCode: 4)
        }
        return data
    }

    static func value(_ credential: CredentialPolicy) throws -> String {
        var data = try readData(credential)
        defer { data.resetBytes(in: 0..<data.count) }
        return String(decoding: data, as: UTF8.self)
    }

    static func authorize(_ credential: CredentialPolicy, context: LAContext) throws {
        var data = try readData(credential, context: context)
        data.resetBytes(in: 0..<data.count)
    }

}
