import Foundation
import CryptoKit
import Security
import LocalAuthentication

// Log encryption. The logger only ever holds the public key, so it can write rows but not
// read them back. The private key lives in the login Keychain and is used by `export`,
// which asks for Touch ID or the login password first.
//
// Each row is sealed on its own with HPKE (X25519, HKDF-SHA256, ChaCha20-Poly1305) and
// written as one base64 line: 32 bytes of encapsulated key followed by the ciphertext.

enum LogCrypto {
    static let info = Data("activity-logger/v1".utf8)
    static let suite = HPKE.Ciphersuite.Curve25519_SHA256_ChachaPoly
    static let encapsulatedKeyLength = 32

    struct Malformed: Error {}

    static func publicKey(base64: String) -> Curve25519.KeyAgreement.PublicKey? {
        guard let raw = Data(base64Encoded: base64) else { return nil }
        return try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: raw)
    }

    /// One row in, one base64 line out (no trailing newline).
    static func encryptLine(_ plaintext: Data, to key: Curve25519.KeyAgreement.PublicKey) throws -> Data {
        var sender = try HPKE.Sender(recipientKey: key, ciphersuite: suite, info: info)
        let sealed = try sender.seal(plaintext)
        return (sender.encapsulatedKey + sealed).base64EncodedData()
    }

    static func decryptLine(_ line: Data, with key: Curve25519.KeyAgreement.PrivateKey) throws -> Data {
        guard let raw = Data(base64Encoded: line), raw.count > encapsulatedKeyLength else { throw Malformed() }
        let enc = raw.prefix(encapsulatedKeyLength)
        let sealed = raw.dropFirst(encapsulatedKeyLength)
        var recipient = try HPKE.Recipient(privateKey: key, ciphersuite: suite, info: info, encapsulatedKey: Data(enc))
        return try recipient.open(Data(sealed))
    }
}

enum KeyStore {
    static let defaultService = "activity-logger"
    /// ACTIVITY_LOGGER_KEYCHAIN_SERVICE points at a throwaway key (used by tests).
    static let service: String = {
        let env = ProcessInfo.processInfo.environment["ACTIVITY_LOGGER_KEYCHAIN_SERVICE"]
        return (env?.isEmpty == false) ? env! : defaultService
    }()
    /// A throwaway key can't open the real logs, so tests may skip the Touch ID prompt for it.
    static var isThrowaway: Bool { service != defaultService }
    static let account = "log-decryption-key"

    struct KeychainError: Error, CustomStringConvertible {
        let status: OSStatus
        var description: String {
            (SecCopyErrorMessageString(status, nil) as String?) ?? "Keychain error \(status)"
        }
    }

    private static var baseQuery: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    static func load() throws -> Curve25519.KeyAgreement.PrivateKey? {
        var q = baseQuery
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = out as? Data else { throw KeychainError(status: status) }
        return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data)
    }

    static func save(_ key: Curve25519.KeyAgreement.PrivateKey) throws {
        var q = baseQuery
        q[kSecValueData as String] = key.rawRepresentation
        q[kSecAttrLabel as String] = "Activity Logger log decryption key"
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError(status: status) }
    }
}

/// Touch ID, or the login password where there is no Touch ID. False if the person cancels.
func confirmUserPresence(reason: String) -> Bool {
    let ctx = LAContext()
    var err: NSError?
    guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &err) else {
        FileHandle.standardError.write(Data("Can't ask for Touch ID or your password: \(err?.localizedDescription ?? "unknown error")\n".utf8))
        return false
    }
    let sem = DispatchSemaphore(value: 0)
    var ok = false
    ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, _ in
        ok = success
        sem.signal()
    }
    sem.wait()
    return ok
}
