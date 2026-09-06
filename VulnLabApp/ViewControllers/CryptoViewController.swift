import UIKit
import CommonCrypto

/**
 * VULN: ios-weak-cryptography (blog: ios-weak-cryptography.md)
 *
 *   Four distinct bugs:
 *     1. DES (kCCAlgorithmDES) with a static 8-byte key and ECB mode
 *     2. MD5 (CC_MD5) used for password hashing
 *     3. AES-CBC with an all-zero IV (Data(repeating: 0, ...))
 *     4. arc4random() for key generation (not a CSPRNG)
 *
 * Fix:
 *   1. Replace DES with AES-256-GCM
 *   2. Replace CC_MD5 with bcrypt / PBKDF2-SHA256
 *   3. Generate a random IV per encryption with SecRandomCopyBytes
 *   4. Generate key material with SecRandomCopyBytes
 */
class CryptoViewController: VulnBaseViewController {

    private var inputField: UITextField!

    override func buildContent() {
        inputField = addTextField("Plaintext / password input")
        addButton("Encrypt (DES ECB, static key)",  action: #selector(encryptWithDES))
        addButton("Hash password (MD5)",             action: #selector(hashPassword))
        addButton("Encrypt (AES-CBC, zero IV)",      action: #selector(encryptWithAESCBC))
        addButton("Show generated key (arc4random)", action: #selector(showGeneratedKey))
    }

    // MARK: - Bug 1: Single DES with static key and ECB mode

    @objc func encryptWithDES(_ sender: UIButton) {
        guard let plaintext = inputField.text, !plaintext.isEmpty else { return }

        if let ct = desEncrypt(plaintext) {
            outputLabel.text = "DES (ECB, static key) ciphertext:\n\(ct.base64EncodedString())\n\n"
                + "Key: \"vulnkey\" (static 8-byte)\nMode: ECB — identical blocks produce identical output"
        }
    }

    // VULN: single DES, 56-bit key, ECB mode, static key
    private func desEncrypt(_ plaintext: String) -> Data? {
        let key  = "vulnkey".data(using: .utf8)!      // VULN: static 8-byte key
        let data = plaintext.data(using: .utf8)!
        var output = Data(count: data.count + kCCBlockSizeDES)
        let outputCount = output.count
        var moved  = 0
        let status = key.withUnsafeBytes { kp in
            data.withUnsafeBytes { dp in
                output.withUnsafeMutableBytes { op in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmDES),                       // VULN: single DES
                        CCOptions(kCCOptionPKCS7Padding | kCCOptionECBMode), // VULN: ECB mode
                        kp.baseAddress!, kCCKeySizeDES,
                        nil,
                        dp.baseAddress!, data.count,
                        op.baseAddress!, outputCount, &moved)
                }
            }
        }
        return status == kCCSuccess ? output.prefix(moved) : nil
    }

    // MARK: - Bug 2: MD5 password hash

    @objc func hashPassword(_ sender: UIButton) {
        guard let password = inputField.text, !password.isEmpty else { return }

        let hash = md5Hash(password)
        outputLabel.text = "MD5(\"\(password)\"):\n\(hash)\n\n"
            + "MD5 is collision-broken. Rainbow tables cover 99%+ of common passwords.\nUse PBKDF2 or bcrypt instead."
    }

    // VULN: MD5 for password hashing — broken since 1996
    private func md5Hash(_ input: String) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        input.withCString { p in
            CC_MD5(p, CC_LONG(strlen(p)), &digest)  // VULN: CC_MD5
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Bug 3: AES-CBC with static all-zero IV

    @objc func encryptWithAESCBC(_ sender: UIButton) {
        guard let plaintext = inputField.text, !plaintext.isEmpty else { return }

        // VULN: key derived from arc4random — also covered by Bug 4
        let key = generateKey()

        if let ct = aesCBCEncrypt(plaintext, key: key) {
            outputLabel.text = "AES-CBC ciphertext:\n\(ct.base64EncodedString())\n\n"
                + "IV: 00000000000000000000000000000000 (all-zero, static)\n"
                + "CBC + static IV: identical plaintexts → identical first blocks.\n"
                + "PKCS7 padding + decryption oracle → padding oracle attack."
        }
    }

    // VULN: all-zero IV — identical plaintexts produce identical first cipher block
    private func aesCBCEncrypt(_ plaintext: String, key: Data) -> Data? {
        let iv   = Data(repeating: 0, count: kCCBlockSizeAES128)   // VULN: static zero IV
        let data = plaintext.data(using: .utf8)!
        var output = Data(count: data.count + kCCBlockSizeAES128)
        let outputCount = output.count
        var moved  = 0
        let status = key.withUnsafeBytes { kp in
            iv.withUnsafeBytes { ivp in
                data.withUnsafeBytes { dp in
                    output.withUnsafeMutableBytes { op in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),    // VULN: CBC+PKCS7 without HMAC = padding oracle risk
                            kp.baseAddress!, kCCKeySizeAES256,
                            ivp.baseAddress!,
                            dp.baseAddress!, data.count,
                            op.baseAddress!, outputCount, &moved)
                    }
                }
            }
        }
        return status == kCCSuccess ? output.prefix(moved) : nil
    }

    // MARK: - Bug 4: arc4random for key generation

    @objc func showGeneratedKey(_ sender: UIButton) {
        let key = generateKey()
        outputLabel.text = "Key (arc4random):\n\(key.hexString)\n\n"
            + "arc4random() has no API-contract guarantee of cryptographic strength.\nApple recommends SecRandomCopyBytes for key material."
    }

    // VULN: arc4random has no documented CSPRNG guarantee — use SecRandomCopyBytes for key material
    private func generateKey() -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        for i in 0..<bytes.count {
            bytes[i] = UInt8(arc4random() % 256)    // VULN: arc4random — no API-contract guarantee of crypto strength
        }
        return Data(bytes)
    }
}

private extension Data {
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
