import UIKit
import LocalAuthentication
import Security

/**
 * VULN: ios-lacontext-biometric-bypass (blog: ios-lacontext-biometric-bypass.md)
 *
 *   LAContext.evaluatePolicy is called but the completion handler trusts the
 *   `success` boolean directly. The boolean is user-space data returned to
 *   this process — it can be flipped to true by a Frida hook with zero effort:
 *
 *     const LAContext = ObjC.classes.LAContext;
 *     Interceptor.attach(LAContext['- evaluatePolicy:localizedReason:reply:'].implementation, {
 *       onEnter(args) {
 *         const originalReply = new ObjC.Block(args[3]);
 *         const newReply = new ObjC.Block({
 *           retType: { type: 'void' },
 *           argTypes: [{ type: 'bool' }, { type: 'object' }],
 *           implementation: (s, e) => originalReply(true, null)
 *         });
 *         args[3] = newReply;
 *       }
 *     });
 *
 *   Even without Frida: if the device has no biometric enrolled, LAContext
 *   falls back to the passcode — the biometric check is bypassed completely.
 *
 *   The underlying issue: the application logic that gates sensitive data
 *   runs in the same process as the LAContext check. "Passed biometric" is
 *   an in-process flag, not a kernel-enforced guarantee.
 *
 * VULN: android-keystore-without-auth-binding (iOS parallel)
 *
 *   The Keychain item loaded after biometric auth uses kSecAttrAccessibleAlways
 *   — so it is accessible without auth anyway. The biometric is purely UI theatre.
 */
class BiometricViewController: VulnBaseViewController {

    override func buildContent() {
        addLabel("Tap Authenticate to trigger LAContext.\n\nOn a jailbroken device, hook evaluatePolicy:reply: to flip the success boolean to true — the secret loads without biometric.")
        addButton("Authenticate (Biometric)", action: #selector(authenticateTapped))
    }

    @objc func authenticateTapped(_ sender: UIButton) {
        let context = LAContext()
        var error: NSError?

        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                        error: &error) else {
            outputLabel.text = "Biometrics not available: \(error?.localizedDescription ?? "unknown")"
            return
        }

        context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: "Authenticate to access sensitive data") { [weak self] success, error in

            DispatchQueue.main.async {
                if success {
                    // VULN: trusts in-process boolean — hookable
                    self?.loadSensitiveData()
                } else {
                    self?.outputLabel.text = "Auth failed: \(error?.localizedDescription ?? "cancelled")"
                }
            }
        }
    }

    private func loadSensitiveData() {
        // VULN: item stored with kSecAttrAccessibleAlways — auth check above is irrelevant,
        //       the data was readable without biometrics all along
        let query: [String: Any] = [
            kSecClass as String:            kSecClassGenericPassword,
            kSecAttrService as String:      "com.vulnlab.iosapp",
            kSecAttrAccount as String:      "api_key",
            kSecReturnData as String:       true,
            kSecMatchLimit as String:       kSecMatchLimitOne
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecSuccess, let data = result as? Data,
           let secret = String(data: data, encoding: .utf8) {
            print("[biometric] loaded secret (was accessible without auth): \(secret)")
            outputLabel.text = "Secret: \(secret)\n\n(LAContext bypass: secret was kSecAttrAccessibleAlways — readable without auth)"
        } else {
            outputLabel.text = "No secret stored. Log in first to seed the Keychain item."
        }
    }
}
