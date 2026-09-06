import UIKit
import Security

/**
 * VULN: ios-nsuserdefaults-secrets (blog: ios-nsuserdefaults-secrets.md)
 *
 *   Session token, email, and password stored in NSUserDefaults. This is
 *   backed by a plist file in Library/Preferences/<bundle-id>.plist —
 *   readable on a jailbroken device, via an encrypted backup (with the
 *   right password), and via idevicebackup2 on an unencrypted backup.
 *
 * VULN: ios-pasteboard-leak (blog: ios-pasteboard-leak.md)
 *
 *   The password field's text is copied to UIPasteboard.general when the
 *   user taps "Copy Password". Since iOS 16, UIPasteboard is accessible
 *   cross-app and shows a banner — but the data is still readable by any
 *   app that calls UIPasteboard.general.string without the user noticing.
 *
 * VULN: ios-keychain-accessible-always (blog: ios-keychain-accessible-always.md)
 *
 *   The API key is stored in the Keychain with kSecAttrAccessibleAlways.
 *   This means it is readable when the device is locked, after cold boot,
 *   and from a jailbroken device with keychain_dumper.
 *
 * VULN: logging-pii-in-release (ios parallel)
 *
 *   print() calls (os_log equivalent in debug) leak email + password.
 */
class LoginViewController: VulnBaseViewController {

    private var emailField:    UITextField!
    private var passwordField: UITextField!

    override func buildContent() {
        emailField    = addTextField("Email")
        passwordField = addTextField("Password", isSecure: true)
        addButton("Log In",  action: #selector(loginTapped))
        addButton("Log Out", action: #selector(logoutTapped))
    }

    @objc func loginTapped(_ sender: UIButton) {
        let email    = emailField.text    ?? ""
        let password = passwordField.text ?? ""

        // VULN: PII logged — visible in Console.app and os_log streams
        print("[login] email=\(email) password=\(password)")

        // VULN: ios-nsuserdefaults-secrets — credentials stored in UserDefaults plist
        let defaults = UserDefaults.standard
        defaults.set(email,    forKey: "user_email")
        defaults.set(password, forKey: "user_password")   // plaintext password
        defaults.set("session_token_fake_abc123", forKey: "session_token")
        defaults.set("sk-prod-8f3k2j9x0q1w5e6r",  forKey: "api_key")
        defaults.synchronize()

        // VULN: ios-keychain-accessible-always — API key in always-accessible Keychain
        storeApiKeyWithAlwaysAccessible("sk-prod-8f3k2j9x0q1w5e6r")

        // VULN: ios-pasteboard-leak — password copied to general pasteboard
        UIPasteboard.general.string = password
        print("[pasteboard] password copied: \(password)")

        outputLabel.text = "Logged in.\nToken, email, and password saved to UserDefaults.\nPassword copied to pasteboard."
    }

    // VULN: kSecAttrAccessibleAlways — readable even when device is locked
    private func storeApiKeyWithAlwaysAccessible(_ apiKey: String) {
        let query: [String: Any] = [
            kSecClass as String:           kSecClassGenericPassword,
            kSecAttrService as String:     "com.vulnlab.iosapp",
            kSecAttrAccount as String:     "api_key",
            kSecValueData as String:       apiKey.data(using: .utf8)!,
            // VULN: kSecAttrAccessibleAlways — readable at any lock state
            kSecAttrAccessible as String:  kSecAttrAccessibleAlways
        ]
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        print("[keychain] stored api_key with kSecAttrAccessibleAlways — status: \(status)")
    }

    // VULN: ios-session-token-persistence - logout does not clear credentials
    @objc func logoutTapped(_ sender: UIButton) {
        // VULN: only sets a flag — all four storage layers retain live credentials
        UserDefaults.standard.set(false, forKey: "isLoggedIn")

        // Missing: SecItemDelete for api_key Keychain entry
        // Missing: UserDefaults.standard.removeObject(forKey: "session_token")
        // Missing: URLCache.shared.removeAllCachedResponses()
        // Missing: HTTPCookieStorage.shared.removeCookies(since: Date.distantPast)

        print("[logout] isLoggedIn cleared but credentials still live in 4 storage layers")
        outputLabel.text = "Logged out (credentials still readable)"
    }
}
