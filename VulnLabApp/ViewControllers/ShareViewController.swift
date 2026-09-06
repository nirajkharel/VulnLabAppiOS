import UIKit
import Security

/**
 * VULN: ios-uiactivity-share-sheet-leak (blog: ios-uiactivity-share-sheet-leak.md)
 *
 *   UIActivityViewController presented with a session token in activityItems
 *   and no excludedActivityTypes. Every built-in activity (Copy, AirDrop, Mail,
 *   Messages) and every installed third-party share extension sees the token.
 *
 *   Attack path:
 *     1. Attacker distributes an app with a share extension that registers for
 *        NSExtensionActivationRule (public.text).
 *     2. User opens VulnLabApp share sheet.
 *     3. User taps the attacker's extension.
 *     4. Extension receives activityItems in its own process and exfiltrates them.
 *
 *   Without an extension: tapping Copy puts the token on UIPasteboard.general,
 *   readable by any app (iOS 13-) or with a paste-banner warning (iOS 14+).
 *
 * Fix:
 *   Do not put session tokens or PII in activityItems.
 *   Set excludedActivityTypes to remove .copyToPasteboard, .airDrop, etc.
 *   from built-in activities — but note this does NOT prevent third-party
 *   share extensions from receiving the data.
 */
class ShareViewController: VulnBaseViewController {

    override func buildContent() {
        addLabel("Presents UIActivityViewController with a session token in activityItems and no excludedActivityTypes.\n\nEvery share extension and built-in activity receives the token.")
        addButton("Share account info (token in activityItems)", action: #selector(shareAccountInfo))
        addButton("Share Keychain token",                        action: #selector(shareWithToken))
    }

    @objc func shareAccountInfo(_ sender: UIButton) {
        let token = UserDefaults.standard.string(forKey: "session_token") ?? "tok_test_8f3k2j9x0q1"
        let email = UserDefaults.standard.string(forKey: "user_email")   ?? "user@vulnlab.example"

        // VULN: sensitive content (session token + email) put directly into activityItems
        let text = "Account: \(email)\nSession token: \(token)"

        // VULN: no excludedActivityTypes — Copy, AirDrop, Mail, Messages, and all share extensions get the token
        let vc = UIActivityViewController(activityItems: [text], applicationActivities: nil)

        // On iPad, UIActivityViewController must be presented from a popover
        if let popover = vc.popoverPresentationController {
            popover.sourceView = sender
            popover.sourceRect = sender.bounds
        }

        present(vc, animated: true) {
            self.outputLabel.text = "Share sheet presented.\n\n"
                + "activityItems: [\"\(text.prefix(60))...\"]\n\n"
                + "excludedActivityTypes: nil — all activities have access."
        }
    }

    @objc func shareWithToken(_ sender: UIButton) {
        // VULN: Keychain token shared without restriction
        let query: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrAccount: "session_token",
            kSecReturnData:  true,
        ]
        var result: AnyObject?
        SecItemCopyMatching(query as CFDictionary, &result)

        let tokenData = result as? Data
        let token     = tokenData.flatMap { String(data: $0, encoding: .utf8) } ?? "keychain_token_abc123"

        // VULN: raw Keychain token in activityItems
        let vc = UIActivityViewController(activityItems: [token], applicationActivities: nil)

        if let popover = vc.popoverPresentationController {
            popover.sourceView = sender
            popover.sourceRect = sender.bounds
        }

        present(vc, animated: true)
    }
}
