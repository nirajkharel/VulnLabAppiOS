import UIKit

/**
 * VULN: ios-deeplink-parsing (blog: ios-deeplink-parsing.md)
 *
 *   URL parameters from deep links (vulnlab://, universal links) are trusted
 *   without validation. Three vulnerable patterns:
 *
 *   1. Open redirect — "redirect" parameter passed to UIApplication.open()
 *      without host allowlist: vulnlab://open?redirect=https://phishing.com
 *
 *   2. Auth code / token in query — logged and stored in UserDefaults:
 *      vulnlab://login?token=secret — token captured by logger
 *
 *   3. Path injection — "filename" parameter passed to FileManager without
 *      canonicalization: vulnlab://view?file=../../Library/Preferences/com.vulnlab.iosapp.plist
 *
 * VULN: ios-custom-url-scheme-hijacking (blog: ios-custom-url-scheme-hijacking.md)
 *
 *   No check that the URL was sent by an authorized app. Any malicious app
 *   that opens vulnlab://callback?code=stolen can trigger this handler.
 */
class DeepLinkViewController: VulnBaseViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        outputLabel.text = "Waiting for deep link.\n\nTry:\n  vulnlab://open?redirect=https://attacker.com\n  vulnlab://login?token=stolen\n  vulnlab://view?file=../../Library/Preferences/com.vulnlab.iosapp.plist"
    }

    func handleURL(_ url: URL) {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            outputLabel.text = "Invalid URL"
            return
        }

        let params = Dictionary(
            uniqueKeysWithValues: (components.queryItems ?? []).compactMap { item in
                item.value.map { _ in (item.name, item) }
            }
        )

        var output = "Deep link: \(url.absoluteString)\n\n"

        // VULN Pattern 1: open redirect
        if let redirect = params["redirect"]?.value {
            output += "redirect: \(redirect)\n"
            // VULN: no host allowlist — any URL opens including phishing pages
            if let redirectURL = URL(string: redirect) {
                UIApplication.shared.open(redirectURL)
            }
        }

        // VULN Pattern 2: token/code in URL — logged
        if let token = params["token"]?.value {
            output += "token: \(token)\n"
            print("[deep-link] token=\(token)")   // VULN: token in log
            UserDefaults.standard.set(token, forKey: "session_token")
        }

        if let code = params["code"]?.value {
            output += "oauth code: \(code)\n"
            print("[deep-link] oauth code=\(code)")   // VULN: code in log
        }

        // VULN Pattern 3: file path — directory traversal
        if let filename = params["file"]?.value {
            output += "file: \(filename)\n"
            // VULN: no canonicalization — ../../ traversal possible
            let basePath = NSHomeDirectory() + "/Documents/"
            let fullPath = (basePath + filename)
            output += "resolved: \(fullPath)\n"
            let content = (try? String(contentsOfFile: fullPath)) ?? "(not found)"
            output += "content preview: \(content.prefix(100))\n"
        }

        outputLabel.text = output
    }
}
