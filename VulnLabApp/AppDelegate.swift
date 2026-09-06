import UIKit

/**
 * VULN: ios-background-snapshot-leak (blog: ios-background-snapshot-leak.md)
 *
 *   applicationWillResignActive does NOT add a privacy overlay before the
 *   system takes the app-switcher snapshot. Sensitive screen contents
 *   (account balances, OTPs, private messages) are captured and stored in:
 *     Library/Caches/Snapshots/<bundle-id>/
 *
 *   Readable by any process with filesystem access to the app container
 *   (e.g. Frida, idevicebackup2, or a jailbroken device's file manager).
 *
 * VULN: ios-custom-url-scheme-hijacking (blog: ios-custom-url-scheme-hijacking.md)
 *
 *   openURL handles vulnlab:// and vulnlaboauth:// without verifying that
 *   the caller is the expected app. Any malicious app can open these URLs.
 *
 * VULN: ios-universal-link-misconfiguration (blog: ios-universal-link-misconfiguration.md)
 *
 *   continueUserActivity handles universal links but never validates the
 *   webpageURL host or path — any app.vulnlabapp.example.com path is trusted.
 */
@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        window = UIWindow(frame: UIScreen.main.bounds)
        window?.rootViewController = UINavigationController(rootViewController: MainMenuViewController())
        window?.makeKeyAndVisible()
        return true
    }

    // VULN: ios-background-snapshot-leak — no privacy overlay added here
    func applicationWillResignActive(_ application: UIApplication) {
        // FIX would be:
        // let overlay = UIView(frame: window!.bounds)
        // overlay.backgroundColor = .systemBackground
        // overlay.tag = 99999
        // window?.addSubview(overlay)
        //
        // Instead: nothing. The snapshot captures whatever is on screen.
    }

    func applicationDidBecomeActive(_ application: UIApplication) {
        window?.viewWithTag(99999)?.removeFromSuperview()
    }

    // VULN: ios-custom-url-scheme-hijacking — handles vulnlab:// without origin check
    func application(_ app: UIApplication, open url: URL,
                     options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
        print("[url-scheme] received: \(url.absoluteString)")

        // VULN: no check on options[.sourceApplication] — any app can send this
        if url.scheme == "vulnlab" {
            handleVulnlabURL(url)
            return true
        }

        if url.scheme == "vulnlaboauth" {
            // VULN: oauth code extracted and logged — mobile-oauth-intent-redirect
            let code = URLComponents(url: url, resolvingAgainstBaseURL: false)?
                .queryItems?.first(where: { $0.name == "code" })?.value
            print("[oauth] code=\(code ?? "nil")")   // VULN: token in log
            return true
        }

        return false
    }

    private func handleVulnlabURL(_ url: URL) {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return }
        let host   = components.host ?? ""
        let params = components.queryItems ?? []

        print("[deep-link] host=\(host) params=\(params)")

        // VULN: ios-deeplink-parsing — no validation on the "redirect" param
        if let redirect = params.first(where: { $0.name == "redirect" })?.value,
           let redirectURL = URL(string: redirect) {
            // Opens any URL — enables open redirect to phishing pages
            UIApplication.shared.open(redirectURL)
        }

        // VULN: wkwebview-allowing-read-access-to — url param passed to loadURL with no scheme validation
        // vulnlab://webview?url=https://attacker.example/payload.html
        if host == "webview",
           let urlString = params.first(where: { $0.name == "url" })?.value {
            guard let nav = window?.rootViewController as? UINavigationController else { return }
            let webVC = WebViewController()
            webVC.title = "WebView"
            webVC.pendingURL = urlString   // set before push so viewDidLoad can load it
            nav.pushViewController(webVC, animated: false)
        }
    }

    // VULN: ios-universal-link-misconfiguration — any path accepted, no host check
    func application(_ application: UIApplication,
                     continue userActivity: NSUserActivity,
                     restorationHandler: @escaping ([UIUserActivityRestoring]?) -> Void) -> Bool {
        guard userActivity.activityType == NSUserActivityTypeBrowsingWeb,
              let url = userActivity.webpageURL else { return false }

        print("[universal-link] received: \(url.absoluteString)")

        // VULN: no validation of host or path — open redirect / param injection
        let token = URLComponents(url: url, resolvingAgainstBaseURL: false)?
            .queryItems?.first(where: { $0.name == "token" })?.value
        print("[universal-link] token=\(token ?? "nil")")   // VULN: token in log

        return true
    }
}
