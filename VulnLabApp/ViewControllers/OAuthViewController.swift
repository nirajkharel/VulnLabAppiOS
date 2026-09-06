import UIKit
import AuthenticationServices

/**
 * VULN: ios-aswebauthenticationsession-no-ephemeral (blog: ios-aswebauthenticationsession-no-ephemeral.md)
 *
 *   ASWebAuthenticationSession with prefersEphemeralWebBrowserSession = false
 *   (the default) shares Safari's full cookie jar. If the user is already
 *   logged in to the IdP in Safari, the IdP can issue an authorization code
 *   without showing a login prompt — silent re-authentication.
 *
 *   The callback scheme (vulnlaboauth://) is also a custom URL scheme,
 *   interceptable by any other app that registers the same scheme.
 *
 * Fix:
 *   Set session.prefersEphemeralWebBrowserSession = true
 *   Migrate callback to a Universal Link (HTTPS associated domain).
 */
class OAuthViewController: VulnBaseViewController, ASWebAuthenticationPresentationContextProviding {

    private var tokenLabel: UILabel!
    var authSession: ASWebAuthenticationSession?

    override func viewDidLoad() {
        super.viewDidLoad()
        outputLabel.text = "Tap 'Login with OAuth' to start the flow.\n\nprefersEphemeralWebBrowserSession is NOT set (defaults to false) — Safari cookies are shared."
        tokenLabel.text  = ""
    }

    override func buildContent() {
        addButton("Login with OAuth", action: #selector(startOAuth))
        tokenLabel = addExtraLabel()
    }

    @objc func startOAuth(_ sender: UIButton) {
        let authURL = URL(string:
            "https://auth.vulnlabapp.example.com/oauth/authorize"
            + "?client_id=vulnlab-ios"
            + "&redirect_uri=vulnlaboauth%3A%2F%2Fcallback"
            + "&response_type=code"
            + "&scope=openid%20profile")!

        // VULN: prefersEphemeralWebBrowserSession defaults to false
        //       Shares Safari's existing session — IdP may silently authenticate
        let session = ASWebAuthenticationSession(
            url: authURL,
            callbackURLScheme: "vulnlaboauth"       // VULN: custom scheme — interceptable
        ) { [weak self] callbackURL, error in
            guard let url = callbackURL, error == nil else {
                DispatchQueue.main.async {
                    self?.outputLabel.text = "Error: \(error?.localizedDescription ?? "cancelled")"
                }
                return
            }

            let code = URLComponents(url: url, resolvingAgainstBaseURL: false)?
                .queryItems?.first(where: { $0.name == "code" })?.value

            // VULN: authorization code logged to console
            print("[oauth] authorization code=\(code ?? "nil")")

            DispatchQueue.main.async {
                self?.outputLabel.text = "Callback received from:\n\(url)"
                self?.tokenLabel.text  = "code=\(code ?? "nil")"
            }
        }

        // VULN: prefersEphemeralWebBrowserSession not set to true
        //       Leaves it at the default (false), sharing the Safari cookie jar
        session.presentationContextProvider = self
        session.start()
        self.authSession = session
    }

    // MARK: - ASWebAuthenticationPresentationContextProviding

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        return view.window!
    }
}
