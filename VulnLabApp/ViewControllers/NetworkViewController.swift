import UIKit
import Foundation

/**
 * VULN: ios-urlsession-cert-error-proceed (blog: ios-urlsession-cert-error-proceed.md)
 *
 *   URLSession delegate that calls completionHandler(.useCredential, cred) for
 *   ANY server trust challenge, including self-signed and expired certificates.
 *   This is the iOS equivalent of Android's broken TrustManager.
 *
 * VULN: ios-pinning-bypass-methodology (blog: ios-pinning-bypass-methodology.md)
 *
 *   No certificate pinning is implemented. The app accepts any certificate
 *   trusted by the system (or user cert store, since ATS is disabled).
 *   Frida script to bypass any pinning a developer later adds:
 *
 *     ['SecTrustEvaluate','SecTrustEvaluateWithError'].forEach(name => {
 *       const addr = Module.findExportByName('Security', name);
 *       if (!addr) return;
 *       Interceptor.attach(addr, {
 *         onLeave(retval) {
 *           if (name === 'SecTrustEvaluateWithError') retval.replace(1);
 *           else { Memory.writeU32(this.context.x1, 1); retval.replace(0); }
 *         }
 *       });
 *     });
 */
class NetworkViewController: VulnBaseViewController, URLSessionDelegate {

    private var urlField: UITextField!

    lazy var brokenSession: URLSession = {
        let config = URLSessionConfiguration.default
        return URLSession(configuration: config, delegate: self, delegateQueue: nil)
    }()

    override func viewDidLoad() {
        super.viewDidLoad()
        urlField.text = "https://self-signed.badssl.com/"
    }

    override func buildContent() {
        urlField = addTextField("URL")
        addButton("Fetch (accept any cert)", action: #selector(fetchTapped))
    }

    @objc func fetchTapped(_ sender: UIButton) {
        guard let urlStr = urlField.text,
              let url = URL(string: urlStr) else {
            outputLabel.text = "Invalid URL"
            return
        }

        let task = brokenSession.dataTask(with: url) { [weak self] data, response, error in
            DispatchQueue.main.async {
                if let error = error {
                    self?.outputLabel.text = "Error: \(error.localizedDescription)"
                    return
                }
                let code = (response as? HTTPURLResponse)?.statusCode ?? 0
                let body = data.flatMap { String(data: $0, encoding: .utf8) } ?? "(no body)"
                self?.outputLabel.text = "HTTP \(code)\n\n\(String(body.prefix(300)))"
            }
        }
        task.resume()
    }

    // VULN: ios-urlsession-cert-error-proceed
    // Accepts ANY server certificate — self-signed, expired, wrong hostname
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition,
                                                  URLCredential?) -> Void) {

        print("[cert-error] challenge for: \(challenge.protectionSpace.host)")
        print("[cert-error] authenticationMethod: \(challenge.protectionSpace.authenticationMethod)")

        // VULN: always proceed — equivalent to 'return true' in a broken HostnameVerifier
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let trust = challenge.protectionSpace.serverTrust {
            let credential = URLCredential(trust: trust)
            completionHandler(.useCredential, credential)
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}
