import UIKit

/*
 * VULN: ios-nsurlcredentialstorage-credential-leak
 *
 *   storeHTTPCredentials() stores a Basic-auth credential with .permanent
 *   persistence in the shared NSURLCredentialStorage. This survives app
 *   restarts and is retrievable via:
 *     Frida: ObjC.classes.NSURLCredentialStorage['+sharedCredentialStorage']['- allCredentials']
 *
 *   Unlike Keychain items, these are not returned by SecItemCopyMatching —
 *   many auditors miss them on first pass.
 *
 *   Fix: use .forSession persistence so credentials expire with the process,
 *   or do not use NSURLCredentialStorage at all — store only in Keychain with
 *   kSecAttrAccessibleWhenUnlockedThisDeviceOnly.
 */
class StoredCredentialViewController: VulnBaseViewController {

    private var emailField:    UITextField!
    private var passwordField: UITextField!

    override func buildContent() {
        addLabel("Stores HTTP Basic-auth credentials with .permanent persistence in NSURLCredentialStorage — survives app restarts.")
        emailField    = addTextField("Email")
        passwordField = addTextField("Password", isSecure: true)
        addButton("Authenticate (store permanently)", action: #selector(authenticateTapped))
        addButton("Dump all credentials",             action: #selector(dumpCredentialsTapped))
    }

    @objc func authenticateTapped(_ sender: UIButton) {
        let email    = emailField.text    ?? ""
        let password = passwordField.text ?? ""
        storeHTTPCredentials(user: email, password: password)
        fetchProtectedResource()
    }

    // VULN: .permanent persistence survives app restart and device backup
    private func storeHTTPCredentials(user: String, password: String) {
        let credential = URLCredential(
            user: user,
            password: password,
            persistence: .permanent   // VULN: permanent - readable after restart
        )
        let space = URLProtectionSpace(
            host: "api.vulnlabapp.example.com",
            port: 443,
            protocol: "https",
            realm: "VulnLabApp API",
            authenticationMethod: NSURLAuthenticationMethodHTTPBasic
        )
        URLCredentialStorage.shared.set(credential, for: space)
        outputLabel.text = "Stored \(user):\(password) permanently in NSURLCredentialStorage"
        print("[credential-storage] stored \(user):\(password) permanently")
    }

    // VULN: URLSession automatically replays the stored credential on 401
    private func fetchProtectedResource() {
        let url = URL(string: "https://api.vulnlabapp.example.com/v1/protected")!
        URLSession.shared.dataTask(with: url) { [weak self] data, response, error in
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            DispatchQueue.main.async {
                let current = self?.outputLabel.text ?? ""
                self?.outputLabel.text = current + "\nHTTP \(status)"
            }
        }.resume()
    }

    // VULN: dump shows plaintext credentials retrievable at runtime
    @objc func dumpCredentialsTapped(_ sender: UIButton) {
        let storage = URLCredentialStorage.shared
        let all     = storage.allCredentials
        var result  = ""
        for (space, credentials) in all {
            for (_, credential) in credentials {
                result += "[\(space.host)] user=\(credential.user ?? "(nil)") "
                result += "pass=\(credential.password ?? "(nil)")\n"
            }
        }
        outputLabel.text = result.isEmpty ? "(empty)" : result
        print("[credential-storage] dump: \(result)")
    }
}
