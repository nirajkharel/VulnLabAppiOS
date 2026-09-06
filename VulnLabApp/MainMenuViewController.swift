import UIKit

class MainMenuViewController: UITableViewController {

    private struct Module {
        let title: String
        let subtitle: String
        let make: () -> UIViewController
    }

    private let modules: [Module] = [
        Module(title: "Login",              subtitle: "UserDefaults · Keychain · Pasteboard",        make: LoginViewController.init),
        Module(title: "File Storage",       subtitle: "NSFileProtectionNone",                         make: FileStorageViewController.init),
        Module(title: "SQLite",             subtitle: "Plaintext DB at Documents/users.db",           make: SQLiteViewController.init),
        Module(title: "Crypto",             subtitle: "DES · MD5 · static IV · arc4random",          make: CryptoViewController.init),
        Module(title: "Network",            subtitle: "Self-signed cert accept, ATS disabled",        make: NetworkViewController.init),
        Module(title: "Network Cache",      subtitle: "URLCache credential leak",                     make: NetworkCacheViewController.init),
        Module(title: "WebView",            subtitle: "JS bridge RCE · allowingReadAccessTo",         make: WebViewController.init),
        Module(title: "Deep Links",         subtitle: "Open redirect · token in URL",                 make: DeepLinkViewController.init),
        Module(title: "Biometric Auth",     subtitle: "LAContext bypass",                             make: BiometricViewController.init),
        Module(title: "OAuth",              subtitle: "Cookie sharing · custom scheme intercept",     make: OAuthViewController.init),
        Module(title: "Share Sheet",        subtitle: "Token in activityItems",                       make: ShareViewController.init),
        Module(title: "Serialization",      subtitle: "NSKeyedUnarchiver class restriction bypass",   make: SerializationViewController.init),
        Module(title: "Core Data",          subtitle: "Unencrypted SQLite backing store",             make: CoreDataViewController.init),
        Module(title: "Stored Credentials", subtitle: "NSURLCredentialStorage permanent persistence", make: StoredCredentialViewController.init),
        Module(title: "Detection",          subtitle: "Jailbreak · Frida · debugger · resign",       make: DetectionViewController.init),
    ]

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "VulnLabApp"
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "cell")
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        modules.count
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "cell", for: indexPath)
        let mod  = modules[indexPath.row]
        var cfg  = cell.defaultContentConfiguration()
        cfg.text            = mod.title
        cfg.secondaryText   = mod.subtitle
        cell.contentConfiguration = cfg
        cell.accessoryType  = .disclosureIndicator
        return cell
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        let mod = modules[indexPath.row]
        let vc  = mod.make()
        vc.title = mod.title
        navigationController?.pushViewController(vc, animated: true)
    }
}
