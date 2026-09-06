import UIKit

// Minimal NSCoding-compliant model so the archive path compiles
class UserSettings: NSObject, NSCoding {
    var theme: String = "default"
    var fontSize: Int = 14
    var sessionToken: String = ""

    override init() { super.init() }

    required init?(coder: NSCoder) {
        theme        = coder.decodeObject(forKey: "theme")        as? String ?? "default"
        fontSize     = coder.decodeInteger(forKey: "fontSize")
        sessionToken = coder.decodeObject(forKey: "sessionToken") as? String ?? ""
    }

    func encode(with coder: NSCoder) {
        coder.encode(theme,        forKey: "theme")
        coder.encode(fontSize,     forKey: "fontSize")
        coder.encode(sessionToken, forKey: "sessionToken")
    }
}

/**
 * VULN: ios-nskeyedunarchiver-insecure (blog: ios-nskeyedunarchiver-insecure.md)
 *
 *   Legacy NSKeyedUnarchiver.unarchiveObject(with:) and
 *   NSKeyedUnarchiver.unarchiveObject(withFile:) permit ANY class in the
 *   Objective-C runtime to be instantiated during decode. Attacker-controlled
 *   archive data → arbitrary class instantiation → gadget chains
 *   (NSExpression, NSInvocation, etc.).
 *
 * Fix:
 *   NSKeyedUnarchiver.unarchivedObject(ofClasses: [UserSettings.self, ...], from: data)
 *   Adopt NSSecureCoding in serializable models.
 */
class SerializationViewController: VulnBaseViewController {

    private var filePathField: UITextField!

    override func viewDidLoad() {
        super.viewDidLoad()
        outputLabel.text = "Tap 'Load from Network' to fetch a settings archive.\nTap 'Load from File' to deserialize from a path (simulate deep-link supplied path)."
    }

    override func buildContent() {
        addLabel("Deserializes with NSKeyedUnarchiver.unarchiveObject — no class restriction. Attacker-controlled data can instantiate any ObjC class.")
        filePathField = addTextField("File path (e.g. from deep link)")
        addButton("Load from Network", action: #selector(loadFromNetwork))
        addButton("Load from File",    action: #selector(loadFromFile))
    }

    // VULN: archive data comes from a network response — attacker-controllable via MITM or rogue server
    @objc func loadFromNetwork(_ sender: UIButton) {
        URLSession.shared.dataTask(
            with: URL(string: "https://api.vulnlabapp.example.com/v1/user-settings")!
        ) { [weak self] data, _, error in
            guard let data = data else {
                DispatchQueue.main.async {
                    self?.outputLabel.text = "Network error: \(error?.localizedDescription ?? "unknown")"
                }
                return
            }

            // VULN: no class restriction — any class in the ObjC runtime can be instantiated
            if let settings = NSKeyedUnarchiver.unarchiveObject(with: data) as? UserSettings {
                DispatchQueue.main.async {
                    self?.apply(settings)
                }
            } else {
                DispatchQueue.main.async {
                    self?.outputLabel.text = "Decode returned nil or unexpected type"
                }
            }
        }.resume()
    }

    // VULN: path comes from a deep link — attacker can supply an arbitrary file path
    @objc func loadFromFile(_ sender: UIButton) {
        let path = filePathField.text ?? ""
        guard !path.isEmpty else {
            outputLabel.text = "Enter a file path (e.g. from a deep link parameter)."
            return
        }

        // VULN: unarchiveObject(withFile:) — same unconstrained decode, path attacker-controlled
        if let settings = NSKeyedUnarchiver.unarchiveObject(withFile: path) as? UserSettings {
            apply(settings)
        } else {
            outputLabel.text = "No archive at path:\n\(path)"
        }
    }

    private func apply(_ settings: UserSettings) {
        outputLabel.text = "Loaded settings:\n  theme=\(settings.theme)\n  fontSize=\(settings.fontSize)\n  sessionToken=\(settings.sessionToken)\n\n(deserialized via legacy unarchiveObject — class was not restricted)"
    }
}
