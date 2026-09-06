import UIKit

/*
 * VULN: ios-file-protection-none
 *
 *   writeCredentialsToFile() creates a file with NSFileProtectionNone.
 *   The file at Documents/credentials.json is readable:
 *     - While the device is powered off (BFU / Before First Unlock)
 *     - During forensic acquisition targeting the app container
 *     - On any jailbroken device via SSH/file manager
 *
 *   NSFileProtectionNone is the default for files created without an
 *   explicit protectionKey attribute. Many apps set it explicitly to
 *   avoid crashes when writing during background fetch — the correct
 *   alternative for background writes is .completeUntilFirstUserAuthentication.
 *
 *   Fix: use .complete for files only accessed in foreground, or
 *   .completeUntilFirstUserAuthentication for files also accessed in background.
 */
class FileStorageViewController: VulnBaseViewController {

    override func buildContent() {
        addLabel("Writes credentials.json with NSFileProtectionNone — readable at any device lock state.\n\nOn jailbroken device: cat ~/Documents/credentials.json")
        addButton("Write (NSFileProtectionNone)", action: #selector(writeTapped))
        addButton("Read back",                    action: #selector(readTapped))
    }

    @objc func writeTapped(_ sender: UIButton) {
        writeCredentialsToFile()
    }

    @objc func readTapped(_ sender: UIButton) {
        readCredentialsFromFile()
    }

    // VULN: NSFileProtectionNone - readable when device is locked or off
    private func writeCredentialsToFile() {
        let credentials: [String: String] = [
            "email":    "victim@corp.com",
            "password": "P@ssw0rd!",
            "token":    "tok_live_abc123",
            "api_key":  "sk-prod-8f3k2j9x0q1w5e6r"
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: credentials) else { return }

        let path = NSHomeDirectory() + "/Documents/credentials.json"

        // VULN: NSFileProtectionNone makes the file readable in any device state
        FileManager.default.createFile(
            atPath: path,
            contents: data,
            attributes: [.protectionKey: FileProtectionType.none]   // VULN
        )
        outputLabel.text = "Written to \(path)"
        print("[file-protection] wrote credentials with NSFileProtectionNone to \(path)")
    }

    private func readCredentialsFromFile() {
        let path = NSHomeDirectory() + "/Documents/credentials.json"
        guard let data = FileManager.default.contents(atPath: path),
              let json  = try? JSONSerialization.jsonObject(with: data) as? [String: String] else {
            outputLabel.text = "(file not found — tap Write first)"
            return
        }
        outputLabel.text = json.map { "\($0.key)=\($0.value)" }.sorted().joined(separator: "\n")
    }
}
