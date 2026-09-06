import UIKit
import CoreData

/**
 * VULN: ios-unencrypted-coredata-realm (blog: ios-unencrypted-coredata-realm.md)
 *
 *   CoreData stack initialized without NSFileProtectionComplete or
 *   NSPersistentStoreFileProtectionKey. The SQLite file backing the
 *   persistent store is created at:
 *     Library/Application Support/VulnLabApp.sqlite
 *
 *   Without file protection, the database is readable:
 *   - When the device is locked (file protection level defaults to
 *     NSFileProtectionCompleteUntilFirstUserAuthentication, which is weaker)
 *   - On a jailbroken device via any file manager
 *   - Via an unencrypted iTunes backup
 *   - Via idevicebackup2 without a backup password
 *
 *   The table stores: email, password (plaintext), session token, credit card.
 *
 * Fix:
 *   options[NSPersistentStoreFileProtectionKey] = FileProtectionType.complete
 *   options[NSSQLitePragmasOption] = ["cipher": "aes-256-cbc", "key": derivedKey]
 */
class CoreDataViewController: VulnBaseViewController {

    // Build the managed object model entirely in code — no .xcdatamodeld file required.
    lazy var persistentContainer: NSPersistentContainer = {
        let entity = NSEntityDescription()
        entity.name = "UserRecord"
        entity.managedObjectClassName = "NSManagedObject"

        for attrName in ["email", "password", "sessionToken", "creditCard", "ssn"] {
            let a = NSAttributeDescription()
            a.name = attrName
            a.attributeType = .stringAttributeType
            a.isOptional = true
            entity.properties.append(a)
        }

        let model = NSManagedObjectModel()
        model.entities = [entity]

        let container = NSPersistentContainer(name: "VulnLabApp", managedObjectModel: model)

        let storeURL = NSPersistentContainer.defaultDirectoryURL()
            .appendingPathComponent("VulnLabApp.sqlite")

        let description = NSPersistentStoreDescription(url: storeURL)
        // VULN: no file protection level set
        // Fix would add:
        // description.setOption(FileProtectionType.complete as NSObject,
        //                       forKey: NSPersistentStoreFileProtectionKey)
        container.persistentStoreDescriptions = [description]

        container.loadPersistentStores { _, error in
            if let error = error {
                print("[coredata] load error: \(error)")
            }
        }
        return container
    }()

    override func buildContent() {
        addLabel("Stores credentials in an unencrypted CoreData SQLite store — no NSFileProtectionComplete, no SQLCipher.")
        addButton("Seed data (plaintext)",  action: #selector(seedData))
        addButton("Read back",              action: #selector(readData))
    }

    @objc func seedData(_ sender: UIButton) {
        let context = persistentContainer.viewContext

        // Store sensitive data in unencrypted CoreData
        let user = NSEntityDescription.insertNewObject(
            forEntityName: "UserRecord", into: context)
        user.setValue("victim@corp.com",      forKey: "email")
        user.setValue("P@ssw0rd!",            forKey: "password")    // VULN: plaintext
        user.setValue("session_abc123",       forKey: "sessionToken")
        user.setValue("4111111111111111",     forKey: "creditCard")   // VULN
        user.setValue("123-45-6789",          forKey: "ssn")          // VULN

        try? context.save()

        let dbPath = NSPersistentContainer.defaultDirectoryURL()
            .appendingPathComponent("VulnLabApp.sqlite").path

        outputLabel.text = "Data saved to unencrypted CoreData.\n\n"
            + "DB path: \(dbPath)\n\n"
            + "On a jailbroken device:\n"
            + "  scp root@device:\(dbPath) .\n"
            + "  sqlite3 VulnLabApp.sqlite 'SELECT * FROM ZUSERRECORD;'"
    }

    @objc func readData(_ sender: UIButton) {
        let context = persistentContainer.viewContext
        let request = NSFetchRequest<NSManagedObject>(entityName: "UserRecord")
        let results = (try? context.fetch(request)) ?? []

        let summary = results.map { obj in
            "email=\(obj.value(forKey: "email") ?? "nil") "
            + "password=\(obj.value(forKey: "password") ?? "nil")"
        }.joined(separator: "\n")

        outputLabel.text = "Records:\n\(summary.isEmpty ? "(empty)" : summary)"
    }
}
