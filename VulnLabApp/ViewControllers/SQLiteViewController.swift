import UIKit
import SQLite3

/*
 * VULN: ios-sqlite-plaintext-storage
 *
 *   The database at Documents/users.db is created with no encryption and no
 *   NSFileProtection attribute. The INSERT statements store email, password,
 *   and session token in cleartext columns.
 *
 *   On a jailbroken device: sqlite3 ~/Documents/users.db 'SELECT * FROM users;'
 *   returns all rows with plaintext credentials.
 *
 *   Fix: use SQLCipher for at-rest encryption, or encrypt sensitive columns
 *   with CryptoKit before INSERT and decrypt after SELECT. Also set
 *   NSFileProtectionComplete on the database file path.
 */
class SQLiteViewController: VulnBaseViewController {

    private var db: OpaquePointer?
    private let dbPath = NSHomeDirectory() + "/Documents/users.db"

    override func viewDidLoad() {
        super.viewDidLoad()
        openDatabase()
        createTable()
    }

    override func buildContent() {
        addLabel("Stores credentials in plaintext SQLite at Documents/users.db — no encryption, no file protection.\n\nsqlite3 ~/Documents/users.db 'SELECT * FROM users;'")
        addButton("Insert row (plaintext)", action: #selector(insertTapped))
        addButton("Query",                  action: #selector(queryTapped))
    }

    // VULN: database file has no encryption and no file protection attribute
    private func openDatabase() {
        if sqlite3_open(dbPath.cString(using: .utf8)!, &db) != SQLITE_OK {
            print("[sqlite] open failed: \(String(cString: sqlite3_errmsg(db)))")
        }
    }

    private func createTable() {
        let sql = """
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                email    TEXT,
                password TEXT,
                token    TEXT
            );
        """
        sqlite3_exec(db, sql, nil, nil, nil)
    }

    @objc func insertTapped(_ sender: UIButton) {
        // VULN: plaintext credentials inserted without encryption
        let sql = """
            INSERT INTO users (email, password, token)
            VALUES ('victim@corp.com', 'P@ssw0rd!', 'tok_live_abc123');
        """
        if sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK {
            outputLabel.text = "Inserted row\nDB: \(dbPath)"
            print("[sqlite] inserted plaintext credentials to \(dbPath)")
        }
    }

    @objc func queryTapped(_ sender: UIButton) {
        var stmt: OpaquePointer?
        var result = ""
        if sqlite3_prepare_v2(db, "SELECT email, password, token FROM users;", -1, &stmt, nil) == SQLITE_OK {
            while sqlite3_step(stmt) == SQLITE_ROW {
                guard let c0 = sqlite3_column_text(stmt, 0),
                      let c1 = sqlite3_column_text(stmt, 1),
                      let c2 = sqlite3_column_text(stmt, 2) else { continue }
                let email = String(cString: c0)
                let pass  = String(cString: c1)
                let tok   = String(cString: c2)
                result += "\(email) / \(pass) / \(tok)\n"
            }
        }
        sqlite3_finalize(stmt)
        outputLabel.text = result.isEmpty ? "(empty)" : result
    }

    deinit { sqlite3_close(db) }
}
