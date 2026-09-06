import UIKit

/**
 * VULN: ios-nsurlcache-sensitive-caching (blog: ios-nsurlcache-sensitive-caching.md)
 *
 *   URLSession with URLSessionConfiguration.default inherits URLCache.shared,
 *   which is disk-backed (default 50 MB). HTTP responses — including bodies
 *   containing tokens, auth headers, and user data — are written to:
 *     Library/Caches/<bundle-id>/Cache.db
 *
 *   Readable on a jailbroken device, via an unencrypted iTunes backup,
 *   and via idevicebackup2. The cache survives app restarts indefinitely.
 *
 * Fix:
 *   Use URLSessionConfiguration.ephemeral, or set cachePolicy =
 *   .reloadIgnoringLocalAndRemoteCacheData on sensitive requests.
 */
class NetworkCacheViewController: VulnBaseViewController {

    // VULN: default session — shares URLCache.shared disk cache
    lazy var session: URLSession = {
        let config = URLSessionConfiguration.default
        // No cache policy override — responses go into Library/Caches/Cache.db
        return URLSession(configuration: config)
    }()

    override func viewDidLoad() {
        super.viewDidLoad()
        outputLabel.text = "Tap 'Fetch' to make an authenticated request.\n\nThe response will be cached to disk at:\nLibrary/Caches/com.vulnlab.iosapp/Cache.db\n\nRead it back:\n  sqlite3 Cache.db\n  SELECT request_key FROM cfurl_cache_response;"
    }

    override func buildContent() {
        addButton("Fetch (caches to disk)",  action: #selector(fetchAccount))
        addButton("Show cache path",         action: #selector(showCachePath))
    }

    @objc func fetchAccount(_ sender: UIButton) {
        var request = URLRequest(
            url: URL(string: "https://api.vulnlabapp.example.com/v1/account")!)

        // VULN: auth header sent — will be stored in cfurl_cache_response request blob
        request.setValue("Bearer sk-prod-8f3k2j9x0q1w5e6r", forHTTPHeaderField: "Authorization")

        // VULN: no cachePolicy set — response body + headers cached to disk
        session.dataTask(with: request) { [weak self] data, response, error in
            DispatchQueue.main.async {
                if let error = error {
                    self?.outputLabel.text = "Error: \(error.localizedDescription)"
                    return
                }
                let code = (response as? HTTPURLResponse)?.statusCode ?? 0
                let body = data.flatMap { String(data: $0, encoding: .utf8) } ?? "(no body)"
                self?.outputLabel.text = "HTTP \(code)\n\n\(body.prefix(200))\n\n(Response cached to Cache.db)"
            }
        }.resume()
    }

    @objc func showCachePath(_ sender: UIButton) {
        let cachePath = NSSearchPathForDirectoriesInDomains(.cachesDirectory, .userDomainMask, true).first ?? ""
        outputLabel.text = "Cache path:\n\(cachePath)/com.vulnlab.iosapp/Cache.db\n\n"
            + "sqlite3 command to read:\n"
            + "SELECT request_key, time_stamp FROM cfurl_cache_response;\n\n"
            + "Cache size: \(URLCache.shared.currentDiskUsage / 1024) KB used"
    }
}
