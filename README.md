# VulnLabAppiOS

An intentionally vulnerable iOS application for learning and practising iOS mobile security testing. Every vulnerability is deliberately introduced — each class carries a comment explaining what is broken, why it matters, and what the fix looks like.

Companion to the [nirajkharel.github.io](https://nirajkharel.github.io) iOS blog series.

---

## Requirements

| Tool | Version |
|---|---|
| Xcode | 15 or later |
| iOS deployment target | iOS 16+ |
| Device / Simulator | Physical device recommended for Frida-based labs |

No third-party dependencies. No Swift Package Manager packages. Builds clean out of the box.

---

## Build and run

```bash
git clone https://github.com/nirajkharel/VulnLabAppiOS.git
cd VulnLabAppiOS
open VulnLabApp.xcodeproj
```

1. Select your target device or simulator in the Xcode toolbar.
2. Set your development team under **Signing & Capabilities** if installing on a physical device.
3. Press **Run** (⌘R).

For dynamic analysis with Frida, install on a jailbroken device running frida-server:

```bash
# spawn and attach
frida -U -f com.vulnlab.iosapp --no-pause -l your-script.js
```

---

## App structure

```
VulnLabApp/
├── AppDelegate.swift                   # URL scheme handler, universal link handler
├── MainMenuViewController.swift        # Navigation menu
├── VulnBaseViewController.swift        # Shared UI base class
├── Detection/
│   └── DetectionViewController.swift  # Jailbreak / Frida / debugger / re-signing checks
└── ViewControllers/
    ├── LoginViewController.swift       # Auth, UserDefaults, Keychain, pasteboard
    ├── WebViewController.swift         # WKWebView, JS bridge, hardcoded endpoints
    ├── DeepLinkViewController.swift    # Deep link parsing, open redirect, path injection
    ├── NetworkViewController.swift     # TLS, ATS, certificate pinning
    ├── NetworkCacheViewController.swift# NSURLCache disk caching
    ├── OAuthViewController.swift       # ASWebAuthenticationSession, OAuth
    ├── BiometricViewController.swift   # LAContext biometric bypass
    ├── FileStorageViewController.swift # NSFileProtectionNone
    ├── SQLiteViewController.swift      # Plaintext SQLite storage
    ├── CoreDataViewController.swift    # Unencrypted CoreData
    ├── CryptoViewController.swift      # Weak cryptography (DES, MD5, zero IV)
    ├── SerializationViewController.swift # NSKeyedUnarchiver deserialization
    ├── ShareViewController.swift       # UIActivityViewController token leak
    └── StoredCredentialViewController.swift # NSURLCredentialStorage
```

---

## Vulnerabilities

### Data storage

| ID | Location | Description |
|---|---|---|
| `ios-nsuserdefaults-secrets` | `LoginViewController` | Session token, email, and password written to `UserDefaults` → stored in `Library/Preferences/<bundle>.plist`, readable on jailbroken device and in unencrypted backup |
| `ios-keychain-accessible-always` | `LoginViewController` | API key stored with `kSecAttrAccessibleAlways` — readable when device is locked, at cold boot, and from jailbroken device |
| `ios-entitlements-keychain-group-sharing` | `VulnLabApp.entitlements` | `keychain-access-groups` uses wildcard `$(AppIdentifierPrefix)com.company.*` — any app sharing the same team prefix can enumerate Keychain items |
| `ios-file-protection-none` | `FileStorageViewController` | Credentials written to `Documents/credentials.json` with `NSFileProtectionNone` — readable at any device lock state including BFU |
| `ios-sqlite-plaintext-storage` | `SQLiteViewController` | `Documents/users.db` stores email, password, and session token in cleartext with no file protection |
| `ios-unencrypted-coredata-realm` | `CoreDataViewController` | CoreData stack has no `NSPersistentStoreFileProtectionKey` — backing SQLite is readable on a jailbroken device and in unencrypted backup |
| `ios-nsurlcache-sensitive-caching` | `NetworkCacheViewController` | `URLSessionConfiguration.default` inherits the 50 MB disk cache; auth headers and response bodies land in `Library/Caches/<bundle>/Cache.db` |
| `ios-nsurlcredentialstorage-credential-leak` | `StoredCredentialViewController` | HTTP Basic-auth credentials stored with `.permanent` persistence in `NSURLCredentialStorage` — survives restarts, not visible to `SecItemCopyMatching` |
| `ios-pasteboard-leak` | `LoginViewController` | Password copied to `UIPasteboard.general` — readable cross-app |

### Network

| ID | Location | Description |
|---|---|---|
| `ios-urlsession-cert-error-proceed` | `NetworkViewController` | `URLSession` delegate calls `completionHandler(.useCredential, cred)` for any server trust challenge — accepts self-signed and expired certificates |
| `ios-pinning-bypass-methodology` | `NetworkViewController` | No certificate pinning implemented |
| `ios-ats-bypass` | `Info.plist` | `NSAllowsArbitraryLoads = true` disables App Transport Security for all connections |

### WebView

| ID | Location | Description |
|---|---|---|
| `wkwebview-allowing-read-access-to` | `WebViewController` | `loadFileURL(_:allowingReadAccessTo:)` called with `NSHomeDirectory()` — JS can `fetch()` any file in the app container |
| `wkwebview-js-bridge-rce` | `WebViewController` | `WKScriptMessageHandler` bridge exposes `exec()`, `readFile()`, and `getToken()` to any JS in the WebView |
| `ios-class-dump-endpoint-leak` | `WebViewController` | API base URLs hardcoded as string literals (`kApiBase`, `kAdminBase`, `kInternalApi`) — visible in `nm` output and class-dump headers |

### Deep links and URL schemes

| ID | Location | Description |
|---|---|---|
| `ios-deeplink-parsing` | `DeepLinkViewController`, `AppDelegate` | `redirect` parameter passed to `UIApplication.open()` without allowlist (open redirect); `token` parameter logged to console; `filename` parameter used without path canonicalization |
| `ios-custom-url-scheme-hijacking` | `AppDelegate` | `vulnlab://` and `vulnlaboauth://` handled without verifying the sender — any app can trigger the handler |
| `ios-universal-link-misconfiguration` | `AppDelegate` | Universal link handler accepts any path under `app.vulnlabapp.example.com` without validation |

### Authentication and session

| ID | Location | Description |
|---|---|---|
| `ios-lacontext-biometric-bypass` | `BiometricViewController` | `LAContext.evaluatePolicy` result trusted as a boolean — flippable with a two-line Frida hook; also bypassed when no biometric is enrolled |
| `ios-aswebauthenticationsession-no-ephemeral` | `OAuthViewController` | `prefersEphemeralWebBrowserSession = false` (default) shares Safari's cookie jar — silent re-authentication if user is already logged in to the IdP |
| `ios-session-token-persistence-after-logout` | `LoginViewController` | Logout sets `isLoggedIn = false` only — token, email, password, and API key remain live in UserDefaults and Keychain |
| `mobile-oauth-intent-redirect` | `AppDelegate` | OAuth authorization code received via custom URL scheme, logged to console in plaintext |

### Cryptography

| ID | Location | Description |
|---|---|---|
| `ios-weak-cryptography` | `CryptoViewController` | DES with static key and ECB mode; MD5 password hashing; AES-CBC with all-zero IV; `arc4random()` for key generation |

### Serialization

| ID | Location | Description |
|---|---|---|
| `ios-nskeyedunarchiver-insecure` | `SerializationViewController` | `NSKeyedUnarchiver.unarchiveObject(with:)` with no class allowlist — arbitrary class instantiation from attacker-controlled archive data |

### UI and information disclosure

| ID | Location | Description |
|---|---|---|
| `ios-uiactivity-share-sheet-leak` | `ShareViewController` | `UIActivityViewController` presented with session token in `activityItems` and no `excludedActivityTypes` — every share extension and built-in activity receives it |
| `ios-background-snapshot-leak` | `AppDelegate` | `applicationWillResignActive` adds no privacy overlay — system app-switcher snapshot captures whatever is on screen |
| `logging-pii-in-release` | `LoginViewController` | `print()` calls log email and password in release builds |

### Detection and anti-analysis

| ID | Location | Description |
|---|---|---|
| `ios-jailbreak-detection-bypass` | `DetectionViewController` | Filesystem, URL scheme, and dyld image checks — all bypassable via Frida hooks on `NSFileManager`, `UIApplication.canOpenURL`, and `_dyld_get_image_name` |
| `ios-frida-detection-bypass` | `DetectionViewController` | Dyld image name scan and `task_threads` + `pthread_getname_np` thread name walk — bypassable via name-rewriting hooks |
| `ios-debugger-detection-bypass` | `DetectionViewController` | `sysctl` P_TRACED flag check and `getppid() != 1` check — bypassable by intercepting the syscalls |
| `ios-resigning-detection-bypass` | `DetectionViewController` | Bundle ID comparison via `NSBundle.bundleIdentifier` and `embedded.mobileprovision` presence check — bypassable with ObjC method hooks |

---

## Disclaimer

This application is for **educational and security research purposes only**. All hardcoded values (bundle IDs, API keys, endpoints) are fictional. Do not install on a production device or distribute outside a lab environment.
