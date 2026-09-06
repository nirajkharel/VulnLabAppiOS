import UIKit
import MachO

/**
 * VULN: ios-jailbreak-detection-bypass (blog: ios-jailbreak-detection-bypass.md)
 * VULN: ios-frida-detection-bypass (blog: ios-frida-detection-bypass.md)
 * VULN: ios-debugger-detection-bypass (blog: ios-debugger-detection-bypass.md)
 * VULN: ios-resigning-detection-bypass (blog: ios-resigning-detection-bypass.md)
 *
 * All detection methods below are bypassable via Frida hooks because they
 * execute as user-space Swift/ObjC code in the same process the attacker controls.
 */
class DetectionViewController: VulnBaseViewController {

    override func buildContent() {
        addButton("Re-run Checks", action: #selector(rerunTapped))
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        runAllChecks()
    }

    @objc func rerunTapped(_ sender: UIButton) {
        runAllChecks()
    }

    func runAllChecks() {
        var sb = ""

        sb += "=== Jailbreak Detection ===\n"
        sb += "filesystem:    \(checkJailbreakFilesystem())\n"
        sb += "url schemes:   \(checkJailbreakURLSchemes())\n"
        sb += "dyld images:   \(checkJailbreakDyldImages())\n\n"

        sb += "=== Frida Detection ===\n"
        sb += "dyld frida:    \(checkFridaDyldImages())\n"
        sb += "threads:       \(checkFridaThreads())\n\n"

        sb += "=== Debugger Detection ===\n"
        sb += "sysctl traced: \(checkSysctlTraced())\n"
        sb += "getppid:       \(checkGetppid())\n\n"

        sb += "=== Re-signing Detection ===\n"
        sb += "bundle ID:     \(checkBundleID())\n"
        sb += "entitlements:  \(checkEntitlements())\n\n"

        sb += "All checks hookable with Frida.\n"
        sb += "See blog post for bypass scripts."

        outputLabel.text = sb
    }

    // ── Jailbreak Detection ───────────────────────────────────────────────

    /** VULN: filesystem check — hookable via Interceptor.attach on stat/access */
    private func checkJailbreakFilesystem() -> Bool {
        let paths = [
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/private/var/lib/apt/",
            "/usr/bin/ssh",
            "/usr/libexec/sshd",
            "/bin/bash",
            "/etc/apt/"
        ]
        for path in paths {
            if FileManager.default.fileExists(atPath: path) { return true }
        }
        return false
    }

    /** VULN: URL scheme check — hookable via UIApplication.canOpenURL hook */
    private func checkJailbreakURLSchemes() -> Bool {
        let schemes = ["cydia://", "sileo://", "zbra://", "filza://"]
        for scheme in schemes {
            if let url = URL(string: scheme),
               UIApplication.shared.canOpenURL(url) { return true }
        }
        return false
    }

    /** VULN: dyld image scan — hookable via _dyld_get_image_name hook */
    private func checkJailbreakDyldImages() -> Bool {
        let count = _dyld_image_count()
        for i in 0..<count {
            if let name = _dyld_get_image_name(i) {
                let s = String(cString: name)
                if s.contains("MobileSubstrate") || s.contains("TweakInject") { return true }
            }
        }
        return false
    }

    // ── Frida Detection ───────────────────────────────────────────────────

    /** VULN: Frida gadget in dyld image list — hookable */
    private func checkFridaDyldImages() -> Bool {
        let count = _dyld_image_count()
        for i in 0..<count {
            if let name = _dyld_get_image_name(i) {
                let s = String(cString: name)
                if s.contains("frida") || s.contains("FridaGadget") { return true }
            }
        }
        return false
    }

    /** VULN: Frida thread names — hookable via pthread_getname_np */
    private func checkFridaThreads() -> Bool {
        var threadList: thread_act_array_t?
        var threadCount: mach_msg_type_number_t = 0
        guard task_threads(mach_task_self_, &threadList, &threadCount) == KERN_SUCCESS,
              let threads = threadList else { return false }
        defer {
            vm_deallocate(mach_task_self_,
                          vm_address_t(UInt(bitPattern: threadList)),
                          vm_size_t(threadCount) * vm_size_t(MemoryLayout<thread_act_t>.size))
        }
        var name = [CChar](repeating: 0, count: 64)
        for i in 0..<Int(threadCount) {
            guard let pt = pthread_from_mach_thread_np(threads[i]) else { continue }
            if pthread_getname_np(pt, &name, name.count) == 0 {
                let s = String(cString: name)
                if s == "gum-js-loop" || s == "gum-dq" || s.hasPrefix("frida-") {
                    return true
                }
            }
        }
        return false
    }

    // ── Debugger Detection ────────────────────────────────────────────────

    /** VULN: sysctl P_TRACED check — hookable via Interceptor.attach on sysctl */
    private func checkSysctlTraced() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        guard result == 0 else { return false }
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }

    /** VULN: getppid() != 1 indicates debugger attachment — hookable */
    private func checkGetppid() -> Bool {
        return getppid() != 1
    }

    // ── Re-signing Detection ──────────────────────────────────────────────

    /**
     * VULN: ios-resigning-detection-bypass — checks bundle ID against hardcoded value.
     * Hookable via ObjC.classes.NSBundle['- bundleIdentifier'].implementation hook.
     */
    private func checkBundleID() -> Bool {
        let expected = "com.vulnlab.iosapp"
        let actual   = Bundle.main.bundleIdentifier ?? ""
        if actual != expected {
            print("[resign-detection] bundle ID mismatch: \(actual) != \(expected)")
            return false  // returns false (mismatch) = re-signed
        }
        return true       // returns true (matches) = ok
    }

    /** VULN: entitlement check — comparing embedded.mobileprovision bytes */
    private func checkEntitlements() -> Bool {
        // Simplified: in a real app, read embedded.mobileprovision and check
        // the application-identifier entitlement matches the expected value
        guard let provisionPath = Bundle.main.path(forResource: "embedded",
                                                    ofType: "mobileprovision") else {
            // No provisioning profile — distributed via App Store (acceptable)
            return true
        }
        // VULN: string search on plist — easily bypassed by patching the binary
        let data = (try? Data(contentsOf: URL(fileURLWithPath: provisionPath))) ?? Data()
        return data.range(of: "com.vulnlab.iosapp".data(using: .utf8)!) != nil
    }
}
