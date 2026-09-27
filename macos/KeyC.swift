import AppKit

struct Snapshot: Decodable {
    let enabled: Bool
    let services: [String: Int?]
    let tunnel_connected: Bool?
    let keep_awake: Bool
    let awake_pid: Int?
    let open_at_login: Bool
    let keep_unlocked: Bool
    let portal_url: String?
    let logs: String
}

final class KeyCApp: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private var item: NSStatusItem!
    private var snapshot: Snapshot?
    private var busy = false
    private var lastError: String?
    private var timer: Timer?
    private let queue = DispatchQueue(label: "com.keyc.menu.commands")
    private let menu = NSMenu()

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Opening the .app again must not create a second controller.
        if NSRunningApplication.runningApplications(withBundleIdentifier: "com.keyc.menubar").count > 1 {
            NSApp.terminate(nil)
            return
        }
        NSApp.setActivationPolicy(.accessory)
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.autosaveName = "KeyCStatus"
        item.button?.image = NSImage(systemSymbolName: "key.horizontal", accessibilityDescription: "Key C")
        item.button?.imagePosition = .imageLeading
        item.button?.title = " C"
        item.button?.toolTip = "Key C"
        menu.delegate = self
        menu.autoenablesItems = false
        item.menu = menu
        render()
        command(["status"])
        timer = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in
            self?.command(["status"])
        }
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        render()
        command(["status"])
    }

    @discardableResult
    private func add(_ title: String, _ action: Selector? = nil, checked: Bool? = nil,
                     enabled: Bool = true) -> NSMenuItem {
        let row = NSMenuItem(title: title, action: action, keyEquivalent: "")
        row.target = self
        row.isEnabled = enabled && action != nil && !busy
        if let checked { row.state = checked ? .on : .off }
        menu.addItem(row)
        return row
    }

    private func render() {
        menu.removeAllItems()
        let allRunning = snapshot?.services.values.allSatisfy { $0 != nil } == true
        let label = busy ? "Updating…" : snapshot.map {
            !$0.enabled ? "Key C · Off" : !allRunning ? "Key C · Needs Attention" :
                $0.tunnel_connected == true ? "Key C · Connected" : "Key C · Tunnel Disconnected"
        } ?? "Key C · Checking…"
        add(label)
        item.button?.title = snapshot?.enabled == false ? " C · Off" :
            snapshot?.tunnel_connected == false ? " C · Offline" : " C"
        item.button?.toolTip = label
        if let error = lastError { add(String(error.prefix(95))) }
        if snapshot?.enabled == true && snapshot?.tunnel_connected == false {
            add("Cloudflare connection unavailable")
        }
        menu.addItem(.separator())
        add("Open Key C", #selector(openPortal), enabled: snapshot?.portal_url != nil)
        add(snapshot?.enabled == false ? "Turn Key C On" : "Turn Key C Off", #selector(toggleEnabled),
            enabled: snapshot != nil)
        menu.addItem(.separator())
        add("Keep Mac Awake", #selector(toggleAwake), checked: snapshot?.keep_awake,
            enabled: snapshot != nil).toolTip = "Keep the Mac and display awake while Key C is on."
        add("Keep Desktop Unlocked", #selector(toggleUnlocked), checked: snapshot?.keep_unlocked,
            enabled: snapshot != nil).toolTip = "Leave the physical desktop unlocked after remote disconnect. Requires administrator approval."
        add("Open Menu at Login", #selector(toggleLogin), checked: snapshot?.open_at_login,
            enabled: snapshot != nil)
        menu.addItem(.separator())
        let services = NSMenu()
        for (name, title) in [("identity", "Identity"), ("terminal", "Terminal"), ("paseo", "Paseo"),
                              ("origin", "Gateway"), ("tunnel", "Tunnel")] {
            let running = snapshot?.services[name].flatMap { $0 } != nil
            let state = !running ? "Stopped" : name == "tunnel" ?
                (snapshot?.tunnel_connected == true ? "Connected" : "Disconnected") : "Running"
            let row = NSMenuItem(title: "\(title): \(state)", action: nil, keyEquivalent: "")
            row.isEnabled = false
            services.addItem(row)
        }
        let awake = snapshot?.awake_pid != nil
        services.addItem(withTitle: "Keep Awake: \(awake ? "Active" : "Inactive")", action: nil, keyEquivalent: "")
        let serviceRow = add("Services")
        serviceRow.submenu = services
        serviceRow.isEnabled = true
        add("Open Logs", #selector(openLogs), enabled: snapshot != nil)
        add("Refresh Status", #selector(refresh))
        menu.addItem(.separator())
        add("Quit Menu (Keep Key C Running)", #selector(quit))
    }

    private func command(_ arguments: [String]) {
        guard !busy else { return }
        busy = true
        render()
        let python = Bundle.main.object(forInfoDictionaryKey: "KeyCPython") as? String ?? "/usr/bin/python3"
        let backend = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/key-c/app/bin/menu_control.py").path
        queue.async {
            var state: Snapshot?
            var error: String?
            do {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: python)
                process.arguments = ["-B", backend] + arguments
                var environment = ProcessInfo.processInfo.environment
                environment["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
                process.environment = environment
                let pipe = Pipe()
                process.standardOutput = pipe
                process.standardError = pipe
                try process.run()
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                if process.terminationStatus == 0 {
                    state = try JSONDecoder().decode(Snapshot.self, from: data)
                } else {
                    let result = (try? JSONSerialization.jsonObject(with: data)) as? [String: String]
                    error = result?["error"] ?? "Could not update Key C. Check the menu log."
                }
            } catch let failure {
                error = failure.localizedDescription
            }
            let result = state
            let failure = error
            DispatchQueue.main.async {
                self.busy = false
                self.lastError = failure
                if let result { self.snapshot = result }
                self.render()
                if let failure, arguments != ["status"] {
                    self.alert("Key C could not finish", failure)
                    self.command(["status"])
                }
            }
        }
    }

    private func alert(_ title: String, _ message: String) {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.runModal()
    }

    @objc private func toggleEnabled() {
        guard let snapshot else { return }
        command(["enabled", snapshot.enabled ? "off" : "on"])
    }

    @objc private func toggleAwake() {
        guard let snapshot else { return }
        command(["awake", snapshot.keep_awake ? "off" : "on"])
    }

    @objc private func toggleLogin() {
        guard let snapshot else { return }
        command(["login", snapshot.open_at_login ? "off" : "on"])
    }

    @objc private func toggleUnlocked() {
        guard let snapshot, !busy else { return }
        busy = true
        render()
        // Fixed command only: never interpolate a hostname, path, or user input.
        let value = snapshot.keep_unlocked ? "YES" : "NO"
        let script = NSAppleScript(source: """
            do shell script "/usr/bin/defaults write /Library/Preferences/com.apple.RemoteManagement RestoreMachineState -bool \(value)" with administrator privileges
            """)
        var error: NSDictionary?
        NSApp.activate(ignoringOtherApps: true)
        script?.executeAndReturnError(&error)
        busy = false
        if let error, error[NSAppleScript.errorNumber] as? Int != -128 {
            alert("Desktop setting was not changed", error[NSAppleScript.errorMessage] as? String ?? "Administrator approval is required.")
        }
        command(["status"])
    }

    @objc private func openPortal() {
        if let value = snapshot?.portal_url, let url = URL(string: value) { NSWorkspace.shared.open(url) }
    }

    @objc private func openLogs() {
        if let path = snapshot?.logs { NSWorkspace.shared.open(URL(fileURLWithPath: path)) }
    }

    @objc private func refresh() { command(["status"]) }
    @objc private func quit() { NSApp.terminate(nil) }
}

let app = NSApplication.shared
let delegate = KeyCApp()
app.delegate = delegate
app.run()
