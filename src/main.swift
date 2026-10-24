import AppKit
import Foundation
import SystemConfiguration
import Network

// ClaudeGuard menu bar daemon.
//
// State machine: compute one GuardState, touch the system only on transitions
// (blocking/unblocking domains, killing the app, alerting) — never on every
// poll. Owns two enforcement surfaces: the Claude Desktop app (force-quit +
// alert) and the claude/anthropic domains (/etc/hosts + pf). The `claude` CLI
// enforces itself from src/cli_wrapper.py — a background daemon has no terminal.

enum GuardState: Equatable {
    case disabled              // protection off
    case offline               // no internet — can't verify
    case allowed(ip: String)   // public IP is whitelisted
    case blocked(ip: String)   // online, IP not whitelisted

    // Fail closed: domains open only on a confirmed good IP; offline blocks too.
    var domainsShouldBeBlocked: Bool {
        switch self {
        case .allowed, .disabled: return false
        case .blocked, .offline:  return true
        }
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!
    var menu: NSMenu!

    var state: GuardState = .offline
    var currentIP: String = "…"
    var protectionEnabled: Bool = true
    var blockAutoUpdates: Bool = true
    var modelOverrideEnabled: Bool = false
    var defaultModel: String = "claude-opus-4-8"
    var allowedIPs: [String] = []
    var ipCheckMode: String = "both"
    var verdictIPCheckMode: String = "both"
    var detectedIPs: [String: String] = [:]
    var policyConfig: [String: Any] = [:]
    var verdictPolicyConfig: [String: Any] = [:]
    var policyReason: String = ""
    var policyScriptPath = NSString(string: "~/.local/share/ClaudeGuard/src/policy_cli.py").expandingTildeInPath
    var riskScores: [String: Any] = [:]
    var jumpBlocked = false

    var usesAdvancedPolicy: Bool {
        let access = policyConfig["access_mode"] == nil ? "whitelist" : (policyConfig["access_mode"] as? String ?? "invalid")
        let rawJump = policyConfig["detect_ip_change"]
        let jump = rawJump as? Bool ?? (rawJump != nil)
        return access != "whitelist" || jump
    }
    var verdictAllowedIPs: [String] = []

    var dynamicStore: SCDynamicStore?
    var pathMonitor: NWPathMonitor?
    // Usable network route, from NWPathMonitor — lets us declare "offline" the
    // instant Wi-Fi drops instead of waiting for HTTP timeouts.
    var hasNetworkPath: Bool = true
    var blinkTimer: Timer?
    var blinkState: Bool = false
    // Serialize + coalesce rechecks. A plain "drop if busy" lock loses the
    // network event that arrives mid-check — the classic cause of a boot (or a
    // VPN handoff) that latches on offline/blocked until a reboot. Instead:
    // while a check runs, fold new requests into a flag and run one more pass
    // when it finishes, so the newest event is always acted on.
    let checkLock = NSLock()
    var checkRunning = false
    var recheckQueued = false
    var configPath = NSString(string: "~/.config/claudeguard/config.json").expandingTildeInPath

    // Last enforcement pushed to the system, to skip redundant work. nil = never
    // applied, force a first apply.
    var lastAppliedDomainsBlocked: Bool? = nil
    var lastAppliedBlockUpdates: Bool? = nil
    // Alerted once for the current blocked episode (reset on leaving blocked).
    var hasAlertedThisBlock: Bool = false

    // MARK: - Lifecycle

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Single-instance guard. LaunchAgent runs the bare binary, Launchpad
        // runs the .app — match both names and the bundle id.
        let myPID = getpid()
        for app in NSWorkspace.shared.runningApplications where app.processIdentifier != myPID {
            let name = app.localizedName ?? ""
            if name == "ClaudeGuardMenuBar" || name == "ClaudeGuard" || app.bundleIdentifier == "com.claudeguard.app" {
                NSApplication.shared.terminate(nil)
                return
            }
        }

        if let iconPath = Bundle.main.path(forResource: "AppIcon", ofType: "icns"),
           let iconImage = NSImage(contentsOfFile: iconPath) {
            NSApplication.shared.applicationIconImage = iconImage
        }

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        menu = NSMenu()
        statusItem.menu = menu

        loadConfig()
        rebuildMenu()

        setupAppLaunchInterceptor()

        // Bring the network monitors up first so no early Wi-Fi/VPN transition
        // is missed, then verify. State is unknown until the first check returns.
        setupPathMonitor()      // connectivity up/down
        setupNetworkObserver()  // VPN/route/IP changes while online
        setupWakeObserver()     // re-verify after the Mac wakes from sleep

        startBlinking()
        DispatchQueue.global(qos: .userInitiated).async { self.recheck() }

        // Fallback poll — catches a public-IP change with no local network event,
        // and (paired with the coalescing recheck) guarantees the daemon
        // self-heals from a bad boot within one interval instead of needing a
        // reboot. .utility so the OS won't suspend it the way it can .background.
        Timer.scheduledTimer(withTimeInterval: 3.0, repeats: true) { _ in
            DispatchQueue.global(qos: .utility).async { self.recheck() }
        }

        // Hook self-heal. Separate from recheck() because it guards a different
        // failure: not a network change, but Claude being reinstalled underneath
        // us and quietly detaching the guard.
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2.0) { self.runIntegrityRepair() }
        Timer.scheduledTimer(withTimeInterval: 60.0, repeats: true) { _ in
            DispatchQueue.global(qos: .utility).async { self.runIntegrityRepair() }
        }
    }

    func runIntegrityRepair() {
        runHelper("integrity", "", "")
    }

    /// True when /etc/hosts no longer matches what we last applied — an OS
    /// update, another tool or a manual edit reverted our block.
    func hostsDrifted() -> Bool {
        guard let wantDomains = lastAppliedDomainsBlocked,
              let wantUpdates = lastAppliedBlockUpdates,
              let content = try? String(contentsOfFile: "/etc/hosts", encoding: .utf8)
        else { return false }
        let hasDomains = content.contains("# BEGIN CLAUDEGUARD BLOCKS")
        let hasUpdates = content.contains("# BEGIN CLAUDEGUARD UPDATE BLOCKS")
        return hasDomains != wantDomains || hasUpdates != wantUpdates
    }

    /// Claude Desktop, matched by bundle-id *prefix* — the exact id has already
    /// changed once (claudefor-mac → claudefordesktop). The name is only a
    /// fallback: it's localized, so it can't be the primary test.
    static func isClaudeDesktop(_ app: NSRunningApplication) -> Bool {
        if let bundleID = app.bundleIdentifier {
            if bundleID.hasPrefix("com.claudeguard") { return false }   // never ourselves
            if bundleID.hasPrefix("com.anthropic.claude") { return true }
        }
        return (app.localizedName ?? "") == "Claude"
    }

    // MARK: - Connectivity monitor (Network framework)

    func setupPathMonitor() {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self = self else { return }
            let satisfied = (path.status == .satisfied)
            let changed = (self.hasNetworkPath != satisfied)
            self.hasNetworkPath = satisfied
            // Connectivity flipped — re-verify. Down → recheck() declares offline
            // instantly; up → recheck() runs the IP check.
            if changed { self.startBlinking() }
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + (satisfied ? 0.4 : 0.0)) {
                self.recheck()
            }
        }
        monitor.start(queue: DispatchQueue(label: "com.claudeguard.path"))
        self.pathMonitor = monitor
    }

    // MARK: - Real-time network observer

    func setupNetworkObserver() {
        var context = SCDynamicStoreContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(), retain: nil, release: nil, copyDescription: nil)

        let callback: SCDynamicStoreCallBack = { (_, _, info) in
            guard let info = info else { return }
            let me = Unmanaged<AppDelegate>.fromOpaque(info).takeUnretainedValue()
            // Network event fired — don't act blindly, just re-verify once it
            // settles; recheck() decides.
            me.startBlinking()
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 0.3) { me.recheck() }
        }

        guard let store = SCDynamicStoreCreate(kCFAllocatorDefault, "com.claudeguard.app" as CFString, callback, &context) else { return }
        self.dynamicStore = store
        let patterns = [
            "State:/Network/Global/IPv4",
            "State:/Network/Global/IPv6",
            "State:/Network/Interface/.*",
            "State:/Network/Service/.*"
        ] as CFArray
        SCDynamicStoreSetNotificationKeys(store, nil, patterns)
        if let src = SCDynamicStoreCreateRunLoopSource(kCFAllocatorDefault, store, 0) {
            CFRunLoopAddSource(CFRunLoopGetCurrent(), src, .defaultMode)
        }
    }

    // MARK: - Wake-from-sleep

    /// After the Mac wakes, the route and VPN re-establish over several seconds
    /// and NWPathMonitor may not emit a clean transition. Fire a few staggered
    /// rechecks so we never sit on a stale pre-sleep verdict.
    func setupWakeObserver() {
        NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            guard let self = self else { return }
            self.startBlinking()
            for delay in [0.5, 3.0, 8.0] {
                DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + delay) {
                    self.recheck()
                }
            }
        }
    }

    // MARK: - Desktop app launch interceptor

    func setupAppLaunchInterceptor() {
        NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.didLaunchApplicationNotification, object: nil, queue: .main) { [weak self] note in
            guard let self = self else { return }
            guard let app = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication else { return }
            if Self.isClaudeDesktop(app) {
                guard self.protectionEnabled else { return }
                // Fail closed on a fresh launch, even offline: an unverified
                // session must not start.
                if case .allowed = self.state { return }
                app.forceTerminate()
                self.runPkill(target: "Claude.app")
                let reason: String
                switch self.state {
                case .offline: reason = "暂时无法确认出口 IP，请检查网络和代理设置。"
                default:       reason = "当前出口未通过白名单检查：\(self.currentIP)。"
                }
                self.showBlockedAlert(reason: self.policyReason.isEmpty ? reason : self.policyReason)
            }
        }
    }

    // MARK: - Core check

    func recheck() {
        // Coalescing gate: at most one check runs at a time; a request that
        // arrives while one is in flight sets a flag so exactly one more pass
        // runs afterwards. No network event is ever silently dropped, and two
        // quick config toggles can't leave enforcement out of sync.
        checkLock.lock()
        if checkRunning {
            recheckQueued = true
            checkLock.unlock()
            return
        }
        checkRunning = true
        checkLock.unlock()

        while true {
            checkLock.lock(); recheckQueued = false; checkLock.unlock()

            performCheck()

            checkLock.lock()
            if recheckQueued { checkLock.unlock(); continue }
            checkRunning = false
            checkLock.unlock()
            break
        }
        stopBlinking()
    }

    /// One verification pass: resolve the public IP, fold it into a GuardState,
    /// push enforcement on transitions, publish the verdict.
    func performCheck() {
        loadConfig()
        let checkedMode = ipCheckMode
        let checkedIPs = allowedIPs
        let checkedPolicy = policyConfig
        let advancedPolicy = usesAdvancedPolicy
        policyReason = ""
        riskScores = [:]
        jumpBlocked = false

        detectedIPs = [:]
        let newState: GuardState
        if !protectionEnabled {
            newState = .disabled
        } else {
            let results = detectExits(mode: checkedMode)
            detectedIPs = results
            if advancedPolicy {
                let outcome = runPolicy(action: "evaluate", request: ["data": checkedPolicy, "ips": results])
                policyReason = outcome["reason"] as? String ?? "策略检查失败，暂不放行"
                riskScores = outcome["scores"] as? [String: Any] ?? [:]
                jumpBlocked = outcome["jump_latched"] as? Bool == true
                currentIP = checkedMode == "both" ? Self.describeBoth(results) : (results[checkedMode] ?? "No Internet")
                if outcome["state"] as? String == "allowed" {
                    newState = .allowed(ip: currentIP)
                } else {
                    newState = .blocked(ip: currentIP)
                }
            } else if checkedMode == "both" {
                currentIP = Self.describeBoth(results)
                newState = Self.bothState(results, allowedList: checkedIPs)
            } else if let ip = results[checkedMode] {
                currentIP = ip
                newState = Self.isIPAllowed(ip, allowedList: checkedIPs) ? .allowed(ip: ip) : .blocked(ip: ip)
            } else {
                currentIP = "No Internet"
                newState = .offline
            }
            if !results.isEmpty { hasNetworkPath = true }

        }

        let previous = state
        state = newState
        verdictIPCheckMode = checkedMode
        verdictAllowedIPs = checkedIPs
        verdictPolicyConfig = checkedPolicy
        apply(from: previous, to: newState)
        writeStateFile()  // publish verdict for the CLI wrapper

        DispatchQueue.main.async { self.updateStatusDisplay(); self.rebuildMenu() }
    }

    /// Publishes the verdict to state.json (single source of truth for the CLI
    /// wrapper). Written atomically each recheck; a stale file signals the
    /// daemon is down and the wrapper should fall back to its own check.
    func writeStateFile() {
        let stateStr: String
        switch state {
        case .allowed:  stateStr = "allowed"
        case .blocked:  stateStr = "blocked"
        case .offline:  stateStr = "offline"
        case .disabled: stateStr = "disabled"
        }
        let dict: [String: Any] = [
            "state": stateStr,
            "ip": currentIP,
            "detected_ips": detectedIPs,
            "access_mode": verdictPolicyConfig["access_mode"] ?? "whitelist",
            "detect_ip_change": verdictPolicyConfig["detect_ip_change"] ?? false,
            "reason": policyReason,
            "scores": riskScores,
            "jump_latched": jumpBlocked,
            "ip_check_mode": verdictIPCheckMode,
            "allowed_ips": verdictAllowedIPs,
            "protection_enabled": stateStr != "disabled",
            "updated_at": Date().timeIntervalSince1970
        ]
        let path = NSString(string: "~/.config/claudeguard/state.json").expandingTildeInPath
        if let data = try? JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted]) {
            try? data.write(to: URL(fileURLWithPath: path), options: .atomic)
        }
    }

    /// The only place that touches the system. Each piece runs only when its
    /// input actually changed.
    func apply(from previous: GuardState, to new: GuardState) {
        // Transition-only enforcement assumes nothing else edits /etc/hosts;
        // drift means "pretend we never applied anything" and re-apply.
        if hostsDrifted() {
            lastAppliedDomainsBlocked = nil
            lastAppliedBlockUpdates = nil
        }

        // Domains: /etc/hosts holds both claude-domain and update-domain blocks,
        // so rewrite when either flips.
        let wantBlocked = new.domainsShouldBeBlocked
        let domainsChanged = (lastAppliedDomainsBlocked != wantBlocked)
        let updatesChanged = (lastAppliedBlockUpdates != blockAutoUpdates)

        if domainsChanged || updatesChanged {
            lastAppliedDomainsBlocked = wantBlocked
            runHelper("sync_hosts", wantBlocked ? "true" : "false", String(blockAutoUpdates))
        }

        // Auto-update lock (chmod/chflags) — only on change.
        if updatesChanged {
            lastAppliedBlockUpdates = blockAutoUpdates
            runHelper("sync_updates", String(blockAutoUpdates), "")
        }

        // Desktop app kill + alert.
        switch new {
        case .blocked:
            let killed = killDesktopIfRunning()
            if killed && !hasAlertedThisBlock {   // alert once per blocked episode
                hasAlertedThisBlock = true
                showBlockedAlert(reason: policyReason.isEmpty ? "当前出口未通过白名单检查：\(currentIP)。" : policyReason)
            }
        case .allowed, .disabled, .offline:
            // offline: don't kill a running app — nothing to protect against.
            hasAlertedThisBlock = false
        }
        _ = previous
    }

    // MARK: - IP fetch (STUN-first, HTTP fallback, raced)

    let stunServers: [(String, UInt16)] = [
        ("stun.l.google.com", 19302),
        ("stun1.l.google.com", 19302),
        ("stun.cloudflare.com", 3478)
    ]
    let httpServices = [
        "https://api.ipify.org?format=json",
        "https://ifconfig.me/ip",
        "https://ipinfo.io/ip",
        "https://icanhazip.com",
        "https://api.myip.com"
    ]

    static func describeBoth(_ ips: [String: String]) -> String {
        return "HTTP: \(ips["http"] ?? "未获取"); STUN: \(ips["stun"] ?? "未获取")"
    }

    static func bothState(_ ips: [String: String], allowedList: [String]) -> GuardState {
        let display = describeBoth(ips)
        // A known unlisted exit blocks even if the other transport timed out.
        if ["http", "stun"].contains(where: { mode in
            guard let ip = ips[mode] else { return false }
            return !isIPAllowed(ip, allowedList: allowedList)
        }) { return .blocked(ip: display) }
        guard ips["http"] != nil, ips["stun"] != nil else { return .offline }
        return .allowed(ip: display)
    }

    /// Resolve one transport. Both-mode callers wait for two independent results.
    func detectExits(mode: String) -> [String: String] {
        let modes = mode == "both" ? ["http", "stun"] : [mode]
        let group = DispatchGroup()
        let lock = NSLock()
        var results: [String: String] = [:]
        for transport in modes {
            group.enter()
            DispatchQueue.global(qos: .utility).async {
                let ip = self.resolvePublicIP(deadline: 2.0, mode: transport)
                lock.lock()
                if let ip = ip { results[transport] = ip }
                lock.unlock()
                group.leave()
            }
        }
        group.wait()
        return results
    }

    func resolvePublicIP(deadline: TimeInterval = 2.0, mode selectedMode: String? = nil) -> String? {
        let mode = selectedMode ?? ipCheckMode
        guard ["http", "stun"].contains(mode) else { return nil }
        let sem = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var result: String? = nil
        func offer(_ ip: String?) {
            guard let ip = ip, !ip.isEmpty else { return }
            lock.lock()
            let first = (result == nil)
            if first { result = ip }
            lock.unlock()
            if first { sem.signal() }
        }

        // STUN (fast path)
        var conns: [NWConnection] = []
        for (host, port) in (mode == "http" ? [] : stunServers) {
            if let c = stunQuery(host: host, port: port, completion: { offer($0) }) {
                conns.append(c)
            }
        }

        // HTTP (fallback, in parallel)
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = deadline
        cfg.timeoutIntervalForResource = deadline
        let session = URLSession(configuration: cfg)
        for service in (mode == "stun" ? [] : httpServices) {
            guard let url = URL(string: service) else { continue }
            var req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: deadline)
            req.setValue("ClaudeGuard/1.0", forHTTPHeaderField: "User-Agent")
            session.dataTask(with: req) { data, _, err in
                guard err == nil else { return }
                offer(Self.parseHTTPIP(data))
            }.resume()
        }

        _ = sem.wait(timeout: .now() + deadline)
        conns.forEach { $0.cancel() }
        session.invalidateAndCancel()

        lock.lock(); let ip = result; lock.unlock()
        return ip
    }

    static func parseHTTPIP(_ data: Data?) -> String? {
        guard let data = data,
              let str = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !str.isEmpty else { return nil }
        if str.contains("{"), let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any], let ip = json["ip"] as? String {
            return ip.trimmingCharacters(in: .whitespacesAndNewlines)
        } else if !str.contains("<") {
            return str
        }
        return nil
    }

    /// Fires one STUN Binding Request over UDP and calls `completion` with the
    /// mapped public IP (or nil). Returns the live connection so the caller can
    /// cancel it. Non-blocking.
    func stunQuery(host: String, port: UInt16, completion: @escaping (String?) -> Void) -> NWConnection? {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { completion(nil); return nil }
        let conn = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .udp)

        // STUN Binding Request: type 0x0001, length 0, magic cookie, 12-byte txid.
        var req = Data([0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42])
        for _ in 0..<12 { req.append(UInt8.random(in: 0...255)) }

        let lock = NSLock()
        var done = false
        func finish(_ ip: String?) {
            lock.lock()
            if done { lock.unlock(); return }
            done = true
            lock.unlock()
            completion(ip)
        }

        conn.stateUpdateHandler = { st in
            switch st {
            case .ready:
                conn.send(content: req, completion: .contentProcessed { err in
                    if err != nil { finish(nil) }
                })
                conn.receiveMessage { data, _, _, _ in
                    finish(data.flatMap { Self.parseStun([UInt8]($0)) })
                }
            case .failed, .cancelled:
                finish(nil)
            default:
                break
            }
        }
        conn.start(queue: DispatchQueue(label: "com.claudeguard.stun"))
        return conn
    }

    /// Parses a STUN Binding Success Response, returning the IPv4 from the
    /// XOR-MAPPED-ADDRESS (0x0020) or plain MAPPED-ADDRESS (0x0001) attribute.
    static func parseStun(_ b: [UInt8]) -> String? {
        guard b.count >= 20, b[0] == 0x01, b[1] == 0x01 else { return nil } // 0x0101 success
        let msgLen = Int(b[2]) << 8 | Int(b[3])
        let cookie: [UInt8] = [0x21, 0x12, 0xA4, 0x42]
        var i = 20
        let end = min(20 + msgLen, b.count)
        while i + 4 <= end {
            let attrType = Int(b[i]) << 8 | Int(b[i + 1])
            let attrLen = Int(b[i + 2]) << 8 | Int(b[i + 3])
            let vs = i + 4
            if vs + attrLen > b.count { break }
            if (attrType == 0x0020 || attrType == 0x0001), attrLen >= 8, b[vs + 1] == 0x01 {
                let a0, a1, a2, a3: UInt8
                if attrType == 0x0020 { // XOR-MAPPED: address XOR'd with the magic cookie
                    a0 = b[vs + 4] ^ cookie[0]
                    a1 = b[vs + 5] ^ cookie[1]
                    a2 = b[vs + 6] ^ cookie[2]
                    a3 = b[vs + 7] ^ cookie[3]
                } else {
                    a0 = b[vs + 4]; a1 = b[vs + 5]; a2 = b[vs + 6]; a3 = b[vs + 7]
                }
                return "\(a0).\(a1).\(a2).\(a3)"
            }
            i = vs + attrLen
            if attrLen % 4 != 0 { i += 4 - (attrLen % 4) } // pad to 4-byte boundary
        }
        return nil
    }

    /// Matches an IP against exact entries or IPv4 CIDR ranges — mirrors
    /// ip_checker.py so the daemon and the CLI agree on what's whitelisted.
    static func isIPAllowed(_ ip: String, allowedList: [String]) -> Bool {
        for raw in allowedList {
            let entry = raw.trimmingCharacters(in: .whitespaces)
            if entry.isEmpty { continue }
            if entry == ip { return true }
            if entry.contains("/"), let ipv = ipv4ToUInt32(ip) {
                let parts = entry.split(separator: "/")
                if parts.count == 2, let net = ipv4ToUInt32(String(parts[0])), let bits = Int(parts[1]), (0...32).contains(bits) {
                    let mask: UInt32 = bits == 0 ? 0 : (~UInt32(0)) << (32 - bits)
                    if (ipv & mask) == (net & mask) { return true }
                }
            }
        }
        return false
    }

    static func ipv4ToUInt32(_ ip: String) -> UInt32? {
        let p = ip.split(separator: ".", omittingEmptySubsequences: false).compactMap { UInt32($0) }
        guard p.count == 4, p.allSatisfy({ $0 <= 255 }) else { return nil }
        return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]
    }

    // MARK: - Process control

    func runPkill(target: String) {
        let t1 = Process()
        t1.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        t1.arguments = ["-15", "-f", target]
        try? t1.run()
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.15) {
            let t2 = Process()
            t2.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
            t2.arguments = ["-9", "-f", target]
            try? t2.run()
        }
    }

    @discardableResult
    func killDesktopIfRunning() -> Bool {
        let victims = NSWorkspace.shared.runningApplications.filter { Self.isClaudeDesktop($0) }
        guard !victims.isEmpty else { return false }
        // Terminate the matched processes directly (precise wherever the app was
        // installed); pkill is the second pass for helpers it spawns.
        victims.forEach { $0.forceTerminate() }
        runPkill(target: "Claude.app")
        return true
    }

    func showBlockedAlert(reason: String) {
        DispatchQueue.main.async {
            NSApp.activate(ignoringOtherApps: true)
            let alert = NSAlert()
            alert.alertStyle = .critical
            alert.messageText = "ClaudeGuard 已拦截"
            alert.informativeText = "Claude 桌面端已关闭。\n\n\(reason)"
            alert.addButton(withTitle: "知道了")
            alert.window.level = .floating
            alert.runModal()
        }
    }

    func runHelper(_ cmd: String, _ a1: String, _ a2: String) {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        let script = NSString(string: "~/.local/share/ClaudeGuard/src/helper.py").expandingTildeInPath
        task.arguments = [script, cmd, a1, a2]
        try? task.run()
    }

    // MARK: - Config

    func loadConfig() {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            policyConfig = ["access_mode": "invalid"]
            protectionEnabled = true
            return
        }
        if let ips = json["allowed_ips"] as? [String] { allowedIPs = ips }
        policyConfig = json
        let storedMode = json["ip_check_mode"] == nil ? "both" : ((json["ip_check_mode"] as? String) ?? "invalid")
        ipCheckMode = storedMode == "auto" ? "both" : storedMode
        if let p = json["protection_enabled"] as? Bool { protectionEnabled = p }
        if let u = json["block_auto_updates"] as? Bool { blockAutoUpdates = u }
        if let m = json["model_override_enabled"] as? Bool { modelOverrideEnabled = m }
        if let d = json["default_model"] as? String { defaultModel = d }
    }

    func saveConfig() {
        var json: [String: Any] = [:]
        if let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)),
           let existing = try? JSONSerialization.jsonObject(with: data) as? [String: Any] { json = existing }
        for key in ["access_mode", "risk_threshold", "risk_cache_ttl", "detect_ip_change"] {
            if let value = policyConfig[key] { json[key] = value }
        }
        json["allowed_ips"] = allowedIPs
        json["ip_check_mode"] = ipCheckMode
        json["protection_enabled"] = protectionEnabled
        json["block_auto_updates"] = blockAutoUpdates
        json["model_override_enabled"] = modelOverrideEnabled
        json["default_model"] = defaultModel
        if let data = try? JSONSerialization.data(withJSONObject: json, options: .prettyPrinted) {
            try? data.write(to: URL(fileURLWithPath: configPath), options: .atomic)
        }
    }

    // MARK: - UI

    var ipCheckModeTitle: String {
        switch ipCheckMode {
        case "both": return "HTTP 和 STUN"
        case "http": return "仅 HTTP"
        case "stun": return "仅 STUN"
        default: return "配置有误"
        }
    }

    func statusText() -> String {
        switch state {
        case .offline:  return "⚪ 暂时无法确认出口 IP"
        case .disabled: return "🟡 防护已关闭"
        case .allowed:  return "🟢 出口已通过访问检查"
        case .blocked:  return "🔴 出口未通过访问检查，已拦截"
        }
    }

    func updateStatusDisplay(isDimmed: Bool = false) {
        guard let button = statusItem.button else { return }
        button.title = ""
        button.attributedTitle = NSAttributedString(string: "")

        let symbol: String
        switch state {
        case .offline:  symbol = "shield.slash.fill"   // crossed-out shield: nothing to verify against
        case .disabled: symbol = "shield"
        case .allowed:  symbol = "lock.shield.fill"
        case .blocked:  symbol = "xmark.shield.fill"
        }

        if let image = NSImage(systemSymbolName: symbol, accessibilityDescription: "ClaudeGuard")?
            .withSymbolConfiguration(NSImage.SymbolConfiguration(pointSize: 15, weight: .semibold)) {
            image.isTemplate = true
            button.image = image
            button.image?.accessibilityDescription = statusText()
            button.alphaValue = isDimmed ? 0.35 : 1.0
        }
    }

    func startBlinking() {
        DispatchQueue.main.async { [self] in
            guard blinkTimer == nil else { return }
            blinkState = false
            // Quick, smooth opacity pulse that fades in/out (like the system's
            // menu-bar input-source switcher) instead of a slow hard blink.
            blinkTimer = Timer.scheduledTimer(withTimeInterval: 0.16, repeats: true) { [weak self] _ in
                guard let self = self, let button = self.statusItem.button else { return }
                self.blinkState.toggle()
                NSAnimationContext.runAnimationGroup { ctx in
                    ctx.duration = 0.14
                    ctx.allowsImplicitAnimation = true
                    button.animator().alphaValue = self.blinkState ? 0.45 : 1.0
                }
            }
        }
    }

    func stopBlinking() {
        DispatchQueue.main.async { [self] in
            blinkTimer?.invalidate()
            blinkTimer = nil
            updateStatusDisplay()
            if let button = statusItem.button {
                NSAnimationContext.runAnimationGroup { ctx in
                    ctx.duration = 0.14
                    ctx.allowsImplicitAnimation = true
                    button.animator().alphaValue = 1.0
                }
            }
            rebuildMenu()
        }
    }

    func rebuildMenu() {
        menu.removeAllItems()

        let status = NSMenuItem(title: statusText(), action: nil, keyEquivalent: "")
        status.isEnabled = false
        menu.addItem(status)

        let ipItem = NSMenuItem(title: "🌐 当前出口：\(currentIP == "No Internet" ? "未获取" : currentIP)", action: nil, keyEquivalent: "")
        ipItem.isEnabled = false
        menu.addItem(ipItem)
        if !policyReason.isEmpty {
            let reason = NSMenuItem(title: policyReason, action: nil, keyEquivalent: "")
            reason.isEnabled = false
            menu.addItem(reason)
        }
        for ip in riskScores.keys.sorted() {
            if let entry = riskScores[ip] as? [String: Any], let score = entry["score"] as? NSNumber {
                let cached = entry["cached"] as? Bool == true ? "缓存" : "刚查询"
                let detail = NSMenuItem(title: "风险分：\(ip)  \(score)/100（\(cached)）", action: nil, keyEquivalent: "")
                detail.isEnabled = false
                menu.addItem(detail)
            }
        }

        menu.addItem(.separator())

        let recheck = NSMenuItem(title: "🔄 重新检测", action: #selector(onRecheck), keyEquivalent: "")
        recheck.target = self
        menu.addItem(recheck)

        menu.addItem(.separator())

        let prot = NSMenuItem(title: protectionEnabled ? "✓ 防护已开启" : "防护已关闭", action: #selector(onToggleProtection), keyEquivalent: "")
        prot.target = self
        menu.addItem(prot)

        let modeItem = NSMenuItem(title: "出口检测：\(ipCheckModeTitle)", action: nil, keyEquivalent: "")
        let modeMenu = NSMenu()
        for (value, title) in [("both", "同时检查 HTTP 和 STUN（两项都须通过）"), ("http", "只检查 HTTP"), ("stun", "只检查 STUN")] {
            let item = NSMenuItem(title: title, action: #selector(onSelectIPCheckMode(_:)), keyEquivalent: "")
            item.target = self
            item.representedObject = value
            item.state = ipCheckMode == value ? .on : .off
            modeMenu.addItem(item)
        }
        modeItem.submenu = modeMenu
        menu.addItem(modeItem)

        let access = policyConfig["access_mode"] as? String ?? "whitelist"
        let jump = policyConfig["detect_ip_change"] as? Bool == true
        let jumpToggle = NSMenuItem(title: jump ? "✓ 检测 IP 跳变" : "检测 IP 跳变", action: #selector(onToggleIPChange), keyEquivalent: "")
        jumpToggle.target = self
        menu.addItem(jumpToggle)
        if jump && jumpBlocked {
            let ack = NSMenuItem(title: "信任当前 IP 并解除拦截…", action: #selector(onAcknowledgeIPChange), keyEquivalent: "")
            ack.target = self
            menu.addItem(ack)
        }

        let settingsItem = NSMenuItem(title: "设置", action: nil, keyEquivalent: "")
        let settingsMenu = NSMenu()
        if access == "risk" {
            let cache = NSMenuItem(title: "评分缓存时间…", action: #selector(onRiskCacheTTL), keyEquivalent: "")
            cache.target = self
            settingsMenu.addItem(cache)
            settingsMenu.addItem(.separator())
        }
        let upd = NSMenuItem(title: blockAutoUpdates ? "✓ 已禁止自动更新" : "允许自动更新", action: #selector(onToggleUpdates), keyEquivalent: "")
        upd.target = self
        settingsMenu.addItem(upd)

        settingsMenu.addItem(.separator())

        let modelToggle = NSMenuItem(title: modelOverrideEnabled ? "✓ 固定模型：\(defaultModel)" : "固定模型（未启用）", action: #selector(onToggleModelOverride), keyEquivalent: "")
        modelToggle.target = self
        settingsMenu.addItem(modelToggle)

        if modelOverrideEnabled {
            let changeModel = NSMenuItem(title: "    更换模型…", action: #selector(onChangeModel), keyEquivalent: "")
            changeModel.target = self
            settingsMenu.addItem(changeModel)
        }

        settingsItem.submenu = settingsMenu
        menu.addItem(settingsItem)
        menu.addItem(.separator())

        let rules = NSMenuItem(title: "访问规则：" + (access == "risk" ? "风险评分" : "IP 白名单"), action: nil, keyEquivalent: "")
        let rulesMenu = NSMenu()
        for (value, title) in [("whitelist", "固定 IP 白名单"), ("risk", "按风险分阈值判断")] {
            let item = NSMenuItem(title: title, action: #selector(onSelectAccessMode(_:)), keyEquivalent: "")
            item.target = self
            item.representedObject = value
            item.state = access == value ? .on : .off
            rulesMenu.addItem(item)
        }
        rules.submenu = rulesMenu
        menu.addItem(rules)
        if access == "risk" {
            let thresholdValue = policyConfig["risk_threshold"] as? NSNumber ?? 50
            let threshold = NSMenuItem(title: "风险分阈值：\(thresholdValue)…", action: #selector(onRiskThreshold), keyEquivalent: "")
            threshold.target = self
            menu.addItem(threshold)
        } else if access == "whitelist" {
            for ip in Set(detectedIPs.values).sorted() where !allowedIPs.contains(ip) {
                let add = NSMenuItem(title: "➕ 将 \(ip) 加入白名单", action: #selector(onAddCurrentIP(_:)), keyEquivalent: "")
                add.target = self
                add.representedObject = ip
                menu.addItem(add)
            }

            let manage = NSMenuItem(title: "⚙️ 管理 IP 白名单…", action: #selector(onManageIPs), keyEquivalent: "")
            manage.target = self
            menu.addItem(manage)

        }

        menu.addItem(.separator())

        let quit = NSMenuItem(title: "退出 ClaudeGuard", action: #selector(onQuit), keyEquivalent: "")
        quit.target = self
        menu.addItem(quit)
    }

    private func recheckAsync() {
        startBlinking()
        DispatchQueue.global(qos: .userInitiated).async { self.recheck() }
    }

    func runPolicy(action: String, request: [String: Any]) -> [String: Any] {
        let failure: [String: Any] = ["state": "blocked", "reason": "策略检查失败，暂不放行"]
        guard let encoded = try? JSONSerialization.data(withJSONObject: request) else { return failure }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = [policyScriptPath, "--config", configPath, action]
        let input = Pipe(), output = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        let done = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in done.signal() }
        do { try process.run() } catch { return failure }
        input.fileHandleForWriting.write(encoded)
        input.fileHandleForWriting.closeFile()
        if done.wait(timeout: .now() + 45) == .timedOut {
            process.terminate()
            return failure
        }
        let raw = output.fileHandleForReading.readDataToEndOfFile()
        return (try? JSONSerialization.jsonObject(with: raw)) as? [String: Any] ?? failure
    }

    @objc func onSelectAccessMode(_ sender: NSMenuItem) {
        guard let mode = sender.representedObject as? String else { return }
        if mode == "risk" {
            let alert = NSAlert()
            alert.messageText = "使用风险评分判断出口？"
            alert.informativeText = "将向 proxycheck.io 查询出口 IP 的风险分，并缓存结果。超过你设置的阈值或无法取得有效评分时，都会拦截。"
            alert.addButton(withTitle: "使用风险评分")
            alert.addButton(withTitle: "取消")
            guard alert.runModal() == .alertFirstButtonReturn else { return }
        }
        policyConfig["access_mode"] = mode
        saveConfig()
        recheckAsync()
    }

    func setPolicyNumber(key: String, title: String, fallback: Double, min: Double, max: Double) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = "可填范围：\(min)～\(max)。"
        let input = NSTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
        input.stringValue = String((policyConfig[key] as? NSNumber)?.doubleValue ?? fallback)
        alert.accessoryView = input
        alert.addButton(withTitle: "保存")
        alert.addButton(withTitle: "取消")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        guard let number = Double(input.stringValue), number.isFinite, number >= min, number <= max else {
            let error = NSAlert()
            error.messageText = "输入无效，请填写范围内的数字。"
            error.runModal()
            return
        }
        policyConfig[key] = number
        saveConfig()
        recheckAsync()
    }
    @objc func onRiskThreshold() {
        setPolicyNumber(key: "risk_threshold", title: "超过多少风险分时拦截？", fallback: 50, min: 0, max: 100)
    }
    @objc func onRiskCacheTTL() {
        setPolicyNumber(key: "risk_cache_ttl", title: "评分缓存时间（秒）", fallback: 21600, min: 1, max: 604800)
    }
    @objc func onToggleIPChange() {
        policyConfig["detect_ip_change"] = !(policyConfig["detect_ip_change"] as? Bool ?? false)
        saveConfig()
        recheckAsync()
    }
    @objc func onAcknowledgeIPChange() {
        let expected = detectedIPs
        let data = policyConfig
        let mode = ipCheckMode
        let alert = NSAlert()
        alert.messageText = "信任当前 IP 并解除跳变拦截？"
        alert.informativeText = "当前出口：\(currentIP)\n\n如果这是你主动切换的线路，可以确认信任。程序会重新检测 IP，确认地址未变后，解除跳变拦截，并将当前 IP 设为新的检测基准。白名单和风险评分仍会单独检查，不通过时继续拦截。"
        alert.addButton(withTitle: "信任并重新检查")
        alert.addButton(withTitle: "取消")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        DispatchQueue.global(qos: .userInitiated).async {
            let freshIPs = self.detectExits(mode: mode)
            let result = self.runPolicy(action: "ack-evaluate", request: ["data": data, "ips": freshIPs, "expected_ips": expected])
            self.recheck()
            DispatchQueue.main.async {
                let notice = NSAlert()
                let acknowledged = result["jump_acknowledged"] as? Bool == true
                notice.messageText = acknowledged ? (result["state"] as? String == "allowed" ? "已解除跳变拦截，允许使用" : "已解除跳变拦截，访问检查未通过") : "未解除跳变拦截"
                notice.informativeText = result["reason"] as? String ?? "策略检查失败"
                notice.addButton(withTitle: "知道了")
                notice.runModal()
            }
        }
    }

    @objc func onRecheck() { recheckAsync() }

    @objc func onSelectIPCheckMode(_ sender: NSMenuItem) {
        guard let mode = sender.representedObject as? String,
              ["both", "http", "stun"].contains(mode) else { return }
        ipCheckMode = mode
        saveConfig()
        rebuildMenu()
        recheckAsync()
    }

    @objc func onToggleProtection() {
        protectionEnabled.toggle()
        saveConfig()
        rebuildMenu()        // reflect the toggle instantly; enforcement follows
        recheckAsync()
    }

    @objc func onToggleUpdates() {
        blockAutoUpdates.toggle()
        saveConfig()
        rebuildMenu()        // reflect the toggle instantly; enforcement follows
        recheckAsync()
    }

    @objc func onToggleModelOverride() {
        modelOverrideEnabled.toggle()
        saveConfig()
        rebuildMenu()
    }

    @objc func onChangeModel() {
        let script = "display dialog \"输入模型名称，例如 claude-opus-4-8：\" default answer \"\(defaultModel)\" with title \"ClaudeGuard 固定模型\" buttons {\"取消\", \"保存\"} default button \"保存\" cancel button \"取消\""
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", script]
        let pipe = Pipe()
        process.standardOutput = pipe
        try? process.run()
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        if let out = String(data: data, encoding: .utf8), out.contains("text returned:") {
            let parts = out.components(separatedBy: "text returned:")
            if parts.count > 1 {
                let raw = parts[1].trimmingCharacters(in: .whitespacesAndNewlines)
                if !raw.isEmpty {
                    defaultModel = raw
                    saveConfig()
                    rebuildMenu()
                }
            }
        }
    }

    @objc func onAddCurrentIP(_ sender: NSMenuItem) {
        guard let ip = sender.representedObject as? String, !allowedIPs.contains(ip) else { return }
        allowedIPs.append(ip)
        saveConfig()
        recheckAsync()
    }

    @objc func onManageIPs() {
        let ipsStr = allowedIPs.joined(separator: ", ")
        let script = "display dialog \"输入允许使用的出口 IP 或 CIDR 网段，多个地址用英文逗号分隔：\" default answer \"\(ipsStr)\" with title \"ClaudeGuard IP 白名单\" buttons {\"取消\", \"保存\"} default button \"保存\" cancel button \"取消\""
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", script]
        let pipe = Pipe()
        process.standardOutput = pipe
        try? process.run()
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        if let out = String(data: data, encoding: .utf8), out.contains("text returned:") {
            let parts = out.components(separatedBy: "text returned:")
            if parts.count > 1 {
                let raw = parts[1].trimmingCharacters(in: .whitespacesAndNewlines)
                allowedIPs = raw.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
                saveConfig()
                recheckAsync()
            }
        }
    }

    @objc func onQuit() { NSApplication.shared.terminate(nil) }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let delegate = AppDelegate()
app.delegate = delegate
app.run()
