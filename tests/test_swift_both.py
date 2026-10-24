"""Exercise the actual Swift decision functions without starting the daemon."""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift compiler required')
class SwiftBothTests(unittest.TestCase):
    def test_both_verdict_matrix(self):
        source = (Path(__file__).resolve().parents[1] / 'src/main.swift').read_text()
        source = source.split('\nlet app = NSApplication.shared')[0]
        harness = r'''
let good = "203.0.113.10"
let bad = "203.0.113.20"
let cases: [([String: String], String)] = [
    (["http": good, "stun": good], "allowed"),
    (["http": good, "stun": bad], "blocked"),
    (["stun": bad, "http": good], "blocked"),
    (["http": bad, "stun": good], "blocked"),
    (["http": bad, "stun": bad], "blocked"),
    (["http": good], "offline"),
    (["stun": good], "offline"),
    ([:], "offline"),
    (["stun": bad], "blocked"),
    (["http": bad], "blocked")
]
for (ips, expected) in cases {
    let state = AppDelegate.bothState(ips, allowedList: [good])
    let result: String
    switch state {
    case .allowed: result = "allowed"
    case .blocked: result = "blocked"
    case .offline: result = "offline"
    case .disabled: result = "disabled"
    }
    precondition(result == expected, "\(ips): got \(result), expected \(expected)")
}
if case .allowed = AppDelegate.bothState(["http": good, "stun": bad], allowedList: ["203.0.113.0/24"]) {} else {
    fatalError("Both distinct whitelisted IPs must pass")
}
precondition(AppDelegate.parseHTTPIP(Data("Too many requests".utf8)) == nil)
precondition(AppDelegate.parseHTTPIP(Data("203.0.113.10".utf8)) == good)
precondition(AppDelegate.parseHTTPIP(Data("2001:db8::1".utf8)) == "2001:db8::1")
let native = AppDelegate()
native.eventLogPath = URL(fileURLWithPath: CommandLine.arguments[2]).deletingLastPathComponent().appendingPathComponent("events.jsonl").path
native.logEvent("test_event", fields: ["reason": "测试"])
let log = try! String(contentsOfFile: native.eventLogPath, encoding: .utf8)
precondition(log.contains("test_event") && log.contains("测试"))
try! Data(repeating: 32, count: 1048576).write(to: URL(fileURLWithPath: native.eventLogPath))
native.logEvent("after_rotation")
precondition(FileManager.default.fileExists(atPath: native.eventLogPath + ".1"))
native.policyScriptPath = CommandLine.arguments[1]
native.configPath = CommandLine.arguments[2]
let config: [String: Any] = ["access_mode": "whitelist", "ip_check_mode": "http", "detect_ip_change": true,
                            "allowed_ips": [good, bad], "protection_enabled": true]
let initial = native.runPolicy(action: "evaluate", request: ["data": config, "ips": ["http": good]])
precondition(initial["state"] as? String == "allowed", "Native policy bridge did not allow first trusted exit")
let changed = native.runPolicy(action: "evaluate", request: ["data": config, "ips": ["http": bad]])
precondition(changed["state"] as? String == "blocked", "Native policy bridge allowed a whitelisted jump")
let returned = native.runPolicy(action: "evaluate", request: ["data": config, "ips": ["http": good]])
precondition(returned["state"] as? String == "blocked", "Jump latch did not survive returning to baseline")
let ackConfig = config.merging(["allowed_ips": [good]]) { _, new in new }
let ack = native.runPolicy(action: "ack-evaluate", request: ["data": ackConfig, "ips": ["http": bad], "expected_ips": ["http": bad]])
precondition(ack["state"] as? String == "blocked", "Acknowledgement bypassed whitelist")
precondition(ack["jump_acknowledged"] as? Bool == true, "Acknowledgement did not clear jump separately")
let ruleBlocked = native.runPolicy(action: "evaluate", request: ["data": ackConfig, "ips": ["http": bad]])
precondition(ruleBlocked["jump_latched"] as? Bool == false, "Whitelist denial incorrectly kept jump latch")
native.policyConfig = ["check_interval": 1.5]
native.configurePolling()
precondition(native.pollTimer!.timeInterval == 1.5)
let originalTimer = native.pollTimer
native.configurePolling()
precondition(native.pollTimer === originalTimer, "Unchanged interval should not reset the timer")
native.policyConfig["check_interval"] = 5
native.configurePolling()
precondition(!originalTimer!.isValid && native.pollTimer!.timeInterval == 5)
native.policyConfig["check_interval"] = true
precondition(native.checkInterval == 3, "Boolean interval must not be accepted")
native.pollTimer?.invalidate()
print("Swift both verdict matrix passed")
'''
        with tempfile.TemporaryDirectory() as d:
            main = Path(d) / 'main.swift'
            executable = Path(d) / 'check'
            main.write_text(source + harness)
            subprocess.run(['swiftc', str(main), '-o', str(executable)], check=True, capture_output=True, text=True)
            result = subprocess.run([str(executable), str(Path(__file__).resolve().parents[1] / "src/policy_cli.py"), str(Path(d) / "config.json")], check=True, capture_output=True, text=True)
            self.assertIn('Swift both verdict matrix passed', result.stdout)
