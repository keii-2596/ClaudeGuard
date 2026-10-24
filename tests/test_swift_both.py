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
print("Swift both verdict matrix passed")
'''
        with tempfile.TemporaryDirectory() as d:
            main = Path(d) / 'main.swift'
            executable = Path(d) / 'check'
            main.write_text(source + harness)
            subprocess.run(['swiftc', str(main), '-o', str(executable)], check=True, capture_output=True, text=True)
            result = subprocess.run([str(executable)], check=True, capture_output=True, text=True)
            self.assertIn('Swift both verdict matrix passed', result.stdout)
