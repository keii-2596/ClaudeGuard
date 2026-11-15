"""Regressions for tray lifetime and in-flight configuration changes."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import psutil
from portable.config import DEFAULTS, Settings
from portable.runtime import daemon, daemon_process
from portable.tray import snapshot, stop_tray


class TrayRegressionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.settings = Settings(Path(self.tmp.name) / "config.json")
        self.data = copy.deepcopy(DEFAULTS)
        self.data["allowed_ips"] = ["203.0.113.10"]
        self.settings.save(self.data)

    def run_check(self, change=False):
        def probe(data, directory):
            if change:
                updated = copy.deepcopy(data)
                updated["allowed_ips"] = ["203.0.113.20"]
                self.settings.save(updated)
                # Preserve mtime: freshness must be bound to actual input, not clocks.
                os.utime(self.settings.path, (1, 1))
            return {"state": "allowed", "ip": "203.0.113.10"}
        with patch("portable.runtime.check", side_effect=probe), \
                patch("portable.runtime.network.publish", return_value={}), \
                patch("portable.runtime.RotatingFileHandler"), \
                patch("portable.runtime.logging.basicConfig"), \
                patch("portable.runtime.time.sleep", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                daemon(self.settings)
        return snapshot(self.settings)[2]

    def test_config_changed_during_check_cannot_turn_green(self):
        self.assertEqual(self.run_check(change=True)["state"], "waiting")
        self.assertEqual(self.run_check()["state"], "allowed")

    def test_current_config_check_can_turn_green(self):
        self.assertEqual(self.run_check()["state"], "allowed")

    def test_legacy_state_without_config_identity_is_not_trusted(self):
        state = {"state": "allowed", "ip": "203.0.113.10", "pid": os.getpid(),
                 "process_created": psutil.Process().create_time(), "checked_at": time.time()}
        self.settings.path.with_name("portable-state.json").write_text(json.dumps(state))
        self.assertEqual(snapshot(self.settings)[2]["state"], "waiting")

    def test_stop_targets_only_tray_even_if_it_has_children(self):
        process = Mock(pid=42)
        process.create_time.return_value = 123
        self.settings.path.with_name("tray-state.json").write_text(
            json.dumps({"pid": 42, "process_created": 123}))
        with patch("portable.tray.psutil.Process", return_value=process), \
                patch("portable.tray.stop_tree") as stop_tree:
            stop_tray(self.settings)
        process.terminate.assert_called_once_with()
        process.children.assert_not_called()
        stop_tree.assert_not_called()

    def test_stop_timeout_kills_only_tray(self):
        process = Mock(pid=42)
        process.create_time.return_value = 123
        process.wait.side_effect = psutil.TimeoutExpired(2)
        self.settings.path.with_name("tray-state.json").write_text(
            json.dumps({"pid": 42, "process_created": 123}))
        with patch("portable.tray.psutil.Process", return_value=process), \
                patch("portable.tray.stop_tree") as stop_tree:
            stop_tray(self.settings)
        process.kill.assert_called_once_with()
        process.children.assert_not_called()
        stop_tree.assert_not_called()

    def test_real_guard_survives_tray_stop(self):
        self.data["protection_enabled"] = False  # no network or enforcement
        self.settings.save(self.data)
        code = """
import os, sys, time, psutil
from portable.config import Settings, atomic_json
from portable.runtime import start_daemon
settings = Settings(sys.argv[1])
start_daemon(settings)
atomic_json(settings.path.with_name('tray-state.json'),
            {'pid': os.getpid(), 'process_created': psutil.Process().create_time()})
time.sleep(60)
"""
        tray = subprocess.Popen([sys.executable, "-c", code, str(self.settings.path)])
        guard = None
        def cleanup():
            from portable.platforms import stop_tree
            active = guard or daemon_process(self.settings)
            if active and active.is_running():
                stop_tree(active)
            if tray.poll() is None:
                tray.kill()
            tray.wait(timeout=5)
        self.addCleanup(cleanup)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            guard = daemon_process(self.settings)
            if guard and self.settings.path.with_name("tray-state.json").exists():
                break
            time.sleep(.05)
        self.assertIsNotNone(guard)
        stop_tray(self.settings)
        tray.wait(timeout=5)
        self.assertTrue(guard.is_running(), "Stopping the tray must leave its daemon alive")
        self.assertIsNotNone(daemon_process(self.settings))


if __name__ == "__main__":
    unittest.main()
