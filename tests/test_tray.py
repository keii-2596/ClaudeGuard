import copy
import json
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import Mock, patch

from portable.config import Settings, DEFAULTS, config_fingerprint
from portable.tray import snapshot, Tray, stop_tray


class TrayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.settings = Settings(Path(self.tmp.name) / "config.json")
        self.data = copy.deepcopy(DEFAULTS)
        self.settings.save(self.data)
        self.now = self.settings.path.stat().st_mtime + 2
        self.process = Mock(pid=42)
        self.process.create_time.return_value = 123
        self.verdict = dict(state="allowed", ip="203.0.113.10", checked_at=self.now,
                            pid=42, process_created=123, config_fingerprint=config_fingerprint(self.data))

    def read(self, running=True):
        self.settings.path.with_name("portable-state.json").write_text(json.dumps(self.verdict))
        with patch("portable.tray.daemon_process", return_value=self.process if running else None):
            return snapshot(self.settings, now=self.now)[2]

    def test_dead_daemon_never_shows_cached_success(self):
        self.assertEqual(self.read(False)["state"], "stopped")

    def test_fresh_success_and_expired_success(self):
        self.assertEqual(self.read()["state"], "allowed")
        self.verdict["checked_at"] -= 90
        self.assertEqual(self.read()["state"], "waiting")

    def test_changed_config_invalidates_previous_success(self):
        self.verdict["checked_at"] = self.settings.path.stat().st_mtime - 1
        self.assertEqual(self.read()["state"], "waiting")

    def test_replaced_daemon_snapshot_is_not_trusted(self):
        self.verdict["process_created"] = 124
        self.assertEqual(self.read()["state"], "waiting")

    def test_enforcement_failure_never_shows_green(self):
        self.verdict["enforcement_errors"] = ["access denied"]
        self.assertEqual(self.read()["state"], "error")

    def test_network_helper_must_confirm_allowed(self):
        self.data["network_guard_enabled"] = True
        self.settings.save(self.data)
        self.verdict["config_fingerprint"] = config_fingerprint(self.data)
        self.assertEqual(self.read()["state"], "error")
        self.verdict["network"] = {"ready": True, "applied_state": "allowed"}
        self.assertEqual(self.read()["state"], "allowed")

    def test_disabled_config_overrides_previous_success(self):
        self.data["protection_enabled"] = False
        self.settings.save(self.data)
        self.assertEqual(self.read()["state"], "disabled")

    def test_empty_whitelist_does_not_start_enforcement(self):
        tray = object.__new__(Tray)
        tray.settings = self.settings
        self.data["cli_path"] = "C:/Claude/claude.exe"
        self.settings.save(self.data)
        with patch("portable.tray.start_daemon") as start:
            with self.assertRaises(ValueError):
                tray.start()
            start.assert_not_called()

    def test_tray_stop_ignores_reused_pid(self):
        self.settings.path.with_name("tray-state.json").write_text(json.dumps({"pid": 42, "process_created": 1}))
        with patch("portable.tray.psutil.Process", return_value=self.process), patch("portable.tray.stop_tree") as stop:
            stop_tray(self.settings)
            stop.assert_not_called()
            self.process.terminate.assert_not_called()
            self.process.kill.assert_not_called()

    @unittest.skipUnless(sys.platform == "win32", "Windows tray backend")
    def test_menu_actions_are_queued_and_heartbeat_does_not_rebuild_menu(self):
        with patch("pystray.Icon") as icon, patch("portable.tray.autostart_enabled", return_value=False), \
                patch("portable.tray.daemon_process", return_value=None):
            tray = Tray(self.settings)
            tray.refresh()
            titles = [entry.text for entry in tray.icon.menu.items]
            self.assertIn("守护未运行", titles)
            self.assertIn("退出托盘（保留守护）", titles)
            settings_item = next(entry for entry in tray.icon.menu.items if entry.text == "打开设置…")
            settings_item(tray.icon)
            self.assertEqual(tray.commands.get_nowait(), tray.open_settings)
            count = icon.return_value.update_menu.call_count
            tray.refresh()
            self.assertEqual(icon.return_value.update_menu.call_count, count)


if __name__ == "__main__":
    unittest.main()
