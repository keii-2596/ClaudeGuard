import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

try:
    import psutil
except ImportError:
    psutil = None


@unittest.skipIf(psutil is None, 'install portable/requirements.txt for platform tests')
class PortableTests(unittest.TestCase):
    def setUp(self):
        from portable.config import Settings, DEFAULTS
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.settings = Settings(Path(self.tmp.name) / 'config.json')
        self.data = copy.deepcopy(DEFAULTS)
        self.data['allowed_ips'] = ['203.0.113.10']

    def test_config_roundtrip_and_invalid_config_rejected(self):
        self.settings.save(self.data)
        self.assertEqual(self.settings.load(), self.data)
        self.data['allowed_ips'] = ['invalid']
        with self.assertRaises(ValueError):
            self.settings.save(self.data)
        self.assertEqual(self.settings.load()['allowed_ips'], ['203.0.113.10'])

    def test_config_corruption_is_not_silently_defaulted(self):
        self.settings.path.write_text('{broken')
        with self.assertRaises(ValueError):
            self.settings.load()

    def test_shared_interpreters_and_batch_files_rejected(self):
        for path in ('python.exe', 'node.exe', 'claude.cmd', 'launch.ps1', sys.executable):
            with self.subTest(path=path):
                self.data['cli_path'] = path
                with self.assertRaises(ValueError):
                    self.settings.save(self.data)

    def test_reject_non_boolean_or_bad_interval(self):
        for key, value in [('protection_enabled', 'false'), ('check_interval', 0), ('check_interval', True), ('check_interval', float('nan'))]:
            with self.subTest(key=key, value=value):
                self.data[key] = value
                with self.assertRaises(ValueError):
                    self.settings.save(self.data)
                self.data[key] = False if key == 'protection_enabled' else 3

    def test_outcome_matrix_and_proxy_forwarded(self):
        from portable.runtime import check
        self.data['http_proxy'] = 'http://127.0.0.1:7897'
        for result, expected in [(('203.0.113.10', True, None), 'allowed'),
                                 (('203.0.113.20', False, None), 'blocked'),
                                 ((None, False, 'timeout'), 'offline')]:
            with patch('portable.runtime.perform_ip_check', return_value=result) as probe:
                self.assertEqual(check(self.data)['state'], expected)
                self.assertEqual(probe.call_args.kwargs['proxy'], self.data['http_proxy'])

    def test_disabled_mode_does_not_probe(self):
        from portable.runtime import check
        self.data['protection_enabled'] = False
        with patch('portable.runtime.perform_ip_check') as probe:
            self.assertEqual(check(self.data)['state'], 'disabled')
            probe.assert_not_called()

    def test_blocked_launch_does_not_spawn(self):
        from portable.runtime import launch
        self.settings.save(self.data)
        with patch('portable.runtime.check', return_value={'state': 'blocked', 'ip': '203.0.113.20', 'error': None}), patch('portable.runtime.spawn') as spawn:
            with self.assertRaises(ValueError):
                launch(self.settings, 'cli', ['--version'])
            spawn.assert_not_called()

    def test_managed_launch_stops_on_failed_recheck(self):
        from portable.runtime import launch
        self.settings.save(self.data)
        verdicts = [{'state': 'allowed'}, {'state': 'offline'}]
        process = MagicMock(pid=os.getpid())
        process.poll.return_value = None
        with patch('portable.runtime.check', side_effect=verdicts), patch('portable.runtime.spawn', return_value=process), patch('portable.runtime.stop_tree') as stop:
            self.assertEqual(launch(self.settings, 'cli', []), 1)
            self.assertTrue(stop.called)

    def test_process_matching_uses_exact_path_and_current_user(self):
        from portable.platforms import enforce
        target = Path(self.tmp.name) / 'claude.exe'
        target.touch()
        ours = MagicMock(info={'username': 'me', 'exe': str(target)}, pid=123)
        other = MagicMock(info={'username': 'other', 'exe': str(target)}, pid=124)
        unrelated = MagicMock(info={'username': 'me', 'exe': str(target)+'-other'}, pid=125)
        with patch('portable.platforms.psutil.process_iter', return_value=[ours, other, unrelated]), patch('portable.platforms.psutil.Process') as current, patch('portable.platforms.stop_tree') as stop:
            current.return_value.username.return_value = 'me'
            self.assertEqual(enforce([str(target)]), [])
            stop.assert_called_once_with(ours)

    def test_real_child_termination(self):
        from portable.platforms import stop_tree
        process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        stop_tree(psutil.Process(process.pid))
        process.wait(timeout=5)
        self.assertIsNotNone(process.returncode)

    def test_real_daemon_start_singleton_and_stop(self):
        from portable.runtime import start_daemon, daemon_process
        from portable.platforms import stop_tree
        self.data['protection_enabled'] = False  # no network or process enforcement
        self.settings.save(self.data)
        child = start_daemon(self.settings)
        def cleanup():
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
        self.addCleanup(cleanup)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not daemon_process(self.settings):
            time.sleep(0.05)
        process = daemon_process(self.settings)
        self.assertIsNotNone(process)
        self.assertEqual(process.pid, child.pid)
        self.assertIsNone(start_daemon(self.settings))
        state = json.loads(self.settings.path.with_name('portable-state.json').read_text())
        self.assertEqual(state['state'], 'disabled')
        stop_tree(process)
        child.wait(timeout=5)
        self.assertIsNone(daemon_process(self.settings))

    def test_stale_pid_record_is_ignored(self):
        from portable.runtime import daemon_process
        self.settings.path.with_name('portable-state.json').write_text(json.dumps({'pid': os.getpid(), 'process_created': 0}))
        self.assertIsNone(daemon_process(self.settings))

    def test_single_instance_lock(self):
        from portable.runtime import InstanceLock
        path = Path(self.tmp.name) / 'lock'
        with InstanceLock(path):
            # Test a separate process; POSIX flock locks are per-open-file description.
            code = 'from portable.runtime import InstanceLock; import sys; x=InstanceLock(sys.argv[1]); x.__enter__()'
            result = subprocess.run([sys.executable, '-c', code, str(path)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)

    def test_linux_autostart_unit_and_removal(self):
        from portable.platforms import autostart
        with patch.dict(os.environ, {'XDG_CONFIG_HOME': self.tmp.name}), patch('portable.platforms.subprocess.run') as run:
            autostart('/some path/python', '/some path/main.py', self.settings.path, True, system='linux')
            unit = Path(self.tmp.name) / 'systemd/user/claudeguard.service'
            self.assertIn('"/some path/python"', unit.read_text())
            self.assertIn('Restart=on-failure', unit.read_text())
            self.assertTrue(any('enable' in call.args[0] for call in run.call_args_list))
            autostart('/some path/python', '/some path/main.py', self.settings.path, False, system='linux')
            self.assertFalse(unit.exists())

    @unittest.skipUnless(sys.platform == 'win32', 'Windows registry integration')
    def test_windows_autostart_registry(self):
        from portable.platforms import autostart
        import winreg
        # Isolate the test key rather than replacing an existing real login entry.
        original_create = winreg.CreateKey
        test_key = r'Software\ClaudeGuard-CI-Test\Run'
        with patch('winreg.CreateKey', side_effect=lambda root, path: original_create(root, test_key)):
            try:
                autostart(sys.executable, 'C:/test/main.py', self.settings.path, True, system='win32')
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, test_key) as key:
                    value, _ = winreg.QueryValueEx(key, 'ClaudeGuard')
                    self.assertIn('daemon', value)
                autostart(sys.executable, 'C:/test/main.py', self.settings.path, False, system='win32')
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, test_key) as key:
                    with self.assertRaises(FileNotFoundError):
                        winreg.QueryValueEx(key, 'ClaudeGuard')
            finally:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, test_key)
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r'Software\ClaudeGuard-CI-Test')

    def test_cli_end_to_end(self):
        entry = Path(__file__).resolve().parents[1] / 'portable/main.py'
        for command in [('set', 'ip_check_mode', 'http'), ('add-ip', '203.0.113.10')]:
            result = subprocess.run([sys.executable, str(entry), '--config', str(self.settings.path), *command], capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(result.returncode, 0, result.stderr)
        data = self.settings.load()
        self.assertEqual(data['ip_check_mode'], 'http')
        self.assertEqual(data['allowed_ips'], ['203.0.113.10'])

    def test_gui_constructs(self):
        if sys.platform.startswith('linux') and not os.environ.get('DISPLAY'):
            self.skipTest('display required; CI runs under Xvfb')
        try:
            import tkinter as tk
            from portable.gui import show
        except ImportError:
            self.skipTest('Tk not installed')
        self.settings.save(self.data)
        def preview(root):
            root.update_idletasks()
            root.destroy()
        with patch.object(tk.Tk, 'mainloop', preview):
            show(self.settings)


if __name__ == '__main__':
    unittest.main()
