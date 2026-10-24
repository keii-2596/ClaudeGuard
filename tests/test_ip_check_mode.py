import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src import ip_checker, brain
from src.config import ConfigManager


class IPModeTests(unittest.TestCase):
    def response(self, data=b'{"ip":"203.0.113.10"}'):
        return io.BytesIO(data)

    def test_http_ignores_available_stun(self):
        with patch.object(ip_checker, 'stun_public_ip') as stun, patch.object(
                ip_checker.urllib.request, 'urlopen', return_value=self.response()):
            self.assertEqual(ip_checker.fetch_public_ip(mode='http'), ('203.0.113.10', None))
            stun.assert_not_called()

    def test_http_failure_never_falls_back_to_stun(self):
        with patch.object(ip_checker, 'stun_public_ip', return_value='203.0.113.10') as stun, patch.object(
                ip_checker.urllib.request, 'urlopen', side_effect=TimeoutError):
            self.assertIsNone(ip_checker.fetch_public_ip(mode='http')[0])
            stun.assert_not_called()

    def test_stun_never_queries_http(self):
        with patch.object(ip_checker, 'stun_public_ip', return_value='203.0.113.20'), patch.object(
                ip_checker.urllib.request, 'urlopen') as http:
            self.assertEqual(ip_checker.fetch_public_ip(mode='stun'), ('203.0.113.20', None))
            http.assert_not_called()

    def test_stun_failure_never_falls_back_to_http(self):
        with patch.object(ip_checker, 'stun_public_ip', return_value=None), patch.object(
                ip_checker.urllib.request, 'urlopen') as http:
            self.assertIsNone(ip_checker.fetch_public_ip(mode='stun')[0])
            http.assert_not_called()

    def test_auto_retains_stun_then_http_fallback(self):
        with patch.object(ip_checker, 'stun_public_ip', return_value=None), patch.object(
                ip_checker.urllib.request, 'urlopen', return_value=self.response()):
            self.assertEqual(ip_checker.fetch_public_ip()[0], '203.0.113.10')

    def test_invalid_mode_queries_nothing(self):
        with patch.object(ip_checker, 'stun_public_ip') as stun, patch.object(
                ip_checker.urllib.request, 'urlopen') as http:
            self.assertIsNone(ip_checker.fetch_public_ip(mode='htpp')[0])
            stun.assert_not_called()
            http.assert_not_called()

    def test_selected_ip_decides_whitelist(self):
        with patch.object(ip_checker.urllib.request, 'urlopen', side_effect=lambda *a, **k: self.response()):
            self.assertTrue(ip_checker.perform_ip_check(['203.0.113.10'], mode='http')[1])
            self.assertFalse(ip_checker.perform_ip_check(['203.0.113.20'], mode='http')[1])

    def test_config_persists_and_defaults_for_old_files(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'config.json'
            path.write_text('{"allowed_ips": []}')
            config = ConfigManager(str(path))
            self.assertEqual(config.ip_check_mode, 'auto')
            config.ip_check_mode = 'http'
            self.assertEqual(ConfigManager(str(path)).ip_check_mode, 'http')
            with self.assertRaises(ValueError):
                config.ip_check_mode = 'typo'
            self.assertEqual(json.loads(path.read_text())['ip_check_mode'], 'http')

    def test_old_mode_or_whitelist_cache_is_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            config = ConfigManager(str(Path(d) / 'config.json'))
            config.ip_check_mode = 'http'
            config.allowed_ips = ['203.0.113.10']
            for mode, ips in [('auto', config.allowed_ips), ('http', ['203.0.113.20'])]:
                state = dict(protection_enabled=True, state='allowed', ip='203.0.113.20', ip_check_mode=mode, allowed_ips=ips)
                with patch.object(brain, 'read_daemon_state', return_value=state), patch.object(
                        brain, 'perform_ip_check', return_value=(None, False, 'timeout')) as probe:
                    self.assertEqual(brain.get_verdict(config)[0], 'offline')
                    probe.assert_called_once_with(config.allowed_ips, timeout=2.0, mode='http')

    def test_matching_cache_is_used_without_network(self):
        with tempfile.TemporaryDirectory() as d:
            config = ConfigManager(str(Path(d) / 'config.json'))
            config.ip_check_mode = 'http'
            state = dict(protection_enabled=True, state='blocked', ip='203.0.113.20', ip_check_mode='http', allowed_ips=config.allowed_ips)
            with patch.object(brain, 'read_daemon_state', return_value=state), patch.object(brain, 'perform_ip_check') as probe:
                self.assertEqual(brain.get_verdict(config)[0], 'blocked')
                probe.assert_not_called()


if __name__ == '__main__':
    unittest.main()
