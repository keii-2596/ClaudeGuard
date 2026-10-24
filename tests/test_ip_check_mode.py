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

    def test_http_explicit_proxy_is_used_without_global_mutation(self):
        opener = unittest.mock.MagicMock()
        opener.open.return_value = self.response()
        with patch.object(ip_checker.urllib.request, 'build_opener', return_value=opener) as build, patch.object(
                ip_checker.urllib.request, 'urlopen') as global_open:
            self.assertEqual(ip_checker.fetch_public_ip(mode='http', proxy='http://127.0.0.1:7897')[0], '203.0.113.10')
            self.assertEqual(build.call_args.args[0].proxies['https'], 'http://127.0.0.1:7897')
            global_open.assert_not_called()

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

    def test_both_requires_each_exit_to_be_whitelisted(self):
        for http, stun, expected in [
            ('203.0.113.10', '203.0.113.10', True),
            ('203.0.113.10', '203.0.113.20', False),
            ('203.0.113.20', '203.0.113.10', False),
            ('203.0.113.20', '203.0.113.20', False),
            ('203.0.113.10', None, False),
            (None, '203.0.113.10', False),
            (None, None, False),
        ]:
            with self.subTest(http=http, stun=stun), patch.object(
                    ip_checker, 'fetch_public_ip', side_effect=lambda timeout, mode: (
                        {'http': http, 'stun': stun}[mode], None)):
                result = ip_checker.perform_ip_check(['203.0.113.10'], mode='both')
                self.assertEqual(result[1], expected)
                if http is None or stun is None:
                    self.assertIsNone(result[0])

    def test_confirmed_unlisted_exit_blocks_despite_other_timeout(self):
        with patch.object(ip_checker, 'fetch_public_ip', side_effect=lambda timeout, mode: (
                '203.0.113.20' if mode == 'stun' else None, None)):
            ip, allowed, _ = ip_checker.perform_ip_check(['203.0.113.10'])
            self.assertIsNotNone(ip)
            self.assertFalse(allowed)

    def test_distinct_whitelisted_exits_pass(self):
        with patch.object(ip_checker, 'fetch_public_ip', side_effect=lambda timeout, mode: (
                '203.0.113.10' if mode == 'http' else '203.0.113.20', None)):
            self.assertTrue(ip_checker.perform_ip_check(['203.0.113.0/24'])[1])

    def test_completion_order_does_not_change_result(self):
        import time
        for slow in ('http', 'stun'):
            def lookup(timeout, mode):
                if mode == slow:
                    time.sleep(0.02)
                return ('203.0.113.10' if mode == 'http' else '203.0.113.20'), None
            with patch.object(ip_checker, 'fetch_public_ip', side_effect=lookup):
                result = ip_checker.perform_ip_check(['203.0.113.10'])
                self.assertFalse(result[1])
                self.assertIn('HTTP: 203.0.113.10', result[0])
                self.assertIn('STUN: 203.0.113.20', result[0])

    def test_legacy_auto_migrates_to_both(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'config.json'
            path.write_text('{"allowed_ips": [], "ip_check_mode": "auto"}')
            self.assertEqual(ConfigManager(str(path)).ip_check_mode, 'both')
        with patch.object(ip_checker, 'fetch_public_ip', side_effect=lambda timeout, mode: (
                '203.0.113.10' if mode == 'http' else '203.0.113.20', None)):
            self.assertFalse(ip_checker.perform_ip_check(['203.0.113.10'], mode='auto')[1])

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
            self.assertEqual(config.ip_check_mode, 'both')
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
