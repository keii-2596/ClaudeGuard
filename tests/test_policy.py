import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
import sys
from unittest.mock import patch, Mock
from concurrent.futures import ThreadPoolExecutor

from src import policy

A, B = '203.0.113.10', '203.0.113.20'


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.data = {**policy.DEFAULTS, 'protection_enabled': True,
                     'allowed_ips': [A, B], 'ip_check_mode': 'http'}

    def evaluate(self, ips=None, **kwargs):
        return policy.evaluate(self.data, ips if ips is not None else {'http': A}, self.directory, **kwargs)

    def test_whitelist_does_not_query_scores(self):
        lookup = Mock(side_effect=AssertionError('unexpected score lookup'))
        self.assertEqual(self.evaluate(score_lookup=lookup)['state'], 'allowed')
        self.data['allowed_ips'] = [B]
        self.assertEqual(self.evaluate(score_lookup=lookup)['state'], 'blocked')
        lookup.assert_not_called()

    def test_risk_mode_does_not_require_whitelist(self):
        self.data.update(access_mode='risk', allowed_ips=[])
        self.assertEqual(self.evaluate(score_lookup=lambda ip: 10)['state'], 'allowed')

    def test_threshold_is_strictly_greater(self):
        self.data.update(access_mode='risk', risk_threshold=50)
        self.assertEqual(self.evaluate(score_lookup=lambda ip: 50)['state'], 'allowed')
        self.data['risk_threshold'] = 49
        result = self.evaluate(score_lookup=lambda ip: 0)
        self.assertEqual(result['state'], 'blocked')
        self.assertEqual(result['scores'][A]['score'], 50)  # cache stores score, not verdict

    def test_cache_expiry_and_future_timestamps(self):
        self.data.update(access_mode='risk', risk_cache_ttl=10)
        lookup = Mock(return_value=10)
        self.evaluate(now=100, score_lookup=lookup)
        self.assertTrue(self.evaluate(now=109, score_lookup=lookup)['scores'][A]['cached'])
        self.assertEqual(lookup.call_count, 1)
        self.assertFalse(self.evaluate(now=110, score_lookup=lookup)['scores'][A]['cached'])
        self.assertEqual(lookup.call_count, 2)
        self.evaluate(now=90, score_lookup=lookup)
        self.assertEqual(lookup.call_count, 3)

    def test_expired_score_cannot_allow_when_provider_fails(self):
        self.data.update(access_mode='risk', risk_cache_ttl=10)
        self.evaluate(now=100, score_lookup=lambda ip: 0)
        failed = Mock(side_effect=TimeoutError)
        self.assertEqual(self.evaluate(now=110, score_lookup=failed)['state'], 'blocked')
        self.assertEqual(self.evaluate(now=111, score_lookup=failed)['state'], 'blocked')
        self.assertEqual(failed.call_count, 1)  # short negative cache, never a pass
        self.assertEqual(self.evaluate(now=126, score_lookup=lambda ip: 0)['state'], 'allowed')

    def test_invalid_scores_never_allow(self):
        self.data['access_mode'] = 'risk'
        for index, score in enumerate([None, True, -1, 101, float('nan'), float('inf'), '0']):
            with self.subTest(score=score):
                self.assertEqual(self.evaluate(now=index*20, score_lookup=lambda ip: score)['state'], 'blocked')

    def test_both_checks_every_unique_ip(self):
        self.data.update(access_mode='risk', ip_check_mode='both')
        lookup = Mock(side_effect=lambda ip: 10 if ip == A else 80)
        result = self.evaluate({'http': A, 'stun': B}, score_lookup=lookup)
        self.assertEqual(result['state'], 'blocked')
        self.assertEqual(lookup.call_count, 2)
        self.assertEqual(set(result['scores']), {A, B})

    def test_same_ip_across_transports_queries_once(self):
        self.data.update(access_mode='risk', ip_check_mode='both')
        lookup = Mock(return_value=10)
        self.assertEqual(self.evaluate({'http': A, 'stun': A}, score_lookup=lookup)['state'], 'allowed')
        lookup.assert_called_once_with(A)

    def test_missing_transport_never_seeds_baseline(self):
        self.data.update(detect_ip_change=True, ip_check_mode='both')
        self.assertEqual(self.evaluate({'http': A})['state'], 'blocked')
        self.assertEqual(self.evaluate({'http': B, 'stun': A})['state'], 'allowed')

    def test_whitelisted_jump_latches_and_survives_return_and_restart(self):
        self.data['detect_ip_change'] = True
        self.assertEqual(self.evaluate()['state'], 'allowed')
        self.assertEqual(self.evaluate({'http': B})['state'], 'blocked')
        result = policy.evaluate(self.data, {'http': A}, self.directory)
        self.assertEqual(result['state'], 'blocked')
        self.assertIn('跳变', result['reason'])

    def test_ack_requires_reviewed_ip_and_access_rule(self):
        self.data['detect_ip_change'] = True
        self.evaluate()
        self.evaluate({'http': B})
        self.assertEqual(self.evaluate({'http': B}, acknowledge=True, expected_ips={'http': A})['state'], 'blocked')
        self.data['allowed_ips'] = [A]
        self.assertEqual(self.evaluate({'http': B}, acknowledge=True, expected_ips={'http': B})['state'], 'blocked')
        self.data['allowed_ips'] = [A, B]
        self.assertEqual(self.evaluate({'http': B}, acknowledge=True, expected_ips={'http': B})['state'], 'allowed')
        self.assertEqual(self.evaluate({'http': B})['state'], 'allowed')
        self.assertEqual(self.evaluate({'http': A})['state'], 'blocked')

    def test_score_failure_does_not_seed_jump_baseline(self):
        self.data.update(access_mode='risk', detect_ip_change=True)
        self.assertEqual(self.evaluate(score_lookup=lambda ip: 90)['state'], 'blocked')
        self.assertEqual(self.evaluate({'http': B}, score_lookup=lambda ip: 0)['state'], 'allowed')

    def test_http_and_stun_have_separate_baselines(self):
        self.data.update(detect_ip_change=True, ip_check_mode='both')
        self.assertEqual(self.evaluate({'http': A, 'stun': B})['state'], 'allowed')
        self.assertEqual(self.evaluate({'stun': B, 'http': A})['state'], 'allowed')
        self.assertEqual(self.evaluate({'http': B, 'stun': A})['state'], 'blocked')

    def test_corrupt_persistent_state_blocks(self):
        (self.directory/'admission-state.json').write_text('{broken')
        self.assertEqual(self.evaluate()['state'], 'blocked')

    def test_concurrent_evaluations_share_one_score_lookup(self):
        import time
        self.data['access_mode'] = 'risk'
        def query(ip):
            time.sleep(0.03)
            return 10
        lookup = Mock(side_effect=query)
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.evaluate(score_lookup=lookup), range(4)))
        self.assertTrue(all(x['state'] == 'allowed' for x in results))
        lookup.assert_called_once_with(A)

    def test_key_change_uses_separate_cache(self):
        self.data['access_mode'] = 'risk'
        lookup = Mock(return_value=10)
        with patch.dict('os.environ', {'CLAUDEGUARD_PROXYCHECK_API_KEY': 'first'}):
            self.evaluate(score_lookup=lookup)
        with patch.dict('os.environ', {'CLAUDEGUARD_PROXYCHECK_API_KEY': 'second'}):
            self.evaluate(score_lookup=lookup)
        self.assertEqual(lookup.call_count, 2)
        content = (self.directory/'admission-state.json').read_text()
        self.assertNotIn('first', content)
        self.assertNotIn('second', content)

    def test_settings_validation_and_disabled_guard(self):
        for key, value in [('risk_threshold', 101), ('risk_threshold', True), ('risk_cache_ttl', 0), ('detect_ip_change', 'false'), ('access_mode', 'typo')]:
            with self.subTest(key=key):
                data = {**self.data, key: value}
                self.assertEqual(policy.evaluate(data, {'http': A}, self.directory)['state'], 'blocked')
        self.data['protection_enabled'] = False
        self.assertEqual(self.evaluate()['state'], 'disabled')

    def test_provider_response_validation(self):
        for score, expected in [(0, 0), ('50', 50), (True, None), (-1, None), (None, None)]:
            payload = {'status': 'ok', A: {'risk': score}}
            with self.subTest(score=score), patch('urllib.request.urlopen', return_value=io.BytesIO(json.dumps(payload).encode())):
                if expected is None:
                    with self.assertRaises(RuntimeError):
                        policy.fetch_score(A)
                else:
                    self.assertEqual(policy.fetch_score(A), expected)

    def test_provider_error_message_cannot_leak_key(self):
        with patch.dict('os.environ', {'CLAUDEGUARD_PROXYCHECK_API_KEY': 'private-value'}), patch('urllib.request.urlopen', side_effect=RuntimeError('private-value')):
            with self.assertRaises(RuntimeError) as error:
                policy.fetch_score(A)
            self.assertNotIn('private-value', str(error.exception))

    def test_advanced_policy_cannot_reuse_old_daemon_allow(self):
        from src.config import ConfigManager
        from src import brain
        config = ConfigManager(str(self.directory / 'config.json'))
        config.config.update(access_mode='risk', allowed_ips=[])
        with patch.object(brain, 'read_daemon_state', return_value={'state': 'allowed'}), patch.object(
                policy, 'check', return_value={'state': 'blocked', 'ip': A, 'error': 'high score'}) as check:
            self.assertEqual(brain.get_verdict(config)[0], 'blocked')
            check.assert_called_once()

    def test_whitelist_mode_cannot_reuse_risk_mode_daemon_allow(self):
        from src.config import ConfigManager
        from src import brain
        config = ConfigManager(str(self.directory / 'config.json'))
        config.allowed_ips = [B]
        state = {'state': 'allowed', 'access_mode': 'risk', 'ip': A,
                 'protection_enabled': True, 'ip_check_mode': config.ip_check_mode, 'allowed_ips': [B]}
        with patch.object(brain, 'read_daemon_state', return_value=state), patch.object(
                brain, 'perform_ip_check', return_value=(A, False, None)):
            self.assertEqual(brain.get_verdict(config)[0], 'blocked')

    @unittest.skipUnless(sys.platform == "darwin", "macOS-specific CLI wrapper")
    def test_risk_mode_empty_whitelist_can_launch_cli(self):
        from src import cli_wrapper
        from src.config import ConfigManager
        config = ConfigManager(str(self.directory / 'config.json'))
        config.config.update(access_mode='risk', allowed_ips=[])
        with patch.object(cli_wrapper, 'ConfigManager', return_value=config), patch.object(
                cli_wrapper, 'get_verdict', return_value=('allowed', A, None)), patch.object(
                cli_wrapper, 'repair_cli'), patch.object(cli_wrapper, 'sync_hosts_file'), patch.object(
                cli_wrapper, 'run_real_claude') as launch, patch.object(cli_wrapper.signal, 'signal'):
            cli_wrapper.main()
            launch.assert_called_once_with(config)

    def test_mac_json_bridge(self):
        import subprocess, sys
        entry = Path(__file__).resolve().parents[1]/'src/policy_cli.py'
        result = subprocess.run([sys.executable, str(entry), '--config', str(self.directory/'config.json'), 'evaluate'],
                                input=json.dumps({'data': self.data, 'ips': {'http': A}}), capture_output=True, text=True, encoding='utf-8')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['state'], 'allowed')


if __name__ == '__main__':
    unittest.main()
