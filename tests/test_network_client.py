import copy
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from portable.config import Settings, DEFAULTS, atomic_json
from portable import network


class NetworkClientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.settings = Settings(self.root / 'config.json')
        self.data = {**copy.deepcopy(DEFAULTS), 'network_guard_enabled': True, 'cli_path': str(self.root / 'claude')}
        self.helper = self.root / 'helper'
        self.helper.mkdir()
        self.patch = patch('portable.network.directory', return_value=self.helper)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def state(self, **values):
        atomic_json(self.helper / 'status.json', {'ready': True, 'updated_at': time.time(), 'configured_paths': network.paths(self.data), **values})

    def test_missing_or_stale_helper_never_authorizes_launch(self):
        self.assertFalse(network.status(self.settings, self.data)['ready'])
        self.state(updated_at=time.time() - 10)
        self.assertFalse(network.status(self.settings, self.data)['ready'])
        with self.assertRaises(RuntimeError):
            network.wait_allowed(self.settings, self.data, timeout=0.05)

    def test_changed_program_paths_require_reinstallation(self):
        self.state(configured_paths=['other'], applied_state='allowed')
        self.assertFalse(network.status(self.settings, self.data)['ready'])

    def test_publish_bound_lease_and_denials(self):
        self.state(applied_state='blocked')
        network.publish(self.settings, self.data, {'state': 'allowed'})
        request = json.loads(self.settings.path.with_name('network-request.json').read_text())
        self.assertTrue(request['allowed'])
        self.assertLessEqual(request['expires_at'], time.time() + 90)
        self.assertEqual(request['configured_paths'], network.paths(self.data))
        network.publish(self.settings, self.data, {'state': 'offline'})
        self.assertFalse(json.loads(self.settings.path.with_name('network-request.json').read_text())['allowed'])

    def test_kernel_error_is_preserved_and_fails_closed(self):
        self.state(ready=False, error='kernel not supported')
        self.assertEqual(network.status(self.settings, self.data)['error'], 'kernel not supported')
        with self.assertRaises(RuntimeError):
            network.publish(self.settings, self.data, {'state': 'allowed'})

    def test_disabled_without_installed_helper_does_not_mutate_system(self):
        self.data['network_guard_enabled'] = False
        self.assertIsNone(network.publish(self.settings, self.data, {'state': 'allowed'}))
        self.assertFalse(self.settings.path.with_name('network-request.json').exists())

    def test_invalid_network_option_is_rejected(self):
        self.data['network_guard_enabled'] = 'true'
        with self.assertRaises(ValueError):
            self.settings.save(self.data)
