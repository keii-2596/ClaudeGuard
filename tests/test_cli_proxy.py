import json
import os
import subprocess
import sys
import unittest
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from src.proxy_config import cli_environment


class CLIProxyTests(unittest.TestCase):
    def test_disabled_preserves_inherited_environment(self):
        env = {'https_proxy': 'http://old:1', 'NO_PROXY': '*'}
        self.assertEqual(cli_environment({}, env), env)

    def test_enabled_overrides_and_reaches_child_process(self):
        inherited = {**os.environ, 'HTTPS_PROXY': 'http://wrong:1', 'https_proxy': 'http://wrong:2', 'NO_PROXY': '*', 'no_proxy': '*'}
        data = {'cli_http_proxy_enabled': True, 'http_proxy': 'http://127.0.0.1:7897'}
        env = cli_environment(data, inherited)
        result = subprocess.check_output([sys.executable, '-c', 'import os,json; print(json.dumps({k:os.environ.get(k) for k in ["HTTP_PROXY","HTTPS_PROXY","http_proxy","https_proxy","ALL_PROXY","all_proxy","NO_PROXY","no_proxy"]}))'], env=env, text=True)
        actual = json.loads(result)
        for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 'ALL_PROXY', 'all_proxy'):
            self.assertEqual(actual[key], data['http_proxy'])
        self.assertEqual(actual['NO_PROXY'], '')
        self.assertEqual(actual['no_proxy'], '')
        self.assertEqual(inherited['NO_PROXY'], '*')

    def test_mac_wrapper_passes_proxy_to_actual_child(self):
        from src.cli_wrapper import run_real_claude
        data = {'cli_http_proxy_enabled': True, 'http_proxy': 'http://127.0.0.1:7897'}
        config = SimpleNamespace(config=data, real_claude_cli=sys.executable,
                                 block_auto_updates=False, model_override_enabled=False,
                                 protection_enabled=False)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'environment.json'
            code = 'import os,json,sys; open(sys.argv[1], "w").write(json.dumps({k:os.environ.get(k) for k in ["https_proxy","HTTPS_PROXY","NO_PROXY"]}))'
            with patch('src.cli_wrapper.is_our_wrapper', return_value=False), patch('src.cli_wrapper.force_restore_terminal'), patch.object(sys, 'argv', ['claude', '-c', code, str(output)]), self.assertRaises(SystemExit) as exited:
                run_real_claude(config)
            self.assertEqual(exited.exception.code, 0)
            actual = json.loads(output.read_text())
            self.assertEqual(actual['https_proxy'], data['http_proxy'])
            self.assertEqual(actual['HTTPS_PROXY'], data['http_proxy'])
            self.assertEqual(actual['NO_PROXY'], '')

    def test_enabled_rejects_missing_or_invalid_proxy(self):
        for value in ('', 'socks5://localhost:7897', 'https://localhost:7897', 'http://localhost', 'http://localhost:99999', 'http://user:secret@localhost:7897', 'http://localhost:7897/path'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                cli_environment({'cli_http_proxy_enabled': True, 'http_proxy': value}, {})
