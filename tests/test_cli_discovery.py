import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src import integrity


class CLIDiscoveryTests(unittest.TestCase):
    def test_native_version_files_recover_after_update(self):
        with tempfile.TemporaryDirectory() as directory:
            versions = Path(directory) / '.local/share/claude/versions'
            versions.mkdir(parents=True)
            for name in ['2.1.9', '2.1.310']:
                binary = versions / name
                binary.write_text('#!/bin/sh\nexit 0\n')
                binary.chmod(0o755)
            config = SimpleNamespace(config={'real_claude_cli_path': str(versions / 'deleted')})
            with patch.object(integrity, 'HOME', directory), patch.object(integrity, '_cask_binaries', return_value=[]), patch.object(integrity, '_path_binaries', return_value=[]):
                self.assertEqual(integrity.discover_real_cli(config), str((versions / '2.1.310').resolve()))
                (versions / '2.1.310').unlink()
                self.assertEqual(integrity.discover_real_cli(config), str((versions / '2.1.9').resolve()))

    def test_manual_wrapper_path_is_rejected_without_saving(self):
        from unittest.mock import Mock
        entry = Path(__file__).resolve().parents[1] / 'bin/claudeguard'
        config = Mock()
        with patch('src.config.ConfigManager', return_value=config), patch.object(sys, 'argv', ['claudeguard', 'set-cli-path', integrity.wrapper_path()]), self.assertRaises(SystemExit) as exited:
            runpy.run_path(str(entry), run_name='__main__')
        self.assertEqual(exited.exception.code, 1)
        config.save_config.assert_not_called()
