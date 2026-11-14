import contextlib
import io
import re
import unittest
from pathlib import Path

import apklab
from apklab.cli import main


class VersionConsistencyTests(unittest.TestCase):
    def test_package_metadata_cli_and_changelog_match(self):
        root = Path(__file__).resolve().parents[1]
        config = (root/'pyproject.toml').read_text(encoding='utf-8')
        package_version = re.search(r'^version\s*=\s*"([^"]+)"', config, re.MULTILINE)
        self.assertIsNotNone(package_version)
        self.assertEqual(package_version.group(1), apklab.__version__)
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as status:
            main(['--version'])
        self.assertEqual(status.exception.code, 0)
        self.assertEqual(output.getvalue().strip(), 'apklab ' + apklab.__version__)
        changelog = (root/'CHANGELOG.md').read_text(encoding='utf-8')
        self.assertIn('## ' + apklab.__version__ + ' (unreleased)', changelog)
        self.assertIn('do not prove APK installability', changelog)
