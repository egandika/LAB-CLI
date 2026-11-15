"""Synthetic tests for bounded, non-extracting APK ZIP limit diagnostics."""
import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from apklab.cli import main
from apklab.core import zip_infos


class ZipLimitDiagnosticsTests(unittest.TestCase):
    def test_limits_report_declared_values_and_preserve_boundaries(self):
        def archive(*sizes):
            return SimpleNamespace(infolist=lambda: [SimpleNamespace(file_size=n) for n in sizes])
        self.assertEqual(len(zip_infos(archive(4, 6), 6, 10)), 2)
        with self.assertRaisesRegex(ValueError, 'largest declared entry 7 bytes exceeds limit 6 bytes'):
            zip_infos(archive(4, 7), 6, 20)
        with self.assertRaisesRegex(ValueError, 'declared total 11 bytes exceeds limit 10 bytes'):
            zip_infos(archive(4, 7), 20, 10)
        with self.assertRaisesRegex(ValueError, 'entry count 100001 exceeds limit 100000'):
            zip_infos(archive(*([0] * 100001)), 1, 1)
        with self.assertRaisesRegex(ValueError, 'limits must be positive'):
            zip_infos(archive(), 0, 1)

    def test_cli_reports_limit_without_running_tools_or_changing_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / 'input.apk'
            with zipfile.ZipFile(apk, 'w', compression=zipfile.ZIP_DEFLATED) as z:
                z.writestr('AndroidManifest.xml', b'fixture')
                z.writestr('assets/big', b'x' * (1024 * 1024 + 1))
            before = apk.read_bytes()
            for command in ('inspect', 'inventory', 'dex'):
                with self.subTest(command=command), patch('apklab.core.find_tool') as find, patch('apklab.core.check_zip_crc') as crc:
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        code = main([command, str(apk), '--max-entry-mib', '1'])
                    report = json.loads(output.getvalue())
                    self.assertEqual(code, 1)
                    self.assertIn('largest declared entry 1048577 bytes exceeds limit 1048576 bytes', report['failures'][0]['detail'])
                    find.assert_not_called(); crc.assert_not_called()
                self.assertEqual(apk.read_bytes(), before)
            output = io.StringIO()
            with patch('apklab.core.find_tool', return_value=None), contextlib.redirect_stdout(output):
                code = main(['inspect', str(apk), '--max-entry-mib', '2'])
            self.assertEqual(code, 3)
            self.assertFalse(json.loads(output.getvalue())['failures'])
            self.assertEqual(apk.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
