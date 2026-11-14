import contextlib
import io
import json
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch

from apklab.cli import main


class SharedApkValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.apk = self.root/'fixture.apk'

    def call(self, command, path):
        out = io.StringIO()
        with patch('apklab.core.find_tool', return_value=None), patch('apklab.cli.find_tool', return_value=None), contextlib.redirect_stdout(out):
            code = main([command, str(path)])
        return code, json.loads(out.getvalue())

    def assert_all_fail(self, detail):
        for command in ('inspect', 'dex', 'inventory'):
            with self.subTest(command=command):
                code, result = self.call(command, self.apk)
                self.assertEqual(code, 1, result)
                self.assertTrue(any(detail in x['detail'] for x in result['failures']), result)

    def test_manifest_missing_or_duplicate_is_rejected_by_all(self):
        for manifests in ([], ['one', 'two']):
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                with zipfile.ZipFile(self.apk, 'w') as z:
                    z.writestr('assets/file', 'test')
                    for manifest in manifests: z.writestr('AndroidManifest.xml', manifest)
            self.assert_all_fail('exactly one AndroidManifest.xml')

    def test_corrupt_unrelated_entry_rejected_by_all(self):
        with zipfile.ZipFile(self.apk, 'w', compression=zipfile.ZIP_STORED) as z:
            z.writestr('AndroidManifest.xml', 'fixture')
            z.writestr('assets/data', 'unique-crc-value')
        self.apk.write_bytes(self.apk.read_bytes().replace(b'unique-crc-value', b'Unique-crc-value', 1))
        self.assert_all_fail('CRC')

    def test_xapk_is_rejected_even_if_it_contains_a_manifest(self):
        self.apk = self.root/'fixture.xapk'
        with zipfile.ZipFile(self.apk, 'w') as z: z.writestr('AndroidManifest.xml', 'fixture')
        self.assert_all_fail('XAPK is an archive, not an APK')

    def test_valid_basic_apk_does_not_imply_signature_or_manifest_validation(self):
        with zipfile.ZipFile(self.apk, 'w') as z: z.writestr('AndroidManifest.xml', 'fixture')
        code, result = self.call('inventory', self.apk)
        self.assertEqual(code, 3, result)
        self.assertFalse(result['failures'])
        self.assertFalse(any('signature' in x['detail'].lower() for x in result['verified']))
