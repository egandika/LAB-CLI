"""Regression cases for duplicate ZIP identities, resource limits and cleanup."""
import contextlib
import io
import json
import struct
import sys
import tempfile
import time
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch

from apklab.cli import main
from apklab.core import check_zip_crc, run
from apklab.dex import read_dex
from test_t04_dex_limits import dex_with_shared_parameters


class AdversarialRegressionTests(unittest.TestCase):
    def test_crc_finds_corruption_in_last_of_three_duplicate_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'duplicates.zip'
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_STORED) as z:
                    for data in (b'first', b'second', b'unique-third'):
                        z.writestr('same', data)
            path.write_bytes(path.read_bytes().replace(b'unique-third', b'Unique-third', 1))
            with zipfile.ZipFile(path) as z:
                self.assertEqual(check_zip_crc(z, z.infolist()), 'same')

    def test_duplicate_dex_failure_does_not_hide_valid_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'sample.apk'
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                with zipfile.ZipFile(path, 'w') as z:
                    z.writestr('AndroidManifest.xml', 'test')
                    z.writestr('classes.dex', b'bad')
                    z.writestr('classes.dex', b'good')
            def parse(data):
                if data == b'bad': raise ValueError('corrupt first')
                return {'classes': [], 'methods': [], 'strings': [], 'endpoints': []}
            out = io.StringIO()
            with patch('apklab.cli.read_dex', side_effect=parse), patch('apklab.cli.find_tool', return_value=None), contextlib.redirect_stdout(out):
                code = main(['dex', str(path)])
            report = json.loads(out.getvalue())
            self.assertEqual(code, 1)
            self.assertIn('corrupt first', report['failures'][0]['detail'])
            self.assertEqual([entry['zip_entry_index'] for entry in report['dex_files']], [2])

    def test_timeout_preserves_capped_output_without_deadlock(self):
        script = "import sys,time; sys.stdout.buffer.write(b'x'*250000); sys.stdout.flush(); sys.stderr.buffer.write(b'y'*25000); sys.stderr.flush(); time.sleep(10)"
        result = run([sys.executable, '-c', script], timeout=2)
        self.assertIsNone(result['returncode'])
        self.assertEqual(len(result['stdout']), 200000)
        self.assertTrue(result['stdout_truncated'])
        self.assertTrue(result['stderr_truncated'])
        self.assertIn('timed out', result['stderr'])
        self.assertFalse(result['capture_incomplete'])

    def test_invalid_shared_parameter_offset_rejected(self):
        sample = bytearray(dex_with_shared_parameters(2, 2))
        struct.pack_into('<I', sample, 120 + 12 + 8, len(sample) - 2)
        with self.assertRaisesRegex(ValueError, 'parameter offset'):
            read_dex(sample)

    def test_monitor_error_terminates_descendant_too(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            started, survived = root / 'started', root / 'survived'
            child = "import time,pathlib; pathlib.Path(%r).write_text('started'); time.sleep(1.5); pathlib.Path(%r).write_text('alive')" % (str(started), str(survived))
            parent = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',%r]); time.sleep(10)" % child
            def monitor():
                if started.exists(): raise ValueError('abort descendant')
            with self.assertRaisesRegex(ValueError, 'abort descendant'):
                run([sys.executable, '-c', parent], timeout=5, monitor=monitor)
            time.sleep(1.8)
            self.assertFalse(survived.exists())

class IntegrationContractTests(unittest.TestCase):
    def test_integration_helper_rejects_unexpected_success_or_not_tested(self):
        from test_integration import AndroidToolIntegration
        test = AndroidToolIntegration('test_round_trip')
        def result_code(code):
            def fake(_args):
                print('{"verified": [], "failures": [], "not_tested": []}')
                return code
            return fake
        for actual, expected in ((0, 3), (3, 0)):
            with self.subTest(actual=actual, expected=expected), patch('test_integration.main', side_effect=result_code(actual)):
                with self.assertRaises(AssertionError):
                    test.cli('fake', expected=expected)

    def test_split_identity_rejects_missing_name_or_signer(self):
        from test_integration import AndroidToolIntegration
        test = AndroidToolIntegration('test_round_trip')
        base = {'package': 'org.example.apklab.splitfixture', 'version_code': '1', 'signer_sha256': ['a' * 64]}
        split = dict(base, split='config.en')
        test.assert_split_identity({'apks': [base, split]})
        for change in ({'split': None}, {'signer_sha256': []}, {'package': 'other'}, {'version_code': '2'}):
            with self.subTest(change=change), self.assertRaises(AssertionError):
                test.assert_split_identity({'apks': [base, dict(split, **change)]})


if __name__ == '__main__':
    unittest.main()
