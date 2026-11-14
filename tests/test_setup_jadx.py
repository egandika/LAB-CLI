import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from apklab.cli import main

class SetupJadxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.apk = self.root / 'input.apk'; self.apk.write_bytes(b'fixture')
    def call(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out): code = main(list(args))
        return code, json.loads(out.getvalue())
    def test_plan_and_doctor_next_steps(self):
        with patch('apklab.cli.find_tool', return_value=None):
            code, result = self.call('setup', '--plan')
            self.assertEqual(code, 3)
            self.assertIn('termux_android', result['plan']['platforms'])
            self.assertIn('macos', result['plan']['platforms'])
            self.assertIn('SHA-256', result['plan']['checksum'])
            self.assertEqual(set(result['plan']['sources']) & {'jadx', 'apktool', 'build-tools'}, {'jadx', 'apktool', 'build-tools'})
            _, doctor = self.call('doctor')
            for name in doctor['tools']:
                self.assertTrue(any(x['subject'] == name and 'apklab setup --plan' in x['detail'] for x in doctor['not_tested']))
    def test_jadx_copy_new_output_and_size_limit(self):
        def fake_run(args, timeout, monitor):
            self.assertEqual(Path(args[-1]).read_bytes(), b'fixture')
            self.assertNotEqual(Path(args[-1]).resolve(), self.apk.resolve())
            Path(args[args.index('-d')+1], 'file.java').write_text('hello', encoding='utf-8')
            monitor()
            return {'returncode': 0, 'stdout': '', 'stderr': ''}
        with patch('apklab.jadx.find_tool', return_value='/fake/jadx'), patch('apklab.jadx.run', side_effect=fake_run):
            code, result = self.call('jadx', str(self.apk), str(self.root/'out'))
            self.assertEqual(code, 3, result); self.assertEqual(result['output_bytes'], 5)
            code, _ = self.call('jadx', str(self.apk), str(self.root/'out'))
            self.assertEqual(code, 1); self.assertEqual(self.apk.read_bytes(), b'fixture')
    def test_jadx_size_and_timeout_cleanup(self):
        def fake_run(args, timeout, monitor):
            Path(args[args.index('-d')+1], 'file').write_bytes(b'x' * (1024 * 1024 + 1))
            monitor()
            return {'returncode': None, 'stdout': '', 'stderr': 'JADX timed out'}
        for mode in ('size', 'timeout'):
            with self.subTest(mode=mode), patch('apklab.jadx.find_tool', return_value='/fake/jadx'), patch('apklab.jadx.run', side_effect=fake_run):
                args = ['jadx', str(self.apk), str(self.root/'out'), '--timeout', '1', '--max-output-mib', '1' if mode == 'size' else '2']
                code, result = self.call(*args)
                self.assertEqual(code, 1); self.assertFalse((self.root/'out').exists())
                self.assertIn('size limit' if mode == 'size' else 'timed out', result['failures'][0]['detail'])
    def test_jadx_failed_process_cleanup(self):
        def fake_run(args, timeout, monitor):
            Path(args[args.index('-d')+1], 'file').write_text('x')
            monitor()
            return {'returncode': 1, 'stdout': '', 'stderr': 'failure'}
        with patch('apklab.jadx.find_tool', return_value='/fake/jadx'), patch('apklab.jadx.run', side_effect=fake_run):
            code, result = self.call('jadx', str(self.apk), str(self.root/'out'))
        self.assertEqual(code, 1); self.assertFalse((self.root/'out').exists()); self.assertTrue(result['failures'])
        self.assertIn('failure', result['failures'][0]['detail'])
