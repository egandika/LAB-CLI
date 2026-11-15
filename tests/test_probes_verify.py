import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from apklab.cli import main


class ProbeAndVerifyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.apk = self.root / 'input.apk'
        with zipfile.ZipFile(self.apk, 'w') as z: z.writestr('AndroidManifest.xml', 'test')
        self.workspace = self.root / 'work'
        self.call('work', 'init', str(self.apk), str(self.workspace))
        (self.workspace / 'signed.apk').write_bytes(self.apk.read_bytes())

    def call(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out): code = main(list(args))
        return code, json.loads(out.getvalue())

    def test_doctor_check_reports_probes_and_untested_tools(self):
        def find(name): return '/fake/' + name if name in ('java', 'zipalign', 'aapt') else None
        def run(args, timeout):
            return {'returncode': 1 if args[0].endswith('aapt') else 0, 'stdout': 'version', 'stderr': ''}
        with patch('apklab.cli.find_tool', side_effect=find), patch('apklab.cli.run', side_effect=run):
            code, r = self.call('doctor', '--check')
        self.assertEqual(code, 3)
        self.assertEqual(r['probes']['java']['returncode'], 0)
        self.assertEqual(r['probes']['aapt']['returncode'], 1)
        self.assertTrue(any(x['subject'] == 'zipalign' and 'No safe' in x['detail'] for x in r['not_tested']))
        self.assertTrue(any(x['subject'] == 'aapt' for x in r['not_tested']))
        self.assertTrue(any(x['subject'] == 'tool functionality' for x in r['not_tested']))

    def test_setup_reports_partial_update_failure(self):
        def fake_run(args, timeout=120):
            if args[-1] == 'update':
                self.assertIn('APT::Update::Error-Mode=any', args)
                return {'returncode': 100, 'stdout': '', 'stderr': 'repository unreachable'}
            return {'returncode': 100, 'stdout': '', 'stderr': 'package unavailable'}
        with patch('apklab.cli.find_executable', return_value='/fake/apt'), patch('apklab.cli.find_tool', return_value=None), patch('apklab.cli.os.geteuid', return_value=0, create=True), patch('apklab.cli.run', side_effect=fake_run):
            code, r = self.call('setup', '--install')
        self.assertEqual(code, 1)
        self.assertTrue(any(x['subject'] == 'apt update' for x in r['failures']))
        self.assertTrue(any(x['subject'] == 'java' for x in r['failures']))

    def test_verify_success_failure_and_unavailable(self):
        def found(name): return '/fake/' + name if name in ('zipalign', 'apksigner') else None
        def run(args, timeout):
            return {'returncode': 1 if args[0].endswith('apksigner') else 0, 'stdout': '', 'stderr': 'invalid'}
        with patch('apklab.cli.find_tool', side_effect=found), patch('apklab.cli.run', side_effect=run):
            code, r = self.call('work', 'verify', str(self.workspace))
        self.assertEqual(code, 1)
        self.assertEqual(set(r['checks']), {'zipalign', 'apksigner'})
        self.assertTrue(any(x['subject'] == 'zipalign' for x in r['verified']))
        self.assertTrue(any(x['subject'] == 'apksigner' for x in r['failures']))
        self.assertTrue(any(x['subject'] == 'runtime' for x in r['not_tested']))
        with patch('apklab.cli.find_tool', return_value=None):
            code, r = self.call('work', 'verify', str(self.workspace))
        self.assertEqual(code, 3)
        self.assertFalse(r['verified'])
        self.assertEqual({x['subject'] for x in r['not_tested']}, {'zipalign', 'zipalign_16k', 'apksigner', 'runtime'})

    def test_native_duplicate_entries_are_processed_individually(self):
        import warnings
        sample = self.root / 'duplicates.apk'
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(sample, 'w') as z:
                z.writestr('AndroidManifest.xml', 'fixture')
                z.writestr('lib/arm64/libsample.so', b'first')
                z.writestr('lib/arm64/libsample.so', b'second')
        observed = []
        def fake_readelf(args, timeout=120):
            observed.append(Path(args[-1]).read_bytes())
            return {'returncode': 0, 'stdout': 'ok', 'stderr': ''}
        with patch('apklab.cli.find_tool', return_value='/fake/readelf'), patch('apklab.cli.run', side_effect=fake_readelf):
            code, r = self.call('inventory', str(sample), '--native-details')
        self.assertEqual(code, 3, r)
        self.assertEqual(observed, [b'first', b'second'])

    def test_verify_refuses_external_input_and_missing_file(self):
        for path in (str(self.apk), 'missing.apk', '../input.apk'):
            with self.subTest(path=path):
                code, r = self.call('work', 'verify', str(self.workspace), '--input', path)
                self.assertEqual(code, 1); self.assertTrue(r['failures'])

    def test_verify_success_is_not_runtime_proof(self):
        with patch('apklab.cli.supports_16k', return_value=False), patch('apklab.cli.find_tool', return_value='/fake/tool'), patch('apklab.cli.run', return_value={'returncode': 0, 'stdout': '', 'stderr': ''}):
            code, r = self.call('work', 'verify', str(self.workspace))
        self.assertEqual(code, 3); self.assertEqual(len(r['verified']), 2)
        messages = {entry['subject']: entry['detail'] for entry in r['verified']}
        self.assertIn('Signature verification', messages['apksigner'])
        self.assertIn('ZIP verification', messages['zipalign'])
        self.assertTrue(any(x['subject'] == 'runtime' for x in r['not_tested']))

if __name__ == '__main__': unittest.main()
