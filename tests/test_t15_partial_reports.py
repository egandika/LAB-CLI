import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from apklab.cli import main
from apklab.core import add


class PartialReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.apk = self.root/'input.apk'
        with zipfile.ZipFile(self.apk, 'w') as z: z.writestr('AndroidManifest.xml', 'test')

    def call(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out): code = main(list(args))
        return code, json.loads(out.getvalue())

    def test_inspect_keeps_first_item_and_progress_when_second_raises(self):
        other = self.root/'other.apk'; other.write_bytes(self.apk.read_bytes())
        def inspect(path, report, *args):
            if Path(path) == other: raise OSError('second failed')
            add(report, 'verified', str(path), 'first inspected')
            return {'file': str(path)}
        with patch('apklab.cli.inspect_one', side_effect=inspect):
            code, result = self.call('inspect', str(self.apk), str(other))
        self.assertEqual(code, 1); self.assertEqual(result['apks'], [{'file':str(self.apk)}])
        self.assertIn('first inspected', result['verified'][0]['detail'])
        self.assertIn('second failed', result['failures'][0]['detail'])

    def test_work_verify_retains_completed_check_on_probe_exception(self):
        work = self.root/'work'; self.call('work', 'init', str(self.apk), str(work)); (work/'signed.apk').write_bytes(b'data')
        success = {'returncode':0, 'stdout':'ok', 'stderr':''}
        with patch('apklab.cli.find_tool', return_value='/fake'), patch('apklab.cli.run', return_value=success), patch('apklab.cli.supports_16k', side_effect=OSError('probe failed')):
            code, result = self.call('work', 'verify', str(work))
        self.assertEqual(code, 1); self.assertEqual(result['checks']['zipalign'], success)
        self.assertEqual(result['verified'][0]['subject'], 'zipalign')
        self.assertIn('probe failed', result['failures'][0]['detail'])

    def test_split_verify_keeps_subreport_and_continues(self):
        split = self.root/'second.apk'; split.write_bytes(self.apk.read_bytes()); work = self.root/'set'
        self.call('splits', 'init', str(work), str(self.apk), str(split))
        for member in ('apk-0000', 'apk-0001'): (work/member/'signed.apk').write_bytes(b'data')
        with patch('apklab.cli.find_tool', return_value='/fake'), patch('apklab.cli.run', return_value={'returncode':0,'stdout':'','stderr':''}), patch('apklab.cli.supports_16k', side_effect=[OSError('probe failed'), False]):
            code, result = self.call('splits', 'run', str(work), 'verify')
        self.assertEqual(code, 1); self.assertEqual(len(result['members']), 2)
        partial = result['members'][0]['report']
        self.assertEqual(partial['verified'][0]['subject'], 'zipalign')
        self.assertIn('probe failed', partial['failures'][0]['detail'])
        self.assertTrue(result['members'][1]['report']['verified'])

    def test_launch_exception_retains_install_evidence_and_warning(self):
        def inspect(path, report):
            add(report, 'verified', 'signature', 'checked')
            return {'package':'org.example.app','version_code':'1','split':None,'signer_sha256':['a'*64]}
        def run(args, timeout=120):
            if 'monkey' in args: raise OSError('launch unavailable')
            if 'get-state' in args: out = 'device\n'
            elif 'emu' in args: out = 'fixture\nOK\n'
            elif 'getprop' in args: out = '1\n'
            elif 'users' in args: out = 'UserInfo{0:Owner:13}\n'
            elif 'packages' in args: out = ''
            elif 'install' in args: out = 'Success\n'
            else: raise AssertionError(args)
            return {'returncode':0, 'stdout':out, 'stderr':''}
        with patch('apklab.device.find_tool', side_effect=lambda name:'/fake/'+name), patch('apklab.device.inspect_one', side_effect=inspect), patch('apklab.device.run', side_effect=run):
            code, result = self.call('device', '--serial', 'emulator-5554', '--confirm-install', '--launch', str(self.apk))
        self.assertEqual(code, 1); self.assertEqual(result['install']['stdout'], 'Success\n')
        self.assertTrue(any(x['subject'] == 'installation' for x in result['verified']))
        self.assertTrue(any(x['subject'] == 'runtime' for x in result['not_tested']))
        self.assertIn('launch unavailable', result['failures'][0]['detail'])


class StagedJadxTests(unittest.TestCase):
    def test_standalone_jadx_does_not_expose_partial_output(self):
        from apklab.jadx import decompile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); apk = root/'input.apk'; apk.write_bytes(b'original'); dest = root/'out'
            def fake(args, timeout, monitor):
                self.assertFalse(dest.exists())
                stage = Path(args[args.index('-d') + 1]); (stage/'partial.java').write_text('partial')
                monitor()
                return {'returncode':1, 'stdout':'', 'stderr':'tool failed'}
            with patch('apklab.jadx.find_tool', return_value='/fake'), patch('apklab.jadx.run', side_effect=fake):
                with self.assertRaisesRegex(RuntimeError, 'tool failed'): decompile(apk, dest, 5, 100)
            self.assertFalse(dest.exists()); self.assertEqual(apk.read_bytes(), b'original')
            self.assertEqual(list(root.glob('.apklab-stage-*')), [])

    def test_standalone_jadx_no_replace_on_publish_race(self):
        from apklab.jadx import decompile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); apk = root/'input.apk'; apk.write_bytes(b'original'); dest = root/'out'
            def fake(args, timeout, monitor):
                (Path(args[args.index('-d')+1])/'output.java').write_text('staged')
                dest.mkdir(); (dest/'owner').write_text('preserve')
                return {'returncode':0, 'stdout':'', 'stderr':''}
            with patch('apklab.jadx.find_tool', return_value='/fake'), patch('apklab.jadx.run', side_effect=fake):
                with self.assertRaises(OSError): decompile(apk, dest, 5, 100)
            self.assertEqual((dest/'owner').read_text(), 'preserve')
            self.assertEqual(list(root.glob('.apklab-stage-*')), [])
