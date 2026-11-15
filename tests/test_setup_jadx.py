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
    def test_goal_plans_are_presence_only_and_do_not_run_tools(self):
        expected = {
            'basic': (set(), {'aapt', 'apksigner'}),
            'jadx': ({'java', 'jadx'}, set()),
            'decode': ({'java', 'apktool'}, set()),
            'rebuild': ({'java', 'apktool', 'zipalign', 'apksigner'}, {'aapt', 'readelf'}),
            'verify': ({'java', 'zipalign', 'apksigner'}, {'readelf'}),
            'device': ({'java', 'adb', 'aapt', 'apksigner'}, {'emulator'}),
        }
        for goal, (required, optional) in expected.items():
            with self.subTest(goal=goal), patch('apklab.cli.find_tool', side_effect=lambda name: '/fake/' + name if name == 'java' else None) as find, patch('apklab.cli.run') as run, patch('apklab.cli.find_executable') as executable:
                code, result = self.call('setup', '--plan', '--for', goal)
            self.assertEqual(code, 3)
            plan = result['plan']['goal']
            self.assertEqual(plan['goal'], goal)
            self.assertEqual({x['name'] for x in plan['tools'] if x['category'] == 'required'}, required)
            self.assertEqual({x['name'] for x in plan['tools'] if x['category'] == 'optional'}, optional)
            self.assertEqual({call.args[0] for call in find.call_args_list}, required | optional)
            self.assertTrue(all(x['source_url'].startswith('https://') for x in plan['tools']))
            self.assertTrue(any(x['subject'] == 'tool functionality' for x in result['not_tested']))
            self.assertFalse(result['failures'])
            run.assert_not_called(); executable.assert_not_called()
            if 'java' in required:
                self.assertTrue(any(x['subject'] == 'java' and 'presence only' in x['detail'] for x in result['verified']))
            for name in (required | optional) - {'java'}:
                self.assertTrue(any(x['subject'] == name for x in result['not_tested']))

    def test_goal_plan_without_plan_flag_and_install_conflict(self):
        with patch('apklab.cli.find_tool', return_value=None), patch('apklab.cli.run') as run:
            code, result = self.call('setup', '--for', 'jadx')
            self.assertEqual(code, 3); self.assertEqual(result['plan']['goal']['goal'], 'jadx')
            for args in (('setup', '--install', '--for', 'jadx'), ('setup', '--for', 'unknown')):
                with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
                    main(list(args))
                self.assertEqual(exc.exception.code, 2)
            run.assert_not_called()

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
