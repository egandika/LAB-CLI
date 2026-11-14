import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from apklab.cli import main


class DeviceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.apk = self.root / 'input.apk'
        with zipfile.ZipFile(self.apk, 'w') as z: z.writestr('AndroidManifest.xml', 'fixture')
        self.before = self.apk.read_bytes(); self.calls = []; self.installed = False; self.users = 'Users:\n UserInfo{0:Owner:13} running\n'
    def call(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out): code = main(list(args))
        return code, json.loads(out.getvalue())
    def find(self, name): return '/fake/' + name
    def inspect(self, path, r):
        self.assertNotEqual(Path(path), self.apk)
        self.assertEqual(Path(path).read_bytes(), self.before)
        return {'file':str(path), 'package':'org.example.app', 'version_code':'1', 'split':None, 'signer_sha256':['a'*64]}
    def fake_run(self, args, timeout=120):
        args = [str(a) for a in args]; self.calls.append(args)
        if 'get-state' in args: out = 'device\n'
        elif 'emu' in args: out = 'test-avd\nOK\n'
        elif 'getprop' in args: out = '1\n'
        elif 'users' in args: out = self.users
        elif 'packages' in args: out = 'package:org.example.app\n' if self.installed else ''
        elif 'install' in args or 'install-multiple' in args: out = 'Success\n'
        elif 'monkey' in args: out = 'Events injected: 1\n'
        else: self.fail('unexpected command ' + str(args))
        return {'returncode':0, 'stdout':out, 'stderr':''}
    def test_emulator_install_and_launch(self):
        with patch('apklab.device.find_tool', side_effect=self.find), patch('apklab.device.inspect_one', side_effect=self.inspect), patch('apklab.device.run', side_effect=self.fake_run):
            code, r = self.call('device','--serial','emulator-5554','--confirm-install','--launch',str(self.apk))
        self.assertEqual(code, 0, r); self.assertEqual(r['package'], 'org.example.app')
        self.assertTrue(any('install' in c for c in self.calls)); self.assertTrue(any('monkey' in c for c in self.calls))
        self.assertEqual(self.apk.read_bytes(), self.before)
        self.assertTrue(any(x['subject']=='runtime' for x in r['not_tested']))
    def test_refuses_physical_or_unconfirmed(self):
        with patch('apklab.device.run') as run:
            code, _ = self.call('device','--serial','physical-123','--confirm-install',str(self.apk))
            self.assertEqual(code, 1)
            code, _ = self.call('device','--serial','emulator-5554',str(self.apk))
            self.assertEqual(code, 1); run.assert_not_called()
    def test_refuses_existing_package_or_other_users(self):
        for mode in ('installed', 'other-user'):
            self.calls.clear(); self.installed = mode == 'installed'
            self.users = 'Users:\n UserInfo{0:Owner:13} running\n' + (' UserInfo{10:Other:30} running\n' if mode == 'other-user' else '')
            with patch('apklab.device.find_tool', side_effect=self.find), patch('apklab.device.inspect_one', side_effect=self.inspect), patch('apklab.device.run', side_effect=self.fake_run):
                code, r = self.call('device','--serial','emulator-5554','--confirm-install',str(self.apk))
            self.assertEqual(code, 1, r); self.assertFalse(any('install' in c for c in self.calls))
    def test_refuses_unverified_signer(self):
        def inspect(path, r):
            item = self.inspect(path, r); item['signer_sha256'] = None; return item
        with patch('apklab.device.find_tool', side_effect=self.find), patch('apklab.device.inspect_one', side_effect=inspect), patch('apklab.device.run', side_effect=self.fake_run):
            code, _ = self.call('device','--serial','emulator-5554','--confirm-install',str(self.apk))
        self.assertEqual(code, 1); self.assertFalse(any('install' in c for c in self.calls))
    def test_refuses_non_emulator_identity(self):
        def run(args, timeout=120):
            result = self.fake_run(args, timeout)
            if 'getprop' in args: result['stdout'] = '0\n'
            return result
        with patch('apklab.device.find_tool', side_effect=self.find), patch('apklab.device.inspect_one', side_effect=self.inspect), patch('apklab.device.run', side_effect=run):
            code, _ = self.call('device','--serial','emulator-5554','--confirm-install',str(self.apk))
        self.assertEqual(code, 1); self.assertFalse(any('install' in c for c in self.calls))

if __name__ == '__main__': unittest.main()
