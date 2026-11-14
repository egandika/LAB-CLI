"""Opt-in real Android-tool integration, using an externally supplied public test APK."""
import contextlib
import hashlib
import io
import json
import os
import subprocess
import struct
import tempfile
import zipfile
import unittest
from pathlib import Path

from apklab.cli import main
from apklab.core import find_tool


@unittest.skipUnless(os.environ.get('APKLAB_INTEGRATION_APK'), 'set APKLAB_INTEGRATION_APK to run real Android-tool tests')
class AndroidToolIntegration(unittest.TestCase):
    def cli(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(list(args))
        try:
            result = json.loads(output.getvalue())
        except ValueError:
            self.fail('CLI did not emit JSON: ' + output.getvalue())
        self.assertEqual(code, 0, json.dumps(result, indent=2))
        return result

    def test_round_trip(self):
        missing = [name for name in ('java', 'keytool', 'apktool', 'aapt', 'zipalign', 'apksigner') if not find_tool(name)]
        self.assertFalse(missing, 'Requested integration test requires tools: ' + ', '.join(missing))
        sample = Path(os.environ['APKLAB_INTEGRATION_APK']).resolve(strict=True)
        original_digest = hashlib.sha256(sample.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory(prefix='apklab-integration-') as tmp:
            root = Path(tmp)
            work = root / 'work'
            self.cli('work', 'init', str(sample), str(work))
            if os.environ.get('APKLAB_TEST_JADX') == '1':
                self.assertTrue(find_tool('jadx'), 'JADX required when APKLAB_TEST_JADX=1')
                self.cli('work', 'jadx', str(work))
                self.assertTrue(any((work / 'jadx').rglob('*.java')), 'JADX produced no Java files')
            self.cli('work', 'decode', str(work))
            self.cli('work', 'build', str(work))
            self.cli('work', 'align', str(work))
            # This is a disposable test key, not a user credential.
            key = root / 'test.jks'
            result = subprocess.run([find_tool('keytool'), '-genkeypair', '-alias', 'test', '-keyalg', 'RSA',
                '-keysize', '2048', '-validity', '30', '-dname', 'CN=APKLab Test', '-keystore', str(key),
                '-storepass', 'testpass', '-keypass', 'testpass', '-noprompt'],
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr)
            old_password = os.environ.get('APKLAB_TEST_KEY_PASSWORD')
            os.environ['APKLAB_TEST_KEY_PASSWORD'] = 'testpass'
            try:
                self.cli('work', 'sign', str(work), '--keystore', str(key), '--alias', 'test', '--pass-env', 'APKLAB_TEST_KEY_PASSWORD')
            finally:
                if old_password is None: os.environ.pop('APKLAB_TEST_KEY_PASSWORD', None)
                else: os.environ['APKLAB_TEST_KEY_PASSWORD'] = old_password
            verification = self.cli('work', 'verify', str(work))
            self.assertEqual(set(verification['checks']), {'zipalign', 'apksigner'})
            inspection = self.cli('inspect', str(work / 'signed.apk'))
            self.assertTrue(inspection['apks'][0]['package'])
            self.assertTrue(inspection['apks'][0]['signer_sha256'])
            self.assertTrue(any(x['subject'] == 'runtime' for x in verification['not_tested']))
            self.assertEqual(original_digest, hashlib.sha256(sample.read_bytes()).hexdigest())
            self.assertEqual(original_digest, hashlib.sha256((work / 'original.apk').read_bytes()).hexdigest())
            if os.environ.get('APKLAB_TEST_16K') == '1':
                # Insert a stored ELF test file into the copy; ZIP alignment is checked, not ELF compatibility.
                with zipfile.ZipFile(work / 'rebuilt.apk', 'a') as z:
                    z.write('/bin/true', 'lib/x86_64/libfixture.so', compress_type=zipfile.ZIP_STORED)
                self.cli('work', 'align', str(work), '--page-size', '16', '--output', 'aligned16.apk')
                with zipfile.ZipFile(work / 'aligned16.apk') as z:
                    info = z.getinfo('lib/x86_64/libfixture.so')
                    with (work / 'aligned16.apk').open('rb') as f:
                        f.seek(info.header_offset)
                        header = f.read(30)
                    name_len, extra_len = struct.unpack_from('<HH', header, 26)
                    self.assertEqual((info.header_offset + 30 + name_len + extra_len) % 16384, 0)
                # Sign the 16 KiB-aligned APK and verify both checks.
                os.environ['APKLAB_TEST_KEY_PASSWORD'] = 'testpass'
                try:
                    self.cli('work', 'sign', str(work), '--input', 'aligned16.apk', '--output', 'signed16.apk', '--keystore', str(key), '--alias', 'test', '--pass-env', 'APKLAB_TEST_KEY_PASSWORD')
                finally:
                    if old_password is None: os.environ.pop('APKLAB_TEST_KEY_PASSWORD', None)
                    else: os.environ['APKLAB_TEST_KEY_PASSWORD'] = old_password
                verification16 = self.cli('work', 'verify', str(work), '--input', 'signed16.apk', '--page-size', '16')
                self.assertEqual(set(verification16['checks']), {'zipalign', 'apksigner'})
            if os.environ.get('APKLAB_TEST_SPLITS') == '1':
                # Two independent copies exercise the orchestration; they are not a real split set.
                second = root / 'second.apk'; second.write_bytes(sample.read_bytes())
                splitset = root / 'split-set'
                self.cli('splits', 'init', str(splitset), str(sample), str(second))
                for stage in ('decode', 'build', 'align'):
                    self.cli('splits', 'run', str(splitset), stage)
                os.environ['APKLAB_TEST_KEY_PASSWORD'] = 'testpass'
                try:
                    self.cli('splits', 'run', str(splitset), 'sign', '--keystore', str(key), '--alias', 'test', '--pass-env', 'APKLAB_TEST_KEY_PASSWORD')
                finally:
                    if old_password is None: os.environ.pop('APKLAB_TEST_KEY_PASSWORD', None)
                    else: os.environ['APKLAB_TEST_KEY_PASSWORD'] = old_password
                self.cli('splits', 'run', str(splitset), 'verify')
                inspected = self.cli('inspect', str(splitset/'apk-0000/signed.apk'), str(splitset/'apk-0001/signed.apk'))
                self.assertEqual(inspected['apks'][0]['signer_sha256'], inspected['apks'][1]['signer_sha256'])
                archive = root/'original.xapk'; repacked = root/'repacked.xapk'; extracted = root/'extracted'
                with zipfile.ZipFile(archive, 'w') as z:
                    z.write(sample, 'base.apk'); z.writestr('Android/obb/example/test.obb', b'test-obb')
                self.cli('xapk', 'repack', str(archive), str(repacked), '--replace', 'base.apk=' + str(work/'signed.apk'))
                self.cli('xapk', 'unpack', str(repacked), str(extracted))
                self.assertEqual((extracted/'base.apk').read_bytes(), (work/'signed.apk').read_bytes())
                self.assertEqual((extracted/'Android/obb/example/test.obb').read_bytes(), b'test-obb')
            serial = os.environ.get('APKLAB_EMULATOR_SERIAL')
            if serial:
                device = self.cli('device', '--serial', serial, '--confirm-install', '--launch', str(work / 'signed.apk'))
                self.assertIn('install', device); self.assertIn('launch', device)
                self.assertTrue(any(x['subject'] == 'runtime' for x in device['not_tested']))

if __name__ == '__main__':
    unittest.main()
