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
from apklab.elf import load_alignment


@unittest.skipUnless(os.environ.get('APKLAB_INTEGRATION_APK'), 'set APKLAB_INTEGRATION_APK to run real Android-tool tests')
class AndroidToolIntegration(unittest.TestCase):
    def cli(self, *args, expected=3):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(list(args))
        try:
            result = json.loads(output.getvalue())
        except ValueError:
            self.fail('CLI did not emit JSON: ' + output.getvalue())
        self.assertEqual(code, expected, json.dumps(result, indent=2))
        return result

    def create_split_fixture(self, root, key):
        """Build two distinct, signed APKs from manifests and a locale resource."""
        sdk = Path(os.environ['ANDROID_HOME'])
        platforms = sorted(sdk.glob('platforms/android-*/android.jar'))
        self.assertTrue(platforms, 'An Android platform android.jar is required for the split fixture')
        common = ('xmlns:android="http://schemas.android.com/apk/res/android" '
                  'package="org.example.apklab.splitfixture" android:versionCode="1" '
                  'android:versionName="1"')
        manifests = {
            'base': '<manifest ' + common + '><uses-sdk android:minSdkVersion="21"/>'
                    '<application android:hasCode="false" android:label="@string/fixture_label"/></manifest>',
            'config.en': '<manifest ' + common + ' split="config.en">'
                         '<uses-sdk android:minSdkVersion="21"/>'
                         '<application android:hasCode="false"/></manifest>',
        }
        default_resources = root / 'base-res' / 'values'
        default_resources.mkdir(parents=True)
        (default_resources / 'strings.xml').write_text('<resources><string name="fixture_label">Default</string></resources>', encoding='utf-8')
        resources = root / 'split-res' / 'values-en'
        resources.mkdir(parents=True)
        (resources / 'strings.xml').write_text('<resources><string name="fixture_label">English</string></resources>', encoding='utf-8')
        signed = []
        for name, xml in manifests.items():
            manifest_dir = root / ('manifest-' + name)
            manifest_dir.mkdir()
            manifest = manifest_dir / 'AndroidManifest.xml'
            manifest.write_text(xml, encoding='utf-8')
            unsigned = root / (name + '-unsigned.apk')
            apk = root / (name + '.apk')
            command = [find_tool('aapt'), 'package', '-f', '-M', str(manifest),
                       '-I', str(platforms[-1]), '-F', str(unsigned)]
            command.extend(['-S', str(default_resources.parent if name == 'base' else resources.parent)])
            built = subprocess.run(command, capture_output=True, text=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stderr)
            signed_result = subprocess.run([find_tool('apksigner'), 'sign', '--ks', str(key),
                '--ks-key-alias', 'test', '--ks-pass', 'pass:testpass', '--key-pass', 'pass:testpass',
                '--out', str(apk), str(unsigned)], capture_output=True, text=True, timeout=120)
            self.assertEqual(signed_result.returncode, 0, signed_result.stderr)
            signed.append(apk)
        return signed

    def assert_split_identity(self, result):
        base, split = result['apks']
        self.assertEqual(base['package'], 'org.example.apklab.splitfixture')
        self.assertEqual(split['package'], base['package'])
        self.assertEqual(base['version_code'], '1')
        self.assertEqual(split['version_code'], base['version_code'])
        self.assertFalse(base.get('split'))
        self.assertEqual(split['split'], 'config.en')
        self.assertTrue(base['signer_sha256'])
        self.assertEqual(base['signer_sha256'], split['signer_sha256'])

    def test_round_trip(self):
        missing = [name for name in ('java', 'keytool', 'apktool', 'aapt', 'zipalign', 'apksigner') if not find_tool(name)]
        self.assertFalse(missing, 'Requested integration test requires tools: ' + ', '.join(missing))
        sample = Path(os.environ['APKLAB_INTEGRATION_APK']).resolve(strict=True)
        original_digest = hashlib.sha256(sample.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory(prefix='apklab-integration-') as tmp:
            root = Path(tmp)
            work = root / 'work'
            self.cli('work', 'init', str(sample), str(work), expected=0)
            if os.environ.get('APKLAB_TEST_JADX') == '1':
                self.assertTrue(find_tool('jadx'), 'JADX required when APKLAB_TEST_JADX=1')
                self.cli('work', 'jadx', str(work))
                self.assertTrue(any((work / 'jadx').rglob('*.java')), 'JADX produced no Java files')
            self.cli('work', 'decode', str(work))
            self.cli('work', 'build', str(work))
            self.cli('work', 'align', str(work), *(['--page-size', '16'] if os.environ.get('APKLAB_TEST_16K') == '1' else []))
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
            self.assertTrue({'zipalign', 'apksigner'} <= set(verification['checks']))
            inspection = self.cli('inspect', str(work / 'signed.apk'), expected=0)
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
                verification16 = self.cli('work', 'verify', str(work), '--input', 'signed16.apk', '--page-size', '16', expected=3 if load_alignment(Path('/bin/true').read_bytes())['aligned_16k'] else 1)
                self.assertEqual(verification16['elf_16k'][0]['aligned_16k'], load_alignment(Path('/bin/true').read_bytes())['aligned_16k'])
                self.assertEqual(set(verification16['checks']), {'zipalign', 'zipalign_16k', 'apksigner'})
            if os.environ.get('APKLAB_TEST_SPLITS') == '1':
                base, split = self.create_split_fixture(root, key)
                self.assertNotEqual(base.read_bytes(), split.read_bytes())
                self.assert_split_identity(self.cli('inspect', str(base), str(split)))
                input_digests = [hashlib.sha256(p.read_bytes()).hexdigest() for p in (base, split)]
                splitset = root / 'split-set'
                self.cli('splits', 'init', str(splitset), str(base), str(split))
                for stage in ('decode', 'build', 'align'):
                    self.cli('splits', 'run', str(splitset), stage)
                os.environ['APKLAB_TEST_KEY_PASSWORD'] = 'testpass'
                try:
                    self.cli('splits', 'run', str(splitset), 'sign', '--keystore', str(key), '--alias', 'test', '--pass-env', 'APKLAB_TEST_KEY_PASSWORD')
                finally:
                    if old_password is None: os.environ.pop('APKLAB_TEST_KEY_PASSWORD', None)
                    else: os.environ['APKLAB_TEST_KEY_PASSWORD'] = old_password
                verified_set = self.cli('splits', 'run', str(splitset), 'verify')
                self.assertEqual(len(verified_set['members']), 2)
                self.assertFalse(verified_set['split_analysis']['issues'])
                self.assertFalse(verified_set['split_analysis']['unknown'])
                self.assertTrue(all(member['inspection']['apk']['signer_sha256'] for member in verified_set['members']))
                inspected = self.cli('inspect', str(splitset/'apk-0000/signed.apk'), str(splitset/'apk-0001/signed.apk'))
                self.assert_split_identity(inspected)
                self.assertEqual(input_digests, [hashlib.sha256(p.read_bytes()).hexdigest() for p in (base, split)])
                archive = root/'original.xapk'; repacked = root/'repacked.xapk'; extracted = root/'extracted'
                with zipfile.ZipFile(archive, 'w') as z:
                    z.write(sample, 'base.apk'); z.writestr('Android/obb/example/test.obb', b'test-obb')
                self.cli('xapk', 'repack', str(archive), str(repacked), '--replace', 'base.apk=' + str(work/'signed.apk'))
                self.cli('xapk', 'unpack', str(repacked), str(extracted))
                self.assertEqual((extracted/'base.apk').read_bytes(), (work/'signed.apk').read_bytes())
                self.assertEqual((extracted/'Android/obb/example/test.obb').read_bytes(), b'test-obb')
                serial = os.environ.get('APKLAB_EMULATOR_SERIAL')
                if serial:
                    split_device = self.cli('device', '--serial', serial, '--confirm-install',
                        str(splitset/'apk-0000/signed.apk'), str(splitset/'apk-0001/signed.apk'))
                    self.assertIn('Success', split_device['install']['stdout'])
                    self.assertTrue(any(x['subject'] == 'runtime' for x in split_device['not_tested']))
            serial = os.environ.get('APKLAB_EMULATOR_SERIAL')
            if serial:
                device = self.cli('device', '--serial', serial, '--confirm-install', '--launch', str(work / 'signed.apk'))
                self.assertIn('install', device); self.assertIn('launch', device)
                self.assertTrue(any(x['subject'] == 'runtime' for x in device['not_tested']))

if __name__ == '__main__':
    unittest.main()
