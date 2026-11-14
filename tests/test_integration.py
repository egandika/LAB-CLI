"""Opt-in real Android-tool integration, using an externally supplied public test APK."""
import contextlib
import hashlib
import io
import json
import os
import subprocess
import tempfile
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

if __name__ == '__main__':
    unittest.main()
