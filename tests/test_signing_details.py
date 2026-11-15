import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from apklab.cli import main
from apklab.signing_details import parse_schemes


class SigningDetailsTests(unittest.TestCase):
    def test_explicit_lines_only_and_untrusted_results(self):
        text = 'Verified using v1 scheme (JAR signing): false\nVerified using v2 scheme (APK Signature Scheme v2): true\nVerified using v3.1 scheme (APK Signature Scheme v3.1): true\n'
        result = {'returncode': 0, 'stdout': text}
        statuses = parse_schemes(result)
        self.assertEqual(statuses['v1'], 'not_verified'); self.assertEqual(statuses['v2'], 'verified'); self.assertEqual(statuses['v3.1'], 'verified'); self.assertEqual(statuses['v4'], 'not_tested')
        for altered in ({**result, 'returncode': 1}, {**result, 'stdout_truncated': True}, {**result, 'capture_incomplete': True}):
            self.assertTrue(all(x == 'not_tested' for x in parse_schemes(altered).values()))
        self.assertEqual(parse_schemes({**result, 'stdout': text + 'Verified using v2 scheme (x): false\n'})['v2'], 'not_tested')
    def test_cli_missing_tool_is_untested(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp)/'test.apk'
            with zipfile.ZipFile(apk, 'w') as z: z.writestr('AndroidManifest.xml', b'x')
            original = apk.read_bytes(); out = io.StringIO()
            with patch('apklab.core.find_tool', return_value=None), patch('apklab.cli.find_tool', return_value=None), contextlib.redirect_stdout(out):
                code = main(['inspect', str(apk), '--signing-details'])
            r = json.loads(out.getvalue()); self.assertEqual(code, 3)
            self.assertTrue(all(x == 'not_tested' for x in r['signing_details'][0]['schemes'].values()))
            self.assertEqual(original, apk.read_bytes())

if __name__ == '__main__': unittest.main()
