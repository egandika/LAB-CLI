import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from apklab.cli import main


class ManifestTruncationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.apk = Path(self.temp.name)/'fixture.apk'
        with zipfile.ZipFile(self.apk, 'w') as z: z.writestr('AndroidManifest.xml', 'test')
    def call(self, stdout, truncated):
        out = io.StringIO()
        result = {'returncode':0, 'stdout':stdout, 'stderr':'', 'stdout_truncated':truncated}
        with patch('apklab.cli.find_tool', return_value='/aapt'), patch('apklab.cli.run', return_value=result), contextlib.redirect_stdout(out):
            code = main(['dex', str(self.apk)])
        return code, json.loads(out.getvalue())

    def test_truncated_manifest_is_partial_and_cut_line_ignored(self):
        text = 'E: manifest (line=1)\n  E: uses-permission (line=2)\n    A: android:name="PERMISSION.OK"\n  E: service (line=3)\n    A: android:name=".Partial"'
        code, result = self.call(text, True)
        self.assertEqual(code, 3, result)
        self.assertTrue(result['manifest']['partial'])
        self.assertEqual(result['manifest']['permissions'], ['PERMISSION.OK'])
        self.assertEqual(result['manifest']['components'], [])
        self.assertFalse(any(x['subject'] == 'manifest' for x in result['verified']))
        self.assertTrue(any(x['subject'] == 'manifest truncation' for x in result['not_tested']))

    def test_truncated_before_root_is_untested_not_success_or_failure(self):
        code, result = self.call('E: manif', True)
        self.assertEqual(code, 3, result); self.assertNotIn('manifest', result)
        self.assertTrue(any('truncated' in x['detail'] for x in result['not_tested']))
        self.assertFalse(result['failures'])

    def test_complete_output_is_not_marked_partial(self):
        code, result = self.call('E: manifest (line=1)\n', False)
        self.assertEqual(code, 3, result); self.assertFalse(result['manifest']['partial'])
        self.assertTrue(any(x['subject'] == 'manifest' for x in result['verified']))

    def test_truncated_on_newline_preserves_complete_last_line(self):
        code, result = self.call('E: manifest\n  E: service\n    A: android:name=".Done"\n', True)
        self.assertEqual(code, 3, result)
        self.assertEqual(result['manifest']['components'], [{'type':'service','name':'.Done'}])
        self.assertTrue(result['manifest']['partial'])
