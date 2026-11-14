import contextlib
import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from apklab.cli import main
from apklab.analysis import candidates, parse_xmltree

class DeepAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.apk = Path(self.tmp.name)/'test.apk'
        with zipfile.ZipFile(self.apk, 'w') as z:
            z.writestr('AndroidManifest.xml', b'manifest')
            z.writestr('assets/icon', b'\x89PNG\r\n\x1a\nexample')
            z.writestr('assets/other', b'other')
    def call(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out): code = main(list(args))
        return code, json.loads(out.getvalue())
    def test_manifest_parser_and_dex(self):
        tree = '''E: manifest (line=1)
  E: uses-permission (line=2)
    A: android:name(0x01010003)="android.permission.INTERNET" (Raw: "android.permission.INTERNET")
  E: application (line=3)
    E: activity (line=4)
      A: android:name(0x01010003)=".Main" (Raw: ".Main")
      E: intent-filter (line=5)
        E: action (line=6)
          A: android:name(0x01010003)="android.intent.action.MAIN"
    E: service (line=7)
      A: android:name(0x01010003)=".Service"
'''
        with patch('apklab.cli.find_tool', return_value='/fake/aapt'), patch('apklab.cli.run', return_value={'returncode':0,'stdout':tree,'stderr':''}):
            code, r = self.call('dex', str(self.apk))
        self.assertEqual(code, 3, r); self.assertEqual(r['manifest']['permissions'], ['android.permission.INTERNET'])
        self.assertEqual(r['manifest']['components'], [{'type':'activity','name':'.Main'}, {'type':'service','name':'.Service'}])
        self.assertTrue(any(x['subject'] == 'manifest completeness' for x in r['not_tested']))
    def test_missing_aapt_and_heuristics(self):
        with patch('apklab.cli.find_tool', return_value=None):
            _, r = self.call('dex', str(self.apk))
        self.assertTrue(any(x['subject'] == 'manifest' for x in r['not_tested']))
        c = candidates(['Lfoo/a;', 'Lfoo/Normal;'], ['YWJjZGVmZ2hpamtsbW5vcHFy', 'readable'], 10)
        self.assertEqual(c['short_classes'], ['Lfoo/a;']); self.assertEqual(c['encoded_string_count'], 1)
    def test_hash_and_magic(self):
        code, r = self.call('inventory', str(self.apk), '--hash')
        self.assertEqual(code, 0, r)
        self.assertEqual(r['files'][0]['magic_type'], 'PNG')
        self.assertEqual(r['files'][0]['sha256'], hashlib.sha256(b'\x89PNG\r\n\x1a\nexample').hexdigest())
        self.assertEqual(r['files'][1]['magic_type'], 'unknown')
        self.assertTrue(r['inferences'])
