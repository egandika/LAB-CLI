import contextlib
import io
import json
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch
from apklab.cli import main

class DuplicateCRCTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
    def duplicate_apk(self):
        path = self.root / 'duplicate.apk'
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_STORED) as z:
                z.writestr('AndroidManifest.xml', b'manifest')
                z.writestr('classes.dex', b'first-unique-content')
                z.writestr('classes.dex', b'second-valid-content')
        path.write_bytes(path.read_bytes().replace(b'first-unique-content', b'First-unique-content', 1))
        return path
    def call(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out): code = main(list(args))
        return code, json.loads(out.getvalue())
    def test_inspect_reads_each_duplicate_and_detects_corrupt_first(self):
        apk = self.duplicate_apk()
        with patch('apklab.core.find_tool', return_value=None):
            code, report = self.call('inspect', str(apk))
        self.assertEqual(code, 1)
        self.assertTrue(any('CRC' in x['detail'] for x in report['failures']))
        self.assertFalse(any('passed CRC' in x['detail'] for x in report['verified']))
    def test_replacement_apk_rejects_corrupt_duplicate(self):
        apk = self.duplicate_apk(); archive = self.root/'source.xapk'; output = self.root/'out.xapk'
        with zipfile.ZipFile(archive, 'w') as z: z.writestr('base.apk', b'base')
        code, result = self.call('xapk', 'repack', str(archive), str(output), '--replace', 'base.apk=' + str(apk))
        self.assertEqual(code, 1, result); self.assertFalse(output.exists())
        self.assertIn('CRC', result['failures'][0]['detail'])
