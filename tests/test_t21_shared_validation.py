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


class ReplacementValidationTests(unittest.TestCase):
    def test_duplicate_manifest_rejected_consistently_without_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); replacement = root/'replacement.apk'; source = root/'source.xapk'; dest = root/'out.xapk'
            with zipfile.ZipFile(source, 'w') as z: z.writestr('base.apk', b'original')
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                with zipfile.ZipFile(replacement, 'w') as z:
                    z.writestr('AndroidManifest.xml', 'first'); z.writestr('AndroidManifest.xml', 'second')
            before = source.read_bytes()
            for argv in (['inspect', str(replacement)], ['xapk', 'repack', str(source), str(dest), '--replace', 'base.apk='+str(replacement)]):
                output = io.StringIO()
                with self.subTest(argv=argv), patch('apklab.core.find_tool', return_value=None), contextlib.redirect_stdout(output):
                    code = main(argv)
                result = json.loads(output.getvalue()); self.assertEqual(code, 1, result)
                self.assertTrue(any('exactly one AndroidManifest.xml' in item['detail'] for item in result['failures']))
                self.assertFalse(dest.exists()); self.assertEqual(source.read_bytes(), before)
