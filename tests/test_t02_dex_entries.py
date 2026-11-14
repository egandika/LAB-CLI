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

class DuplicateDexTests(unittest.TestCase):
    def test_duplicate_names_read_by_entry_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp)/'input.apk'
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                with zipfile.ZipFile(apk, 'w') as z:
                    z.writestr('AndroidManifest.xml', b'manifest')
                    z.writestr('classes.dex', b'first')
                    z.writestr('classes.dex', b'second')
            seen = []
            def fake_read(data):
                seen.append(data)
                return {'classes':[], 'methods':[], 'strings':[], 'endpoints':[]}
            out = io.StringIO()
            with patch('apklab.cli.read_dex', side_effect=fake_read), patch('apklab.cli.find_tool', return_value=None), contextlib.redirect_stdout(out):
                code = main(['dex', str(apk)])
            self.assertEqual(code, 3); self.assertEqual(seen, [b'first', b'second'])
            self.assertEqual([x['zip_entry_index'] for x in json.loads(out.getvalue())['dex_files']], [1, 2])
