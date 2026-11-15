import contextlib
import io
import json
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from apklab.cli import main


class ApkDiffTests(unittest.TestCase):
    def test_changes_unchanged_inputs_and_unknown_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp)/'old.apk', Path(tmp)/'new.apk'
            for path, entries in ((a, [('a', 'old'), ('removed', 'x')]), (b, [('a', 'new'), ('added', 'x'), ('lib/arm64-v8a/libx.so', 'x')])):
                with zipfile.ZipFile(path, 'w') as z:
                    z.writestr('AndroidManifest.xml', 'not axml')
                    for name, value in entries: z.writestr(name, value)
            before = [p.read_bytes() for p in (a, b)]; out = io.StringIO()
            with contextlib.redirect_stdout(out): code = main(['diff', str(a), str(b)])
            r = json.loads(out.getvalue()); self.assertEqual(code, 3, r)
            self.assertEqual([x['path'] for x in r['diff']['added']], ['added', 'lib/arm64-v8a/libx.so'])
            self.assertEqual([x['path'] for x in r['diff']['removed']], ['removed'])
            self.assertEqual([x['path'] for x in r['diff']['changed']], ['a'])
            self.assertEqual(r['diff']['native_abi_directories'], {'old': [], 'new': ['arm64-v8a']})
            self.assertEqual(r['metadata']['old']['source'], 'unavailable')
            self.assertEqual(before, [p.read_bytes() for p in (a, b)])
    def test_duplicate_entry_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'bad.apk'
            with warnings.catch_warnings(), zipfile.ZipFile(p, 'w') as z:
                warnings.simplefilter('ignore'); z.writestr('AndroidManifest.xml', 'm'); z.writestr('a', '1'); z.writestr('a', '2')
            out = io.StringIO()
            with contextlib.redirect_stdout(out): code = main(['diff', str(p), str(p)])
            self.assertEqual(code, 1); self.assertTrue(any('Duplicate' in x['detail'] for x in json.loads(out.getvalue())['failures']))

if __name__ == '__main__': unittest.main()
