import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from apklab.cli import main


class ApksTests(unittest.TestCase):
    def call(self, path, *options):
        out = io.StringIO()
        with contextlib.redirect_stdout(out): code = main(['apks', 'inspect', str(path), *options])
        return code, json.loads(out.getvalue())
    def test_inventory_and_verify_no_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'x.apks'
            with zipfile.ZipFile(p, 'w') as z: z.writestr('toc.pb', b'unknown'); z.writestr('splits/base.apk', b'not an apk')
            before = p.read_bytes()
            for options in ((), ('--verify',)):
                code, r = self.call(p, *options)
                self.assertEqual(code, 3, r); self.assertTrue(r['toc_present'])
                self.assertEqual(r['entries'][1]['path'], 'splits/base.apk')
                self.assertTrue(any(x['subject'] == 'APKS targeting' for x in r['not_tested']))
            self.assertEqual(before, p.read_bytes()); self.assertEqual(list(Path(tmp).iterdir()), [p])
    def test_unsafe_or_missing_apk_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'x.apks'
            for name in ('../evil.apk', 'toc.pb'):
                with zipfile.ZipFile(p, 'w') as z: z.writestr(name, b'x')
                code, r = self.call(p); self.assertEqual(code, 1, r)
    def test_corrupt_crc_in_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'x.apks'
            with zipfile.ZipFile(p, 'w') as z: z.writestr('base.apk', b'fixture')
            p.write_bytes(p.read_bytes().replace(b'fixture', b'Fixture', 1))
            code, _ = self.call(p, '--verify'); self.assertEqual(code, 1)

if __name__ == '__main__': unittest.main()
