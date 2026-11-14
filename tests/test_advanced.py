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


class AdvancedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.apk = self.root/'base.apk'
        with zipfile.ZipFile(self.apk, 'w') as z:
            z.writestr('AndroidManifest.xml', 'fixture')
            z.writestr('lib/arm64-v8a/fake.so', b'native')
        self.work = self.root/'work'
        self.call('work', 'init', str(self.apk), str(self.work))
        (self.work/'rebuilt.apk').write_bytes(self.apk.read_bytes())
        # These ZIP-verification tests do not exercise ELF parsing.
        with zipfile.ZipFile(self.work/'signed.apk', 'w') as z: z.writestr('AndroidManifest.xml', 'fixture')

    def call(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out): code = main(list(args))
        return code, json.loads(out.getvalue())

    def test_16k_align_and_verify(self):
        calls = []
        def fake_run(args, timeout=120):
            calls.append([str(a) for a in args])
            if '-h' in args: return {'returncode': 0, 'stdout': '  -P <pagesize_kb>', 'stderr': ''}
            if '-P' in args and '-c' not in args: Path(args[-1]).write_bytes(b'aligned')
            return {'returncode': 0, 'stdout': '', 'stderr': ''}
        with patch('apklab.workflow.find_tool', return_value='/tool/zipalign'), patch('apklab.workflow.run', side_effect=fake_run):
            code, r = self.call('work', 'align', str(self.work), '--page-size', '16')
        self.assertEqual(code, 3, r); self.assertTrue(any('-P' in c and '16' in c for c in calls))
        with patch('apklab.cli.find_tool', return_value='/tool'), patch('apklab.cli.supports_16k', return_value=True), patch('apklab.cli.run', side_effect=fake_run):
            code, r = self.call('work', 'verify', str(self.work), '--page-size', '16')
        self.assertEqual(code, 3, r); self.assertTrue(any('-c' in c and '-P' in c for c in calls))
        self.assertTrue(any('ELF' in x['detail'] for x in r['not_tested']))

    def test_unsupported_16k_is_not_verified(self):
        with patch('apklab.cli.find_tool', return_value='/tool'), patch('apklab.cli.supports_16k', return_value=False), patch('apklab.cli.run', return_value={'returncode': 0, 'stdout':'', 'stderr':''}):
            code, r = self.call('work', 'verify', str(self.work), '--page-size', '16')
        self.assertEqual(code, 3); self.assertTrue(any(x['subject']=='zipalign_16k' for x in r['not_tested']))
        with patch('apklab.workflow.find_tool', return_value='/tool'), patch('apklab.workflow.supports_16k', return_value=False):
            code, r = self.call('work', 'align', str(self.work), '--page-size', '16')
        self.assertEqual(code, 1); self.assertFalse((self.work/'aligned.apk').exists())

    def test_jadx_uses_copy_and_refuses_overwrite(self):
        def fake_run(args, timeout=600, monitor=None):
            self.assertEqual(Path(args[-1]).resolve(), (self.work/'original.apk').resolve())
            self.assertIn('--no-res', args); Path(args[args.index('-d')+1]).mkdir()
            self.assertIsNotNone(monitor); monitor()
            return {'returncode':0,'stdout':'','stderr':''}
        with patch('apklab.workflow.find_tool', return_value='/tool/jadx'), patch('apklab.workflow.run', side_effect=fake_run):
            code, r = self.call('work','jadx',str(self.work)); self.assertEqual(code, 3, r)
            code, r = self.call('work','jadx',str(self.work)); self.assertEqual(code, 1, r)

    def test_split_candidates_and_abi_are_limited_observations(self):
        split = self.root/'other.apk'; split.write_bytes(self.apk.read_bytes())
        def fake_run(args, timeout=120):
            name = Path(args[-1]).name
            data = "package: name='org.example' versionCode='1'" + (" split='config.arm64'" if name == 'other.apk' else '')
            return {'returncode':0,'stdout':data,'stderr':''}
        with patch('apklab.core.find_tool', side_effect=lambda x: '/aapt' if x == 'aapt' else None), patch('apklab.core.run', side_effect=fake_run):
            code, r = self.call('inspect',str(self.apk),str(split),'--device-abi','arm64-v8a')
        self.assertEqual(code, 3, r); self.assertEqual(r['split_candidates']['base'], [str(self.apk)])
        self.assertTrue(any(x['subject']=='device compatibility' for x in r['not_tested']))

    def test_repack_preserves_source_and_obb(self):
        archive = self.root/'in.xapk'; output = self.root/'out.xapk'; replacement = self.root/'new.apk'
        with zipfile.ZipFile(replacement, 'w') as z: z.writestr('AndroidManifest.xml', 'new')
        with zipfile.ZipFile(archive, 'w') as z:
            z.write(self.apk, 'base.apk'); z.writestr('Android/obb/test.obb', b'obb'); z.writestr('manifest.json', '{}')
        before = hashlib.sha256(archive.read_bytes()).hexdigest()
        code, r = self.call('xapk','repack',str(archive),str(output),'--replace','base.apk='+str(replacement))
        self.assertEqual(code, 3, r); self.assertTrue(any(x['subject']=='repacked XAPK' for x in r['not_tested']))
        with zipfile.ZipFile(output) as z:
            self.assertEqual(z.read('base.apk'), replacement.read_bytes()); self.assertEqual(z.read('Android/obb/test.obb'), b'obb')
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), before)
        code, _ = self.call('xapk','repack',str(archive),str(output)); self.assertEqual(code, 1)

    def test_repack_rejects_bad_inputs(self):
        archive = self.root/'in.xapk'; output = self.root/'out.xapk'
        with zipfile.ZipFile(archive, 'w') as z: z.write(self.apk,'base.apk')
        code, _ = self.call('xapk','repack',str(archive),str(output),'--replace','missing.apk='+str(self.apk))
        self.assertEqual(code,1); self.assertFalse(output.exists())
        bad = self.root/'bad.apk'; bad.write_bytes(b'broken')
        code, _ = self.call('xapk','repack',str(archive),str(output),'--replace','base.apk='+str(bad))
        self.assertEqual(code,1); self.assertFalse(output.exists())
        code, _ = self.call('xapk','repack',str(archive),str(archive))
        self.assertEqual(code,1); self.assertTrue(zipfile.is_zipfile(archive))

    def test_asset_text_search_is_bounded_and_skips_binary(self):
        with zipfile.ZipFile(self.apk, 'a') as z:
            z.writestr('assets/settings.txt', 'alpha\nServer=example.org\n')
            z.writestr('assets/data.bin', b'\x00server')
        code, r = self.call('inventory',str(self.apk),'--text','server')
        self.assertEqual(code, 3, r)
        self.assertEqual(r['content_matches'][0]['line'], 2)
        self.assertEqual(r['content_matches'][0]['path'], 'assets/settings.txt')
        self.assertTrue(any(x['subject']=='asset text search' for x in r['not_tested']))

    def test_repack_cleans_up_after_corrupt_source(self):
        archive = self.root/'corrupt.xapk'; output = self.root/'out.xapk'
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_STORED) as z:
            z.write(self.apk, 'base.apk'); z.writestr('asset.dat', b'xyz-unique')
        archive.write_bytes(archive.read_bytes().replace(b'xyz-unique', b'Xyz-unique', 1))
        before = archive.read_bytes()
        code, _ = self.call('xapk', 'repack', str(archive), str(output))
        self.assertEqual(code, 1); self.assertFalse(output.exists()); self.assertEqual(archive.read_bytes(), before)

    def test_native_symbols(self):
        def fake_run(args, timeout=120):
            self.assertIn('-s', args)
            return {'returncode':0,'stdout':'symbol-table','stderr':''}
        with patch('apklab.cli.find_tool', return_value='/tool/readelf'), patch('apklab.cli.run', side_effect=fake_run):
            code, r = self.call('inventory',str(self.apk),'--native-symbols')
        self.assertEqual(code, 3,r); self.assertEqual(r['files'][0]['symbols'],'symbol-table')
        self.assertTrue(r['not_tested'])

if __name__ == '__main__': unittest.main()
