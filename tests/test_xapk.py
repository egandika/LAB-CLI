import contextlib
import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from apklab.cli import main


class XapkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.source = self.root / 'test.xapk'
        self.apk = self.root / 'source.apk'
        with zipfile.ZipFile(self.apk, 'w') as z:
            z.writestr('AndroidManifest.xml', 'manifest')
        with zipfile.ZipFile(self.source, 'w') as z:
            z.write(self.apk, 'base.apk')
            z.write(self.apk, 'split/config.apk')
            z.writestr('Android/obb/org.example/main.1.org.example.obb', b'asset-data')
            z.writestr('manifest.json', '{"package_name":"org.example"}')
    def call(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output): code = main(list(args))
        return code, json.loads(output.getvalue())
    def write_archive(self, entries):
        with zipfile.ZipFile(self.source, 'w') as z:
            for name, data in entries: z.writestr(name, data)
    def test_inspect_unverified_and_verify(self):
        code, r = self.call('xapk', 'inspect', str(self.source))
        self.assertEqual(code, 3); self.assertEqual([e['kind'] for e in r['entries']], ['apk', 'apk', 'obb', 'other'])
        self.assertTrue(any(x['subject'] == 'XAPK CRC' for x in r['not_tested']))
        code, r = self.call('xapk', 'inspect', str(self.source), '--verify')
        self.assertEqual(code, 3); self.assertEqual(r['entries'][0]['sha256'], hashlib.sha256(self.apk.read_bytes()).hexdigest())
    def test_unpack_original_untouched_and_no_overwrite(self):
        digest = hashlib.sha256(self.source.read_bytes()).digest(); dest = self.root/'output'
        code, r = self.call('xapk', 'unpack', str(self.source), str(dest))
        self.assertEqual(code, 3, r); self.assertEqual((dest/'base.apk').read_bytes(), self.apk.read_bytes())
        self.assertEqual((dest/'Android/obb/org.example/main.1.org.example.obb').read_bytes(), b'asset-data')
        self.assertEqual(digest, hashlib.sha256(self.source.read_bytes()).digest())
        code, _ = self.call('xapk', 'unpack', str(self.source), str(dest)); self.assertEqual(code, 1)
        self.assertEqual((dest/'base.apk').read_bytes(), self.apk.read_bytes())
    def test_unsafe_paths(self):
        names = ['../escape.apk', '/abs.apk', 'a/../../escape', 'a\\..\\escape', 'C:/evil.apk', 'con.txt', 'dir/./x']
        for name in names:
            with self.subTest(name=name):
                self.write_archive([('base.apk', b'x'), (name, b'x')])
                dest = self.root / 'out'
                code, r = self.call('xapk', 'unpack', str(self.source), str(dest))
                self.assertEqual(code, 1, r); self.assertFalse(dest.exists())
        self.assertFalse((self.root/'escape.apk').exists())
    def test_duplicate_and_conflicting_paths(self):
        for names in [[('base.apk', b'a'), ('BASE.APK', b'b')], [('base.apk', b'a'), ('base.apk/child', b'b')]]:
            self.write_archive(names); code, _ = self.call('xapk', 'inspect', str(self.source)); self.assertEqual(code, 1)
    def test_symlink(self):
        with zipfile.ZipFile(self.source, 'w') as z:
            z.writestr('base.apk', b'fake')
            link = zipfile.ZipInfo('link'); link.create_system = 3; link.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(link, '../outside')
        code, r = self.call('xapk', 'unpack', str(self.source), str(self.root/'out'))
        self.assertEqual(code, 1, r); self.assertFalse((self.root/'out').exists())
    def test_limits(self):
        self.write_archive([('base.apk', b'x'*(1024*1024+1))])
        code, _ = self.call('xapk', 'inspect', str(self.source), '--max-entry-mib', '1'); self.assertEqual(code, 1)
        code, _ = self.call('xapk', 'inspect', str(self.source), '--max-total-mib', '1'); self.assertEqual(code, 1)
        code, _ = self.call('xapk', 'inspect', str(self.source), '--max-total-mib', '2'); self.assertEqual(code, 3)
        code, _ = self.call('inspect', str(self.apk), '--max-total-mib', '0'); self.assertEqual(code, 1)
    def test_corrupt_cleanup(self):
        self.write_archive([('base.apk', b'special-value'), ('a.obb', b'other')])
        raw = self.source.read_bytes().replace(b'special-value', b'Special-value', 1); self.source.write_bytes(raw)
        dest = self.root / 'out'; code, r = self.call('xapk', 'unpack', str(self.source), str(dest))
        self.assertEqual(code, 1, r); self.assertFalse(dest.exists())
        code, _ = self.call('xapk', 'inspect', str(self.source), '--verify'); self.assertEqual(code, 1)
    def test_manifest_references(self):
        self.write_archive([('base.apk', b'fake'), ('manifest.json', json.dumps({'split_apks': [{'file': 'base.apk'}, {'file': 'missing.apk'}]}))])
        code, r = self.call('xapk', 'inspect', str(self.source))
        self.assertEqual(code, 1); self.assertEqual(r['manifest']['missing_apks'], ['missing.apk'])
        self.write_archive([('base.apk', b'fake'), ('manifest.json', json.dumps({'split_apks': [{'file': 'base.apk'}]}))])
        code, r = self.call('xapk', 'inspect', str(self.source))
        self.assertEqual(code, 3); self.assertEqual(r['manifest']['missing_apks'], [])
        self.assertEqual(r['manifest']['status'], 'parsed')
        self.write_archive([('base.apk', b'fake'), ('manifest.json', '{bad json')])
        code, r = self.call('xapk', 'inspect', str(self.source))
        self.assertEqual(code, 1); self.assertEqual(r['manifest']['status'], 'invalid')
    def test_no_apks(self):
        self.write_archive([('manifest.json', b'{}')])
        code, _ = self.call('xapk', 'inspect', str(self.source)); self.assertEqual(code, 1)
        code, _ = self.call('xapk', 'unpack', str(self.source), str(self.root/'out')); self.assertEqual(code, 1)
        self.assertFalse((self.root/'out').exists())
    def test_recursive_apk_inspection(self):
        dest = self.root/'out'
        code, _ = self.call('xapk', 'unpack', str(self.source), str(dest)); self.assertEqual(code, 3)
        with patch('apklab.core.find_tool', return_value=None):
            code, top = self.call('inspect', str(dest))
            self.assertEqual(code, 3); self.assertEqual(len(top['apks']), 1)
            code, all_apks = self.call('inspect', str(dest), '--recursive')
            self.assertEqual(code, 3); self.assertEqual(len(all_apks['apks']), 2)
            self.assertTrue(any('not verified' in e['detail'] for e in all_apks['not_tested']))
    def test_xapk_is_not_apk(self):
        code, r = self.call('inspect', str(self.source))
        self.assertEqual(code, 1); self.assertIn('XAPK is an archive', r['failures'][0]['detail'])
    def test_duplicate_split_names(self):
        second = self.root/'second.apk'; second.write_bytes(self.apk.read_bytes())
        def fake_run(args, timeout=120):
            return {'returncode': 0, 'stdout': "package: name='org.example' versionCode='1' split='config.arm64'", 'stderr': ''}
        with patch('apklab.core.find_tool', side_effect=lambda name: '/aapt' if name == 'aapt' else None), patch('apklab.core.run', side_effect=fake_run):
            code, r = self.call('inspect', str(self.apk), str(second))
        self.assertEqual(code, 1)
        self.assertTrue(any('Duplicate non-empty split names' in x['detail'] for x in r['failures']))
        self.assertEqual(r['apks'][0]['split'], 'config.arm64')

    def test_split_digest_mismatch_and_missing(self):
        from apklab import core
        def fake_run(args, timeout=120):
            if args[0] == '/aapt': out = "package: name='org.example' versionCode='1' versionName='x'"
            else:
                digest = 'a'*64 if str(args[-1]).endswith('source.apk') else 'b'*64
                out = 'Signer #1 certificate SHA-256 digest: ' + digest
            return {'returncode': 0, 'stdout': out, 'stderr': ''}
        another = self.root/'other.apk'; another.write_bytes(self.apk.read_bytes())
        with patch('apklab.core.find_tool', side_effect=lambda x: '/'+x), patch('apklab.core.run', side_effect=fake_run):
            code, r = self.call('inspect', str(self.apk), str(another))
        self.assertEqual(code, 1); self.assertTrue(any('signer certificate' in x['detail'] for x in r['failures']))
        with patch('apklab.core.find_tool', return_value=None):
            code, r = self.call('inspect', str(self.apk), str(another))
        self.assertEqual(code, 3); self.assertTrue(any('Cannot compare signer' in x['detail'] for x in r['not_tested']))

if __name__ == '__main__': unittest.main()
