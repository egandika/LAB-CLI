import contextlib
import hashlib
import io
import json
import os
import stat
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from apklab.cli import main
from apklab.dex import read_dex


def tiny_dex():
    # Minimal index-bearing DEX fixture; no executable class data/code items.
    strings = [b'Lcom/example/model/User;', b'V', b'load', b'https://example.org/api']
    header = bytearray(112); header[:8] = b'dex\n035\0'
    string_ids = 112; types = string_ids + len(strings) * 4
    protos = types + 8; methods = protos + 12; classes = methods + 8
    data_off = classes + 32
    data = bytearray(); offsets = []
    for s in strings:
        offsets.append(data_off + len(data)); data.extend(bytes([len(s)]) + s + b'\0')
    result = header + bytearray(len(strings)*4 + 8 + 12 + 8 + 32) + data
    def put(off, val): struct.pack_into('<I', result, off, val)
    put(32, len(result)); put(36, 112); put(40, 0x12345678)
    for off, count, start in [(56, len(strings), string_ids), (64, 2, types), (72, 1, protos), (88, 1, methods), (96, 1, classes)]:
        put(off, count); put(off+4, start)
    for i, o in enumerate(offsets): put(string_ids + i*4, o)
    put(types, 0); put(types+4, 1)
    struct.pack_into('<III', result, protos, 1, 1, 0)
    struct.pack_into('<HHI', result, methods, 0, 0, 2)
    put(classes, 0)
    return bytes(result)


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.apk = self.root / 'fixture.apk'
        with zipfile.ZipFile(self.apk, 'w') as z:
            z.writestr('AndroidManifest.xml', 'synthetic manifest')
            z.writestr('classes.dex', tiny_dex())
            z.writestr('assets/config.json', '{}')
            z.writestr('lib/arm64-v8a/libfake.so', 'not an ELF')
    def call(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out): code = main(list(args))
        return code, json.loads(out.getvalue())
    def test_dex_index(self):
        d = read_dex(tiny_dex())
        self.assertEqual(d['classes'], ['Lcom/example/model/User;'])
        self.assertEqual(d['methods'], ['Lcom/example/model/User;->load()V'])
        self.assertEqual(d['endpoints'], ['https://example.org/api'])
        with patch('apklab.cli.find_tool', return_value=None):
            code, result = self.call('dex', str(self.apk))
        self.assertEqual(code, 3); self.assertEqual(result['dex_files'][0]['counts']['methods'], 1)
        self.assertTrue(result['inferences']); self.assertTrue(result['not_tested'])
    def test_invalid_dex(self):
        with self.assertRaises(ValueError): read_dex(b'dex\n035\0')
        bad = bytearray(tiny_dex()); struct.pack_into('<I', bad, 56, 0xffffffff)
        with self.assertRaises(ValueError): read_dex(bad)
    def test_inspect_and_splits(self):
        with patch('apklab.core.find_tool', return_value=None):
            code, r = self.call('inspect', str(self.apk), str(self.apk))
        self.assertEqual(code, 3); self.assertEqual(r['apks'][0]['architectures'], ['arm64-v8a'])
        self.assertIsNone(r['apks'][0]['package']); self.assertTrue(r['not_tested'])
    def test_metadata_and_signature_tools(self):
        def find(t): return '/tool/' + t if t in ('aapt', 'apksigner') else None
        def run(args, timeout=120):
            text = "package: name='com.example' versionCode='7' versionName='1.0'" if args[0].endswith('aapt') else 'Verified using v2 scheme: true'
            return {'returncode': 0, 'stdout': text, 'stderr': ''}
        with patch('apklab.core.find_tool', side_effect=find), patch('apklab.core.run', side_effect=run):
            code, r = self.call('inspect', str(self.apk))
        self.assertEqual(code, 3); self.assertEqual(r['apks'][0]['package'], 'com.example')
        self.assertTrue(any('signature' not in x['detail'].lower() and 'apksigner' in x['detail'] for x in r['verified']))
    def test_bad_zip_and_missing_manifest(self):
        p = self.root/'bad.apk'; p.write_bytes(b'garbage')
        code, r = self.call('inspect', str(p)); self.assertEqual(code, 1); self.assertTrue(r['failures'])
        with zipfile.ZipFile(p, 'w') as z: z.writestr('x', 'x')
        code, r = self.call('inspect', str(p)); self.assertEqual(code, 1)
    def test_inventory(self):
        code, r = self.call('inventory', str(self.apk), '--search', 'arm64')
        self.assertEqual(code, 3); self.assertEqual(len(r['files']), 1)
        code, r = self.call('inventory', str(self.apk), '--native-details')
        if os.system('command -v readelf >/dev/null 2>&1') == 0:
            self.assertEqual(code, 1); self.assertTrue(r['failures'])
    def test_crc_corruption(self):
        p = self.root/'corrupt.apk'
        with zipfile.ZipFile(p, 'w', compression=zipfile.ZIP_STORED) as z:
            z.writestr('AndroidManifest.xml', 'unique-metadata')
        raw = p.read_bytes().replace(b'unique-metadata', b'unique-Metadata', 1)
        p.write_bytes(raw)
        code, r = self.call('inspect', str(p))
        self.assertEqual(code, 1); self.assertTrue(any('CRC' in x['detail'] for x in r['failures']))
    def test_real_readelf(self):
        import shutil
        if not shutil.which('readelf') or not Path('/bin/true').is_file():
            self.skipTest('readelf or /bin/true unavailable')
        p = self.root/'native.apk'
        with zipfile.ZipFile(p, 'w') as z:
            z.writestr('AndroidManifest.xml', 'fixture')
            z.writestr('lib/test/libtest.so', Path('/bin/true').read_bytes())
        code, r = self.call('inventory', str(p), '--native-details')
        self.assertEqual(code, 3); self.assertIn('ELF Header', r['files'][0]['readelf'])
    def test_workspace_immutability(self):
        before = hashlib.sha256(self.apk.read_bytes()).hexdigest(); workspace = self.root/'work'
        code, r = self.call('work', 'init', str(self.apk), str(workspace)); self.assertEqual(code, 0)
        self.assertEqual((workspace/'original.apk').read_bytes(), self.apk.read_bytes())
        code, _ = self.call('work', 'init', str(self.apk), str(workspace)); self.assertEqual(code, 1)
        code, _ = self.call('work', 'decode', str(workspace), '--output', '../fixture.apk'); self.assertEqual(code, 1)
        self.assertEqual(before, hashlib.sha256(self.apk.read_bytes()).hexdigest())
    def test_workflow_with_fake_tools(self):
        workspace = self.root/'work'; self.call('work', 'init', str(self.apk), str(workspace))
        def run(args, timeout=600):
            # Simulate an external tool writing its expected output.
            if 'd' in args: Path(args[args.index('-o') + 1]).mkdir()
            elif 'b' in args: Path(args[args.index('-o') + 1]).write_bytes(b'apk')
            elif 'sign' in args: Path(args[args.index('--out') + 1]).write_bytes(b'signed')
            else: Path(args[-1]).write_bytes(b'aligned')
            return {'returncode': 0, 'stdout': '', 'stderr': ''}
        with patch('apklab.workflow.find_tool', return_value='/fake/tool'), patch('apklab.workflow.run', side_effect=run), patch.dict(os.environ, {'TEST_PASS': 'secret'}):
            for stage in ('decode', 'build', 'align'):
                code, r = self.call('work', stage, str(workspace)); self.assertEqual(code, 3, r)
            code, r = self.call('work', 'sign', str(workspace), '--keystore', 'test.jks', '--alias', 'test', '--pass-env', 'TEST_PASS')
            self.assertEqual(code, 3); self.assertNotIn('secret', json.dumps(r))
            code, r = self.call('work', 'decode', str(workspace)); self.assertEqual(code, 1)
    def test_report_no_overwrite(self):
        before = self.apk.read_bytes()
        code, _ = self.call('doctor', '--report', str(self.apk))
        self.assertEqual(code, 1); self.assertEqual(before, self.apk.read_bytes())
    def test_setup_plan(self):
        code, r = self.call('setup'); self.assertEqual(code, 3); self.assertTrue(r['plan']); self.assertTrue(r['not_tested'])

if __name__ == '__main__': unittest.main()
