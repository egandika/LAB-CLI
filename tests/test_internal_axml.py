import contextlib
import io
import json
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from apklab.axml import parse_manifest, ANDROID, NONE
from apklab.cli import main


def fixture(resource=False):
    values = ['manifest', 'package', 'org.example', ANDROID, 'versionCode', 'versionName', '1.2',
              'uses-permission', 'name', 'android.permission.INTERNET', 'application', 'activity', '.Main']
    idx = {s: i for i, s in enumerate(values)}
    def chunk(t, header, content):
        size = 8 + len(content)
        assert size % 4 == 0
        return struct.pack('<HHI', t, header, size) + content
    blob = bytearray(); offsets = []
    for value in values:
        b = value.encode(); offsets.append(len(blob)); blob.extend(bytes([len(value), len(b)]) + b + b'\0')
    blob.extend(b'\0' * (-len(blob) % 4))
    pool = chunk(1, 28, struct.pack('<IIIII', len(values), 0, 0x100, 28 + 4*len(values), 0) + b''.join(struct.pack('<I', o) for o in offsets) + blob)
    def start(tag, attributes=()):
        attrs = b''
        for ns, name, kind, value in attributes:
            val = idx[value] if kind == 3 else value
            attrs += struct.pack('<IIIHBBI', NONE if ns is None else idx[ns], idx[name], NONE, 8, 0, kind, val)
        return chunk(0x102, 16, struct.pack('<II', 1, NONE) + struct.pack('<IIHHHHHH', NONE, idx[tag], 20, 20, len(attributes), 0, 0, 0) + attrs)
    def end(tag): return chunk(0x103, 16, struct.pack('<II', 1, NONE) + struct.pack('<II', NONE, idx[tag]))
    chunks = [pool, start('manifest', [(None, 'package', 3, 'org.example'), (ANDROID, 'versionCode', 0x10, 42), (ANDROID, 'versionName', 1 if resource else 3, 0x7f010001 if resource else '1.2')]),
              start('uses-permission', [(ANDROID, 'name', 3, 'android.permission.INTERNET')]), end('uses-permission'),
              start('application'), start('activity', [(ANDROID, 'name', 3, '.Main')]), end('activity'), end('application'), end('manifest')]
    content = b''.join(chunks)
    return struct.pack('<HHI', 3, 8, 8 + len(content)) + content


class InternalAxmlTests(unittest.TestCase):
    def test_literals_and_unresolved_resource(self):
        parsed = parse_manifest(fixture())
        self.assertEqual((parsed['package'], parsed['version_code'], parsed['version_name']), ('org.example', '42', '1.2'))
        self.assertEqual(parsed['permissions'], ['android.permission.INTERNET'])
        self.assertEqual(parsed['components'], [{'type':'activity','name':'.Main'}])
        parsed = parse_manifest(fixture(True)); self.assertIsNone(parsed['version_name']); self.assertTrue(parsed['unresolved'])
    def test_truncated_and_corrupt_document_rejected(self):
        b = fixture()
        for data in (b[:-1], b'not binary', b[:8] + b'\x01\0\0\0\xff\xff\xff\xff' + b[16:], b[:30]):
            with self.subTest(size=len(data)), self.assertRaises(ValueError): parse_manifest(data)
    def test_cli_fallback_and_tool_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp)/'app.apk'
            with zipfile.ZipFile(apk, 'w') as z: z.writestr('AndroidManifest.xml', fixture())
            def call(*args):
                out = io.StringIO()
                with contextlib.redirect_stdout(out): code = main(list(args))
                return code, json.loads(out.getvalue())
            with patch('apklab.core.find_tool', return_value=None), patch('apklab.cli.find_tool', return_value=None):
                code, inspected = call('inspect', str(apk)); self.assertEqual(code, 3)
                self.assertEqual(inspected['apks'][0]['package'], 'org.example')
                self.assertEqual(inspected['apks'][0]['metadata_source'], 'internal_axml')
                self.assertTrue(inspected['inferences']); self.assertTrue(inspected['not_tested'])
                _, dex = call('dex', str(apk)); self.assertEqual(dex['manifest']['components'][0]['name'], '.Main')
                _, doctor = call('doctor'); self.assertTrue(any(x['feature'] == 'signature verification' and x['missing'] == ['apksigner'] for x in doctor['feature_tools']))
                _, plan = call('setup', '--plan'); self.assertIn('other_linux', plan['plan']['platforms']); self.assertIn('termux_android', plan['plan']['platforms'])
