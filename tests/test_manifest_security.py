import contextlib
import io
import json
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from apklab.axml import ANDROID, NONE, parse_manifest
from apklab.cli import main


def fixture(exported_kind=0x12, exported_value=1, ns=ANDROID):
    strings = ['manifest', 'application', 'activity', ANDROID, 'name', '.Main', 'exported', 'debuggable', 'permission', 'org.example.PERMISSION', ns]
    strings = list(dict.fromkeys(strings)); index = {s: i for i, s in enumerate(strings)}
    blob = bytearray(); offsets = []
    for s in strings:
        b = s.encode(); offsets.append(len(blob)); blob.extend(bytes([len(s), len(b)]) + b + b'\0')
    blob.extend(b'\0' * (-len(blob) % 4))
    def chunk(t, h, data): return struct.pack('<HHI', t, h, len(data) + 8) + data
    pool = chunk(1, 28, struct.pack('<IIIII', len(strings), 0, 0x100, 28 + 4 * len(strings), 0) + b''.join(struct.pack('<I', x) for x in offsets) + blob)
    def start(tag, attrs=()):
        encoded = b''.join(struct.pack('<IIIHBBI', index[n], index[k], NONE, 8, 0, t, index[v] if t == 3 else v) for n, k, t, v in attrs)
        return chunk(0x102, 16, struct.pack('<II', 1, NONE) + struct.pack('<IIHHHHHH', NONE, index[tag], 20, 20, len(attrs), 0, 0, 0) + encoded)
    def end(tag): return chunk(0x103, 16, struct.pack('<IIII', 1, NONE, NONE, index[tag]))
    content = pool + start('manifest') + start('application', [(ANDROID, 'debuggable', 0x12, 1)]) + start('activity', [(ANDROID, 'name', 3, '.Main'), (ns, 'exported', exported_kind, exported_value), (ANDROID, 'permission', 3, 'org.example.PERMISSION')]) + end('activity') + end('application') + end('manifest')
    return struct.pack('<HHI', 3, 8, len(content)+8) + content


class ManifestSecurityTests(unittest.TestCase):
    def test_literals_unknown_and_unusual_namespace(self):
        result = parse_manifest(fixture())['security']
        self.assertTrue(result['application']['debuggable']['value'])
        self.assertTrue(result['components'][0]['attributes']['exported']['value'])
        self.assertEqual(result['components'][0]['attributes']['permission']['value'], 'org.example.PERMISSION')
        for data in (fixture(1, 0x7f010001), fixture(ns='other.namespace')):
            self.assertEqual(parse_manifest(data)['security']['components'][0]['attributes']['exported']['status'], 'unknown')
    def test_cli_inferences_and_no_vulnerability_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp)/'x.apk'
            with zipfile.ZipFile(apk,'w') as z: z.writestr('AndroidManifest.xml', fixture())
            before = apk.read_bytes(); out = io.StringIO()
            with patch('apklab.core.find_tool', return_value=None), patch('apklab.split_metadata.find_tool', return_value=None), contextlib.redirect_stdout(out):
                code = main(['inspect', str(apk), '--manifest-security'])
            r = json.loads(out.getvalue()); self.assertEqual(code, 3, r)
            self.assertTrue(r['manifest_security'][0]['components'][0]['attributes']['exported']['value'])
            self.assertTrue(any(x['subject'] == 'manifest security' for x in r['not_tested']))
            self.assertFalse(r['failures']); self.assertEqual(before, apk.read_bytes())

if __name__ == '__main__': unittest.main()
