import contextlib
import hashlib
import io
import json
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest.mock import patch
from apklab.cli import main
from apklab.dex_integrity import check_integrity


def dex():
    b = bytearray(112); b[:8] = b'dex\n035\0'
    struct.pack_into('<III', b, 32, len(b), 112, 0x12345678)
    b[12:32] = hashlib.sha1(b[32:]).digest()
    struct.pack_into('<I', b, 8, zlib.adler32(b[12:]) & 0xffffffff)
    return bytes(b)


class DexIntegrityTests(unittest.TestCase):
    def test_digests_corruption_unsupported_and_truncated(self):
        good = dex(); self.assertTrue(check_integrity(good)['sha1_matches']); self.assertTrue(check_integrity(good)['adler32_matches'])
        b = bytearray(good); b[48] ^= 1
        self.assertFalse(check_integrity(b)['sha1_matches']); self.assertFalse(check_integrity(b)['adler32_matches'])
        self.assertEqual(check_integrity(b'dex\n041\0')['status'], 'not_tested')
        self.assertEqual(check_integrity(b'dex\n999\0')['status'], 'not_tested')
        with self.assertRaises(ValueError): check_integrity(good[:40])
    def test_cli_and_input_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'x.apk'; bad = bytearray(dex()); bad[8] ^= 1
            with zipfile.ZipFile(p, 'w') as z: z.writestr('AndroidManifest.xml', 'x'); z.writestr('classes.dex', dex()); z.writestr('classes2.dex', bad)
            before = p.read_bytes(); out = io.StringIO()
            with patch('apklab.cli.find_tool', return_value=None), contextlib.redirect_stdout(out): code = main(['dex', str(p), '--check-integrity'])
            r = json.loads(out.getvalue()); self.assertEqual(code, 1, r)
            self.assertTrue(r['dex_integrity'][0]['sha1_matches']); self.assertFalse(r['dex_integrity'][1]['adler32_matches'])
            self.assertEqual(before, p.read_bytes())

if __name__ == '__main__': unittest.main()
