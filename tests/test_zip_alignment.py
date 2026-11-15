import contextlib
import io
import json
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from apklab.cli import main
from apklab.zip_alignment import native_offsets


class ZipAlignmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'fixture.apk'
    def make(self, aligned=False, compressed=False):
        with zipfile.ZipFile(self.path, 'w') as z:
            z.writestr('AndroidManifest.xml', b'fixture')
            info = zipfile.ZipInfo('lib/x86_64/libfixture.so')
            info.compress_type = zipfile.ZIP_DEFLATED if compressed else zipfile.ZIP_STORED
            if aligned:
                pad = (-(z.fp.tell() + 30 + len(info.filename.encode()) + 4)) % 16384
                info.extra = struct.pack('<HH', 0xcafe, pad) + b'\0' * pad
            z.writestr(info, b'synthetic native')
    def call(self):
        output = io.StringIO()
        with patch('apklab.core.find_tool', return_value=None), patch('apklab.split_metadata.find_tool', return_value=None), contextlib.redirect_stdout(output):
            code = main(['inspect', str(self.path), '--zip-alignment', '16'])
        return code, json.loads(output.getvalue())
    def test_aligned_and_unaligned_and_input_unchanged(self):
        for aligned in (False, True):
            self.make(aligned); original = self.path.read_bytes(); code, r = self.call()
            self.assertEqual(code, 3 if aligned else 1, r)
            self.assertEqual(r['zip_alignment'][0]['libraries'][0]['aligned'], aligned)
            self.assertEqual(original, self.path.read_bytes())
    def test_compressed_is_not_tested(self):
        self.make(compressed=True); code, result = self.call()
        self.assertEqual(code, 3); self.assertEqual(result['zip_alignment'][0]['libraries'][0]['status'], 'not_tested')
    def test_corrupt_local_header_rejected(self):
        self.make(); data = bytearray(self.path.read_bytes())
        with zipfile.ZipFile(self.path) as z: offset = z.getinfo('lib/x86_64/libfixture.so').header_offset
        data[offset:offset+4] = b'bad!'; self.path.write_bytes(data)
        with self.assertRaises(ValueError): native_offsets(self.path)

if __name__ == '__main__': unittest.main()
