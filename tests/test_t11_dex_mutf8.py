import contextlib
import io
import json
import struct
import unittest

from apklab.core import emit, report
from apklab.dex import read_dex
from test_apklab import tiny_dex


def one_string(payload):
    data = bytearray(116)
    data[:8] = b'dex\n035\0'
    data.extend(payload)
    struct.pack_into('<III', data, 32, len(data), 112, 0x12345678)
    struct.pack_into('<II', data, 56, 1, 112)
    struct.pack_into('<I', data, 112, 116)
    return bytes(data)


class DexMutf8Tests(unittest.TestCase):
    def test_nul_supplementary_and_surrogate_units(self):
        # U+0000 uses C0 80; U+1F600 is encoded as a UTF-16 surrogate pair.
        payload = b'\x05A\xc0\x80\xed\xa0\xbd\xed\xb8\x80Z\x00'
        self.assertEqual(read_dex(one_string(payload))['strings'], ['A\0😀Z'])
        result = read_dex(one_string(b'\x01\xed\xa0\x80\x00'))
        self.assertEqual(result['strings'], ['\ud800'])
        r = report(); r.update(result)
        output = io.StringIO()
        with contextlib.redirect_stdout(output): emit(r)
        self.assertEqual(json.loads(output.getvalue())['strings'], ['\ud800'])
        self.assertIn('\\ud800', output.getvalue())

    def test_invalid_mutf_and_lengths_are_rejected(self):
        samples = [b'\x01\xc1\x81\x00', b'\x01\xe0\x80\x80\x00',
                   b'\x02\xf0\x9f\x98\x80\x00', b'\x01\xc2\x00',
                   b'\x01\x80\x00', b'\x02A\x00', b'\x00A\x00',
                   b'\x01A', b'\xff\xff\xff\xff\x10A\x00',
                   b'\x80\x80\x80\x80\x80\x00']
        for sample in samples:
            with self.subTest(sample=sample), self.assertRaises(ValueError): read_dex(one_string(sample))

    def test_utf16_count_is_units_not_codepoints(self):
        valid = b'\x02\xed\xa0\xbd\xed\xb8\x80\x00'
        self.assertEqual(read_dex(one_string(valid))['strings'], ['😀'])
        with self.assertRaisesRegex(ValueError, 'length mismatch'):
            read_dex(one_string(b'\x01' + valid[1:]))

    def test_unsupported_version_and_invalid_table_offsets(self):
        for version in (b'000', b'036', b'041', b'999'):
            data = bytearray(tiny_dex()); data[4:7] = version
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, 'unsupported'):
                read_dex(data)
        for offset in (4, 113, 0xfffffff0):
            data = bytearray(tiny_dex()); struct.pack_into('<I', data, 60, offset)
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, 'DEX table'):
                read_dex(data)

    def test_shorty_and_field_table_bounds_are_validated(self):
        data = bytearray(tiny_dex()); proto = struct.unpack_from('<I', data, 76)[0]
        struct.pack_into('<I', data, proto, 999)
        with self.assertRaisesRegex(ValueError, 'string index'): read_dex(data)
        data = bytearray(tiny_dex()); struct.pack_into('<II', data, 80, 1, len(data) - 1)
        with self.assertRaisesRegex(ValueError, 'DEX table'): read_dex(data)
