import struct
import unittest
from unittest.mock import patch
from apklab.dex import read_dex


def dex_with_shared_parameters(n_protos, n_params):
    strings = 112; types = 116; protos = 120
    params = protos + n_protos * 12
    text = params + 4 + n_params * 2
    data = bytearray(text + 3)
    data[:8] = b'dex\n035\0'
    def put(off, value): struct.pack_into('<I', data, off, value)
    put(32, len(data)); put(36, 112); put(40, 0x12345678)
    for offset, count, start in [(56, 1, strings), (64, 1, types), (72, n_protos, protos)]:
        put(offset, count); put(offset+4, start)
    put(strings, text); put(types, 0)
    for i in range(n_protos): struct.pack_into('<III', data, protos + 12*i, 0, 0, params)
    put(params, n_params)
    data[text:] = b'\x01V\0'
    return bytes(data)

class DexWorkLimitsTests(unittest.TestCase):
    def test_repeated_parameter_list_has_cumulative_limit(self):
        sample = dex_with_shared_parameters(3, 4)
        with patch('apklab.dex.MAX_TOTAL_PARAMETERS', 11):
            with self.assertRaisesRegex(ValueError, 'total prototype parameters'):
                read_dex(sample)
        with patch('apklab.dex.MAX_TOTAL_PARAMETERS', 12):
            self.assertEqual(read_dex(sample)['classes'], [])
    def test_parameter_rendering_and_cumulative_text_are_bounded(self):
        sample = dex_with_shared_parameters(3, 4)
        with patch('apklab.dex.MAX_PROTO_CHARS', 20):
            with self.assertRaisesRegex(ValueError, 'total prototype text'):
                read_dex(sample)
        with patch('apklab.dex.MAX_PROTO_CHARS', 5):
            with self.assertRaisesRegex(ValueError, 'prototype text'):
                read_dex(sample)

    def test_method_references_cannot_amplify_a_large_prototype(self):
        data = bytearray(dex_with_shared_parameters(1, 4))
        data.extend(b'\0' * (-len(data) % 4))
        method_offset = len(data)
        data.extend(struct.pack('<HHI', 0, 0, 0) * 3)
        struct.pack_into('<I', data, 32, len(data))
        struct.pack_into('<II', data, 88, 3, method_offset)
        with patch('apklab.dex.MAX_METHOD_CHARS', 20):
            with self.assertRaisesRegex(ValueError, 'total method text'):
                read_dex(data)
        with patch('apklab.dex.MAX_METHOD_CHARS', 100):
            self.assertEqual(len(read_dex(data)['methods']), 3)
