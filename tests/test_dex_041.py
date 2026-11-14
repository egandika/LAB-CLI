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
from apklab.dex import read_dex, UnsupportedDexContainer


def container():
    b = bytearray(120); b[:8] = b'dex\n041\0'
    struct.pack_into('<III', b, 32, 120, 120, 0x12345678)
    struct.pack_into('<II', b, 112, 120, 0)
    return bytes(b)


class DexContainerTests(unittest.TestCase):
    def test_unsupported_container_distinct_from_malformed(self):
        with self.assertRaises(UnsupportedDexContainer): read_dex(container())
        for b in (container()[:20], container()[:112]+b'\x00'*8):
            with self.assertRaises(ValueError) as caught: read_dex(b)
            self.assertNotIsInstance(caught.exception, UnsupportedDexContainer)
    def test_cli_per_entry_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp)/'a.apk'
            with zipfile.ZipFile(apk, 'w') as z:
                z.writestr('AndroidManifest.xml', 'synthetic')
                z.writestr('classes.dex', container())
                z.writestr('classes2.dex', container()[:20])
            out = io.StringIO()
            with contextlib.redirect_stdout(out), patch('apklab.cli.find_tool', return_value=None):
                code = main(['dex', str(apk)])
            r = json.loads(out.getvalue()); self.assertEqual(code, 1)
            self.assertTrue(any(x['subject'] == 'classes.dex' and '041' in x['detail'] for x in r['not_tested']))
            self.assertTrue(any(x['subject'] == 'classes2.dex' and 'Truncated' in x['detail'] for x in r['failures']))
            self.assertEqual(r['dex_files'][0]['status'], 'not_tested')
