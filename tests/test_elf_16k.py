import contextlib
import io
import json
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from apklab.elf import load_alignment, UnsupportedElf
from apklab.cli import main


def elf64(align=16384, offset=0, vaddr=0):
    ident = b'\x7fELF\x02\x01\x01' + b'\0'*9
    header = struct.pack('<HHIQQQIHHHHHH',3,183,1,0,64,0,0,64,56,1,0,0,0)
    program = struct.pack('<IIQQQQQQ',1,5,offset,vaddr,0,0,0,align)
    return ident + header + program


class ElfAlignmentTests(unittest.TestCase):
    def test_valid_invalid_and_unsupported(self):
        self.assertTrue(load_alignment(elf64())['aligned_16k'])
        self.assertFalse(load_alignment(elf64(4096))['aligned_16k'])
        for bad in (b'ELF', elf64(3000), elf64(16384, 1, 0), elf64()[:80]):
            with self.subTest(bad=bad[:8]), self.assertRaises(ValueError): load_alignment(bad)
        unsupported = bytearray(elf64()); unsupported[4] = 3
        with self.assertRaises(UnsupportedElf): load_alignment(unsupported)
    def test_work_verify_reports_each_library(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); apk = root/'source.apk'; work = root/'work'
            with zipfile.ZipFile(apk,'w') as z:
                z.writestr('AndroidManifest.xml','fixture')
                z.writestr('lib/arm64/good.so',elf64())
                z.writestr('lib/arm64/old.so',elf64(4096))
                z.writestr('lib/arm64/bad.so',b'broken')
            with contextlib.redirect_stdout(io.StringIO()): main(['work','init',str(apk),str(work)])
            (work/'signed.apk').write_bytes(apk.read_bytes())
            out = io.StringIO()
            with contextlib.redirect_stdout(out), patch('apklab.cli.find_tool',return_value=None): code = main(['work','verify',str(work)])
            r = json.loads(out.getvalue()); self.assertEqual(code,1)
            self.assertEqual(len(r['elf_16k']),3)
            self.assertTrue(any(x['subject'].endswith('good.so') for x in r['verified']))
            self.assertTrue(any(x['subject'].endswith('old.so') for x in r['failures']))
            self.assertTrue(any(x['subject'].endswith('bad.so') for x in r['failures']))
