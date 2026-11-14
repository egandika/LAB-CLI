import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from apklab.cli import main

class WorkflowImprovements(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.apk = self.root/'input.apk'
        with zipfile.ZipFile(self.apk, 'w') as z: z.writestr('AndroidManifest.xml', 'fixture')
        self.archive = self.root/'input.xapk'
    def call(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out): code = main(list(args))
        return code, json.loads(out.getvalue())
    def test_verify_reports_4_and_16_independently(self):
        work = self.root/'work'; self.call('work', 'init', str(self.apk), str(work))
        (work/'signed.apk').write_bytes(self.apk.read_bytes())
        def run(args, timeout=120):
            return {'returncode':1 if '-P' in args else 0,'stdout':'not aligned' if '-P' in args else '', 'stderr':''}
        with patch('apklab.cli.find_tool', return_value='/fake'), patch('apklab.cli.supports_16k', return_value=True), patch('apklab.cli.run', side_effect=run):
            code, r = self.call('work', 'verify', str(work))
        self.assertEqual(code, 1); self.assertEqual(set(r['checks']), {'zipalign','zipalign_16k','apksigner'})
        self.assertTrue(any(x['subject']=='zipalign' for x in r['verified']))
        self.assertTrue(any(x['subject']=='zipalign_16k' for x in r['failures']))
    def test_build_diagnostics(self):
        work = self.root/'work'; self.call('work', 'init', str(self.apk), str(work)); (work/'decoded').mkdir()
        with patch('apklab.workflow.find_tool', return_value='/fake'), patch('apklab.workflow.run', return_value={'returncode':1,'stdout':'','stderr':'resource error'}):
            code, r = self.call('work','build',str(work))
        self.assertEqual(code,1); self.assertIn('resource error',r['failures'][0]['detail']); self.assertIn('Next:',r['failures'][0]['detail'])
    def write_xapk(self, location='Android/obb/org.example/', declare=True):
        item = {'file':'main.1.org.example.obb','install_location':location}
        with zipfile.ZipFile(self.archive, 'w') as z:
            z.write(self.apk, 'base.apk')
            z.writestr('main.1.org.example.obb', b'obb')
            z.writestr('manifest.json', json.dumps({'package_name':'org.example','expansions':[item] if declare else [], 'split_apks':[{'file':'base.apk'}]}))
    def test_directory_repack_validates_and_copies_obb(self):
        self.write_xapk(); original = self.archive.read_bytes(); dest = self.root/'output'
        code, r = self.call('xapk','repack',str(self.archive),str(dest),'--directory')
        self.assertEqual(code, 3, r); self.assertEqual((dest/'Android/obb/org.example/main.1.org.example.obb').read_bytes(), b'obb')
        self.assertTrue(zipfile.is_zipfile(dest/'repacked.xapk')); self.assertEqual(original,self.archive.read_bytes())
        code, _ = self.call('xapk','repack',str(self.archive),str(dest),'--directory'); self.assertEqual(code,1)
    def test_directory_repack_refuses_invalid_manifest(self):
        for location, declare in [('Android/obb/other/', True), ('Android/obb/org.example/', False)]:
            self.write_xapk(location,declare); original = self.archive.read_bytes(); dest = self.root/'output'
            code, r = self.call('xapk','repack',str(self.archive),str(dest),'--directory')
            self.assertEqual(code,1,r); self.assertFalse(dest.exists()); self.assertEqual(original,self.archive.read_bytes())
