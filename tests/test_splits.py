import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from apklab.cli import main


class SplitWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.a = self.root/'base.apk'; self.b = self.root/'split.apk'
        for file in (self.a, self.b):
            with zipfile.ZipFile(file, 'w') as z: z.writestr('AndroidManifest.xml', file.name)
        self.workspace = self.root/'set'
    def call(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out): code = main(list(args))
        return code, json.loads(out.getvalue())
    def init(self):
        code, r = self.call('splits','init',str(self.workspace),str(self.a),str(self.b)); self.assertEqual(code, 3,r)
    def test_init_copies_files_and_refuses_existing_workspace(self):
        self.init()
        self.assertEqual((self.workspace/'apk-0000/original.apk').read_bytes(),self.a.read_bytes())
        self.assertEqual((self.workspace/'apk-0001/original.apk').read_bytes(),self.b.read_bytes())
        code, _ = self.call('splits','init',str(self.workspace),str(self.a)); self.assertEqual(code,1)
        self.assertTrue(self.a.exists()); self.assertTrue(self.b.exists())
    def test_run_all_and_report_partial_failure(self):
        self.init(); calls = []
        def fake(stage, folder, source, output, key, alias, env, page):
            calls.append((stage, folder, key, alias, env, page))
            if folder.endswith('apk-0001'): raise RuntimeError('example failure')
            return folder + '/decoded', {'returncode':0,'stdout':'','stderr':''}
        with patch('apklab.cli.perform', side_effect=fake):
            code, r = self.call('splits','run',str(self.workspace),'decode')
        self.assertEqual(code,1); self.assertEqual(len(calls),2)
        self.assertEqual(len(r['verified']),1); self.assertEqual(len(r['failures']),1)
        self.assertTrue(r['not_tested'])
    def test_sign_uses_same_identity_and_requires_parameters(self):
        self.init(); calls=[]
        def fake(stage, folder, source, output, key, alias, env, page):
            calls.append((key,alias,env)); return folder+'/signed.apk', {'returncode':0,'stdout':'','stderr':''}
        with patch('apklab.cli.perform', side_effect=fake):
            code, _ = self.call('splits','run',str(self.workspace),'sign'); self.assertEqual(code,1); self.assertFalse(calls)
            code, r = self.call('splits','run',str(self.workspace),'sign','--keystore','key.jks','--alias','mykey','--pass-env','PASSWORD_NAME')
        self.assertEqual(code, 3,r); self.assertEqual(calls,[('key.jks','mykey','PASSWORD_NAME')]*2)
    def test_tampered_copy_and_metadata_are_rejected(self):
        self.init(); (self.workspace/'apk-0000/original.apk').write_bytes(b'changed')
        code, r = self.call('splits','run',str(self.workspace),'decode'); self.assertEqual(code,1,r)
        data = json.loads((self.workspace/'split-set.json').read_text()); data['members'][0]['id'] = '../evil'
        (self.workspace/'split-set.json').write_text(json.dumps(data))
        code, r = self.call('splits','run',str(self.workspace),'decode'); self.assertEqual(code,1,r)
    def test_no_duplicate_inputs(self):
        code, _ = self.call('splits','init',str(self.workspace),str(self.a),str(self.a))
        self.assertEqual(code,1); self.assertFalse(self.workspace.exists())

if __name__ == '__main__': unittest.main()
