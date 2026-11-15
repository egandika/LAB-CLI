import contextlib
import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from apklab.cli import main
from apklab.split_metadata import assess_outputs


class SplitXapkUpdateTests(unittest.TestCase):
    def call(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out): code = main(list(args))
        return code, json.loads(out.getvalue())
    def test_base_requires_split_and_unknown_is_not_failure(self):
        base = {'id':'base', 'apk':{'package':'a.b','version_code':'1','split':None,'signer_sha256':['a'*64]},
                'dependencies':{'status':'observed','is_split_required':True}}
        self.assertTrue(any('requires at least one' in x for x in assess_outputs([base])['issues']))
        base['dependencies']['status'] = 'partial'
        result = assess_outputs([base]); self.assertFalse(result['issues']); self.assertIn('dependency declarations', result['unknown'])
    def test_inspect_surfaces_missing_declared_split(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp)/'a.apk'
            with zipfile.ZipFile(apk,'w') as z: z.writestr('AndroidManifest.xml', 'fixture')
            identity = {'file':str(apk),'package':'a.b','version_code':'1','split':None,'signer_sha256':['a'*64], 'architectures':[], 'entries':1}
            with patch('apklab.cli.inspect_one', return_value=identity), patch('apklab.cli.read_dependencies', return_value={'status':'observed','uses_splits':['feature'], 'is_split_required':True}):
                code, r = self.call('inspect',str(apk))
            self.assertEqual(code,1); self.assertTrue(any('Missing declared' in x['detail'] for x in r['failures']))
    def test_duplicate_json_keys_rejected_across_xapk_operations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); xapk = root / 'source.xapk'
            manifests = (
                '{"split_apks":[{"file":"missing.apk"}],"split_apks":[{"file":"base.apk"}]}',
                '{"split_apks":[{"file":"missing.apk","file":"base.apk"}]}',
            )
            for index, manifest in enumerate(manifests):
                with zipfile.ZipFile(xapk, 'w') as z:
                    z.writestr('base.apk', b'synthetic'); z.writestr('manifest.json', manifest)
                for command in ('inspect', 'unpack', 'repack'):
                    target = root / ('out-%s-%s' % (index, command))
                    args = ['xapk', command, str(xapk)] + ([] if command == 'inspect' else [str(target)])
                    code, result = self.call(*args)
                    self.assertEqual(code, 1, result)
                    self.assertTrue(any('Duplicate JSON key' in x['detail'] for x in result['failures']), result)
                    if command != 'inspect': self.assertFalse(target.exists())

    def test_update_manifest_and_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); apk = root/'new.apk'; xapk = root/'source.xapk'
            with zipfile.ZipFile(apk,'w') as z: z.writestr('AndroidManifest.xml','new')
            manifest = json.dumps({'split_apks':[{'file':'base.apk','size':1,'sha256':'old'}], 'other':'unchanged'})
            with zipfile.ZipFile(xapk,'w') as z: z.writestr('base.apk',b'old'); z.writestr('manifest.json',manifest)
            original = xapk.read_bytes()
            for update in (False, True):
                dest = root/('updated.xapk' if update else 'default.xapk')
                args = ['xapk','repack',str(xapk),str(dest),'--replace','base.apk='+str(apk)]
                if update: args += ['--update-manifest']
                code, result = self.call(*args); self.assertEqual(code,3,result)
                with zipfile.ZipFile(dest) as z:
                    self.assertEqual(z.read('base.apk'),apk.read_bytes())
                    m = json.loads(z.read('manifest.json'))
                    if update:
                        self.assertEqual(m['split_apks'][0]['size'], apk.stat().st_size)
                        self.assertEqual(m['split_apks'][0]['sha256'],hashlib.sha256(apk.read_bytes()).hexdigest())
                        self.assertTrue(any('not validated' in x['detail'] for x in result['not_tested']))
                    else: self.assertEqual(z.read('manifest.json').decode(),manifest)
            self.assertEqual(xapk.read_bytes(),original)
    def test_update_rejects_ambiguous_manifest_without_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); apk = root/'new.apk'; xapk = root/'source.xapk'
            with zipfile.ZipFile(apk,'w') as z: z.writestr('AndroidManifest.xml','new')
            for m in ('{}', '{"split_apks":[{"file":"base.apk","md5":"old"}]}', '{"split_apks":[],"split_apks":[]}'):
                with zipfile.ZipFile(xapk,'w') as z: z.writestr('base.apk',b'old'); z.writestr('manifest.json',m)
                dest = root/'dest.xapk'; code, r = self.call('xapk','repack',str(xapk),str(dest),'--replace','base.apk='+str(apk),'--update-manifest')
                self.assertEqual(code,1,r); self.assertFalse(dest.exists())
