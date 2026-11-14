import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from apklab.cli import main
from apklab.core import add, inspect_one, report
from apklab.split_metadata import assess_outputs, parse_dependencies, read_dependencies


class SplitDependencyParsingTests(unittest.TestCase):
    def test_declared_attributes_and_uses_split(self):
        tree = '''E: manifest (line=1)
  A: android:isFeatureSplit(0x0101055b)=(type 0x12)0xffffffff
  A: android:configForSplit(0x01010591)="feature.camera" (Raw: "feature.camera")
  A: android:versionCodeMajor(0x01010576)=(type 0x10)0x2
  E: uses-split (line=2)
    A: android:name(0x01010003)="feature.maps" (Raw: "feature.maps")
  E: application (line=3)
    A: android:isSplitRequired(0x01010592)=(type 0x12)0x0
'''
        dep = parse_dependencies(tree)
        self.assertEqual(dep['status'], 'observed'); self.assertEqual(dep['uses_splits'], ['feature.maps'])
        self.assertEqual(dep['config_for_split'], 'feature.camera'); self.assertTrue(dep['is_feature_split']); self.assertFalse(dep['is_split_required']); self.assertEqual(dep['version_code_major'], 2)

    def test_truncated_resource_and_missing_name_are_unknown(self):
        for tree, truncated in [('E: manifest\n  E: uses-split\n    A: android:name="camera"', True),
                                ('E: manifest\n  A: android:configForSplit=@0x7f010001\n', False),
                                ('E: manifest\n  E: uses-split\n', False),
                                ('E: manifest\n  A: android:configForSplit="@string/name"\n', False),
                                ('E: manifest\n  A: android:isFeatureSplit=(type 0x01)0x1\n', False)]:
            with self.subTest(tree=tree):
                dep = parse_dependencies(tree, truncated)
                self.assertEqual(dep['status'], 'partial'); self.assertFalse(dep['config_for_split'])
        with patch('apklab.split_metadata.find_tool', return_value=None):
            self.assertEqual(read_dependencies('input.apk')['status'], 'unavailable')

    def test_aapt_failure_and_truncation_are_not_complete_metadata(self):
        with patch('apklab.split_metadata.find_tool', return_value='/fake/aapt'):
            with patch('apklab.split_metadata.run', return_value={'returncode':1,'stdout':'','stderr':'failed'}):
                self.assertEqual(read_dependencies('x.apk')['status'], 'unavailable')
            with patch('apklab.split_metadata.run', return_value={'returncode':0,'stdout':'E: manifest\n','stderr':'','stdout_truncated':True}):
                self.assertEqual(read_dependencies('x.apk')['status'], 'partial')

    def test_cycles_missing_dependencies_and_unknown_not_misclassified(self):
        def apk(split, signer='a'):
            return {'split':split,'package':'org.example','version_code':'1','signer_sha256':[signer*64]}
        def obs(split, refs=(), status='observed', signer='a'):
            return {'id':str(split), 'apk':apk(split, signer), 'dependencies':{'status':status,'uses_splits':list(refs)}}
        for records, message in (([obs(None), obs('one',['absent'])], 'Missing declared split dependency'),
                                 ([obs(None), obs('one',['two']), obs('two',['one'])], 'Cycle'),
                                 ([obs(None), obs('one',signer='b')], 'signer certificate'),
                                 ([obs(None), obs('one'), obs('one')], 'Duplicate split')):
            with self.subTest(message=message):
                result = assess_outputs(records)
                self.assertTrue(any(message in issue for issue in result['issues']), result)
        first, second = obs(None), obs('one')
        second['dependencies']['version_code_major'] = 2
        self.assertTrue(any('versionCodeMajor' in e for e in assess_outputs([first, second])['issues']))
        result = assess_outputs([obs(None), {'id':'missing'}, obs('one',['unknown'], 'partial')])
        self.assertIn('base and split names', result['unknown'])
        self.assertIn('dependency declarations', result['unknown'])
        self.assertFalse(any('Missing declared' in issue for issue in result['issues']))

    def test_limits_and_partial_metadata_do_not_trigger_false_missing_dependency(self):
        text = 'E: manifest\n' + ''.join('  E: uses-split\n    A: android:name="feature"\n' for _ in range(513))
        result = parse_dependencies(text)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(len(result['uses_splits']), 512)
        records = [
            {'id':'base', 'apk':{'package':'org.example','version_code':'1','split':None,'signer_sha256':['a'*64]}, 'dependencies':{'status':'observed'}},
            {'id':'split', 'apk':{'package':'org.example','version_code':'1','split':'config.en','signer_sha256':['a'*64]}, 'dependencies':result},
        ]
        assessment = assess_outputs(records)
        self.assertFalse(any('Missing declared' in item for item in assessment['issues']))
        self.assertIn('dependency declarations', assessment['unknown'])

    def test_badging_cut_mid_package_line_cannot_establish_base(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp)/'x.apk'
            with zipfile.ZipFile(apk, 'w') as z: z.writestr('AndroidManifest.xml', 'test')
            def fake(args, timeout=120):
                if 'badging' in args:
                    return {'returncode':0,'stdout':"package: name='org.example' versionCode='1' spl",'stderr':'','stdout_truncated':True}
                return {'returncode':0,'stdout':'Signer #1 certificate SHA-256 digest: '+('a'*64)+'\n','stderr':''}
            r = report()
            with patch('apklab.core.find_tool', side_effect=lambda n:'/fake/'+n), patch('apklab.core.run', side_effect=fake):
                item = inspect_one(apk, r)
            self.assertIsNone(item['package']); self.assertNotIn('split', item)
            self.assertTrue(any('truncated' in x['detail'] for x in r['not_tested']))

    def test_truncated_or_inconsistent_signer_output_is_not_compared(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp)/'fixture.apk'
            with zipfile.ZipFile(apk, 'w') as z: z.writestr('AndroidManifest.xml', 'test')
            for truncated, count in ((True, 1), (False, 2), (False, 1)):
                def fake(args, timeout=120):
                    if 'badging' in args: return {'returncode':0,'stdout':"package: name='org.example' versionCode='1'",'stderr':''}
                    return {'returncode':0,'stdout':'Number of signers: %d\nSigner #1 certificate SHA-256 digest: %s\n' % (count, 'a'*64), 'stderr':'', 'stdout_truncated':truncated}
                r = report()
                with self.subTest(truncated=truncated,count=count), patch('apklab.core.find_tool', side_effect=lambda n:'/fake/'+n), patch('apklab.core.run', side_effect=fake):
                    item = inspect_one(apk, r)
                self.assertEqual(item['signer_sha256'], ['a'*64] if not truncated and count == 1 else None)
                if item['signer_sha256'] is None: self.assertTrue(any('digest' in x['detail'] for x in r['not_tested']))


class SplitVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.inputs = []
        for name in ('base.apk', 'config.apk'):
            apk = self.root/name
            with zipfile.ZipFile(apk, 'w') as z: z.writestr('AndroidManifest.xml', name)
            self.inputs.append(apk)
        self.workspace = self.root/'set'
        code, _ = self.call('splits','init',str(self.workspace),*(str(p) for p in self.inputs)); self.assertEqual(code, 3)
        for i in range(2): (self.workspace/('apk-%04d'%i)/'signed.apk').write_bytes(b'fixture')
    def call(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out): code = main(list(args))
        return code, json.loads(out.getvalue())
    def verify(self, signer_mismatch=False, missing_dependency=False, partial=False):
        def inspect(path, r):
            index = int(Path(path).parent.name[-1]); add(r,'verified',str(path),'signature verified')
            return {'file':str(path), 'package':'org.example', 'version_code':'1', 'split':None if index == 0 else 'config.en', 'signer_sha256':[('b' if signer_mismatch and index else 'a')*64]}
        def dependencies(path):
            index = int(Path(path).parent.name[-1])
            return {'status':'partial' if partial and index else 'observed', 'uses_splits':['missing'] if missing_dependency and index else [], 'config_for_split':None}
        sub = report(); add(sub,'verified','zipalign','checked')
        with patch('apklab.cli.work', return_value=sub), patch('apklab.cli.inspect_one', side_effect=inspect), patch('apklab.cli.read_dependencies', side_effect=dependencies):
            return self.call('splits','run',str(self.workspace),'verify')
    def test_records_every_output_and_detects_mismatch(self):
        code, result = self.verify()
        self.assertEqual(code, 3, result); self.assertEqual(len(result['members']), 2)
        self.assertEqual([m['inspection']['apk']['split'] for m in result['members']], [None, 'config.en'])
        self.assertTrue(all(m['inspection']['apk']['signer_sha256'] for m in result['members']))
        self.assertEqual(result['split_analysis']['issues'], [])
        for kw, expected in (({'signer_mismatch':True}, 'signer certificate'), ({'missing_dependency':True}, 'Missing declared split')):
            with self.subTest(kw=kw):
                code, result = self.verify(**kw); self.assertEqual(code, 1)
                self.assertTrue(any(expected in e['detail'] for e in result['failures']))
    def test_partial_dependencies_are_not_claimed_complete(self):
        code, result = self.verify(partial=True)
        self.assertEqual(code, 3, result); self.assertIn('dependency declarations', result['split_analysis']['unknown'])
        self.assertTrue(result['not_tested'])


class SplitDeviceTests(unittest.TestCase):
    def test_install_multiple_uses_copies_and_blocks_missing_dependency(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); apks = []
            for name in ('base.apk', 'split.apk'):
                apk = root/name
                with zipfile.ZipFile(apk, 'w') as z: z.writestr('AndroidManifest.xml', name)
                apks.append(apk)
            original = [p.read_bytes() for p in apks]
            for missing in (False, True, 'unknown'):
                calls = []
                def inspect(path, r):
                    index = int(Path(path).stem.split('-')[-1]); self.assertEqual(Path(path).read_bytes(), original[index])
                    return {'file':str(path), 'package':'org.example.app', 'version_code':'1', 'split':None if index == 0 else 'feature', 'signer_sha256':['a'*64]}
                def deps(path):
                    index = int(Path(path).stem.split('-')[-1])
                    return {'status':'unavailable' if missing == 'unknown' and index else 'observed', 'uses_splits':['not_in_set'] if missing is True and index else [], 'config_for_split':None}
                def fake_run(args, timeout=120):
                    args = [str(a) for a in args]; calls.append(args)
                    if 'get-state' in args: out = 'device\n'
                    elif 'emu' in args: out = 'test\nOK\n'
                    elif 'getprop' in args: out = '1\n'
                    elif 'users' in args: out = 'UserInfo{0:Owner:13}\n'
                    elif 'packages' in args: out = ''
                    elif 'install-multiple' in args:
                        copies = [Path(a) for a in args[args.index('install-multiple')+1:]]
                        self.assertEqual(len(copies), 2); self.assertTrue(all(p not in apks for p in copies))
                        self.assertEqual([p.read_bytes() for p in copies], original); out = 'Success\n'
                    else: raise AssertionError(args)
                    return {'returncode':0, 'stdout':out, 'stderr':''}
                out = io.StringIO()
                with self.subTest(missing=missing), patch('apklab.device.find_tool', side_effect=lambda n:'/fake/'+n), patch('apklab.device.inspect_one', side_effect=inspect), patch('apklab.device.read_dependencies', side_effect=deps), patch('apklab.device.run', side_effect=fake_run), contextlib.redirect_stdout(out):
                    code = main(['device','--serial','emulator-5554','--confirm-install',*(str(p) for p in apks)])
                result = json.loads(out.getvalue())
                self.assertEqual(code, 1 if missing is True else 3, result)
                self.assertEqual(any('install-multiple' in call for call in calls), missing is not True)
                self.assertEqual([p.read_bytes() for p in apks], original)
                if missing is True: self.assertTrue(any('Missing declared split dependency' in e['detail'] for e in result['failures']))
                else:
                    self.assertEqual(result['install']['stdout'], 'Success\n')
                    self.assertTrue(any(e['subject'] == 'runtime' for e in result['not_tested']))
                    if missing == 'unknown': self.assertIn('dependency declarations', result['split_analysis']['unknown'])
