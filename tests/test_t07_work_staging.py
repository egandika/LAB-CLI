import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from apklab.workflow import init, perform


class WorkStagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.apk = self.root/'source.apk'; self.work = self.root/'work'
        with zipfile.ZipFile(self.apk, 'w') as z: z.writestr('AndroidManifest.xml', 'test')
        self.before = self.apk.read_bytes(); init(self.apk, self.work)
        (self.work/'decoded').mkdir(); (self.work/'rebuilt.apk').write_bytes(b'rebuilt'); (self.work/'aligned.apk').write_bytes(b'aligned')

    def output_arg(self, stage, args):
        if stage in ('decode', 'build'): return Path(args[args.index('-o')+1])
        if stage == 'jadx': return Path(args[args.index('-d')+1])
        if stage == 'sign': return Path(args[args.index('--out')+1])
        return Path(args[-1])

    def test_failures_clean_staged_output_and_allow_retry(self):
        for stage in ('decode', 'jadx', 'build', 'align', 'sign'):
            with self.subTest(stage=stage):
                destination = self.work/('custom-'+stage)
                def fake(args, **kwargs):
                    out = self.output_arg(stage, args)
                    if stage in ('decode', 'jadx'):
                        out.mkdir(); (out/'partial').write_text('partial')
                    else: out.write_bytes(b'partial')
                    return {'returncode':1, 'stdout':'', 'stderr':'failure detail'}
                with patch('apklab.workflow.find_tool', return_value='/tool'), patch('apklab.workflow.run', side_effect=fake), patch.dict(os.environ, {'TEST_PASS':'x'}):
                    with self.assertRaisesRegex(RuntimeError, 'failure detail'):
                        perform(stage, self.work, output=destination.name, keystore='key', alias='alias', pass_env='TEST_PASS')
                self.assertFalse(destination.exists())
                self.assertEqual(list(self.work.glob('.apklab-stage-*')), [])
        self.assertEqual(self.apk.read_bytes(), self.before)

    def test_wrong_type_and_racing_destination_are_not_overwritten(self):
        def wrong(args, **kwargs): Path(args[args.index('-o')+1]).write_text('not a directory'); return {'returncode':0,'stdout':'','stderr':''}
        with patch('apklab.workflow.find_tool', return_value='/tool'), patch('apklab.workflow.run', side_effect=wrong):
            with self.assertRaisesRegex(RuntimeError, 'expected output type'): perform('decode', self.work, output='fresh')
        self.assertFalse((self.work/'fresh').exists())
        def race(args, **kwargs):
            Path(args[args.index('-o')+1]).mkdir()
            (self.work/'fresh').mkdir(); (self.work/'fresh'/'owner').write_text('preserve')
            return {'returncode':0,'stdout':'','stderr':''}
        with patch('apklab.workflow.find_tool', return_value='/tool'), patch('apklab.workflow.run', side_effect=race):
            with self.assertRaises(OSError): perform('decode', self.work, output='fresh')
        self.assertEqual((self.work/'fresh'/'owner').read_text(), 'preserve')
        self.assertEqual(list(self.work.glob('.apklab-stage-*')), [])

    def test_dangling_output_symlink_is_not_followed(self):
        link = self.work/'link'
        try: link.symlink_to(self.work/'elsewhere')
        except (OSError, NotImplementedError): self.skipTest('symlink creation not available')
        with patch('apklab.workflow.find_tool') as find:
            with self.assertRaisesRegex(ValueError, 'already exists'):
                perform('decode', self.work, output='link')
            find.assert_not_called()
        self.assertTrue(link.is_symlink()); self.assertFalse((self.work/'elsewhere').exists())

    def test_successful_retry_after_failed_decode(self):
        dest = self.work/'retried'
        def fake(args, **kwargs):
            out = Path(args[args.index('-o')+1]); out.mkdir(); (out/'result').write_text('data')
            return {'returncode':0, 'stdout':'', 'stderr':''}
        with patch('apklab.workflow.find_tool', return_value='/tool'), patch('apklab.workflow.run', side_effect=fake):
            result, _ = perform('decode', self.work, output='retried')
        self.assertEqual(Path(result), dest); self.assertEqual((dest/'result').read_text(), 'data')
        self.assertEqual(list(self.work.glob('.apklab-stage-*')), [])
