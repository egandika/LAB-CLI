import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from apklab.cli import main


class XapkPublishTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.source = self.root/'input.xapk'

    def call(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out): code = main(list(args))
        return code, json.loads(out.getvalue())

    def test_manifest_failure_never_publishes_for_unpack_or_repack(self):
        for manifest in ('{broken', json.dumps({'package_name':'org.example', 'expansions':[], 'split_apks':[{'file':'missing.apk'}]}),
                         json.dumps({'package_name':'org.example', 'expansions':[], 'split_apks':[{'file':'base.apk'}, {'file':'base.apk'}]})):
            with self.subTest(manifest=manifest):
                with zipfile.ZipFile(self.source, 'w') as z:
                    z.writestr('base.apk', b'fake'); z.writestr('manifest.json', manifest)
                before = self.source.read_bytes()
                for action, flags in (('unpack', ()), ('repack', ()), ('repack', ('--directory',))):
                    dest = self.root/'output'
                    code, report = self.call('xapk', action, str(self.source), str(dest), *flags)
                    self.assertEqual(code, 1, report)
                    self.assertFalse(dest.exists())
                    self.assertTrue(report['failures'])
                    if flags != ('--directory',) or manifest != '{broken':
                        self.assertIn('manifest', report)
                    self.assertEqual(before, self.source.read_bytes())
                    self.assertEqual(list(self.root.glob('.apklab-stage-*')), [])

    def test_destination_race_never_overwrites_existing_file(self):
        with zipfile.ZipFile(self.source, 'w') as z:
            z.writestr('base.apk', b'fake')
        destination = self.root/'output.xapk'
        from apklab.publish import publish_new as real_publish
        def race(source, dest, directory=False):
            destination.write_bytes(b'owner data')
            return real_publish(source, dest, directory)
        with patch('apklab.publish.publish_new', side_effect=race):
            code, report = self.call('xapk', 'repack', str(self.source), str(destination))
        self.assertEqual(code, 1, report)
        self.assertEqual(destination.read_bytes(), b'owner data')
        self.assertEqual(list(self.root.glob('.apklab-stage-*')), [])
