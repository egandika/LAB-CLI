import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from apklab.cli import main


class PageSizeContractTests(unittest.TestCase):
    def test_verify_checks_both_page_sizes_for_either_option(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); apk = root/'source.apk'; workspace = root/'work'
            with zipfile.ZipFile(apk, 'w') as z: z.writestr('AndroidManifest.xml', 'fixture')
            with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(main(['work', 'init', str(apk), str(workspace)]), 0)
            (workspace/'signed.apk').write_bytes(b'fixture')
            for page in ('4', '16'):
                calls = []
                def fake(args, timeout=120):
                    calls.append([str(a) for a in args]); return {'returncode':0, 'stdout':'', 'stderr':''}
                out = io.StringIO()
                with self.subTest(page=page), patch('apklab.cli.find_tool', return_value='/fake'), patch('apklab.cli.supports_16k', return_value=True), patch('apklab.cli.run', side_effect=fake), contextlib.redirect_stdout(out):
                    code = main(['work', 'verify', str(workspace), '--page-size', page])
                result = json.loads(out.getvalue())
                self.assertEqual(code, 3, result)
                self.assertEqual(set(result['checks']), {'zipalign', 'zipalign_16k', 'apksigner'})
                self.assertTrue(any('-p' in args for args in calls)); self.assertTrue(any('-P' in args for args in calls))
                self.assertIn('does not select', result['page_size_policy'])

    def test_help_explains_verify_and_split_semantics(self):
        for argv, phrase in ((['work', 'verify', '--help'], 'Compatibility option only'), (['splits', 'run', '--help'], 'verify attempts both')):
            out = io.StringIO()
            with self.subTest(argv=argv), contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as exit_code:
                main(argv)
            self.assertEqual(exit_code.exception.code, 0)
            self.assertIn(phrase, ' '.join(out.getvalue().split()))
