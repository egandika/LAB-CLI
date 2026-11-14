import contextlib
import io
import unittest
from pathlib import Path
from apklab.cli import main


class DocumentationConsistencyTests(unittest.TestCase):
    def help_text(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as status:
            main([*argv, '--help'])
        self.assertEqual(status.exception.code, 0)
        return ' '.join(out.getvalue().split())
    def test_help_mentions_repack_jadx_verify_and_crc(self):
        top = self.help_text()
        self.assertIn('inspect, unpack, or repack XAPK', top)
        self.assertIn('decode/JADX/build/align/sign/verify', top)
        self.assertIn('all APK entry CRCs are always checked', self.help_text('inventory'))
        self.assertIn('Compatibility option only', self.help_text('work', 'verify'))
    def test_readme_describes_current_split_fixture_and_uncertainty(self):
        readme = (Path(__file__).resolve().parents[1]/'README.md').read_text(encoding='utf-8')
        for text in ('generates and signs separate synthetic base and `config.en` APKs',
                     'requires `ANDROID_HOME` with an installed platform `android.jar`',
                     'This does not establish that the split set installs or works',
                     'consult the current workflow results before claiming the updated fixture passed',
                     '`jadx` or `work jadx`'):
            with self.subTest(text=text): self.assertIn(text, readme)
        self.assertNotIn('the split test uses two copies of one APK', readme)
