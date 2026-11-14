import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

@unittest.skipUnless(shutil.which('git'), 'git required to check ignore rules')
class IgnoreRulesTests(unittest.TestCase):
    def ignored(self, name):
        result = subprocess.run(['git', 'check-ignore', '--no-index', '-q', '--', name], cwd=ROOT)
        self.assertIn(result.returncode, (0, 1))
        return result.returncode == 0
    def test_example_outputs_and_sensitive_extensions_are_ignored(self):
        for path in ('jadx-output/a.java', 'split-work/apk-0000/decoded/file.xml',
                     'xapk-copy/manifest.json', 'new-output/file.txt', 'apklab-work-test/decoded/file.xml',
                     'apklab-report-analysis.json', 'test.apk', 'test.obb', 'key.jks'):
            with self.subTest(path=path): self.assertTrue(self.ignored(path))
    def test_project_source_and_documentation_remain_visible(self):
        for path in ('apklab/cli.py', 'tests/test_t06_ignore.py', 'README.md', 'report.json'):
            with self.subTest(path=path): self.assertFalse(self.ignored(path))
