import unittest
from pathlib import Path

class DocumentationTests(unittest.TestCase):
    def test_limitations_and_statuses_documented(self):
        readme = (Path(__file__).resolve().parents[1]/'README.md').read_text(encoding='utf-8')
        for phrase in ('## Limitations', 'apklab setup --plan', '--max-output-mib', 'not a hard disk quota',
                       'xapk repack game.xapk ./new-output --directory', 'ELF segment alignment',
                       '**3** (no failures', 'untested entries'):
            with self.subTest(phrase=phrase): self.assertIn(phrase, readme)
