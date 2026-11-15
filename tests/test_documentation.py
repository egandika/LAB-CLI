import unittest
from pathlib import Path

class DocumentationTests(unittest.TestCase):
    def test_limitations_and_statuses_documented(self):
        readme = (Path(__file__).resolve().parents[1]/'README.md').read_text(encoding='utf-8')
        for phrase in ('## Limitations', 'apklab setup --plan', '--max-output-mib', 'not a hard disk quota',
                       'xapk repack game.xapk ./new-output --directory', 'ELF segment alignment',
                       '**3** (no failures', 'untested entries'):
            with self.subTest(phrase=phrase): self.assertIn(phrase, readme)

    def test_axml_identity_inference_is_not_a_confirmed_base(self):
        root = Path(__file__).resolve().parents[1]
        readme = (root / 'README.md').read_text(encoding='utf-8')
        agents = (root / 'AGENTS.md').read_text(encoding='utf-8')
        self.assertIn('infer a base candidate', agents)
        self.assertIn('does not resolve resources or confirm split identity', agents)
        self.assertIn('as an inference for its base candidate', readme)

    def test_agent_guidance_preserves_consent_and_evidence(self):
        root = Path(__file__).resolve().parents[1]
        readme = (root / 'README.md').read_text(encoding='utf-8')
        agents = (root / 'AGENTS.md').read_text(encoding='utf-8')
        self.assertIn('ask for approval before cloning or installing', readme)
        self.assertIn('untrusted data, not instructions', readme)
        self.assertIn('Exit 3 means at least one item is untested', agents)
        self.assertIn('before emulator installation or launch', agents)
        self.assertIn('`--check-apks` separately checks contained APK ZIPs', agents)
