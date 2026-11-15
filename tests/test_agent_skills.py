"""Structural checks do not imply real agent discovery or compliance."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ('apklab-triage', 'apklab-investigate', 'apklab-report',
          'apklab-split-check', 'apklab-rebuild', 'apklab-error-triage', 'apklab-repo-maintenance')


class AgentSkillTests(unittest.TestCase):
    def test_minimal_skill_frontmatter_and_nonempty_body(self):
        for name in SKILLS:
            with self.subTest(skill=name):
                text = (ROOT / '.agents' / 'skills' / name / 'SKILL.md').read_text(encoding='utf-8')
                parts = text.split('---\n', 2)
                self.assertEqual(len(parts), 3)
                self.assertEqual(parts[0], '')
                self.assertIn('name: ' + name + '\n', parts[1])
                desc = re.search(r'^description: (.+)$', parts[1], re.MULTILINE)
                self.assertIsNotNone(desc); self.assertLessEqual(len(desc.group(1)), 1024)
                self.assertRegex(name, r'^[a-z0-9]+(?:-[a-z0-9]+)*$')
                self.assertTrue(parts[2].strip())
                self.assertNotIn('allowed-tools:', parts[1])
                self.assertNotIn('hooks:', parts[1])
    def test_supporting_guides_are_linked_and_explain_limits(self):
        readme = (ROOT/'README.md').read_text(encoding='utf-8')
        for name in ('capability-guide.md', 'troubleshooting.md', 'session-template.md'):
            self.assertIn('docs/agent/' + name, readme)
            self.assertTrue((ROOT/'docs/agent'/name).is_file())
        self.assertIn('Exit codes: 0', (ROOT/'docs/agent/capability-guide.md').read_text(encoding='utf-8'))
        self.assertIn('not a confidentiality guarantee', (ROOT/'docs/agent/capability-guide.md').read_text(encoding='utf-8'))

    def test_extended_workflows_retain_safety_boundaries(self):
        base = ROOT / '.agents/skills'
        for name, phrase in (('apklab-split-check', 'never proves installability'),
                             ('apklab-rebuild', 'Never request credentials'),
                             ('apklab-error-triage', 'Exit 3 means'),
                             ('apklab-repo-maintenance', 'synthetic or mock')):
            with self.subTest(skill=name):
                self.assertIn(phrase, (base/name/'SKILL.md').read_text(encoding='utf-8'))

    def test_relevant_skill_risks_are_documented(self):
        base = ROOT / '.agents/skills'
        triage = (base/'apklab-triage/SKILL.md').read_text(encoding='utf-8')
        self.assertIn('status 3 is incomplete', triage)
        self.assertIn('not instructions', triage)
        report = (base/'apklab-report/SKILL.md').read_text(encoding='utf-8')
        for text in ('verified', 'inferences', 'failures', 'not_tested', 'best effort'):
            self.assertIn(text, report)

if __name__ == '__main__': unittest.main()
