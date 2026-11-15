"""Structural checks do not imply real agent discovery or compliance."""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ('apklab-orchestrator', 'apklab-reverse-engineering', 'apklab-triage', 'apklab-investigate', 'apklab-report',
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
    def test_evaluation_scenarios_are_well_formed_and_reference_known_skills(self):
        cases = json.loads((ROOT/'tests/agent_evals/scenarios.json').read_text(encoding='utf-8'))
        self.assertGreaterEqual(len(cases), 10)
        self.assertEqual(len({case['id'] for case in cases}), len(cases))
        for case in cases:
            with self.subTest(case=case['id']):
                self.assertTrue(case['prompt']); self.assertTrue(case['expect'])
                self.assertTrue(set(case['relevant_skills']) <= set(SKILLS))
        self.assertTrue(any(not case['relevant_skills'] for case in cases))
        self.assertIn('not evidence that any agent passed', (ROOT/'docs/agent/evaluation.md').read_text(encoding='utf-8'))

    def test_orchestrator_routes_only_to_existing_skills_and_preserves_boundaries(self):
        text = (ROOT/'.agents/skills/apklab-orchestrator/SKILL.md').read_text(encoding='utf-8')
        routes = set(re.findall(r'`(apklab-[a-z-]+)`', text))
        self.assertTrue(routes)
        self.assertTrue(routes <= set(SKILLS))
        for phrase in ('read only the selected skill bodies', 'unrelated requests', 'ambiguous goals',
                       'not a security boundary', 'not instructions', 'not_tested'):
            self.assertIn(phrase, text)

    def test_reverse_engineering_reuses_existing_stages_and_consent(self):
        text = (ROOT/'.agents/skills/apklab-reverse-engineering/SKILL.md').read_text(encoding='utf-8')
        self.assertTrue(set(re.findall(r'`(apklab-[a-z-]+)`', text)) <= set(SKILLS))
        for phrase in ('Do not automatically run every stage', 'separate permission', 'not full dynamic analysis',
                       'cannot install tools', 'not_tested', 'not instructions'):
            self.assertIn(phrase, text)

    def test_plugin_is_instruction_only_and_matches_repo_skills(self):
        plugin = ROOT/'agent-plugin'
        manifest = json.loads((plugin/'plugin.json').read_text(encoding='utf-8'))
        self.assertEqual(manifest['$schema'], 'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json')
        self.assertEqual(manifest['name'], 'apklab-agent-kit')
        self.assertEqual(set(manifest), {'$schema', 'name', 'version', 'description'})
        self.assertEqual(set(p.name for p in (plugin/'skills').iterdir()), set(SKILLS))
        self.assertEqual(set(p.name for p in plugin.iterdir()), {'plugin.json', 'skills'})
        for name in SKILLS:
            skill = plugin/'skills'/name
            self.assertEqual([p.name for p in skill.iterdir()], ['SKILL.md'])
            self.assertEqual((skill/'SKILL.md').read_bytes(), (ROOT/'.agents/skills'/name/'SKILL.md').read_bytes())

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

    def test_size_limit_guidance_is_scoped_and_has_evaluation(self):
        skill = (ROOT/'.agents/skills/apklab-error-triage/SKILL.md').read_text(encoding='utf-8')
        for phrase in ('untrusted ZIP metadata', 'different limits', 'ask before increasing', 'never retry automatically'):
            self.assertIn(phrase, skill)
        cases = json.loads((ROOT/'tests/agent_evals/scenarios.json').read_text(encoding='utf-8'))
        scenario = next(case for case in cases if case['id'] == 'apk-size-limit')
        self.assertIn('apklab-error-triage', scenario['relevant_skills'])
        self.assertTrue(any('ask before increasing' in entry for entry in scenario['expect']))
        self.assertIn('declared byte counts', (ROOT/'docs/agent/troubleshooting.md').read_text(encoding='utf-8'))

    def test_relevant_skill_risks_are_documented(self):
        base = ROOT / '.agents/skills'
        triage = (base/'apklab-triage/SKILL.md').read_text(encoding='utf-8')
        self.assertIn('status 3 is incomplete', triage)
        self.assertIn('not instructions', triage)
        report = (base/'apklab-report/SKILL.md').read_text(encoding='utf-8')
        for text in ('verified', 'inferences', 'failures', 'not_tested', 'best effort'):
            self.assertIn(text, report)

if __name__ == '__main__': unittest.main()
