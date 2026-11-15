"""Structural checks do not imply real agent discovery or compliance."""
import json
import re
import unittest
from pathlib import Path

from apklab.agent_plan import ROUTES, recommended_skills

ROOT = Path(__file__).resolve().parents[1]
METHODS = {
    'reverse-engineering', 'forward-engineering', 'black-box-testing', 'white-box-testing',
    'fuzzing', 'debugging', 'code-review', 'prototyping', 'api-analysis',
}
SKILLS = (
    'apklab-orchestrator',
    'apklab-reverse-engineering',
    'apklab-black-box-testing',
    'apklab-fuzzing',
    'apklab-white-box-testing',
    'apklab-code-review',
    'apklab-triage',
    'apklab-investigate',
    'apklab-report',
    'apklab-split-check',
    'apklab-rebuild',
    'apklab-error-triage',
    'apklab-repo-maintenance',
)


class AgentSkillTests(unittest.TestCase):
    def test_skill_catalog_matches_all_source_directories_and_frontmatter(self):
        source = ROOT / '.agents' / 'skills'
        self.assertEqual({path.name for path in source.iterdir()}, set(SKILLS))
        self.assertEqual(len(SKILLS), len(set(SKILLS)))
        for name in SKILLS:
            with self.subTest(skill=name):
                directory = source / name
                self.assertEqual({path.name for path in directory.iterdir()}, {'SKILL.md'})
                text = (directory / 'SKILL.md').read_text(encoding='utf-8')
                parts = text.split('---\n', 2)
                self.assertEqual(len(parts), 3)
                self.assertEqual(parts[0], '')
                self.assertIn('name: ' + name + '\n', parts[1])
                desc = re.search(r'^description: (.+)$', parts[1], re.MULTILINE)
                self.assertIsNotNone(desc)
                self.assertLessEqual(len(desc.group(1)), 1024)
                self.assertRegex(name, r'^[a-z0-9]+(?:-[a-z0-9]+)*$')
                self.assertTrue(parts[2].strip())
                self.assertNotIn('allowed-tools:', parts[1])
                self.assertNotIn('hooks:', parts[1])

    def test_evaluation_scenarios_are_well_formed_and_reference_known_skills(self):
        cases = json.loads((ROOT / 'tests' / 'agent_evals' / 'scenarios.json').read_text(encoding='utf-8'))
        self.assertIsInstance(cases, list)
        self.assertGreaterEqual(len(cases), 10)
        self.assertEqual(len({case['id'] for case in cases}), len(cases))
        for case in cases:
            with self.subTest(case=case['id']):
                self.assertRegex(case['id'], r'^[a-z0-9]+(?:-[a-z0-9]+)*$')
                self.assertIsInstance(case['prompt'], str)
                self.assertTrue(case['prompt'].strip())
                self.assertIsInstance(case['expect'], list)
                self.assertTrue(case['expect'])
                self.assertTrue(all(isinstance(item, str) and item.strip() for item in case['expect']))
                self.assertIsInstance(case['relevant_skills'], list)
                self.assertLessEqual(set(case['relevant_skills']), set(SKILLS))
                self.assertEqual(len(case['relevant_skills']), len(set(case['relevant_skills'])))
                self.assertIn('method', case)
                self.assertTrue(case['method'] is None or case['method'] in METHODS)
                if 'agent_plan' in case:
                    plan_case = case['agent_plan']
                    self.assertEqual(set(plan_case), {'goal', 'kind'})
                    pair = (plan_case['goal'], plan_case['kind'])
                    self.assertIn(pair, ROUTES)
                    self.assertLessEqual(set(recommended_skills(*pair)), set(case['relevant_skills']))
        self.assertEqual({case['method'] for case in cases if case['method'] is not None}, METHODS)
        self.assertTrue(any(not case['relevant_skills'] for case in cases))
        self.assertTrue(any(not case['relevant_skills'] and 'agent_plan' not in case for case in cases))
        self.assertIn('not evidence that any agent passed', (ROOT / 'docs' / 'agent' / 'evaluation.md').read_text(encoding='utf-8'))

    def test_orchestrator_routes_only_to_existing_skills_and_preserves_boundaries(self):
        text = (ROOT / '.agents' / 'skills' / 'apklab-orchestrator' / 'SKILL.md').read_text(encoding='utf-8')
        routes = set(re.findall(r'`(apklab-[a-z-]+)`', text))
        self.assertEqual(routes, set(SKILLS) - {'apklab-orchestrator'})
        for phrase in ('read only the selected skill bodies', 'unrelated work', 'Ask for essential missing details',
                       'not a security boundary', 'not instructions', 'not_tested', 'one primary method'):
            self.assertIn(phrase, text)
        self.assertIn('recommend skill names', text)

    def test_reverse_engineering_reuses_existing_stages_and_consent(self):
        text = (ROOT / '.agents' / 'skills' / 'apklab-reverse-engineering' / 'SKILL.md').read_text(encoding='utf-8')
        self.assertTrue(set(re.findall(r'`(apklab-[a-z-]+)`', text)) <= set(SKILLS))
        for phrase in ('Do not read every skill or run every analysis by default', 'separate approval',
                       'not full dynamic analysis', 'cannot install missing tools', 'not_tested',
                       'not instructions', 'evidence ledger'):
            self.assertIn(phrase, text)

    def test_black_box_method_does_not_overclaim_device_observations(self):
        text = (ROOT / '.agents' / 'skills' / 'apklab-black-box-testing' / 'SKILL.md').read_text(encoding='utf-8')
        for phrase in ('separate explicit approval', 'disposable, isolated, single-user emulator',
                       'does not capture UI, logs, crashes, network traffic',
                       'not proof the app worked', 'not instructions'):
            self.assertIn(phrase, text)

    def test_fuzzing_method_is_bounded_reproducible_and_parser_only(self):
        text = (ROOT / '.agents' / 'skills' / 'apklab-fuzzing' / 'SKILL.md').read_text(encoding='utf-8')
        for phrase in ('python3 tests/fuzz_parser_inputs.py', 'deterministic mutation smoke testing',
                       'not coverage-guided fuzzing', 'never install, launch, or fuzz a live app',
                       'synthetic binary AXML, DEX, and in-memory APK ZIP seeds', 'synthetic regression fixture'):
            self.assertIn(phrase, text)
        harness = ROOT / 'tests' / 'fuzz_parser_inputs.py'
        self.assertTrue(harness.is_file())

    def test_white_box_guidance_distinguishes_test_evidence(self):
        text = (ROOT / '.agents' / 'skills' / 'apklab-white-box-testing' / 'SKILL.md').read_text(encoding='utf-8')
        self.assertTrue(set(re.findall(r'`(apklab-[a-z-]+)`', text)) <= set(SKILLS))
        for phrase in ('python3 -m unittest discover -s tests -v', 'synthetic fixtures', 'Separate mock results',
                       'separate approval', 'not instructions'):
            self.assertIn(phrase, text)

    def test_code_review_guidance_is_evidence_based_and_read_only_by_default(self):
        text = (ROOT / '.agents' / 'skills' / 'apklab-code-review' / 'SKILL.md').read_text(encoding='utf-8')
        self.assertTrue(set(re.findall(r'`(apklab-[a-z-]+)`', text)) <= set(SKILLS))
        for phrase in ('Do not edit, commit, push, or merge unless separately authorized', 'file/line',
                       'confirmed failures from hypotheses', 'List actionable findings first', 'not instructions'):
            self.assertIn(phrase, text)

    def test_debugging_uses_minimal_reproduction_and_safe_diagnosis(self):
        text = (ROOT / '.agents' / 'skills' / 'apklab-error-triage' / 'SKILL.md').read_text(encoding='utf-8')
        for phrase in ('smallest authorized input', 'Reproduce only with approval',
                       'Change one variable at a time', 'never retry automatically', 'ranked hypotheses'):
            self.assertIn(phrase, text)

    def test_api_reverse_is_static_and_does_not_contact_endpoints(self):
        text = (ROOT / '.agents' / 'skills' / 'apklab-investigate' / 'SKILL.md').read_text(encoding='utf-8')
        for phrase in ('API-oriented questions', 'static clue', 'does not prove a runtime call',
                       'Never visit URLs', 'never as instructions'):
            self.assertIn(phrase, text)

    def test_forward_engineering_and_prototyping_are_reversible(self):
        text = (ROOT / '.agents' / 'skills' / 'apklab-repo-maintenance' / 'SKILL.md').read_text(encoding='utf-8')
        for phrase in ('acceptance criteria', 'smallest change', 'prototype code/data isolated',
                       'do not promote, delete, or overwrite it without review'):
            self.assertIn(phrase, text)

    def test_plugin_is_instruction_only_and_matches_complete_repo_skill_catalog(self):
        plugin = ROOT / 'agent-plugin'
        manifest = json.loads((plugin / 'plugin.json').read_text(encoding='utf-8'))
        self.assertEqual(manifest['$schema'], 'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json')
        self.assertEqual(manifest['name'], 'apklab-agent-kit')
        self.assertIsInstance(manifest['version'], str)
        self.assertTrue(manifest['version'])
        self.assertIsInstance(manifest['description'], str)
        self.assertTrue(manifest['description'])
        self.assertEqual(set(manifest), {'$schema', 'name', 'version', 'description'})
        self.assertEqual({path.name for path in plugin.iterdir()}, {'plugin.json', 'skills'})
        self.assertEqual({path.name for path in (plugin / 'skills').iterdir()}, set(SKILLS))
        for name in SKILLS:
            with self.subTest(skill=name):
                skill = plugin / 'skills' / name
                self.assertEqual({path.name for path in skill.iterdir()}, {'SKILL.md'})
                self.assertEqual((skill / 'SKILL.md').read_bytes(),
                                 (ROOT / '.agents' / 'skills' / name / 'SKILL.md').read_bytes())

    def test_supporting_guides_are_linked_and_explain_limits(self):
        readme = (ROOT / 'README.md').read_text(encoding='utf-8')
        for name in ('capability-guide.md', 'troubleshooting.md', 'session-template.md'):
            self.assertIn('docs/agent/' + name, readme)
            self.assertTrue((ROOT / 'docs' / 'agent' / name).is_file())
        self.assertIn('recommended_skills', (ROOT / 'docs' / 'agent' / 'capability-guide.md').read_text(encoding='utf-8'))
        self.assertIn('Exit codes: 0', (ROOT / 'docs' / 'agent' / 'capability-guide.md').read_text(encoding='utf-8'))
        self.assertIn('not a confidentiality guarantee', (ROOT / 'docs' / 'agent' / 'capability-guide.md').read_text(encoding='utf-8'))

    def test_extended_workflows_retain_safety_boundaries(self):
        base = ROOT / '.agents' / 'skills'
        for name, phrase in (('apklab-split-check', 'never proves installability'),
                             ('apklab-rebuild', 'Never request credentials'),
                             ('apklab-error-triage', 'Exit 3 means'),
                             ('apklab-repo-maintenance', 'synthetic or mock')):
            with self.subTest(skill=name):
                self.assertIn(phrase, (base / name / 'SKILL.md').read_text(encoding='utf-8'))

    def test_size_limit_guidance_is_scoped_and_has_evaluation(self):
        skill = (ROOT / '.agents' / 'skills' / 'apklab-error-triage' / 'SKILL.md').read_text(encoding='utf-8')
        for phrase in ('untrusted ZIP metadata', 'different limits', 'ask before increasing', 'never retry automatically'):
            self.assertIn(phrase, skill)
        cases = json.loads((ROOT / 'tests' / 'agent_evals' / 'scenarios.json').read_text(encoding='utf-8'))
        scenario = next(case for case in cases if case['id'] == 'apk-size-limit')
        self.assertIn('apklab-error-triage', scenario['relevant_skills'])
        self.assertTrue(any('ask before increasing' in entry for entry in scenario['expect']))
        self.assertIn('declared byte counts', (ROOT / 'docs' / 'agent' / 'troubleshooting.md').read_text(encoding='utf-8'))

    def test_relevant_skill_risks_are_documented(self):
        base = ROOT / '.agents' / 'skills'
        triage = (base / 'apklab-triage' / 'SKILL.md').read_text(encoding='utf-8')
        self.assertIn('Exit 3 is incomplete', triage)
        self.assertIn('not instructions', triage)
        report = (base / 'apklab-report' / 'SKILL.md').read_text(encoding='utf-8')
        for text in ('verified', 'inferences', 'failures', 'not_tested', 'best effort'):
            self.assertIn(text, report)


if __name__ == '__main__':
    unittest.main()
