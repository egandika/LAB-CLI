import contextlib
import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from apklab.agent_plan import ROUTES, SKILL_ROUTES, plan, recommended_skills
from apklab.cli import main


class AgentPlanTests(unittest.TestCase):
    def call(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(['agent', 'plan', *args])
        return code, json.loads(out.getvalue())

    def test_supported_plans_do_not_touch_files_or_run_tools(self):
        with patch('builtins.open', side_effect=AssertionError('unexpected file I/O')), \
             patch('apklab.cli.find_tool', side_effect=AssertionError('unexpected tool discovery')), \
             patch('apklab.cli.run', side_effect=AssertionError('unexpected tool execution')):
            for goal, kind in ROUTES:
                with self.subTest(goal=goal, kind=kind):
                    code, result = self.call('--goal', goal, '--kind', kind)
                    self.assertEqual(code, 3)
                    self.assertTrue(result['agent_plan']['steps'])
                    self.assertEqual(result['agent_plan']['recommended_skills'], recommended_skills(goal, kind))
                    self.assertEqual(result['verified'], [])
                    self.assertIn('Planning only', result['not_tested'][0]['detail'])
                    self.assertTrue(any('no skill is discovered' in x for x in result['agent_plan']['limits']))

    def test_every_supported_route_has_only_existing_skill_recommendations(self):
        skills_dir = Path(__file__).resolve().parents[1] / '.agents' / 'skills'
        available = {path.name for path in skills_dir.iterdir() if path.is_dir()}
        self.assertEqual(set(ROUTES), set(SKILL_ROUTES))
        self.assertTrue(all(SKILL_ROUTES.values()))
        for pair, names in SKILL_ROUTES.items():
            with self.subTest(route=pair):
                self.assertEqual(len(names), len(set(names)))
                self.assertLessEqual(len(names), 3)
                self.assertLessEqual(set(names), available)
                self.assertNotIn('apklab-orchestrator', names)
                self.assertEqual(recommended_skills(*pair), list(names))

    def test_incomplete_route_catalog_fails_closed(self):
        with patch.dict(SKILL_ROUTES, {}, clear=True):
            with self.assertRaisesRegex(ValueError, 'Unsupported'):
                plan('triage', 'apk')
            with self.assertRaisesRegex(ValueError, 'Unsupported'):
                recommended_skills('triage', 'apk')

    def test_routes_and_invalid_combinations(self):
        self.assertEqual(plan('compare', 'two-apks')[0]['command'], 'diff')
        self.assertEqual(plan('triage', 'apks')[0]['command'], 'apks inspect')
        self.assertEqual(plan('rebuild', 'xapk')[0]['command'], 'xapk unpack')
        self.assertEqual(plan('review', 'diff')[0]['type'], 'guidance')
        self.assertEqual(recommended_skills('black-box', 'apk')[0], 'apklab-black-box-testing')
        self.assertEqual(plan('fuzz', 'parser')[0]['command'], 'fuzz')
        self.assertIn('synthetic AXML/DEX/ZIP', plan('fuzz', 'parser')[0]['purpose'])
        self.assertEqual(plan('black-box', 'apk')[0]['command'], 'device')
        code, report = self.call('--goal', 'compare', '--kind', 'xapk')
        self.assertEqual(code, 1)
        self.assertIn('Unsupported', report['failures'][0]['detail'])

    def test_guidance_is_not_a_fake_executable_command(self):
        for goal in ('report', 'diagnose', 'review', 'test', 'maintain'):
            with self.subTest(goal=goal):
                kind = {'report': 'report', 'diagnose': 'report', 'review': 'diff',
                        'test': 'source', 'maintain': 'repo', 'black-box': 'apk', 'fuzz': 'parser'}[goal]
                _, result = self.call('--goal', goal, '--kind', kind)
                step = result['agent_plan']['steps'][0]
                self.assertEqual(step['type'], 'guidance')
                self.assertIsNone(step['command'])
        for steps in (plan(goal, kind) for goal, kind in ROUTES):
            for step in steps:
                if step['type'] == 'command':
                    self.assertIsInstance(step['command'], str)
                    with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as result:
                        main(step['command'].split() + ['--help'])
                    self.assertEqual(result.exception.code, 0, step['command'])

    def test_help_lists_supported_goal_kind_pairs(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as result:
            main(['agent', 'plan', '--help'])
        self.assertEqual(result.exception.code, 0)
        normalized = ' '.join(out.getvalue().split())
        for goal, kind in ROUTES:
            self.assertIn(goal + '/' + kind, normalized)

    def test_cli_process_report_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / 'plan.json'
            command = [sys.executable, '-m', 'apklab', 'agent', '--report', str(report_path),
                       'plan', '--goal', 'triage', '--kind', 'xapk']
            first = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(first.returncode, 3, first.stderr)
            document = json.loads(first.stdout)
            self.assertEqual(document, json.loads(report_path.read_text(encoding='utf-8')))
            self.assertEqual(document['agent_plan']['steps'][0]['command'], 'xapk inspect')
            self.assertEqual(document['agent_plan']['recommended_skills'], ['apklab-triage', 'apklab-report'])
            original = report_path.read_bytes()
            second = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(second.returncode, 1)
            self.assertEqual(report_path.read_bytes(), original)
            self.assertTrue(any(x['subject'] == 'report' for x in json.loads(second.stdout)['failures']))

    def test_unsupported_combinations_fail_closed(self):
        goals = {goal for goal, _ in ROUTES}
        kinds = {kind for _, kind in ROUTES}
        for goal in goals:
            for kind in kinds:
                if (goal, kind) not in ROUTES:
                    with self.subTest(goal=goal, kind=kind):
                        code, result = self.call('--goal', goal, '--kind', kind)
                        self.assertEqual(code, 1)
                        self.assertNotIn('agent_plan', result)

    def test_plan_reports_approval_and_limitations(self):
        _, result = self.call('--goal', 'rebuild', '--kind', 'apk')
        self.assertTrue(any('Ask before' in x for x in result['agent_plan']['permissions']))
        self.assertTrue(any('no files or tools' in x for x in result['agent_plan']['limits']))
        self.assertEqual(result['agent_plan']['steps'][0]['command'], 'work init')
        self.assertEqual(result['agent_plan']['recommended_skills'], ['apklab-rebuild', 'apklab-report'])

    def test_advanced_methods_name_real_commands_and_keep_their_limits(self):
        for goal, kind, skill, command in (
                ('black-box', 'apk', 'apklab-black-box-testing', 'device'),
                ('black-box', 'splits', 'apklab-black-box-testing', 'inspect'),
                ('fuzz', 'parser', 'apklab-fuzzing', 'fuzz')):
            with self.subTest(goal=goal, kind=kind):
                code, result = self.call('--goal', goal, '--kind', kind)
                self.assertEqual(code, 3)
                self.assertEqual(result['agent_plan']['recommended_skills'][0], skill)
                step = result['agent_plan']['steps'][0]
                self.assertEqual(step['type'], 'command')
                self.assertEqual(step['command'], command)
                self.assertTrue(any(item['type'] == 'guidance'
                                    for item in result['agent_plan']['steps']))
        blackbox = self.call('--goal', 'black-box', '--kind', 'apk')[1]['agent_plan']['steps']
        self.assertIn('separate approval', blackbox[0]['purpose'])
        self.assertIn('does not capture UI', blackbox[1]['purpose'])
        fuzz = self.call('--goal', 'fuzz', '--kind', 'parser')[1]['agent_plan']['steps']
        self.assertIn('synthetic AXML/DEX/ZIP', fuzz[0]['purpose'])
        self.assertIn('not coverage-guided', fuzz[1]['purpose'])


if __name__ == '__main__':
    unittest.main()
