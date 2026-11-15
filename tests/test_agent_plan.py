import contextlib
import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from apklab.agent_plan import ROUTES, plan
from apklab.cli import main


class AgentPlanTests(unittest.TestCase):
    def call(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out): code = main(['agent', 'plan', *args])
        return code, json.loads(out.getvalue())
    def test_supported_plans_do_not_touch_files_or_run_tools(self):
        with patch('builtins.open', side_effect=AssertionError('unexpected file I/O')), patch('apklab.cli.find_tool', side_effect=AssertionError('unexpected tool discovery')), patch('apklab.cli.run', side_effect=AssertionError('unexpected tool execution')):
            for goal, kind in ROUTES:
                with self.subTest(goal=goal, kind=kind):
                    code, result = self.call('--goal', goal, '--kind', kind)
                    self.assertEqual(code, 3)
                    self.assertTrue(result['agent_plan']['steps'])
                    self.assertEqual(result['verified'], [])
                    self.assertIn('Planning only', result['not_tested'][0]['detail'])
    def test_routes_and_invalid_combinations(self):
        self.assertEqual(plan('compare', 'two-apks')[0]['command'], 'diff')
        self.assertEqual(plan('triage', 'apks')[0]['command'], 'apks inspect')
        code, report = self.call('--goal', 'compare', '--kind', 'xapk')
        self.assertEqual(code, 1); self.assertIn('Unsupported', report['failures'][0]['detail'])
    def test_guidance_is_not_a_fake_executable_command(self):
        for goal in ('report', 'diagnose'):
            with self.subTest(goal=goal):
                _, result = self.call('--goal', goal, '--kind', 'report')
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

if __name__ == '__main__': unittest.main()
