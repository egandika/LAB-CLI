import contextlib
import io
import os
import runpy
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


class CiDiagnosticsTests(unittest.TestCase):
    def invoke(self, args, returncode, output, actions=True):
        script = str(Path(__file__).resolve().parent.parent / '.github' / 'scripts' / 'run_unit_tests.py')
        result = SimpleNamespace(returncode=returncode, stdout=output)
        stdout = io.StringIO(); stderr = io.StringIO()
        env = {'GITHUB_ACTIONS': 'true'} if actions else {}
        with patch.object(sys, 'argv', [script] + args), patch('subprocess.run', return_value=result) as run, patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as exit_status:
                runpy.run_path(script, run_name='__main__')
        return exit_status.exception.code, stdout.getvalue(), run

    def test_integration_failure_preserves_exit_and_annotation(self):
        code, text, run = self.invoke(['--integration'], 1, 'header\n=== FAILURE ===\nproblem % value\n')
        self.assertEqual(code, 1)
        self.assertIn('::error title=Integration test failure::', text)
        self.assertIn('problem %25 value%0A', text)
        self.assertIn('test_integration.py', run.call_args.args[0])

    def test_success_and_non_ci_do_not_annotate(self):
        for args, code, actions in (([], 0, True), (['--integration'], 0, True), (['--integration'], 1, False)):
            with self.subTest(args=args, code=code, actions=actions):
                actual, text, _ = self.invoke(args, code, 'ordinary output\n', actions)
                self.assertEqual(actual, code); self.assertNotIn('::error', text)

    def test_annotation_is_bounded(self):
        code, text, _ = self.invoke(['--integration'], 1, 'a' * 20000)
        self.assertEqual(code, 1)
        annotation = text.split('::error title=Integration test failure::')[-1].rstrip('\n')
        self.assertEqual(len(annotation), 12000)

    def test_unknown_args_fail_without_running(self):
        code, _, run = self.invoke(['--bad'], 0, '')
        self.assertEqual(code, 2); run.assert_not_called()


if __name__ == '__main__': unittest.main()
