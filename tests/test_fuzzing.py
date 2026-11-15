import json
import subprocess
import sys
import unittest
from pathlib import Path

TEST_DIR = str(Path(__file__).resolve().parent)
if TEST_DIR not in sys.path:
    sys.path.insert(0, TEST_DIR)

from fuzz_parser_inputs import run_smoke


class ParserFuzzSmokeTests(unittest.TestCase):
    def test_synthetic_mutations_are_bounded_and_reproducible(self):
        first = run_smoke(seed=1234, cases=64, max_input_bytes=64 * 1024)
        second = run_smoke(seed=1234, cases=64, max_input_bytes=64 * 1024)
        self.assertEqual(first, second)
        self.assertTrue(first['synthetic_inputs_only'])
        self.assertFalse(first['app_code_executed'])
        self.assertEqual(first['cases_per_parser'], 64)
        self.assertEqual(first['total_cases'], 192)
        self.assertLessEqual(first['max_input_bytes'], 8 * 1024 * 1024)
        self.assertEqual(set(first['parsers']), {'axml', 'dex', 'zip'})
        self.assertEqual(first['harness_version'], 1)
        for result in first['parsers'].values():
            self.assertEqual(result['cases'], 64)
            self.assertEqual(len(result['seed_sha256']), 64)
            self.assertEqual(result['accepted'] + result['rejected_as_invalid'], 64)
        self.assertEqual(first['unexpected_exceptions'], [])

    def test_smoke_harness_enforces_input_and_case_caps(self):
        with self.assertRaisesRegex(ValueError, 'cases must be'):
            run_smoke(cases=10001)
        with self.assertRaisesRegex(ValueError, 'max_input_bytes must be'):
            run_smoke(max_input_bytes=8 * 1024 * 1024 + 1)

    def test_command_line_emits_synthetic_only_result_without_side_effects(self):
        result = subprocess.run(
            [sys.executable, 'tests/fuzz_parser_inputs.py', '--seed', '7', '--cases', '8'],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report['synthetic_inputs_only'])
        self.assertFalse(report['app_code_executed'])
        self.assertEqual(report['cases_per_parser'], 8)
        self.assertEqual(report['unexpected_exceptions'], [])


if __name__ == '__main__':
    unittest.main()
