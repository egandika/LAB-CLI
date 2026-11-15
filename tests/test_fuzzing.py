import contextlib
import io
import json
import subprocess
import sys
import unittest
from unittest.mock import patch
from pathlib import Path

TEST_DIR = str(Path(__file__).resolve().parent)
if TEST_DIR not in sys.path:
    sys.path.insert(0, TEST_DIR)

from apklab.cli import main
from apklab.fuzzing import run_smoke


class ParserFuzzSmokeTests(unittest.TestCase):
    def test_synthetic_mutations_are_bounded_and_reproducible(self):
        first = run_smoke(seed=1234, cases=64, max_input_bytes=64 * 1024)
        second = run_smoke(seed=1234, cases=64, max_input_bytes=64 * 1024)
        self.assertEqual(first, second)
        self.assertTrue(first['synthetic_inputs_only'])
        self.assertFalse(first['app_code_executed'])
        self.assertEqual(first['cases_per_parser'], 64)
        self.assertEqual(first['total_cases'], 384)
        self.assertEqual(first['seed_validation_count'], 6)
        self.assertEqual(first['seed_failures'], [])
        self.assertLessEqual(first['max_input_bytes'], 8 * 1024 * 1024)
        self.assertEqual(set(first['parsers']), {
            'binary_axml', 'aapt_dependencies', 'aapt_split_types',
            'aapt_manifest', 'dex', 'apk_zip'})
        self.assertEqual(first['harness_version'], 3)
        for result in first['parsers'].values():
            self.assertTrue(result['seed_accepted'])
            self.assertEqual(result['cases'], 64)
            self.assertEqual(len(result['seed_sha256']), 64)
            self.assertEqual(result['returned'] + result['rejected_as_invalid'], 64)
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
        self.assertEqual(report['total_cases'], 48)
        self.assertEqual(report['seed_validation_count'], 6)
        self.assertEqual(report['seed_failures'], [])
        self.assertTrue(all(parser['seed_accepted'] for parser in report['parsers'].values()))
        self.assertEqual(report['unexpected_exceptions'], [])

    def test_apklab_fuzz_command_runs_the_real_engine(self):
        output = io.StringIO()
        with patch('apklab.cli.run', side_effect=AssertionError('fuzz must not run external tools')), contextlib.redirect_stdout(output):
            code = main(['fuzz', '--seed', '7', '--cases', '8', '--max-input-mib', '1'])
        self.assertEqual(code, 3)
        result = json.loads(output.getvalue())
        self.assertTrue(result['fuzz']['synthetic_inputs_only'])
        self.assertFalse(result['fuzz']['app_code_executed'])
        self.assertEqual(result['fuzz']['total_cases'], 48)
        self.assertEqual(result['fuzz']['seed_failures'], [])
        self.assertEqual(result['fuzz']['unexpected_exceptions'], [])
        self.assertTrue(result['verified'])
        self.assertTrue(result['not_tested'])

    def test_invalid_synthetic_seed_is_not_reported_as_verified(self):
        output = io.StringIO()
        with patch('apklab.fuzzing.parse_manifest', side_effect=ValueError('invalid seed')), contextlib.redirect_stdout(output):
            code = main(['fuzz', '--seed', '7', '--cases', '1', '--max-input-mib', '1'])
        result = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertFalse(result['verified'])
        self.assertEqual(result['fuzz']['seed_failures'][0]['parser'], 'binary_axml')
        self.assertFalse(result['fuzz']['parsers']['binary_axml']['seed_accepted'])
        self.assertEqual(result['fuzz']['seed_failures'][0]['message'], 'invalid seed')


if __name__ == '__main__':
    unittest.main()
